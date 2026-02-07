// Package daemon implements the secrets daemon that serves credentials over a Unix socket.
package daemon

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"claw-wrap/internal/auth"
	"claw-wrap/internal/config"
	"claw-wrap/internal/credentials"
	"claw-wrap/internal/framing"
	"claw-wrap/internal/protocol"
)

// DefaultSocketPath is the default Unix socket path.
const DefaultSocketPath = "/run/openclaw/secrets.sock"

// Daemon is the secrets daemon server.
type Daemon struct {
	socketPath      string
	configPath      string
	allowedUID      uint32
	allowedBinaries []string
	listener        net.Listener
	secret          []byte

	cfg   *config.Config
	cfgMu sync.RWMutex
}

// Option configures the daemon.
type Option func(*Daemon)

// WithSocketPath sets the socket path.
func WithSocketPath(path string) Option {
	return func(d *Daemon) { d.socketPath = path }
}

// WithConfigPath sets the config file path.
func WithConfigPath(path string) Option {
	return func(d *Daemon) { d.configPath = path }
}

// WithAllowedUID sets the allowed UID for connections.
func WithAllowedUID(uid uint32) Option {
	return func(d *Daemon) { d.allowedUID = uid }
}

// WithAllowedBinaries sets the allowed binary paths.
func WithAllowedBinaries(binaries []string) Option {
	return func(d *Daemon) { d.allowedBinaries = binaries }
}

// New creates a new daemon with the given options.
func New(opts ...Option) *Daemon {
	d := &Daemon{
		socketPath:     DefaultSocketPath,
		configPath:     config.DefaultConfigPath,
		allowedUID:     1000, // Default UID (typically first non-root user)
		allowedBinaries: []string{"/usr/local/bin/claw-wrap"},
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Run starts the daemon and blocks until shutdown.
func (d *Daemon) Run() error {
	// Load initial config
	cfg, err := config.Load(d.configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	log.Printf("[INFO] Loaded %d credentials from config", len(cfg.Credentials))

	// Generate HMAC secret for proxy authentication
	secret, err := auth.GenerateSecret()
	if err != nil {
		return fmt.Errorf("generate HMAC secret: %w", err)
	}
	d.secret = secret

	// Write secret to configured path
	secretPath := cfg.GetHMACSecretFile()
	if err := auth.WriteSecret(secretPath, secret); err != nil {
		return fmt.Errorf("write HMAC secret: %w", err)
	}
	log.Printf("[INFO] HMAC secret written to %s", secretPath)

	// Ensure runtime directory exists
	runtimeDir := "/run/openclaw"
	if err := os.MkdirAll(runtimeDir, 0755); err != nil {
		return fmt.Errorf("create runtime dir: %w", err)
	}

	// Remove stale socket
	if err := os.Remove(d.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	// Create listener with world-writable permissions via umask (no chmod race)
	oldUmask := syscall.Umask(0o111)
	listener, err := net.Listen("unix", d.socketPath)
	syscall.Umask(oldUmask)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	d.listener = listener

	// Cache initial config
	d.cfgMu.Lock()
	d.cfg = cfg
	d.cfgMu.Unlock()

	log.Printf("Secrets daemon listening on %s", d.socketPath)

	// Handle signals: SIGINT/SIGTERM for shutdown, SIGHUP for config reload
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			if sig == syscall.SIGHUP {
				if err := d.reloadConfig(); err != nil {
					log.Printf("[ERROR] Config reload failed: %v (keeping previous config)", err)
				} else {
					log.Printf("[INFO] Config reloaded successfully")
				}
				continue
			}
			log.Println("[INFO] Shutting down...")
			listener.Close()
			return
		}
	}()

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				return nil // Clean shutdown
			}
			log.Printf("[ERROR] Accept: %v", err)
			continue
		}

		go d.handleConnection(conn, d.getConfig())
	}
}

// reloadConfig loads and validates a new config, replacing the cached one.
// On error, the previous config is preserved.
func (d *Daemon) reloadConfig() error {
	newCfg, err := config.Load(d.configPath)
	if err != nil {
		return err
	}

	d.cfgMu.Lock()
	d.cfg = newCfg
	d.cfgMu.Unlock()
	return nil
}

// getConfig returns the current cached config.
func (d *Daemon) getConfig() *config.Config {
	d.cfgMu.RLock()
	defer d.cfgMu.RUnlock()
	return d.cfg
}

// handleConnection processes a single client connection.
func (d *Daemon) handleConnection(conn net.Conn, cfg *config.Config) {
	defer conn.Close()

	// Read request
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("[ERROR] Read: %v", err)
		return
	}

	// Get peer credentials
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		d.sendError(conn, "internal error: not a unix connection")
		return
	}

	ucred, err := getPeerCredentials(unixConn)
	if err != nil {
		log.Printf("[ERROR] Get peer credentials: %v", err)
		d.sendError(conn, "failed to verify caller")
		return
	}

	// Verify caller
	if ucred.UID != d.allowedUID {
		log.Printf("[WARN] Unauthorized UID %d", ucred.UID)
		d.sendError(conn, "unauthorized caller")
		return
	}

	// Check binary path if we can read it
	exePath := fmt.Sprintf("/proc/%d/exe", ucred.PID)
	exe, err := os.Readlink(exePath)
	callerInfo := fmt.Sprintf("sandboxed-pid:%d", ucred.PID)
	if err == nil {
		callerInfo = exe
		if !d.isAllowedBinary(exe) {
			log.Printf("[WARN] Unauthorized binary %s", exe)
			d.sendError(conn, "unauthorized caller")
			return
		}
	}
	log.Printf("[DEBUG] Peer PID=%d UID=%d EXE=%s", ucred.PID, ucred.UID, callerInfo)

	// Parse request
	var rawRequest map[string]interface{}
	if err := json.Unmarshal(buf[:n], &rawRequest); err != nil {
		d.sendError(conn, fmt.Sprintf("invalid json: %v", err))
		return
	}

	// Route based on request type (check admin first since admin requests now include hmac)
	switch {
	case rawRequest["admin"] != nil:
		d.handleAdminRequest(conn, buf[:n], cfg)
	case rawRequest["hmac"] != nil:
		d.handleProxyRequest(conn, buf[:n], cfg, callerInfo)
	default:
		d.sendError(conn, "invalid request: use proxy protocol")
	}
}

// handleAdminRequest processes an admin command.
func (d *Daemon) handleAdminRequest(conn net.Conn, data []byte, cfg *config.Config) {
	var req protocol.AdminRequest
	if err := json.Unmarshal(data, &req); err != nil {
		d.sendError(conn, err.Error())
		return
	}

	// Verify HMAC (admin requests use tool="admin:<command>", no args, no cwd)
	if err := auth.VerifyHMAC(d.secret, req.Timestamp, "admin:"+req.Admin, "", nil, req.HMAC); err != nil {
		log.Printf("[WARN] Admin auth failed for %s: %v", req.Admin, err)
		d.sendError(conn, "authentication failed")
		return
	}

	switch req.Admin {
	case "list":
		resp := protocol.AdminListResponse{Tools: make(map[string]protocol.ToolInfo)}
		for name, tool := range cfg.Tools {
			mode := "env"
			if tool.ConfigFile != nil {
				mode = "config_file"
			}
			resp.Tools[name] = protocol.ToolInfo{Binary: tool.Binary, Mode: mode}
		}
		d.sendJSON(conn, resp)

	case "check":
		resp := protocol.AdminCheckResponse{Credentials: make(map[string]protocol.CredentialInfo)}
		for name, credDef := range cfg.Credentials {
			value, err := credentials.Fetch(credDef.Source, credentials.WithPassBinary(cfg.GetPassBinary()))
			if err != nil || value == "" {
				resp.Credentials[name] = protocol.CredentialInfo{Status: "failed"}
			} else {
				preview := value
				if len(preview) > 12 {
					preview = preview[:4] + "..." + preview[len(preview)-4:]
				}
				resp.Credentials[name] = protocol.CredentialInfo{Status: "ok", Preview: preview}
			}
		}
		d.sendJSON(conn, resp)

	default:
		d.sendError(conn, fmt.Sprintf("unknown admin command: %s", req.Admin))
	}
}

// handleProxyRequest processes a proxy mode tool execution request.
func (d *Daemon) handleProxyRequest(conn net.Conn, data []byte, cfg *config.Config, callerInfo string) {
	var req protocol.ProxyRequest
	if err := json.Unmarshal(data, &req); err != nil {
		d.sendProxyError(conn, "invalid request")
		return
	}

	// Verify HMAC
	if err := auth.VerifyHMAC(d.secret, req.Timestamp, req.Tool, req.Cwd, req.Args, req.HMAC); err != nil {
		log.Printf("[WARN] Auth failed for %s: %v", req.Tool, err)
		d.sendProxyError(conn, "authentication failed")
		return
	}

	// Look up tool
	tool, ok := cfg.Tools[req.Tool]
	if !ok {
		d.sendProxyError(conn, fmt.Sprintf("unknown tool: %s", req.Tool))
		return
	}

	// Check blocked args
	if allowed, msg := checkBlockedArgs(req.Args, tool.BlockedArgs); !allowed {
		log.Printf("[INFO] Blocked: %s - %s", req.Tool, msg)
		d.sendProxyError(conn, fmt.Sprintf("blocked: %s", msg))
		return
	}

	// Log (redacted args)
	log.Printf("[INFO] Proxy: tool=%s cwd=%s from=%s", req.Tool, req.Cwd, callerInfo)

	// Create and run executor
	executor := NewToolExecutor(conn, &req, &tool, cfg)
	if err := executor.Run(); err != nil {
		log.Printf("[ERROR] Executor failed: %v", err)
	}
}

// sendProxyError sends an error message using the proxy protocol (length-prefixed framing).
func (d *Daemon) sendProxyError(conn net.Conn, message string) {
	encoder := framing.NewEncoder(conn)
	encoder.Encode(&protocol.ResponseMessage{
		Type:    protocol.MsgTypeError,
		Message: message,
	})
}

// checkBlockedArgs validates args against blocked patterns.
func checkBlockedArgs(args []string, blocked []config.BlockedArg) (bool, string) {
	if len(blocked) == 0 {
		return true, ""
	}

	cmdLine := strings.Join(args, " ")
	for _, b := range blocked {
		if b.Compiled == nil {
			log.Printf("[ERROR] Nil compiled pattern for %q - fail-closed", b.Pattern)
			return false, "internal error: invalid security pattern"
		}
		if b.Compiled.MatchString(cmdLine) {
			msg := b.Message
			if msg == "" {
				msg = "operation blocked by security policy"
			}
			return false, msg
		}
	}

	return true, ""
}

// renderTemplate substitutes credential values into a template.
func renderTemplate(template string, values map[string]string) string {
	content := template
	for name, value := range values {
		placeholder := "{{ ." + name + " }}"
		content = strings.ReplaceAll(content, placeholder, value)

		// Also support underscore variant
		underscoreName := strings.ReplaceAll(name, "-", "_")
		placeholder = "{{ ." + underscoreName + " }}"
		content = strings.ReplaceAll(content, placeholder, value)
	}
	return content
}

// isAllowedBinary checks if the binary path is allowed.
func (d *Daemon) isAllowedBinary(exe string) bool {
	for _, allowed := range d.allowedBinaries {
		if exe == allowed {
			return true
		}
	}
	return false
}

// sendError sends an error response to the client (for admin requests).
func (d *Daemon) sendError(conn net.Conn, msg string) {
	d.sendJSON(conn, map[string]string{"error": msg})
}

// sendJSON sends a JSON response to the client.
func (d *Daemon) sendJSON(conn net.Conn, v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		log.Printf("[ERROR] Marshal response: %v", err)
		return
	}
	conn.Write(data)
}

// Ucred holds Unix credentials from SO_PEERCRED.
type Ucred struct {
	PID int32
	UID uint32
	GID uint32
}

// getPeerCredentials retrieves the peer's credentials via SO_PEERCRED.
func getPeerCredentials(conn *net.UnixConn) (*Ucred, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var ucred *Ucred
	var credErr error

	err = rawConn.Control(func(fd uintptr) {
		buf := make([]byte, 12) // sizeof(struct ucred)
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.SOL_SOCKET,
			syscall.SO_PEERCRED,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&[]int{12}[0])),
			0,
		)
		if errno != 0 {
			credErr = errno
			return
		}
		ucred = &Ucred{
			PID: int32(binary.LittleEndian.Uint32(buf[0:4])),
			UID: binary.LittleEndian.Uint32(buf[4:8]),
			GID: binary.LittleEndian.Uint32(buf[8:12]),
		}
	})

	if err != nil {
		return nil, err
	}
	if credErr != nil {
		return nil, credErr
	}

	return ucred, nil
}
