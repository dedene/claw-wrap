// Package daemon implements the secrets daemon that serves credentials over a Unix socket.
package daemon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"claw-wrap/internal/auth"
	"claw-wrap/internal/config"
	"claw-wrap/internal/credentials"
	"claw-wrap/internal/framing"
	"claw-wrap/internal/protocol"
)

// DefaultSocketPath is the default Unix socket path.
const DefaultSocketPath = "/run/openclaw/secrets.sock"

// Ucred holds Unix peer credentials.
type Ucred struct {
	PID int32
	UID uint32
	GID uint32
}

// Daemon is the secrets daemon server.
type Daemon struct {
	socketPath      string
	configPath      string
	allowedUID      uint32
	allowedBinaries []string
	version         string
	listener        net.Listener
	secret          []byte

	cfg         *config.Config
	cfgMu       sync.RWMutex
	connSem     chan struct{}
	replayCache *auth.ReplayCache
	metrics     *securityMetrics
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

// WithVersion sets the daemon version for admin responses.
func WithVersion(v string) Option {
	return func(d *Daemon) { d.version = v }
}

// New creates a new daemon with the given options.
func New(opts ...Option) *Daemon {
	// Auto-detect own binary path; fall back to common default.
	selfPath := "/usr/local/bin/claw-wrap"
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			selfPath = resolved
		}
	}

	d := &Daemon{
		socketPath:      DefaultSocketPath,
		configPath:      config.DefaultConfigPath,
		allowedUID:      1000, // Default UID (typically first non-root user)
		allowedBinaries: []string{selfPath},
		metrics:         newSecurityMetrics(),
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Run starts the daemon and blocks until shutdown.
func (d *Daemon) Run() error {
	cfg, err := config.Load(d.configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	log.Printf("[INFO] Loaded %d credentials from config", len(cfg.Credentials))

	secret, err := auth.GenerateSecret()
	if err != nil {
		return fmt.Errorf("generate HMAC secret: %w", err)
	}
	d.secret = secret

	secretPath := cfg.GetHMACSecretFile()
	if err := auth.WriteSecret(secretPath, secret); err != nil {
		return fmt.Errorf("write HMAC secret: %w", err)
	}
	log.Printf("[INFO] HMAC secret written to %s", secretPath)

	runtimeDir := "/run/openclaw"
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return fmt.Errorf("create runtime dir: %w", err)
	}
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		return fmt.Errorf("chmod runtime dir: %w", err)
	}

	if err := os.Remove(d.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	oldUmask := syscall.Umask(0o177)
	listener, err := net.Listen("unix", d.socketPath)
	syscall.Umask(oldUmask)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	d.listener = listener

	if err := os.Chmod(d.socketPath, 0o600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	d.cfgMu.Lock()
	d.cfg = cfg
	d.cfgMu.Unlock()

	d.connSem = make(chan struct{}, cfg.GetMaxConnections())
	d.replayCache = auth.NewReplayCache(cfg.GetReplayCacheTTL(), cfg.GetReplayCacheMaxEntries())

	go d.logMetricsLoop()
	log.Printf("[INFO] Secrets daemon listening on %s", d.socketPath)

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

	for {
		conn, err := listener.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				return nil
			}
			log.Printf("[ERROR] accept err=%v", err)
			continue
		}

		if !d.acquireConnSlot() {
			d.metrics.Inc("rate_limited")
			log.Printf("[WARN] deny reason=rate_limited")
			d.sendError(conn, "server busy")
			_ = conn.Close()
			continue
		}

		go func(c net.Conn) {
			defer d.releaseConnSlot()
			d.handleConnection(c, d.getConfig())
		}(conn)
	}
}

func (d *Daemon) acquireConnSlot() bool {
	select {
	case d.connSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (d *Daemon) releaseConnSlot() {
	select {
	case <-d.connSem:
	default:
	}
}

func (d *Daemon) reloadConfig() error {
	newCfg, err := config.Load(d.configPath)
	if err != nil {
		return err
	}

	d.cfgMu.Lock()
	d.cfg = newCfg
	d.replayCache = auth.NewReplayCache(newCfg.GetReplayCacheTTL(), newCfg.GetReplayCacheMaxEntries())
	d.cfgMu.Unlock()
	return nil
}

func (d *Daemon) getConfig() *config.Config {
	d.cfgMu.RLock()
	defer d.cfgMu.RUnlock()
	return d.cfg
}

func (d *Daemon) handleConnection(conn net.Conn, cfg *config.Config) {
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(cfg.GetReadHeaderTimeout())); err != nil {
		log.Printf("[WARN] set header deadline: %v", err)
	}

	buf := make([]byte, 64*1024)
	n, err := conn.Read(buf)
	if err != nil {
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			d.metrics.Inc("read_timeout")
			log.Printf("[WARN] deny reason=read_timeout stage=header")
			d.sendError(conn, "request read timeout")
			return
		}
		log.Printf("[ERROR] read request: %v", err)
		return
	}

	_ = conn.SetReadDeadline(time.Time{})

	if n == len(buf) {
		d.metrics.Inc("oversized_msg")
		log.Printf("[WARN] deny reason=oversized_msg stage=header")
		d.sendError(conn, "request too large")
		return
	}

	payload := bytes.TrimSpace(buf[:n])
	if len(payload) == 0 {
		d.sendError(conn, "empty request")
		return
	}

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		d.metrics.Inc("caller_verify_fail")
		d.sendError(conn, "internal error: not a unix connection")
		return
	}

	ucred, err := getPeerCredentials(unixConn)
	if err != nil {
		d.metrics.Inc("caller_verify_fail")
		log.Printf("[WARN] deny reason=peer_cred_error err=%v", err)
		d.sendError(conn, "failed to verify caller")
		return
	}

	if ucred.UID != d.allowedUID {
		d.metrics.Inc("caller_verify_fail")
		log.Printf("[WARN] deny reason=uid_mismatch uid=%d expected=%d", ucred.UID, d.allowedUID)
		d.sendError(conn, "unauthorized caller")
		return
	}

	callerInfo := fmt.Sprintf("pid:%d", ucred.PID)
	exe, err := resolvePeerExecutable(ucred.PID)
	if err != nil {
		if !cfg.AllowUnverifiedCallerExe() {
			d.metrics.Inc("caller_verify_fail")
			log.Printf("[WARN] deny reason=exe_unreadable pid=%d err=%v", ucred.PID, err)
			d.sendError(conn, "unauthorized caller")
			return
		}
		callerInfo = fmt.Sprintf("pid:%d exe:unverified", ucred.PID)
	} else {
		callerInfo = exe
		if !d.isAllowedBinary(exe) {
			d.metrics.Inc("caller_verify_fail")
			log.Printf("[WARN] deny reason=exe_not_allowed exe=%q", exe)
			d.sendError(conn, "unauthorized caller")
			return
		}
	}

	log.Printf("[DEBUG] peer pid=%d uid=%d exe=%s", ucred.PID, ucred.UID, callerInfo)

	var rawRequest map[string]interface{}
	if err := json.Unmarshal(payload, &rawRequest); err != nil {
		d.sendError(conn, "invalid json")
		return
	}

	switch {
	case rawRequest["admin"] != nil:
		d.handleAdminRequest(conn, payload, cfg, ucred.UID)
	case rawRequest["hmac"] != nil:
		d.handleProxyRequest(conn, payload, cfg, callerInfo, ucred.UID)
	default:
		d.sendError(conn, "invalid request: use proxy protocol")
	}
}

func (d *Daemon) handleAdminRequest(conn net.Conn, data []byte, cfg *config.Config, uid uint32) {
	var req protocol.AdminRequest
	if err := json.Unmarshal(data, &req); err != nil {
		d.sendError(conn, "invalid request")
		return
	}

	if req.Version != protocol.ProtocolVersion {
		d.sendError(conn, fmt.Sprintf("protocol version mismatch: got %d want %d", req.Version, protocol.ProtocolVersion))
		return
	}

	if err := auth.VerifyHMAC(d.secret, req.Timestamp, "admin:"+req.Admin, "", nil, req.HMAC); err != nil {
		d.metrics.Inc("auth_fail")
		log.Printf("[WARN] deny reason=auth_failed admin=%s err=%v", req.Admin, err)
		d.sendError(conn, "authentication failed")
		return
	}

	replayKey := fmt.Sprintf("%d:admin:%s", uid, req.HMAC)
	if d.replayCache.SeenOrStore(replayKey, time.Now()) {
		d.metrics.Inc("replay_reject")
		log.Printf("[WARN] deny reason=replay admin=%s", req.Admin)
		d.sendError(conn, "authentication failed")
		return
	}

	switch req.Admin {
	case "list":
		resp := protocol.AdminListResponse{Tools: make(map[string]protocol.ToolInfo), Version: d.version}
		for name, tool := range cfg.Tools {
			mode := "env"
			if tool.ConfigFile != nil {
				mode = "config_file"
			}
			resp.Tools[name] = protocol.ToolInfo{Binary: tool.Binary, Mode: mode}
		}
		d.sendJSON(conn, resp)

	case "check":
		resp := protocol.AdminCheckResponse{Credentials: make(map[string]protocol.CredentialInfo), Version: d.version}
		for name, credDef := range cfg.Credentials {
			value, err := credentials.Fetch(credDef.Source, credentials.WithPassBinary(cfg.GetPassBinary()))
			if err != nil || value == "" {
				resp.Credentials[name] = protocol.CredentialInfo{Status: "failed"}
			} else {
				resp.Credentials[name] = protocol.CredentialInfo{Status: "ok", Preview: credentialPreview(value)}
			}
		}
		d.sendJSON(conn, resp)

	default:
		d.sendError(conn, fmt.Sprintf("unknown admin command: %s", req.Admin))
	}
}

func (d *Daemon) handleProxyRequest(conn net.Conn, data []byte, cfg *config.Config, callerInfo string, uid uint32) {
	var req protocol.ProxyRequest
	if err := json.Unmarshal(data, &req); err != nil {
		d.sendProxyError(conn, "invalid request")
		return
	}

	if req.Version != protocol.ProtocolVersion {
		d.sendProxyError(conn, fmt.Sprintf("protocol version mismatch: got %d want %d", req.Version, protocol.ProtocolVersion))
		return
	}

	if err := auth.VerifyHMACWithEnv(d.secret, req.Timestamp, req.Tool, req.Cwd, req.Args, req.Env, req.HMAC); err != nil {
		d.metrics.Inc("auth_fail")
		log.Printf("[WARN] deny reason=auth_failed tool=%s err=%v", req.Tool, err)
		d.sendProxyError(conn, "authentication failed")
		return
	}

	replayKey := fmt.Sprintf("%d:proxy:%s", uid, req.HMAC)
	if d.replayCache.SeenOrStore(replayKey, time.Now()) {
		d.metrics.Inc("replay_reject")
		log.Printf("[WARN] deny reason=replay tool=%s", req.Tool)
		d.sendProxyError(conn, "authentication failed")
		return
	}

	tool, ok := cfg.Tools[req.Tool]
	if !ok {
		d.sendProxyError(conn, fmt.Sprintf("unknown tool: %s", req.Tool))
		return
	}

	if allowed, msg := checkBlockedArgs(req.Args, tool.BlockedArgs); !allowed {
		d.metrics.Inc("blocked_args")
		log.Printf("[INFO] deny reason=blocked_args tool=%s msg=%s", req.Tool, msg)
		d.sendProxyError(conn, fmt.Sprintf("blocked: %s", msg))
		return
	}

	log.Printf("[INFO] proxy tool=%s cwd=%s from=%s", req.Tool, req.Cwd, callerInfo)

	executor := NewToolExecutor(conn, &req, &tool, cfg)
	if err := executor.Run(); err != nil {
		log.Printf("[ERROR] executor failed: %v", err)
	}
}

func (d *Daemon) sendProxyError(conn net.Conn, message string) {
	encoder := framing.NewEncoder(conn)
	_ = encoder.Encode(&protocol.ResponseMessage{
		Type:    protocol.MsgTypeError,
		Message: message,
	})
}

func checkBlockedArgs(args []string, blocked []config.BlockedArg) (bool, string) {
	if len(blocked) == 0 {
		return true, ""
	}

	cmdLine := strings.Join(args, " ")
	for _, b := range blocked {
		if b.Compiled == nil {
			log.Printf("[ERROR] nil compiled pattern for %q - fail-closed", b.Pattern)
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

		underscoreName := strings.ReplaceAll(name, "-", "_")
		placeholder = "{{ ." + underscoreName + " }}"
		content = strings.ReplaceAll(content, placeholder, value)
	}
	return content
}

func (d *Daemon) isAllowedBinary(exe string) bool {
	normalizedExe := normalizeExecutablePath(exe)
	for _, allowed := range d.allowedBinaries {
		if normalizeExecutablePath(allowed) == normalizedExe {
			return true
		}
	}
	return false
}

func normalizeExecutablePath(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		p = resolved
	}
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	return filepath.Clean(p)
}

func (d *Daemon) sendError(conn net.Conn, msg string) {
	d.sendJSON(conn, map[string]string{"error": msg})
}

func (d *Daemon) sendJSON(conn net.Conn, v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		log.Printf("[ERROR] marshal response: %v", err)
		return
	}
	if _, err := conn.Write(data); err != nil {
		log.Printf("[WARN] write response: %v", err)
	}
}

type securityMetrics struct {
	mu       sync.Mutex
	counters map[string]uint64
}

func newSecurityMetrics() *securityMetrics {
	return &securityMetrics{counters: make(map[string]uint64)}
}

func (m *securityMetrics) Inc(key string) {
	m.mu.Lock()
	m.counters[key]++
	m.mu.Unlock()
}

func (m *securityMetrics) Snapshot() map[string]uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]uint64, len(m.counters))
	for k, v := range m.counters {
		out[k] = v
	}
	return out
}

func (d *Daemon) logMetricsLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s := d.metrics.Snapshot()
		if len(s) == 0 {
			continue
		}
		payload, _ := json.Marshal(s)
		log.Printf("[INFO] security_metrics %s", payload)
	}
}
