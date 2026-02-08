// Package daemon implements the secrets daemon that serves credentials over a Unix socket.
package daemon

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"claw-wrap/internal/httpproxy"
	"claw-wrap/internal/paths"
	"claw-wrap/internal/protocol"
	"golang.org/x/sys/unix"
)

// DefaultSocketPath is the default Unix socket path.
var DefaultSocketPath = paths.SocketPath()

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
	httpProxy   *httpproxy.Proxy

	proxyAuthToken     string
	proxyAuthTokenPath string
}

var (
	resolvePeerExecutableFunc = resolvePeerExecutable
	resolvePeerArgv0Func      = resolvePeerArgv0
	setAgeIdentityFileFunc    = credentials.SetAgeIdentityFile
	setOPTokenFileFunc        = credentials.SetOPTokenFile
	setCredentialCacheTTLFunc = credentials.SetCredentialCacheTTL
	fetchCredentialFunc       = credentials.Fetch
	cleanupBWSessionFunc      = credentials.CleanupBWSession
)

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
		socketPath:         DefaultSocketPath,
		configPath:         config.DefaultConfigPath,
		allowedUID:         uint32(os.Getuid()),
		allowedBinaries:    []string{selfPath},
		metrics:            newSecurityMetrics(),
		proxyAuthTokenPath: paths.ProxyAuthTokenPath(),
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
	setAgeIdentityFileFunc(cfg.GetAgeIdentityFile())
	setOPTokenFileFunc(cfg.GetOPTokenFile())
	setCredentialCacheTTLFunc(cfg.GetCredentialCacheTTL())
	defer cleanupBWSessionFunc()

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

	runtimeDir := paths.RuntimeDir()
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

	// Sweep stale temp directories from crashed daemon processes
	sweepStaleTempDirs()

	d.connSem = make(chan struct{}, cfg.GetMaxConnections())
	d.replayCache = auth.NewReplayCache(cfg.GetReplayCacheTTL(), cfg.GetReplayCacheMaxEntries())

	// Start HTTP proxy if enabled
	if err := d.startHTTPProxy(cfg); err != nil {
		log.Printf("[WARN] HTTP proxy failed to start: %v", err)
		// Continue without HTTP proxy - it's optional
	}

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
			if err := d.stopHTTPProxy(); err != nil {
				log.Printf("[WARN] HTTP proxy stop: %v", err)
			}
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
	defer d.cfgMu.Unlock()

	switch {
	case d.httpProxy != nil && !newCfg.GetHTTPProxyEnabled():
		if err := d.httpProxy.Stop(); err != nil {
			return fmt.Errorf("stop HTTP proxy: %w", err)
		}
		d.httpProxy = nil
	case d.httpProxy == nil && newCfg.GetHTTPProxyEnabled():
		if err := d.startHTTPProxy(newCfg); err != nil {
			return fmt.Errorf("start HTTP proxy: %w", err)
		}
	case d.httpProxy != nil && newCfg.GetHTTPProxyEnabled():
		// Check if settings changed that require a restart
		oldCfg := d.cfg.GetHTTPProxyConfig()
		newHTTPCfg := newCfg.GetHTTPProxyConfig()
		needsRestart := oldCfg.Listen != newHTTPCfg.Listen ||
			oldCfg.GetRequireAuth() != newHTTPCfg.GetRequireAuth() ||
			oldCfg.CA.Path != newHTTPCfg.CA.Path

		if needsRestart {
			log.Printf("[INFO] HTTP proxy config changed (listen/auth/CA), restarting proxy")
			if err := d.httpProxy.Stop(); err != nil {
				return fmt.Errorf("stop HTTP proxy for restart: %w", err)
			}
			d.httpProxy = nil
			if err := d.startHTTPProxy(newCfg); err != nil {
				return fmt.Errorf("restart HTTP proxy: %w", err)
			}
		} else {
			d.httpProxy.ReloadConfig(newHTTPCfg, newCfg.Credentials)
		}
	}

	d.cfg = newCfg
	if d.replayCache != nil {
		d.replayCache.UpdateSettings(newCfg.GetReplayCacheTTL(), newCfg.GetReplayCacheMaxEntries())
	}

	// Configure credential backends only after config transition succeeds.
	setAgeIdentityFileFunc(newCfg.GetAgeIdentityFile())
	setOPTokenFileFunc(newCfg.GetOPTokenFile())
	setCredentialCacheTTLFunc(newCfg.GetCredentialCacheTTL())

	return nil
}

// startHTTPProxy starts the HTTP proxy if enabled in config.
func (d *Daemon) startHTTPProxy(cfg *config.Config) error {
	httpCfg := cfg.GetHTTPProxyConfig()
	if httpCfg == nil || !httpCfg.Enabled {
		return nil
	}
	requireAuth := httpCfg.GetRequireAuth()
	if requireAuth {
		if err := d.ensureProxyAuthToken(); err != nil {
			return fmt.Errorf("initialize HTTP proxy auth token: %w", err)
		}
	}

	proxy := httpproxy.New(httpCfg, cfg.Credentials,
		httpproxy.WithPassBinary(cfg.GetPassBinary()),
		httpproxy.WithOPBinary(cfg.GetOPBinary()),
		httpproxy.WithBWBinary(cfg.GetBWBinary()),
		httpproxy.WithAuthToken(d.proxyAuthToken),
		httpproxy.WithRequireAuth(requireAuth),
	)

	if err := proxy.Start(proxy.ListenAddr()); err != nil {
		return fmt.Errorf("start HTTP proxy: %w", err)
	}

	d.httpProxy = proxy
	return nil
}

// stopHTTPProxy stops the HTTP proxy with proper mutex protection.
func (d *Daemon) stopHTTPProxy() error {
	d.cfgMu.Lock()
	proxy := d.httpProxy
	d.httpProxy = nil
	d.cfgMu.Unlock()

	if proxy != nil {
		return proxy.Stop()
	}
	return nil
}

func (d *Daemon) getConfig() *config.Config {
	d.cfgMu.RLock()
	defer d.cfgMu.RUnlock()
	return d.cfg
}

func (d *Daemon) handleConnection(conn net.Conn, cfg *config.Config) {
	defer conn.Close()

	// Enforce overall connection lifetime if configured.
	if maxLife := cfg.GetMaxConnectionLifetime(); maxLife > 0 {
		_ = conn.SetDeadline(time.Now().Add(maxLife))
		// Individual read/write deadlines below may shorten this further
		// but can never extend past the overall deadline.
	}

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

	// Parse JSON early to determine request type so we can use the
	// correct error framing (raw JSON for admin, length-prefixed for proxy).
	var rawRequest map[string]interface{}
	if err := json.Unmarshal(payload, &rawRequest); err != nil {
		d.sendError(conn, "invalid json")
		return
	}
	isProxy := rawRequest["hmac"] != nil
	errSend := d.sendError
	if isProxy {
		errSend = d.sendProxyError
	}

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		d.metrics.Inc("caller_verify_fail")
		errSend(conn, "internal error: not a unix connection")
		return
	}

	ucred, err := getPeerCredentials(unixConn)
	if err != nil {
		d.metrics.Inc("caller_verify_fail")
		log.Printf("[WARN] deny reason=peer_cred_error err=%v", err)
		errSend(conn, "failed to verify caller")
		return
	}

	if ucred.UID != d.allowedUID {
		d.metrics.Inc("caller_verify_fail")
		log.Printf("[WARN] deny reason=uid_mismatch uid=%d expected=%d", ucred.UID, d.allowedUID)
		errSend(conn, "unauthorized caller")
		return
	}

	callerInfo := fmt.Sprintf("pid:%d", ucred.PID)
	exe, err := resolvePeerExecutableFunc(ucred.PID)
	if err != nil {
		if cfg.DenyUnverifiedCallerExe() {
			d.metrics.Inc("caller_verify_fail")
			log.Printf("[WARN] deny reason=exe_unreadable pid=%d err=%v", ucred.PID, err)
			errSend(conn, "unauthorized caller")
			return
		}
		callerInfo = fmt.Sprintf("pid:%d exe:unverified", ucred.PID)
	} else {
		callerInfo = exe
		if !d.isAllowedBinary(exe) {
			d.metrics.Inc("caller_verify_fail")
			log.Printf("[WARN] deny reason=exe_not_allowed exe=%q", exe)
			errSend(conn, "unauthorized caller")
			return
		}
	}

	log.Printf("[DEBUG] peer pid=%d uid=%d exe=%s", ucred.PID, ucred.UID, callerInfo)

	switch {
	case rawRequest["admin"] != nil:
		d.handleAdminRequest(conn, payload, cfg, ucred.UID, ucred.PID)
	case isProxy:
		d.handleProxyRequest(conn, payload, cfg, callerInfo, ucred.UID)
	default:
		d.sendError(conn, "invalid request: use proxy protocol")
	}
}

func (d *Daemon) handleAdminRequest(conn net.Conn, data []byte, cfg *config.Config, uid uint32, pid int32) {
	var req protocol.AdminRequest
	if err := json.Unmarshal(data, &req); err != nil {
		d.sendError(conn, "invalid request")
		return
	}

	if req.Version != protocol.ProtocolVersion {
		log.Printf("[WARN] admin protocol version mismatch: got %d want %d", req.Version, protocol.ProtocolVersion)
		d.sendError(conn, "protocol version mismatch")
		return
	}

	if err := auth.VerifyHMAC(d.secret, req.Timestamp, "admin:"+req.Admin, "", nil, req.Nonce, req.HMAC); err != nil {
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

	if req.Admin == "check" {
		if err := d.authorizeAdminCheckCaller(pid); err != nil {
			d.metrics.Inc("caller_verify_fail")
			log.Printf("[WARN] deny reason=check_gate pid=%d err=%v", pid, err)
			d.sendError(conn, "authentication failed")
			return
		}
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
			value, err := fetchCredentialFunc(
				credDef.Source,
				credentials.WithPassBinary(cfg.GetPassBinary()),
				credentials.WithOPBinary(cfg.GetOPBinary()),
				credentials.WithBWBinary(cfg.GetBWBinary()),
				credentials.WithBypassCache(),
			)
			if err != nil || value == "" {
				if err != nil {
					log.Printf("[ERROR] credential %q fetch failed: %v", name, err)
				} else {
					log.Printf("[ERROR] credential %q returned empty value", name)
				}
				resp.Credentials[name] = protocol.CredentialInfo{Status: "failed"}
			} else {
				resp.Credentials[name] = protocol.CredentialInfo{Status: "ok", Preview: credentialPreview(value)}
			}
		}
		// Add HTTP proxy info if enabled
		if cfg.HTTPProxy != nil && cfg.HTTPProxy.Enabled {
			caPath := cfg.GetHTTPProxyCAPath()
			if caPath == "" {
				caPath = httpproxy.DefaultCAPath()
			}
			info := &protocol.HTTPProxyInfo{
				Enabled:    true,
				Listen:     cfg.GetHTTPProxyListen(),
				CACertPath: filepath.Join(caPath, "ca.crt"),
			}
			if cfg.HTTPProxy.GetRequireAuth() {
				info.AuthTokenPath = d.proxyAuthTokenPath
			}
			resp.HTTPProxy = info
		}
		d.sendJSON(conn, resp)

	default:
		log.Printf("[WARN] unknown admin command: %s", req.Admin)
		d.sendError(conn, "unknown admin command")
	}
}

func (d *Daemon) authorizeAdminCheckCaller(pid int32) error {
	exe, err := resolvePeerExecutableFunc(pid)
	if err != nil {
		return fmt.Errorf("resolve caller executable: %w", err)
	}
	if !d.isAllowedBinary(exe) {
		return fmt.Errorf("caller executable not allowed: %q", exe)
	}

	argv0, err := resolvePeerArgv0Func(pid)
	if err != nil {
		return fmt.Errorf("resolve caller argv0: %w", err)
	}
	if filepath.Base(argv0) != "claw-wrap" {
		return fmt.Errorf("unexpected caller argv0 %q", argv0)
	}
	return nil
}

func (d *Daemon) handleProxyRequest(conn net.Conn, data []byte, cfg *config.Config, callerInfo string, uid uint32) {
	var req protocol.ProxyRequest
	if err := json.Unmarshal(data, &req); err != nil {
		d.sendProxyError(conn, "invalid request")
		return
	}

	if req.Version != protocol.ProtocolVersion {
		log.Printf("[WARN] proxy protocol version mismatch: got %d want %d", req.Version, protocol.ProtocolVersion)
		d.sendProxyError(conn, "protocol version mismatch")
		return
	}

	if err := auth.VerifyHMACWithEnv(d.secret, req.Timestamp, req.Tool, req.Cwd, req.Args, req.Env, req.Nonce, req.HMAC); err != nil {
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
		log.Printf("[WARN] unknown tool requested: %s", req.Tool)
		d.sendProxyError(conn, "unknown tool")
		return
	}

	if allowed, msg := checkBlockedArgs(req.Args, tool.BlockedArgs); !allowed {
		d.metrics.Inc("blocked_args")
		log.Printf("[INFO] deny reason=blocked_args tool=%s msg=%s", req.Tool, msg)
		d.sendProxyError(conn, fmt.Sprintf("blocked: %s", msg))
		return
	}

	log.Printf("[INFO] proxy tool=%s cwd=%s from=%s", req.Tool, req.Cwd, callerInfo)

	executor, err := NewToolExecutor(conn, &req, &tool, cfg, d.proxyAuthToken)
	if err != nil {
		log.Printf("[ERROR] executor init failed: %v", err)
		d.sendProxyError(conn, err.Error())
		return
	}
	if err := executor.Run(); err != nil {
		log.Printf("[ERROR] executor failed: %v", err)
	}
}

const proxyAuthTokenBytes = 32

var errProxyAuthTokenNotFound = errors.New("proxy auth token file not found")

func (d *Daemon) ensureProxyAuthToken() error {
	if d.proxyAuthToken != "" {
		return nil
	}

	token, err := loadProxyAuthToken(d.proxyAuthTokenPath)
	if err == nil {
		d.proxyAuthToken = token
		return nil
	}
	if !errors.Is(err, errProxyAuthTokenNotFound) {
		return err
	}

	token, err = generateProxyAuthToken()
	if err != nil {
		return err
	}
	if err := writeProxyAuthToken(d.proxyAuthTokenPath, token); err != nil {
		return err
	}
	d.proxyAuthToken = token
	return nil
}

func generateProxyAuthToken() (string, error) {
	buf := make([]byte, proxyAuthTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func loadProxyAuthToken(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOENT):
			return "", errProxyAuthTokenNotFound
		case errors.Is(err, unix.ELOOP):
			return "", fmt.Errorf("proxy auth token file must not be a symlink: %s", path)
		default:
			return "", fmt.Errorf("open proxy auth token file: %w", err)
		}
	}

	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return "", fmt.Errorf("open proxy auth token file: failed to create file handle")
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat proxy auth token file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("proxy auth token file must be a regular file: %s", path)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		return "", fmt.Errorf("proxy auth token file permissions must be 0600: %s has %04o", path, perm)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("unsupported proxy auth token file stat type")
	}
	if int(stat.Uid) != os.Geteuid() {
		return "", fmt.Errorf("proxy auth token file owner must match daemon uid: %s owner=%d daemon=%d", path, stat.Uid, os.Geteuid())
	}

	data, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("read proxy auth token file: %w", err)
	}

	token := strings.TrimSpace(string(data))
	if err := validateProxyAuthToken(token); err != nil {
		return "", fmt.Errorf("invalid proxy auth token in %s: %w", path, err)
	}
	return token, nil
}

func writeProxyAuthToken(path, token string) error {
	if err := validateProxyAuthToken(token); err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create proxy auth token dir: %w", err)
	}

	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write proxy auth token: %s is a symlink", path)
	}

	tmpFile, err := os.CreateTemp(dir, ".proxy-auth-token-*")
	if err != nil {
		return fmt.Errorf("create proxy auth token temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("chmod proxy auth token temp file: %w", err)
	}
	if _, err := tmpFile.WriteString(token + "\n"); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write proxy auth token: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync proxy auth token temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close proxy auth token temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename proxy auth token file: %w", err)
	}

	tmpPath = ""
	return nil
}

func validateProxyAuthToken(token string) error {
	if token == "" {
		return fmt.Errorf("proxy auth token is empty")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return fmt.Errorf("proxy auth token is not valid base64url: %w", err)
	}
	if len(decoded) != proxyAuthTokenBytes {
		return fmt.Errorf("proxy auth token entropy size = %d, want %d", len(decoded), proxyAuthTokenBytes)
	}
	return nil
}

func (d *Daemon) sendProxyError(conn net.Conn, message string) {
	writeTO := d.getConfig().GetWriteTimeout()
	if writeTO > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(writeTO))
		defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
	}

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

	joinedArgs := strings.Join(args, " ")

	for _, b := range blocked {
		if b.Compiled == nil {
			log.Printf("[ERROR] nil compiled pattern for %q - fail-closed", b.Pattern)
			return false, "internal error: invalid security pattern"
		}

		switch b.Match {
		case "", config.BlockedArgMatchArg:
			for _, arg := range args {
				if b.Compiled.MatchString(arg) {
					return false, blockedArgMessage(b.Message)
				}
			}
		case config.BlockedArgMatchCommand:
			if b.Compiled.MatchString(joinedArgs) {
				return false, blockedArgMessage(b.Message)
			}
		default:
			log.Printf("[ERROR] invalid blocked_args match mode %q - fail-closed", b.Match)
			return false, "internal error: invalid security pattern"
		}
	}

	return true, ""
}

func blockedArgMessage(msg string) string {
	if msg == "" {
		return "operation blocked by security policy"
	}
	return msg
}

// yamlEscapeValue wraps a credential value in single quotes for safe YAML
// interpolation. Embedded single quotes are escaped per the YAML spec by
// doubling them (” inside a single-quoted scalar).
func yamlEscapeValue(v string) string {
	escaped := strings.ReplaceAll(v, "'", "''")
	return "'" + escaped + "'"
}

// renderTemplate substitutes credential values into a template.
// Values are YAML-escaped (single-quoted) to prevent credential contents
// from breaking the template structure via special YAML characters.
func renderTemplate(template string, values map[string]string) string {
	content := template
	for name, value := range values {
		escaped := yamlEscapeValue(value)

		placeholder := "{{ ." + name + " }}"
		content = strings.ReplaceAll(content, placeholder, escaped)

		underscoreName := strings.ReplaceAll(name, "-", "_")
		placeholder = "{{ ." + underscoreName + " }}"
		content = strings.ReplaceAll(content, placeholder, escaped)
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
	writeTO := d.getConfig().GetWriteTimeout()
	if writeTO > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(writeTO))
		defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
	}

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

// sweepStaleTempDirs removes leftover claw-wrap-config-* directories
// from os.TempDir(). These are leftovers from crashed daemon processes.
func sweepStaleTempDirs() {
	pattern := filepath.Join(os.TempDir(), "claw-wrap-config-*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		log.Printf("[WARN] sweep stale temp dirs: glob error: %v", err)
		return
	}
	for _, m := range matches {
		if err := os.RemoveAll(m); err != nil {
			log.Printf("[WARN] sweep stale temp dir %s: %v", m, err)
		} else {
			log.Printf("[INFO] swept stale temp dir: %s", m)
		}
	}
}
