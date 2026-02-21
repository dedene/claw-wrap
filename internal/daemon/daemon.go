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

	"claw-wrap/internal/audit"
	"claw-wrap/internal/auth"
	"claw-wrap/internal/config"
	"claw-wrap/internal/credentials"
	"claw-wrap/internal/framing"
	"claw-wrap/internal/httpproxy"
	"claw-wrap/internal/paths"
	"claw-wrap/internal/protocol"
	"github.com/fsnotify/fsnotify"
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
	auditLogger        audit.Logger

	configWatcher     *fsnotify.Watcher
	configWatcherWg   sync.WaitGroup
	configWatcherMu   sync.Mutex
	configWatcherInit bool
	configStopCh      chan struct{}
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
	// Build allowed binary paths: resolved exe + invocation path.
	// The invocation path (os.Args[0]) is often a stable symlink that
	// survives package-manager upgrades (e.g. Homebrew Cellar versioned
	// paths change, but the bin/ symlink stays). normalizeExecutablePath
	// re-resolves symlinks at check time, so a stored symlink adapts to
	// new versions without a daemon restart.
	selfPath := "/usr/local/bin/claw-wrap"
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			selfPath = resolved
		}
	}
	allowed := []string{selfPath}
	if len(os.Args) > 0 {
		arg0 := os.Args[0]
		if abs, err := filepath.Abs(arg0); err == nil {
			arg0 = abs
		}
		if arg0 != selfPath {
			allowed = append(allowed, arg0)
		}
	}

	d := &Daemon{
		socketPath:         DefaultSocketPath,
		configPath:         config.DefaultConfigPath,
		allowedUID:         uint32(os.Getuid()),
		allowedBinaries:    allowed,
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

	auditLogger, err := audit.New(cfg.GetAuditConfig())
	if err != nil {
		return fmt.Errorf("init audit logger: %w", err)
	}
	d.auditLogger = auditLogger
	defer d.auditLogger.Close()

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

	// Start config file watcher (non-fatal; SIGHUP still works as fallback)
	if err := d.startConfigWatcher(); err != nil {
		log.Printf("[WARN] Config file watcher failed to start: %v", err)
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
			d.stopConfigWatcher()
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

	// Reload audit logger if config changed (before swapping d.cfg)
	if auditConfigChanged(d.cfg, newCfg) {
		if d.auditLogger != nil {
			d.auditLogger.Close()
		}
		newLogger, err := audit.New(newCfg.GetAuditConfig())
		if err != nil {
			return fmt.Errorf("reload audit logger: %w", err)
		}
		d.auditLogger = newLogger
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

// configWatchDebounce is the delay before reloading config after a file change.
// Editors often emit multiple events per save (rename+create, write+chmod).
const configWatchDebounce = 500 * time.Millisecond

// startConfigWatcher starts an fsnotify watcher on the config file directory.
// It calls reloadConfig when the config file changes. Non-fatal if it fails.
func (d *Daemon) startConfigWatcher() error {
	d.configWatcherMu.Lock()
	defer d.configWatcherMu.Unlock()

	if d.configWatcherInit {
		return nil // Already running
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create config watcher: %w", err)
	}

	dir := filepath.Dir(d.configPath)
	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		return fmt.Errorf("watch config directory %s: %w", dir, err)
	}

	d.configWatcher = watcher
	d.configStopCh = make(chan struct{})
	d.configWatcherInit = true

	stopCh := d.configStopCh
	events := watcher.Events
	errors := watcher.Errors

	d.configWatcherWg.Add(1)
	go d.configWatchLoop(stopCh, events, errors)

	log.Printf("[INFO] Config file watcher started for %s", dir)
	return nil
}

// configWatchLoop watches for config file changes and triggers reload with debounce.
func (d *Daemon) configWatchLoop(stopCh <-chan struct{}, events <-chan fsnotify.Event, errs <-chan error) {
	defer d.configWatcherWg.Done()

	configFile := filepath.Base(d.configPath)

	// Create timer in stopped state
	debounce := time.NewTimer(0)
	if !debounce.Stop() {
		<-debounce.C
	}
	defer debounce.Stop()

	for {
		select {
		case <-stopCh:
			return

		case event, ok := <-events:
			if !ok {
				return
			}

			if filepath.Base(event.Name) != configFile {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Chmod|fsnotify.Rename) == 0 {
				continue
			}

			// Reset debounce timer — coalesces rapid events into one reload
			debounce.Reset(configWatchDebounce)

		case <-debounce.C:
			if err := d.reloadConfig(); err != nil {
				log.Printf("[ERROR] Config reload failed: %v (keeping previous config)", err)
			} else {
				log.Printf("[INFO] Config reloaded successfully (file change detected)")
			}

		case err, ok := <-errs:
			if !ok {
				return
			}
			log.Printf("[WARN] Config watcher error: %v", err)
		}
	}
}

// stopConfigWatcher stops the config file watcher. Safe to call multiple times
// and concurrently (protected by configWatcherMu).
func (d *Daemon) stopConfigWatcher() {
	d.configWatcherMu.Lock()
	if !d.configWatcherInit {
		d.configWatcherMu.Unlock()
		return
	}

	close(d.configStopCh)
	d.configStopCh = nil
	d.configWatcherInit = false
	watcher := d.configWatcher
	d.configWatcher = nil
	d.configWatcherMu.Unlock() // Release before Wait to avoid deadlock with watchLoop

	d.configWatcherWg.Wait()

	if watcher != nil {
		watcher.Close()
	}
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

	var callerExe string // actual exe path; empty if unresolvable
	exe, err := resolvePeerExecutableFunc(ucred.PID)
	if err != nil {
		if cfg.DenyUnverifiedCallerExe() {
			d.metrics.Inc("caller_verify_fail")
			log.Printf("[WARN] deny reason=exe_unreadable pid=%d err=%v", ucred.PID, err)
			errSend(conn, "unauthorized caller")
			return
		}
		// callerExe stays empty — audit will record empty string
	} else {
		callerExe = exe
		if !d.isAllowedBinary(exe) {
			d.metrics.Inc("caller_verify_fail")
			log.Printf("[WARN] deny reason=exe_not_allowed exe=%q", exe)
			errSend(conn, "unauthorized caller")
			return
		}
	}

	if callerExe != "" {
		log.Printf("[DEBUG] peer pid=%d uid=%d exe=%s", ucred.PID, ucred.UID, callerExe)
	} else {
		log.Printf("[DEBUG] peer pid=%d uid=%d exe=unverified", ucred.PID, ucred.UID)
	}

	switch {
	case rawRequest["admin"] != nil:
		d.handleAdminRequest(conn, payload, cfg, ucred.UID, ucred.PID)
	case isProxy:
		d.handleProxyRequest(conn, payload, cfg, ucred.PID, callerExe, ucred.UID)
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

func (d *Daemon) handleProxyRequest(conn net.Conn, data []byte, cfg *config.Config, callerPID int32, callerExe string, uid uint32) {
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

	if err := auth.VerifyHMACWithPTY(d.secret, req.Timestamp, req.Tool, req.Cwd, req.Args, req.Env, req.Nonce, req.UsePTY, req.HMAC); err != nil {
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

	if allowed, msg := checkToolArgs(req.Args, &tool); !allowed {
		d.metrics.Inc("args_denied")
		log.Printf("[INFO] deny reason=args_policy tool=%s msg=%s", req.Tool, msg)
		d.sendProxyError(conn, fmt.Sprintf("blocked: %s", msg))
		return
	}

	log.Printf("[INFO] proxy tool=%s cwd=%s from=%s", req.Tool, req.Cwd, callerExe)

	executor, err := NewToolExecutor(conn, &req, &tool, cfg, d.proxyAuthToken, d.auditLogger, callerPID, callerExe)
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

func auditConfigChanged(old, new *config.Config) bool {
	if old == nil && new == nil {
		return false
	}
	if old == nil || new == nil {
		return true
	}

	oa := old.GetAuditConfig()
	na := new.GetAuditConfig()
	if oa == nil && na == nil {
		return false
	}
	if oa == nil || na == nil {
		return true
	}
	return oa.Enabled != na.Enabled ||
		oa.File != na.File ||
		oa.Syslog != na.Syslog ||
		oa.SyslogFacility != na.SyslogFacility
}
