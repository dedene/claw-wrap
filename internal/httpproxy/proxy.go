// Package httpproxy implements an HTTP/HTTPS proxy that injects credentials into requests.
package httpproxy

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/elazarl/goproxy"

	"claw-wrap/internal/config"
	"claw-wrap/internal/credentials"
)

// DefaultListenAddr is the default proxy listen address.
const DefaultListenAddr = "127.0.0.1:8080"

// Proxy is an HTTP/HTTPS proxy that injects credentials based on route matching.
type Proxy struct {
	server   *goproxy.ProxyHttpServer
	listener net.Listener

	cfg   *config.HTTPProxyConfig
	cfgMu sync.RWMutex

	ca          *CAManager
	creds       map[string]config.CredentialDef // Named credentials for injection
	credOpts    []credentials.FetchOption
	authToken   string
	requireAuth bool

	// For graceful shutdown
	shutdownCh chan struct{}
	wg         sync.WaitGroup
}

// Option configures the proxy.
type Option func(*Proxy)

const (
	proxyAuthUser  = "claw"
	proxyAuthRealm = "claw-wrap"
)

var (
	validateRequestSecurityFunc = validateRequestSecurity
	// safeTransportFunc and safeConnectDialFunc are injectable for testing.
	safeTransportFunc   = safeTransport
	safeConnectDialFunc = safeConnectDial
)

// WithPassBinary sets the pass binary path for credential resolution.
func WithPassBinary(path string) Option {
	return func(p *Proxy) {
		p.credOpts = append(p.credOpts, credentials.WithPassBinary(path))
	}
}

// WithOPBinary sets the 1Password CLI binary path.
func WithOPBinary(path string) Option {
	return func(p *Proxy) {
		p.credOpts = append(p.credOpts, credentials.WithOPBinary(path))
	}
}

// WithBWBinary sets the Bitwarden CLI binary path.
func WithBWBinary(path string) Option {
	return func(p *Proxy) {
		p.credOpts = append(p.credOpts, credentials.WithBWBinary(path))
	}
}

// WithAuthToken sets the required proxy auth token.
func WithAuthToken(token string) Option {
	return func(p *Proxy) {
		p.authToken = token
	}
}

// WithRequireAuth sets whether proxy authentication is required.
func WithRequireAuth(require bool) Option {
	return func(p *Proxy) {
		p.requireAuth = require
	}
}

// New creates a new proxy with the given configuration.
func New(cfg *config.HTTPProxyConfig, creds map[string]config.CredentialDef, opts ...Option) *Proxy {
	p := &Proxy{
		cfg:         cfg,
		creds:       creds,
		server:      goproxy.NewProxyHttpServer(),
		ca:          NewCAManager(cfg.CA),
		shutdownCh:  make(chan struct{}),
		requireAuth: true, // Default: require auth
	}

	for _, opt := range opts {
		opt(p)
	}

	// Configure verbose logging based on config
	p.server.Verbose = cfg.LogLevel == "debug"

	// Configure safe transport with SSRF protection.
	// The Control callback validates IPs after DNS resolution, preventing DNS rebinding.
	p.server.Tr = safeTransportFunc()
	p.server.ConnectDial = safeConnectDialFunc()

	// Authenticate CONNECT before MITM.
	p.server.OnRequest().HandleConnectFunc(p.handleConnect)

	// Set up request handler for credential injection
	p.server.OnRequest().DoFunc(p.handleRequest)

	// Set up response handler for header stripping
	p.server.OnResponse().DoFunc(p.handleResponse)

	return p
}

// Start begins listening for proxy connections.
func (p *Proxy) Start(addr string) error {
	if addr == "" {
		addr = DefaultListenAddr
	}
	if p.requireAuth && p.authToken == "" {
		return fmt.Errorf("proxy auth token is required")
	}

	// Ensure we only bind to localhost for security
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return fmt.Errorf("proxy must bind to localhost only, got %s", host)
	}

	// Set up MITM for HTTPS interception
	if err := p.setupMITM(); err != nil {
		return fmt.Errorf("setup MITM: %w", err)
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	p.listener = listener

	log.Printf("[INFO] HTTP proxy listening on %s", addr)

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := http.Serve(listener, p.server); err != nil {
			select {
			case <-p.shutdownCh:
				// Normal shutdown, ignore error
			default:
				log.Printf("[ERROR] proxy serve: %v", err)
			}
		}
	}()

	return nil
}

// setupMITM configures the proxy for HTTPS interception.
func (p *Proxy) setupMITM() error {
	cert, err := p.ca.EnsureCA()
	if err != nil {
		return fmt.Errorf("ensure CA: %w", err)
	}

	// Set the CA for goproxy
	goproxy.GoproxyCa = *cert
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(cert)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(cert)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(cert)}

	log.Printf("[INFO] MITM enabled with CA from %s", p.ca.CertPath())
	return nil
}

// CAPath returns the path to the CA certificate for trust injection.
func (p *Proxy) CAPath() string {
	return p.ca.CertPath()
}

// Stop gracefully shuts down the proxy.
func (p *Proxy) Stop() error {
	close(p.shutdownCh)

	if p.listener != nil {
		if err := p.listener.Close(); err != nil {
			return fmt.Errorf("close listener: %w", err)
		}
	}

	p.wg.Wait()
	log.Printf("[INFO] HTTP proxy stopped")
	return nil
}

// ReloadConfig updates the proxy configuration and credentials.
func (p *Proxy) ReloadConfig(cfg *config.HTTPProxyConfig, creds map[string]config.CredentialDef) {
	p.cfgMu.Lock()
	defer p.cfgMu.Unlock()

	p.cfg = cfg
	p.creds = creds
	p.server.Verbose = cfg.LogLevel == "debug"

	log.Printf("[INFO] HTTP proxy config reloaded with %d routes, %d credentials", len(cfg.Routes), len(creds))
}

// getConfig returns the current configuration thread-safely.
func (p *Proxy) getConfig() *config.HTTPProxyConfig {
	p.cfgMu.RLock()
	defer p.cfgMu.RUnlock()
	return p.cfg
}

func (p *Proxy) handleConnect(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	if !p.isAuthenticatedProxyRequest(ctx.Req, ctx) {
		log.Printf("[WARN] proxy denied reason=auth_failed phase=connect host=%s", sanitizeForLog(host))
		return p.proxyAuthRequiredConnectAction(), host
	}

	p.markConnectAuthenticated(ctx)
	return goproxy.MitmConnect, host
}

// handleRequest is the goproxy request handler for credential injection.
func (p *Proxy) handleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	cfg := p.getConfig()
	if cfg == nil || !cfg.Enabled {
		return req, goproxy.NewResponse(req, "application/json", http.StatusServiceUnavailable, `{"error":"proxy_disabled"}`)
	}

	if !p.isAuthenticatedProxyRequest(req, ctx) {
		log.Printf("[WARN] proxy denied reason=auth_failed phase=request")
		return req, p.proxyAuthRequiredResponse(req)
	}

	// Never forward proxy auth headers upstream.
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")

	canonicalHost, err := canonicalRequestHost(req)
	if err != nil {
		log.Printf("[WARN] proxy denied reason=bad_target err=%v", err)
		return req, goproxy.NewResponse(req, "application/json", http.StatusBadRequest, `{"error":"invalid_target_host"}`)
	}

	if hostHeaderMismatched(req, canonicalHost) {
		log.Printf("[WARN] proxy denied reason=host_mismatch target=%s host=%s", canonicalHost, sanitizeForLog(req.Host))
		return req, goproxy.NewResponse(req, "application/json", http.StatusBadRequest, `{"error":"host_mismatch"}`)
	}

	if err := validateRequestSecurityFunc(req); err != nil {
		log.Printf("[WARN] proxy denied reason=smuggling_detected target=%s err=%v", canonicalHost, err)
		return req, goproxy.NewResponse(req, "application/json", http.StatusBadRequest, `{"error":"invalid_request"}`)
	}

	// Note: SSRF protection is now handled by the dialer's Control callback,
	// which validates IPs after DNS resolution, preventing DNS rebinding attacks.

	// Find matching route
	route := p.findMatchingRoute(cfg, canonicalHost)
	if route == nil {
		// No matching route, pass through transparently
		return req, nil
	}

	// Check allow/deny patterns
	if !p.isRequestAllowed(route, req) {
		if cfg.LogLevel == "debug" || cfg.LogLevel == "info" {
			log.Printf("[INFO] proxy denied request host=%s method=%s path=%s", canonicalHost, req.Method, req.URL.Path)
		}
		return req, goproxy.NewResponse(req, "application/json", http.StatusForbidden, `{"error":"request denied by policy"}`)
	}

	// Inject credentials
	if route.Inject.Header != "" && route.Inject.Value != "" {
		value, err := resolveHeaderValue(route.Inject.Value, p.creds, p.credOpts)
		if err != nil {
			// Log error but don't expose details
			if cfg.LogLevel == "debug" || cfg.LogLevel == "errors" {
				log.Printf("[ERROR] proxy credential resolution failed: %v", err)
			}
			return req, goproxy.NewResponse(req, "application/json", http.StatusBadGateway,
				`{"error":"credential_resolution_failed"}`)
		}
		req.Header.Set(route.Inject.Header, value)

		if cfg.LogLevel == "debug" {
			log.Printf("[DEBUG] proxy injected header %s for host=%s", route.Inject.Header, canonicalHost)
		}
	}

	if cfg.LogLevel == "debug" || cfg.LogLevel == "info" {
		log.Printf("[INFO] proxy matched route host=%s path=%s", canonicalHost, req.URL.Path)
	}

	return req, nil
}

// isRequestAllowed checks if the request is allowed by the route's allow/deny rules.
// Evaluation order: deny rules first, then allow rules, default permit if no rules.
func (p *Proxy) isRequestAllowed(route *config.ProxyRoute, req *http.Request) bool {
	method := req.Method
	path := req.URL.Path

	// Check deny rules first (if any match, deny)
	for _, rule := range route.DenyRules {
		if p.matchPathRule(&rule, method, path) {
			return false
		}
	}

	// If there are allow rules, at least one must match
	if len(route.AllowRules) > 0 {
		for _, rule := range route.AllowRules {
			if p.matchPathRule(&rule, method, path) {
				return true
			}
		}
		return false // No allow rules matched
	}

	// No deny matched and no allow rules, default permit
	return true
}

// matchPathRule checks if a request matches a path rule.
func (p *Proxy) matchPathRule(rule *config.PathRule, method, path string) bool {
	// Check method
	if rule.Method != "*" && rule.Method != method {
		return false
	}
	// Check path
	return rule.Pattern.MatchString(path)
}

// handleResponse is the goproxy response handler for header stripping.
func (p *Proxy) handleResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp == nil {
		return nil
	}

	cfg := p.getConfig()

	// Strip configured response headers
	for _, header := range cfg.StripResponseHeaders {
		resp.Header.Del(header)
	}

	return resp
}

// findMatchingRoute finds the first route that matches the canonical target host.
func (p *Proxy) findMatchingRoute(cfg *config.HTTPProxyConfig, host string) *config.ProxyRoute {
	for i := range cfg.Routes {
		route := &cfg.Routes[i]
		if p.matchHostWithRoute(route, host) {
			return route
		}
	}

	return nil
}

// matchHost checks if a host matches a pattern.
// Supports exact matches and wildcard patterns like *.example.com
func (p *Proxy) matchHost(pattern string, host string) bool {
	// Use exact match for simple patterns
	return pattern == host
}

// matchHostWithRoute checks if a host matches a route using compiled regex.
func (p *Proxy) matchHostWithRoute(route *config.ProxyRoute, host string) bool {
	if route.HostRegex != nil {
		return route.HostRegex.MatchString(host)
	}
	// Fall back to exact match if not compiled
	return route.Host == host
}

type proxyAuthState struct {
	connectAuthenticated bool
}

func (p *Proxy) markConnectAuthenticated(ctx *goproxy.ProxyCtx) {
	ctx.UserData = &proxyAuthState{connectAuthenticated: true}
}

func (p *Proxy) isConnectAuthenticated(ctx *goproxy.ProxyCtx) bool {
	if ctx == nil {
		return false
	}
	state, ok := ctx.UserData.(*proxyAuthState)
	return ok && state.connectAuthenticated
}

func (p *Proxy) isAuthenticatedProxyRequest(req *http.Request, ctx *goproxy.ProxyCtx) bool {
	if !p.requireAuth {
		return true
	}
	if p.isConnectAuthenticated(ctx) {
		return true
	}
	if req == nil {
		return false
	}

	user, pass, ok := parseProxyAuthorization(req.Header.Get("Proxy-Authorization"))
	if !ok {
		return false
	}
	if !secureEqual(user, proxyAuthUser) {
		return false
	}
	return secureEqual(pass, p.authToken)
}

func (p *Proxy) proxyAuthRequiredResponse(req *http.Request) *http.Response {
	resp := goproxy.NewResponse(req, "application/json", http.StatusProxyAuthRequired, `{"error":"proxy_auth_required"}`)
	resp.Header.Set("Proxy-Authenticate", fmt.Sprintf(`Basic realm=%q`, proxyAuthRealm))
	return resp
}

func (p *Proxy) proxyAuthRequiredConnectAction() *goproxy.ConnectAction {
	return &goproxy.ConnectAction{
		Action: goproxy.ConnectProxyAuthHijack,
		Hijack: func(req *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
			// goproxy sends "HTTP/1.1 407 Proxy Authentication Required\r\n" before Hijack.
			// We only need to send the headers and terminate.
			_, _ = fmt.Fprintf(client,
				"Proxy-Authenticate: Basic realm=%q\r\n"+
					"Content-Length: 0\r\n"+
					"Connection: close\r\n\r\n", proxyAuthRealm)
			_ = client.Close()
		},
	}
}

func parseProxyAuthorization(raw string) (username string, password string, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(raw), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", false
	}

	credentials := string(decoded)
	user, pass, found := strings.Cut(credentials, ":")
	if !found {
		return "", "", false
	}
	return user, pass, true
}

func secureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func canonicalRequestHost(req *http.Request) (string, error) {
	if req == nil || req.URL == nil {
		return "", fmt.Errorf("request URL is missing")
	}

	target := req.URL.Host
	if strings.TrimSpace(target) == "" {
		// For HTTP proxy requests (absolute URL with scheme), URL.Host should always be present.
		// Falling back to Host header would allow attacker to bypass route matching.
		if req.URL.Scheme != "" {
			return "", fmt.Errorf("proxy request missing URL host")
		}
		// For direct requests without scheme, fall back to Host header.
		target = req.Host
	}
	host := normalizeHost(target)
	if host == "" {
		return "", fmt.Errorf("request target host is empty")
	}
	return host, nil
}

func hostHeaderMismatched(req *http.Request, canonicalHost string) bool {
	if req == nil {
		return false
	}
	if strings.TrimSpace(req.Host) == "" {
		// For HTTPS via CONNECT, Host header may legitimately be empty (target in URL).
		// For HTTP proxy requests (scheme present), empty Host with URL.Host is suspicious.
		return req.URL != nil && req.URL.Scheme == "http" && req.URL.Host != ""
	}
	return normalizeHost(req.Host) != canonicalHost
}

func normalizeHost(authority string) string {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return ""
	}

	if parsed, err := url.Parse("//" + authority); err == nil {
		host := parsed.Hostname()
		if host != "" {
			return strings.TrimSuffix(strings.ToLower(host), ".")
		}
	}
	return strings.TrimSuffix(strings.ToLower(authority), ".")
}

// Enabled returns whether the proxy is enabled in the current config.
func (p *Proxy) Enabled() bool {
	cfg := p.getConfig()
	return cfg != nil && cfg.Enabled
}

// ListenAddr returns the configured listen address.
func (p *Proxy) ListenAddr() string {
	cfg := p.getConfig()
	if cfg == nil || cfg.Listen == "" {
		return DefaultListenAddr
	}
	return cfg.Listen
}

// SetupFromConfig configures the proxy from daemon config.
func SetupFromConfig(cfg *config.Config) (*Proxy, error) {
	httpCfg := cfg.GetHTTPProxyConfig()
	if httpCfg == nil || !httpCfg.Enabled {
		return nil, nil
	}

	proxy := New(httpCfg, cfg.Credentials,
		WithPassBinary(cfg.GetPassBinary()),
		WithOPBinary(cfg.GetOPBinary()),
		WithBWBinary(cfg.GetBWBinary()),
	)

	return proxy, nil
}

// StartFromConfig creates and starts a proxy from daemon config.
func StartFromConfig(ctx context.Context, cfg *config.Config) (*Proxy, error) {
	proxy, err := SetupFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	if proxy == nil {
		return nil, nil // Proxy not enabled
	}

	if err := proxy.Start(proxy.ListenAddr()); err != nil {
		return nil, fmt.Errorf("start proxy: %w", err)
	}

	return proxy, nil
}
