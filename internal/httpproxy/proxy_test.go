package httpproxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"claw-wrap/internal/config"
	"github.com/elazarl/goproxy"
)

const testProxyAuthToken = "test-proxy-token"

func TestNew(t *testing.T) {
	cfg := &config.HTTPProxyConfig{
		Enabled:  true,
		Listen:   "127.0.0.1:8080",
		LogLevel: "errors",
		Routes: []config.ProxyRoute{
			{
				Host: "api.example.com",
				Inject: config.InjectSpec{
					Header: "Authorization",
					Value:  "Bearer test-token",
				},
			},
		},
	}

	proxy := New(cfg, nil, WithAuthToken(testProxyAuthToken))
	if proxy == nil {
		t.Fatal("New() returned nil")
	}
	if proxy.server == nil {
		t.Error("proxy.server is nil")
	}
	if !proxy.Enabled() {
		t.Error("proxy should be enabled")
	}
}

func TestProxy_ListenAddr(t *testing.T) {
	tests := []struct {
		name     string
		listen   string
		expected string
	}{
		{"default", "", DefaultListenAddr},
		{"custom", "127.0.0.1:9090", "127.0.0.1:9090"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.HTTPProxyConfig{
				Enabled: true,
				Listen:  tt.listen,
			}
			proxy := New(cfg, nil, WithAuthToken(testProxyAuthToken))
			if got := proxy.ListenAddr(); got != tt.expected {
				t.Errorf("ListenAddr() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestProxy_Start_RejectsNonLocalhost(t *testing.T) {
	cfg := &config.HTTPProxyConfig{
		Enabled: true,
	}
	proxy := New(cfg, nil, WithAuthToken(testProxyAuthToken))

	// Should reject non-localhost addresses
	err := proxy.Start("0.0.0.0:8080")
	if err == nil {
		proxy.Stop()
		t.Fatal("Start() should reject 0.0.0.0")
	}
}

func TestProxy_StartStop(t *testing.T) {
	disableSSRFForTest(t)

	cfg := &config.HTTPProxyConfig{
		Enabled:  true,
		LogLevel: "errors",
		CA:       config.CAConfig{Path: t.TempDir()},
	}
	proxy := New(cfg, nil, WithAuthToken(testProxyAuthToken))

	// Use port 0 to get a random available port
	err := proxy.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Verify we can make a request through the proxy
	// (will fail to connect to non-existent upstream, but that's ok)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustAuthenticatedProxyURL(t, proxy.listener.Addr().String(), testProxyAuthToken)),
		},
		Timeout: 1 * time.Second,
	}

	// Make a request to a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer ts.Close()

	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// Stop the proxy
	if err := proxy.Stop(); err != nil {
		t.Errorf("Stop() error: %v", err)
	}
}

func TestProxy_Start_RequiresAuthToken(t *testing.T) {
	cfg := &config.HTTPProxyConfig{
		Enabled: true,
	}
	proxy := New(cfg, nil)

	err := proxy.Start("127.0.0.1:0")
	if err == nil {
		t.Fatal("Start() should fail without auth token")
	}
	if !strings.Contains(err.Error(), "auth token") {
		t.Fatalf("Start() error = %v, want auth token error", err)
	}
}

func TestProxy_Start_NoAuthTokenNeededWhenAuthDisabled(t *testing.T) {
	cfg := &config.HTTPProxyConfig{
		Enabled: true,
		CA:      config.CAConfig{Path: t.TempDir()},
	}
	proxy := New(cfg, nil, WithRequireAuth(false))

	// Should start without auth token
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer proxy.Stop()
}

func TestProxy_NoAuthRequired_AllowsUnauthenticatedRequests(t *testing.T) {
	disableSSRFForTest(t)

	cfg := &config.HTTPProxyConfig{
		Enabled: true,
		CA:      config.CAConfig{Path: t.TempDir()},
	}
	proxy := New(cfg, nil, WithRequireAuth(false))
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer proxy.Stop()

	// Request without any auth should succeed
	proxyURL, _ := url.Parse("http://" + proxy.listener.Addr().String())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get("http://api.example.com/test")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	defer resp.Body.Close()

	// Should not get 407 (proxy auth required)
	if resp.StatusCode == http.StatusProxyAuthRequired {
		t.Fatal("should not require proxy auth when require_auth=false")
	}
}

func TestProxy_HTTPAuthRequired(t *testing.T) {
	disableSSRFForTest(t)

	cfg := &config.HTTPProxyConfig{Enabled: true, CA: config.CAConfig{Path: t.TempDir()}}
	proxy := New(cfg, nil, WithAuthToken(testProxyAuthToken))
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer proxy.Stop()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer upstream.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(t, "http://"+proxy.listener.Addr().String())),
		},
		Timeout: 2 * time.Second,
	}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); !strings.Contains(got, "Basic") {
		t.Fatalf("Proxy-Authenticate = %q, want Basic challenge", got)
	}
}

func TestProxy_HTTPWrongCredentialsRejected(t *testing.T) {
	disableSSRFForTest(t)

	cfg := &config.HTTPProxyConfig{Enabled: true, CA: config.CAConfig{Path: t.TempDir()}}
	proxy := New(cfg, nil, WithAuthToken(testProxyAuthToken))
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer proxy.Stop()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer upstream.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustAuthenticatedProxyURL(t, proxy.listener.Addr().String(), "wrong-token")),
		},
		Timeout: 2 * time.Second,
	}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
	}
}

func TestProxy_CONNECTAuthRequired(t *testing.T) {
	cfg := &config.HTTPProxyConfig{Enabled: true, CA: config.CAConfig{Path: t.TempDir()}}
	proxy := New(cfg, nil, WithAuthToken(testProxyAuthToken))
	if err := proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer proxy.Stop()

	conn, err := net.Dial("tcp", proxy.listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()

	_, _ = fmt.Fprintf(conn, "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("ReadResponse() error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); !strings.Contains(got, "Basic") {
		t.Fatalf("Proxy-Authenticate = %q, want Basic challenge", got)
	}
}

func TestProxy_handleRequest_AuthenticatedInjectsAndStripsProxyHeaders(t *testing.T) {
	disableSSRFForTest(t) // api.example.com won't resolve; bypass DNS check

	cfg := &config.HTTPProxyConfig{
		Enabled: true,
		Routes: []config.ProxyRoute{
			{
				Host: "api.example.com",
				Inject: config.InjectSpec{
					Header: "Authorization",
					Value:  "Bearer static-token",
				},
			},
		},
	}
	if err := (&config.Config{HTTPProxy: cfg}).Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}

	proxy := New(cfg, nil, WithAuthToken(testProxyAuthToken))
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/v1/test", nil)
	req.Host = "api.example.com"
	req.Header.Set("Proxy-Authorization", basicProxyAuthHeader(proxyAuthUser, testProxyAuthToken))
	req.Header.Set("Proxy-Connection", "keep-alive")

	gotReq, resp := proxy.handleRequest(req, &goproxy.ProxyCtx{Req: req})
	if resp != nil {
		t.Fatalf("handleRequest() returned unexpected response: %d", resp.StatusCode)
	}
	if gotReq.Header.Get("Authorization") != "Bearer static-token" {
		t.Fatalf("Authorization header = %q, want %q", gotReq.Header.Get("Authorization"), "Bearer static-token")
	}
	if gotReq.Header.Get("Proxy-Authorization") != "" {
		t.Fatal("Proxy-Authorization should be stripped")
	}
	if gotReq.Header.Get("Proxy-Connection") != "" {
		t.Fatal("Proxy-Connection should be stripped")
	}
}

func TestProxy_handleRequest_HostMismatchRejected(t *testing.T) {
	cfg := &config.HTTPProxyConfig{
		Enabled: true,
		Routes: []config.ProxyRoute{
			{
				Host: "allowed.example.com",
				Inject: config.InjectSpec{
					Header: "Authorization",
					Value:  "Bearer should-not-inject",
				},
			},
		},
	}
	if err := (&config.Config{HTTPProxy: cfg}).Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}

	proxy := New(cfg, nil, WithAuthToken(testProxyAuthToken))
	req := httptest.NewRequest(http.MethodGet, "http://attacker.example.com/data", nil)
	req.Host = "allowed.example.com"
	req.Header.Set("Proxy-Authorization", basicProxyAuthHeader(proxyAuthUser, testProxyAuthToken))

	gotReq, resp := proxy.handleRequest(req, &goproxy.ProxyCtx{Req: req})
	if resp == nil {
		t.Fatal("expected host mismatch response")
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if gotReq.Header.Get("Authorization") != "" {
		t.Fatal("Authorization header should not be injected on host mismatch")
	}
}

func TestProxy_handleRequest_PassesThroughSSRF(t *testing.T) {
	// SSRF protection is now handled at dial-time via the safeDialer's Control callback,
	// not in handleRequest. This test verifies handleRequest passes through the request.
	// See ssrf_test.go for dial-time SSRF blocking tests.
	proxy := New(&config.HTTPProxyConfig{Enabled: true}, nil, WithAuthToken(testProxyAuthToken))
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/private", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("Proxy-Authorization", basicProxyAuthHeader(proxyAuthUser, testProxyAuthToken))

	_, resp := proxy.handleRequest(req, &goproxy.ProxyCtx{Req: req})
	// handleRequest should pass through (nil response) - SSRF is blocked at dial time
	if resp != nil {
		t.Errorf("expected nil response (pass through), got status %d", resp.StatusCode)
	}
}

func TestProxy_handleRequest_BlocksSmuggling(t *testing.T) {
	proxy := New(&config.HTTPProxyConfig{Enabled: true}, nil, WithAuthToken(testProxyAuthToken))
	req := httptest.NewRequest(http.MethodPost, "http://api.example.com/path", nil)
	req.Host = "api.example.com"
	req.Header.Set("Proxy-Authorization", basicProxyAuthHeader(proxyAuthUser, testProxyAuthToken))
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("Content-Length", "5")

	_, resp := proxy.handleRequest(req, &goproxy.ProxyCtx{Req: req})
	if resp == nil {
		t.Fatal("expected smuggling block response")
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestProxy_ReloadConfig(t *testing.T) {
	cfg := &config.HTTPProxyConfig{
		Enabled:  true,
		LogLevel: "errors",
		Routes: []config.ProxyRoute{
			{Host: "api.example.com"},
		},
	}
	proxy := New(cfg, nil, WithAuthToken(testProxyAuthToken))

	// Reload with new config
	newCfg := &config.HTTPProxyConfig{
		Enabled:  true,
		LogLevel: "debug",
		Routes: []config.ProxyRoute{
			{Host: "api.example.com"},
			{Host: "api.other.com"},
		},
	}
	newCreds := map[string]config.CredentialDef{
		"test-cred": {Source: "literal:test-value"},
	}
	proxy.ReloadConfig(newCfg, newCreds)

	// Verify config was updated
	gotCfg := proxy.getConfig()
	if len(gotCfg.Routes) != 2 {
		t.Errorf("expected 2 routes, got %d", len(gotCfg.Routes))
	}
	if gotCfg.LogLevel != "debug" {
		t.Errorf("expected log_level=debug, got %s", gotCfg.LogLevel)
	}
}

func TestProxy_matchHost(t *testing.T) {
	proxy := New(&config.HTTPProxyConfig{Enabled: true}, nil, WithAuthToken(testProxyAuthToken))

	tests := []struct {
		pattern string
		host    string
		want    bool
	}{
		// Exact matches
		{"api.github.com", "api.github.com", true},
		{"api.github.com", "other.github.com", false},
		{"api.github.com", "api.github.com.evil.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.host, func(t *testing.T) {
			if got := proxy.matchHost(tt.pattern, tt.host); got != tt.want {
				t.Errorf("matchHost(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
			}
		})
	}
}

func TestProxy_matchHostWithRoute_Wildcard(t *testing.T) {
	// Create config with wildcard routes and validate to compile patterns
	cfg := &config.Config{
		HTTPProxy: &config.HTTPProxyConfig{
			Enabled: true,
			Routes: []config.ProxyRoute{
				{
					Host:   "*.github.com",
					Inject: config.InjectSpec{Header: "Authorization", Value: "token"},
				},
				{
					Host:   "api.openai.com",
					Inject: config.InjectSpec{Header: "Authorization", Value: "key"},
				},
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}

	proxy := New(cfg.HTTPProxy, nil, WithAuthToken(testProxyAuthToken))

	tests := []struct {
		name      string
		routeIdx  int
		host      string
		wantMatch bool
	}{
		// Wildcard route tests
		{"wildcard matches subdomain", 0, "api.github.com", true},
		{"wildcard matches different subdomain", 0, "raw.github.com", true},
		{"wildcard no match bare domain", 0, "github.com", false},
		{"wildcard no match suffix attack", 0, "evil.github.com.attacker.com", false},
		{"wildcard no match deep subdomain", 0, "deep.sub.github.com", false},

		// Exact match route tests
		{"exact match", 1, "api.openai.com", true},
		{"exact no match", 1, "other.openai.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := &cfg.HTTPProxy.Routes[tt.routeIdx]
			got := proxy.matchHostWithRoute(route, tt.host)
			if got != tt.wantMatch {
				t.Errorf("matchHostWithRoute(route[%d], %q) = %v, want %v", tt.routeIdx, tt.host, got, tt.wantMatch)
			}
		})
	}
}

func TestProxy_findMatchingRoute(t *testing.T) {
	cfg := &config.HTTPProxyConfig{
		Enabled: true,
		Routes: []config.ProxyRoute{
			{
				Host: "api.github.com",
				Inject: config.InjectSpec{
					Header: "Authorization",
					Value:  "Bearer github-token",
				},
			},
			{
				Host: "api.openai.com",
				Inject: config.InjectSpec{
					Header: "Authorization",
					Value:  "Bearer openai-key",
				},
			},
		},
	}
	proxy := New(cfg, nil, WithAuthToken(testProxyAuthToken))

	tests := []struct {
		name      string
		host      string
		wantMatch bool
		wantHost  string
	}{
		{"match github", "api.github.com", true, "api.github.com"},
		{"match github with port", "api.github.com:443", true, "api.github.com"},
		{"match openai", "api.openai.com", true, "api.openai.com"},
		{"no match", "api.anthropic.com", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://"+tt.host+"/test", nil)
			req.Host = tt.host

			targetHost, err := canonicalRequestHost(req)
			if err != nil {
				t.Fatalf("canonicalRequestHost() error: %v", err)
			}
			route := proxy.findMatchingRoute(cfg, targetHost)
			if tt.wantMatch {
				if route == nil {
					t.Error("expected route match, got nil")
				} else if route.Host != tt.wantHost {
					t.Errorf("matched wrong route: got %s, want %s", route.Host, tt.wantHost)
				}
			} else {
				if route != nil {
					t.Errorf("expected no match, got route for %s", route.Host)
				}
			}
		})
	}
}

func TestProxy_ResponseHeaderStripping(t *testing.T) {
	disableSSRFForTest(t)

	cfg := &config.HTTPProxyConfig{
		Enabled:  true,
		LogLevel: "errors",
		CA:       config.CAConfig{Path: t.TempDir()},
		StripResponseHeaders: []string{
			"Server",
			"X-Powered-By",
		},
	}
	proxy := New(cfg, nil, WithAuthToken(testProxyAuthToken))

	// Start proxy
	err := proxy.Start("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer proxy.Stop()

	// Create test server that returns headers we want stripped
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestServer/1.0")
		w.Header().Set("X-Powered-By", "Go")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer ts.Close()

	// Make request through proxy
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustAuthenticatedProxyURL(t, proxy.listener.Addr().String(), testProxyAuthToken)),
		},
		Timeout: 2 * time.Second,
	}

	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Verify stripped headers are gone
	if resp.Header.Get("Server") != "" {
		t.Error("Server header should be stripped")
	}
	if resp.Header.Get("X-Powered-By") != "" {
		t.Error("X-Powered-By header should be stripped")
	}

	// Verify other headers are preserved
	if resp.Header.Get("Content-Type") != "text/plain" {
		t.Error("Content-Type header should be preserved")
	}
}

func TestSetupFromConfig_Disabled(t *testing.T) {
	cfg := &config.Config{
		// HTTPProxy not set or disabled
	}

	proxy, err := SetupFromConfig(cfg)
	if err != nil {
		t.Fatalf("SetupFromConfig error: %v", err)
	}
	if proxy != nil {
		t.Error("expected nil proxy when disabled")
	}
}

// Helper functions

func disableSSRFForTest(t *testing.T) {
	t.Helper()
	// Override transport and dial functions to allow localhost connections in tests.
	// The safe dialer blocks private IPs including localhost, which breaks tests
	// using local mock servers.
	origTransport := safeTransportFunc
	origDial := safeConnectDialFunc

	safeTransportFunc = func() *http.Transport {
		return &http.Transport{} // Default transport without SSRF protection
	}
	safeConnectDialFunc = func() func(string, string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 30 * time.Second}).Dial
	}

	t.Cleanup(func() {
		safeTransportFunc = origTransport
		safeConnectDialFunc = origDial
	})
}

func basicProxyAuthHeader(username, password string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return "Basic " + encoded
}

func mustAuthenticatedProxyURL(t *testing.T, addr string, token string) *url.URL {
	t.Helper()
	u := &url.URL{
		Scheme: "http",
		User:   url.UserPassword(proxyAuthUser, token),
		Host:   addr,
	}
	return mustParseURL(t, u.String())
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse URL %q: %v", rawURL, err)
	}
	return u
}

// Ensure body is fully read and closed
func mustReadBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	return string(body)
}

func TestProxy_isRequestAllowed(t *testing.T) {
	// Create config with allow/deny rules and validate
	cfg := &config.Config{
		HTTPProxy: &config.HTTPProxyConfig{
			Enabled: true,
			Routes: []config.ProxyRoute{
				{
					Host:   "api.example.com",
					Inject: config.InjectSpec{Header: "Authorization", Value: "token"},
					Allow:  []string{"GET /api/**", "POST /api/users"},
					Deny:   []string{"DELETE /**"},
				},
				{
					Host:   "open.example.com",
					Inject: config.InjectSpec{Header: "X-Key", Value: "key"},
					// No allow/deny rules - should allow all
				},
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}

	proxy := New(cfg.HTTPProxy, nil, WithAuthToken(testProxyAuthToken))

	tests := []struct {
		name      string
		routeIdx  int
		method    string
		path      string
		wantAllow bool
	}{
		// Route with allow/deny rules
		{"allowed GET /api/users", 0, "GET", "/api/users", true},
		{"allowed GET /api/users/123", 0, "GET", "/api/users/123", true},
		{"allowed POST /api/users", 0, "POST", "/api/users", true},
		{"denied POST /api/users/123", 0, "POST", "/api/users/123", false}, // POST only matches /api/users exactly
		{"denied DELETE /api/users", 0, "DELETE", "/api/users", false},
		{"denied PUT not in allow list", 0, "PUT", "/api/users", false},

		// Route with no rules - should allow all
		{"no rules allows GET", 1, "GET", "/anything", true},
		{"no rules allows DELETE", 1, "DELETE", "/anything", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := &cfg.HTTPProxy.Routes[tt.routeIdx]
			req := httptest.NewRequest(tt.method, "https://example.com"+tt.path, nil)
			got := proxy.isRequestAllowed(route, req)
			if got != tt.wantAllow {
				t.Errorf("isRequestAllowed(route[%d], %s %s) = %v, want %v",
					tt.routeIdx, tt.method, tt.path, got, tt.wantAllow)
			}
		})
	}
}

func TestProxy_CAPath(t *testing.T) {
	cfg := &config.HTTPProxyConfig{
		Enabled: true,
		CA: config.CAConfig{
			Path: "/custom/ca/path",
		},
	}
	proxy := New(cfg, nil, WithAuthToken(testProxyAuthToken))
	want := "/custom/ca/path/ca.crt"
	if got := proxy.CAPath(); got != want {
		t.Errorf("CAPath() = %q, want %q", got, want)
	}
}
