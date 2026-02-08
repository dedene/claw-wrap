package daemon

import (
	"net/url"
	"strings"
	"testing"

	"claw-wrap/internal/config"
	"claw-wrap/internal/protocol"
)

// envContains checks if an env slice contains a given key and returns its value.
func envContains(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return strings.TrimPrefix(e, prefix), true
		}
	}
	return "", false
}

func TestIsDeniedEnvVar_ExactMatch(t *testing.T) {
	denied := []string{
		// Shell injection
		"BASH_ENV", "ENV", "CDPATH", "SHELLOPTS", "BASHOPTS", "SHELL", "IFS",
		"GLOBIGNORE", "PROMPT_COMMAND",
		// Language runtimes
		"PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME",
		"PERL5LIB", "PERL5OPT", "RUBYLIB", "RUBYOPT",
		"NODE_OPTIONS", "NODE_PATH",
		"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JAVA_OPTIONS",
		// Execution hijack
		"GIT_SSH_COMMAND", "EDITOR", "VISUAL", "PAGER",
		// Proxy vars
		"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
		"ftp_proxy", "FTP_PROXY", "all_proxy", "ALL_PROXY",
		"no_proxy", "NO_PROXY",
		// Misc dangerous
		"CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR",
		"GIT_PROXY_COMMAND", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
		"GIT_EXEC_PATH", "GIT_TEMPLATE_DIR",
	}

	for _, key := range denied {
		t.Run(key, func(t *testing.T) {
			if !isDeniedEnvVar(key) {
				t.Errorf("isDeniedEnvVar(%q) = false, want true", key)
			}
		})
	}
}

func TestIsDeniedEnvVar_PrefixMatch(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		// BASH_FUNC_ prefix
		{"bash_func prefix", "BASH_FUNC_"},
		{"bash function export", "BASH_FUNC_myfunc%%"},
		{"bash nested name", "BASH_FUNC_some_helper%%"},
		// LD_ prefix
		{"LD_PRELOAD", "LD_PRELOAD"},
		{"LD_LIBRARY_PATH", "LD_LIBRARY_PATH"},
		{"LD_AUDIT", "LD_AUDIT"},
		{"LD_DEBUG", "LD_DEBUG"},
		{"LD_BIND_NOW", "LD_BIND_NOW"},
		// DYLD_ prefix
		{"DYLD_INSERT_LIBRARIES", "DYLD_INSERT_LIBRARIES"},
		{"DYLD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"},
		{"DYLD_FRAMEWORK_PATH", "DYLD_FRAMEWORK_PATH"},
		{"DYLD_FALLBACK_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH"},
		{"DYLD_FORCE_FLAT_NAMESPACE", "DYLD_FORCE_FLAT_NAMESPACE"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !isDeniedEnvVar(tc.key) {
				t.Errorf("isDeniedEnvVar(%q) = false, want true", tc.key)
			}
		})
	}
}

func TestIsDeniedEnvVar_Allowed(t *testing.T) {
	allowed := []string{
		"MY_CUSTOM_VAR", "GOPATH", "LANG", "TZ",
		"HOME", "USER", "PATH", "TERM",
		"HOSTNAME", "TMPDIR",
	}

	for _, key := range allowed {
		t.Run(key, func(t *testing.T) {
			if isDeniedEnvVar(key) {
				t.Errorf("isDeniedEnvVar(%q) = true, want false", key)
			}
		})
	}
}

func TestIsDeniedEnvVar_CaseSensitive(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{"all lower", "ld_preload"},
		{"mixed case", "Ld_Preload"},
		{"title case", "Node_Options"},
		{"lower bash_func", "bash_func_myfunc%%"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if isDeniedEnvVar(tc.key) {
				t.Errorf("isDeniedEnvVar(%q) = true, want false (denylist is case-sensitive)", tc.key)
			}
		})
	}
}

func TestBuildEnvironment_DeniedVarRejected(t *testing.T) {
	executor := &ToolExecutor{
		req: &protocol.ProxyRequest{
			Env: map[string]string{
				"LD_PRELOAD": "/evil.so",
			},
		},
		tool: &config.ToolDef{},
		cfg:  &config.Config{},
	}

	env, err := executor.buildEnvironment()
	if err != nil {
		t.Fatalf("buildEnvironment() error: %v", err)
	}

	if _, found := envContains(env, "LD_PRELOAD"); found {
		t.Error("buildEnvironment() included denied var LD_PRELOAD in output")
	}
}

func TestBuildEnvironment_AllowedVarAccepted(t *testing.T) {
	executor := &ToolExecutor{
		req: &protocol.ProxyRequest{
			Env: map[string]string{
				"MY_VAR": "hello",
			},
		},
		tool: &config.ToolDef{},
		cfg:  &config.Config{},
	}

	env, err := executor.buildEnvironment()
	if err != nil {
		t.Fatalf("buildEnvironment() error: %v", err)
	}

	val, found := envContains(env, "MY_VAR")
	if !found {
		t.Fatal("buildEnvironment() did not include MY_VAR")
	}
	if val != "hello" {
		t.Errorf("MY_VAR = %q, want %q", val, "hello")
	}
}

func TestBuildEnvironment_ForcedEnvStillWorks(t *testing.T) {
	executor := &ToolExecutor{
		req: &protocol.ProxyRequest{
			Env: map[string]string{
				"GH_PAGER": "less",
			},
		},
		tool: &config.ToolDef{
			ForcedEnv: map[string]string{
				"GH_PAGER": "",
			},
		},
		cfg: &config.Config{},
	}

	env, err := executor.buildEnvironment()
	if err != nil {
		t.Fatalf("buildEnvironment() error: %v", err)
	}

	val, found := envContains(env, "GH_PAGER")
	if !found {
		t.Fatal("buildEnvironment() did not include GH_PAGER from forced_env")
	}
	if val != "" {
		t.Errorf("GH_PAGER = %q, want %q (forced_env should win)", val, "")
	}
}

func TestBuildEnvironment_MinimalBase(t *testing.T) {
	executor := &ToolExecutor{
		req:  &protocol.ProxyRequest{},
		tool: &config.ToolDef{},
		cfg:  &config.Config{},
	}

	env, err := executor.buildEnvironment()
	if err != nil {
		t.Fatalf("buildEnvironment() error: %v", err)
	}

	required := []string{"PATH", "HOME", "USER", "TERM"}
	for _, key := range required {
		if _, found := envContains(env, key); !found {
			t.Errorf("buildEnvironment() missing base env var %s", key)
		}
	}
}

func TestBuildEnvironment_DeniedVarInForcedEnv(t *testing.T) {
	// Admin controls forced_env; denylist only blocks req.Env
	executor := &ToolExecutor{
		req: &protocol.ProxyRequest{},
		tool: &config.ToolDef{
			ForcedEnv: map[string]string{
				"LD_PRELOAD": "/lib/something.so",
			},
		},
		cfg: &config.Config{},
	}

	env, err := executor.buildEnvironment()
	if err != nil {
		t.Fatalf("buildEnvironment() error: %v", err)
	}

	val, found := envContains(env, "LD_PRELOAD")
	if !found {
		t.Fatal("buildEnvironment() should allow LD_PRELOAD via forced_env (admin-controlled)")
	}
	if val != "/lib/something.so" {
		t.Errorf("LD_PRELOAD = %q, want %q", val, "/lib/something.so")
	}
}

func TestBuildEnvironment_MultipleDeniedVarsFiltered(t *testing.T) {
	executor := &ToolExecutor{
		req: &protocol.ProxyRequest{
			Env: map[string]string{
				"LD_PRELOAD":         "/evil.so",
				"PYTHONPATH":         "/tmp/backdoor",
				"NODE_OPTIONS":       "--require /tmp/evil.js",
				"BASH_FUNC_myfunc%%": "() { evil; }",
				"MY_SAFE_VAR":        "safe-value",
			},
		},
		tool: &config.ToolDef{},
		cfg:  &config.Config{},
	}

	env, err := executor.buildEnvironment()
	if err != nil {
		t.Fatalf("buildEnvironment() error: %v", err)
	}

	// All denied vars must be absent
	deniedKeys := []string{"LD_PRELOAD", "PYTHONPATH", "NODE_OPTIONS", "BASH_FUNC_myfunc%%"}
	for _, key := range deniedKeys {
		if _, found := envContains(env, key); found {
			t.Errorf("buildEnvironment() should have filtered denied var %s", key)
		}
	}

	// Safe var must be present
	if _, found := envContains(env, "MY_SAFE_VAR"); !found {
		t.Error("buildEnvironment() filtered safe var MY_SAFE_VAR")
	}
}

func TestBuildEnvironment_ReqEnvCannotOverrideForcedEnv(t *testing.T) {
	executor := &ToolExecutor{
		req: &protocol.ProxyRequest{
			Env: map[string]string{
				"SOME_KEY": "attacker-value",
			},
		},
		tool: &config.ToolDef{
			ForcedEnv: map[string]string{
				"SOME_KEY": "admin-value",
			},
		},
		cfg: &config.Config{},
	}

	env, err := executor.buildEnvironment()
	if err != nil {
		t.Fatalf("buildEnvironment() error: %v", err)
	}

	val, found := envContains(env, "SOME_KEY")
	if !found {
		t.Fatal("buildEnvironment() missing SOME_KEY")
	}
	if val != "admin-value" {
		t.Errorf("SOME_KEY = %q, want %q (forced_env must win)", val, "admin-value")
	}
}

func TestBuildAuthenticatedProxyURL(t *testing.T) {
	token := "token-with:/?special#chars"
	rawURL, err := buildAuthenticatedProxyURL("127.0.0.1:8080", token)
	if err != nil {
		t.Fatalf("buildAuthenticatedProxyURL() error: %v", err)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse() error: %v", err)
	}
	if parsed.Scheme != "http" {
		t.Fatalf("scheme = %q, want %q", parsed.Scheme, "http")
	}
	if parsed.Host != "127.0.0.1:8080" {
		t.Fatalf("host = %q, want %q", parsed.Host, "127.0.0.1:8080")
	}
	if parsed.User == nil {
		t.Fatal("missing user info")
	}
	if got := parsed.User.Username(); got != "claw" {
		t.Fatalf("username = %q, want %q", got, "claw")
	}
	pass, ok := parsed.User.Password()
	if !ok {
		t.Fatal("missing password")
	}
	if pass != token {
		t.Fatalf("password = %q, want %q", pass, token)
	}
}

func TestBuildEnvironment_UseProxyInjectsAuthenticatedURL(t *testing.T) {
	executor := &ToolExecutor{
		req: &protocol.ProxyRequest{},
		tool: &config.ToolDef{
			UseProxy: true,
		},
		cfg: &config.Config{
			HTTPProxy: &config.HTTPProxyConfig{
				Enabled: true,
				Listen:  "127.0.0.1:9090",
				CA: config.CAConfig{
					Path: "/tmp/test-ca",
				},
			},
		},
		proxyAuthToken: "test-token",
	}

	env, err := executor.buildEnvironment()
	if err != nil {
		t.Fatalf("buildEnvironment() error: %v", err)
	}

	proxyURL, found := envContains(env, "HTTP_PROXY")
	if !found {
		t.Fatal("HTTP_PROXY not set")
	}
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("url.Parse(HTTP_PROXY) error: %v", err)
	}
	if parsed.Host != "127.0.0.1:9090" {
		t.Fatalf("HTTP_PROXY host = %q, want %q", parsed.Host, "127.0.0.1:9090")
	}
	if parsed.User == nil {
		t.Fatal("HTTP_PROXY missing user info")
	}
	if got := parsed.User.Username(); got != "claw" {
		t.Fatalf("HTTP_PROXY username = %q, want %q", got, "claw")
	}

	if _, found := envContains(env, "SSL_CERT_FILE"); !found {
		t.Fatal("SSL_CERT_FILE not set")
	}
	if _, found := envContains(env, "NODE_EXTRA_CA_CERTS"); !found {
		t.Fatal("NODE_EXTRA_CA_CERTS not set")
	}
	if _, found := envContains(env, "REQUESTS_CA_BUNDLE"); !found {
		t.Fatal("REQUESTS_CA_BUNDLE not set")
	}
	if _, found := envContains(env, "CURL_CA_BUNDLE"); !found {
		t.Fatal("CURL_CA_BUNDLE not set")
	}
}

func TestBuildEnvironment_UseProxyRequiresToken(t *testing.T) {
	executor := &ToolExecutor{
		req: &protocol.ProxyRequest{},
		tool: &config.ToolDef{
			UseProxy: true,
		},
		cfg: &config.Config{
			HTTPProxy: &config.HTTPProxyConfig{
				Enabled: true,
				Listen:  "127.0.0.1:9090",
			},
		},
	}

	_, err := executor.buildEnvironment()
	if err == nil {
		t.Fatal("buildEnvironment() should fail when proxy auth token is missing")
	}
	if !strings.Contains(err.Error(), "missing proxy auth token") {
		t.Fatalf("error = %v, want missing proxy auth token", err)
	}
}
