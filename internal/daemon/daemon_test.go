//go:build linux

package daemon

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDaemon_ReloadConfig(t *testing.T) {
	// Create temp config file with one tool
	tmpDir, _ := os.MkdirTemp("", "daemon-test-*")
	defer os.RemoveAll(tmpDir)
	configPath := filepath.Join(tmpDir, "wrappers.yaml")

	initialConfig := `
tools:
  gh:
    binary: /usr/bin/gh
`
	os.WriteFile(configPath, []byte(initialConfig), 0644)

	// Create daemon with temp config
	d := New(WithConfigPath(configPath))

	// Set initial config
	if err := d.reloadConfig(); err != nil {
		t.Fatalf("initial reloadConfig() error = %v", err)
	}

	cfg := d.getConfig()
	if cfg == nil {
		t.Fatal("getConfig() returned nil")
	}
	if len(cfg.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(cfg.Tools))
	}
	if _, ok := cfg.Tools["gh"]; !ok {
		t.Error("expected tool 'gh' in config")
	}

	// Modify config file — add new tool
	updatedConfig := `
tools:
  gh:
    binary: /usr/bin/gh
  npm:
    binary: /usr/bin/npm
`
	os.WriteFile(configPath, []byte(updatedConfig), 0644)

	// Reload should pick up changes
	if err := d.reloadConfig(); err != nil {
		t.Fatalf("reloadConfig() after update error = %v", err)
	}

	cfg = d.getConfig()
	if len(cfg.Tools) != 2 {
		t.Fatalf("after reload expected 2 tools, got %d", len(cfg.Tools))
	}
	if _, ok := cfg.Tools["npm"]; !ok {
		t.Error("expected tool 'npm' after reload")
	}
}

func TestDaemon_ReloadConfig_InvalidFile(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "daemon-test-*")
	defer os.RemoveAll(tmpDir)
	configPath := filepath.Join(tmpDir, "wrappers.yaml")

	// Write valid config first
	validConfig := `
tools:
  gh:
    binary: /usr/bin/gh
`
	os.WriteFile(configPath, []byte(validConfig), 0644)

	d := New(WithConfigPath(configPath))
	d.reloadConfig()

	// Now write invalid YAML
	os.WriteFile(configPath, []byte("{{invalid yaml}}"), 0644)

	// reloadConfig should return error
	err := d.reloadConfig()
	if err == nil {
		t.Fatal("reloadConfig() should fail for invalid YAML")
	}

	// Previous valid config should be preserved
	cfg := d.getConfig()
	if cfg == nil {
		t.Fatal("getConfig() returned nil after failed reload")
	}
	if len(cfg.Tools) != 1 {
		t.Errorf("previous config should be preserved, got %d tools", len(cfg.Tools))
	}
}

func TestDaemon_ReloadConfig_InvalidRegex(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "daemon-test-*")
	defer os.RemoveAll(tmpDir)
	configPath := filepath.Join(tmpDir, "wrappers.yaml")

	// Write valid config first
	validConfig := `
tools:
  gh:
    binary: /usr/bin/gh
`
	os.WriteFile(configPath, []byte(validConfig), 0644)

	d := New(WithConfigPath(configPath))
	d.reloadConfig()

	// Write config with invalid blocked_args regex
	badConfig := `
tools:
  gh:
    binary: /usr/bin/gh
    blocked_args:
      - pattern: "[invalid("
        message: "bad pattern"
`
	os.WriteFile(configPath, []byte(badConfig), 0644)

	// reloadConfig should fail (Validate catches bad regex)
	err := d.reloadConfig()
	if err == nil {
		t.Fatal("reloadConfig() should fail for invalid regex pattern")
	}

	// Previous config preserved
	cfg := d.getConfig()
	if _, ok := cfg.Tools["gh"]; !ok {
		t.Error("previous config should still have 'gh' tool")
	}
	if len(cfg.Tools["gh"].BlockedArgs) != 0 {
		t.Error("previous config should have no blocked args")
	}
}

func TestDaemon_ReloadConfig_MissingFile(t *testing.T) {
	d := New(WithConfigPath("/nonexistent/config.yaml"))

	err := d.reloadConfig()
	if err == nil {
		t.Fatal("reloadConfig() should fail for missing file")
	}
}

func TestDaemon_GetConfig_NilBeforeLoad(t *testing.T) {
	d := New()
	cfg := d.getConfig()
	if cfg != nil {
		t.Error("getConfig() should return nil before any config loaded")
	}
}

func TestDaemon_ReloadConfig_SetsBackendTokenPaths(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wrappers.yaml")
	initialConfig := `
proxy:
  age_identity_file: /tmp/age-a
  op_token_file: /tmp/op-a
  credential_cache_ttl: 20s
tools: {}
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	origSetAge := setAgeIdentityFileFunc
	origSetOP := setOPTokenFileFunc
	origSetCacheTTL := setCredentialCacheTTLFunc
	defer func() {
		setAgeIdentityFileFunc = origSetAge
		setOPTokenFileFunc = origSetOP
		setCredentialCacheTTLFunc = origSetCacheTTL
	}()

	var seenAge []string
	var seenOP []string
	var seenCacheTTL []time.Duration
	setAgeIdentityFileFunc = func(path string) {
		seenAge = append(seenAge, path)
	}
	setOPTokenFileFunc = func(path string) {
		seenOP = append(seenOP, path)
	}
	setCredentialCacheTTLFunc = func(ttl time.Duration) {
		seenCacheTTL = append(seenCacheTTL, ttl)
	}

	d := New(WithConfigPath(configPath))
	if err := d.reloadConfig(); err != nil {
		t.Fatalf("initial reloadConfig() error = %v", err)
	}

	updatedConfig := `
proxy:
  age_identity_file: /tmp/age-b
  op_token_file: /tmp/op-b
  credential_cache_ttl: 45s
tools: {}
`
	if err := os.WriteFile(configPath, []byte(updatedConfig), 0o644); err != nil {
		t.Fatalf("write updated config: %v", err)
	}
	if err := d.reloadConfig(); err != nil {
		t.Fatalf("second reloadConfig() error = %v", err)
	}

	if len(seenAge) != 2 {
		t.Fatalf("setAgeIdentityFileFunc called %d times, want 2", len(seenAge))
	}
	if seenAge[0] != "/tmp/age-a" || seenAge[1] != "/tmp/age-b" {
		t.Fatalf("setAgeIdentityFileFunc calls = %v, want [/tmp/age-a /tmp/age-b]", seenAge)
	}
	if len(seenOP) != 2 {
		t.Fatalf("setOPTokenFileFunc called %d times, want 2", len(seenOP))
	}
	if seenOP[0] != "/tmp/op-a" || seenOP[1] != "/tmp/op-b" {
		t.Fatalf("setOPTokenFileFunc calls = %v, want [/tmp/op-a /tmp/op-b]", seenOP)
	}
	if len(seenCacheTTL) != 2 {
		t.Fatalf("setCredentialCacheTTLFunc called %d times, want 2", len(seenCacheTTL))
	}
	if seenCacheTTL[0] != 20*time.Second || seenCacheTTL[1] != 45*time.Second {
		t.Fatalf("setCredentialCacheTTLFunc calls = %v, want [20s 45s]", seenCacheTTL)
	}
}

func TestDaemon_Run_ConfiguresBackendsAndCleansUpOnFailure(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wrappers.yaml")
	cfg := `
proxy:
  age_identity_file: /tmp/startup-age
  op_token_file: /tmp/startup-op
  credential_cache_ttl: 30s
  hmac_secret_file: /this/path/does/not/exist/auth
tools: {}
`
	if err := os.WriteFile(configPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	origSetAge := setAgeIdentityFileFunc
	origSetOP := setOPTokenFileFunc
	origSetCacheTTL := setCredentialCacheTTLFunc
	origCleanup := cleanupBWSessionFunc
	defer func() {
		setAgeIdentityFileFunc = origSetAge
		setOPTokenFileFunc = origSetOP
		setCredentialCacheTTLFunc = origSetCacheTTL
		cleanupBWSessionFunc = origCleanup
	}()

	setAgePath := ""
	setAgeIdentityFileFunc = func(path string) {
		setAgePath = path
	}
	setOPPath := ""
	setOPTokenFileFunc = func(path string) {
		setOPPath = path
	}
	setCacheTTL := time.Duration(0)
	setCredentialCacheTTLFunc = func(ttl time.Duration) {
		setCacheTTL = ttl
	}

	cleanupCalls := 0
	cleanupBWSessionFunc = func() {
		cleanupCalls++
	}

	d := New(WithConfigPath(configPath))
	err := d.Run()
	if err == nil {
		t.Fatal("Run() should fail when hmac_secret_file path is invalid")
	}
	if !strings.Contains(err.Error(), "write HMAC secret") {
		t.Fatalf("Run() error = %v, want write HMAC secret failure", err)
	}

	if setAgePath != "/tmp/startup-age" {
		t.Fatalf("setAgeIdentityFileFunc path = %q, want %q", setAgePath, "/tmp/startup-age")
	}
	if setOPPath != "/tmp/startup-op" {
		t.Fatalf("setOPTokenFileFunc path = %q, want %q", setOPPath, "/tmp/startup-op")
	}
	if setCacheTTL != 30*time.Second {
		t.Fatalf("setCredentialCacheTTLFunc ttl = %v, want 30s", setCacheTTL)
	}
	if cleanupCalls != 1 {
		t.Fatalf("cleanupBWSessionFunc calls = %d, want 1", cleanupCalls)
	}
}

func TestDaemon_ReloadConfig_HTTPProxy_EnableDisable(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wrappers.yaml")

	enabledConfig := `
http_proxy:
  enabled: true
  listen: 127.0.0.1:0
tools: {}
`
	if err := os.WriteFile(configPath, []byte(enabledConfig), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	d := New(WithConfigPath(configPath))
	d.proxyAuthTokenPath = filepath.Join(tmpDir, "proxy-auth-token")
	defer func() {
		if d.httpProxy != nil {
			_ = d.httpProxy.Stop()
		}
	}()

	if err := d.reloadConfig(); err != nil {
		t.Fatalf("reloadConfig() enable error = %v", err)
	}
	if d.httpProxy == nil {
		t.Fatal("expected HTTP proxy to be started")
	}

	disabledConfig := `
http_proxy:
  enabled: false
tools: {}
`
	if err := os.WriteFile(configPath, []byte(disabledConfig), 0o644); err != nil {
		t.Fatalf("write disabled config: %v", err)
	}

	if err := d.reloadConfig(); err != nil {
		t.Fatalf("reloadConfig() disable error = %v", err)
	}
	if d.httpProxy != nil {
		t.Fatal("expected HTTP proxy to be stopped after disable")
	}
}

func TestDaemon_ReloadConfig_HTTPProxy_DisableEnable(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wrappers.yaml")

	disabledConfig := `
http_proxy:
  enabled: false
tools: {}
`
	if err := os.WriteFile(configPath, []byte(disabledConfig), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	d := New(WithConfigPath(configPath))
	d.proxyAuthTokenPath = filepath.Join(tmpDir, "proxy-auth-token")
	defer func() {
		if d.httpProxy != nil {
			_ = d.httpProxy.Stop()
		}
	}()

	if err := d.reloadConfig(); err != nil {
		t.Fatalf("reloadConfig() initial error = %v", err)
	}
	if d.httpProxy != nil {
		t.Fatal("expected HTTP proxy to be nil when disabled")
	}

	enabledConfig := `
http_proxy:
  enabled: true
  listen: 127.0.0.1:0
tools: {}
`
	if err := os.WriteFile(configPath, []byte(enabledConfig), 0o644); err != nil {
		t.Fatalf("write enabled config: %v", err)
	}

	if err := d.reloadConfig(); err != nil {
		t.Fatalf("reloadConfig() enable error = %v", err)
	}
	if d.httpProxy == nil {
		t.Fatal("expected HTTP proxy to be started after enable")
	}
}

func TestDaemon_ReloadConfig_HTTPProxy_EnabledToEnabledReloadsInPlace(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wrappers.yaml")

	initialConfig := `
http_proxy:
  enabled: true
  listen: 127.0.0.1:0
  log_level: errors
tools: {}
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	d := New(WithConfigPath(configPath))
	d.proxyAuthTokenPath = filepath.Join(tmpDir, "proxy-auth-token")
	defer func() {
		if d.httpProxy != nil {
			_ = d.httpProxy.Stop()
		}
	}()

	if err := d.reloadConfig(); err != nil {
		t.Fatalf("reloadConfig() initial error = %v", err)
	}
	if d.httpProxy == nil {
		t.Fatal("expected HTTP proxy to be started")
	}
	firstProxy := d.httpProxy

	updatedConfig := `
http_proxy:
  enabled: true
  listen: 127.0.0.1:0
  log_level: debug
tools: {}
`
	if err := os.WriteFile(configPath, []byte(updatedConfig), 0o644); err != nil {
		t.Fatalf("write updated config: %v", err)
	}

	if err := d.reloadConfig(); err != nil {
		t.Fatalf("reloadConfig() update error = %v", err)
	}
	if d.httpProxy == nil {
		t.Fatal("expected HTTP proxy to remain running")
	}
	if d.httpProxy != firstProxy {
		t.Fatal("expected HTTP proxy instance to reload in place")
	}

	cfg := d.getConfig()
	if cfg.HTTPProxy == nil || cfg.HTTPProxy.LogLevel != "debug" {
		t.Fatalf("config log_level = %v, want debug", cfg.HTTPProxy)
	}
}

func TestDaemon_EnsureProxyAuthToken_PersistsAcrossDaemonInstances(t *testing.T) {
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "proxy-auth-token")

	first := New()
	first.proxyAuthTokenPath = tokenPath
	if err := first.ensureProxyAuthToken(); err != nil {
		t.Fatalf("first ensureProxyAuthToken() error = %v", err)
	}
	if first.proxyAuthToken == "" {
		t.Fatal("first proxyAuthToken should not be empty")
	}

	second := New()
	second.proxyAuthTokenPath = tokenPath
	if err := second.ensureProxyAuthToken(); err != nil {
		t.Fatalf("second ensureProxyAuthToken() error = %v", err)
	}

	if second.proxyAuthToken != first.proxyAuthToken {
		t.Fatalf("proxyAuthToken mismatch across daemon instances: got %q, want %q", second.proxyAuthToken, first.proxyAuthToken)
	}
}

func TestDaemon_EnsureProxyAuthToken_CreatesSecureTokenFile(t *testing.T) {
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "proxy-auth-token")

	d := New()
	d.proxyAuthTokenPath = tokenPath
	if err := d.ensureProxyAuthToken(); err != nil {
		t.Fatalf("ensureProxyAuthToken() error = %v", err)
	}

	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("token file mode = %04o, want 0600", mode)
	}

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	token := strings.TrimSpace(string(data))
	if token != d.proxyAuthToken {
		t.Fatalf("token file contents mismatch: got %q, want %q", token, d.proxyAuthToken)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token decode error: %v", err)
	}
	if len(decoded) != proxyAuthTokenBytes {
		t.Fatalf("decoded token length = %d, want %d", len(decoded), proxyAuthTokenBytes)
	}
}

func TestDaemon_EnsureProxyAuthToken_RejectsInsecurePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "proxy-auth-token")

	token, err := generateProxyAuthToken()
	if err != nil {
		t.Fatalf("generateProxyAuthToken() error = %v", err)
	}
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o644); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	d := New()
	d.proxyAuthTokenPath = tokenPath
	err = d.ensureProxyAuthToken()
	if err == nil {
		t.Fatal("ensureProxyAuthToken() should fail for insecure token file permissions")
	}
	if !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("ensureProxyAuthToken() error = %v, want permissions failure", err)
	}
}

func TestDaemon_EnsureProxyAuthToken_RejectsSymlinkFile(t *testing.T) {
	tmpDir := t.TempDir()
	realPath := filepath.Join(tmpDir, "real-token")
	linkPath := filepath.Join(tmpDir, "proxy-auth-token")

	token, err := generateProxyAuthToken()
	if err != nil {
		t.Fatalf("generateProxyAuthToken() error = %v", err)
	}
	if err := os.WriteFile(realPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatalf("write real token file: %v", err)
	}
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	d := New()
	d.proxyAuthTokenPath = linkPath
	err = d.ensureProxyAuthToken()
	if err == nil {
		t.Fatal("ensureProxyAuthToken() should fail for symlink token file")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("ensureProxyAuthToken() error = %v, want symlink failure", err)
	}
}

func TestDaemon_EnsureProxyAuthToken_RejectsNonRegularFile(t *testing.T) {
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "proxy-auth-token")
	if err := os.Mkdir(tokenPath, 0o700); err != nil {
		t.Fatalf("mkdir token path: %v", err)
	}

	d := New()
	d.proxyAuthTokenPath = tokenPath
	err := d.ensureProxyAuthToken()
	if err == nil {
		t.Fatal("ensureProxyAuthToken() should fail for non-regular token file")
	}
	if !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("ensureProxyAuthToken() error = %v, want regular file failure", err)
	}
}

func TestDaemon_EnsureProxyAuthToken_RejectsInvalidToken(t *testing.T) {
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "proxy-auth-token")
	if err := os.WriteFile(tokenPath, []byte("not-a-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	d := New()
	d.proxyAuthTokenPath = tokenPath
	err := d.ensureProxyAuthToken()
	if err == nil {
		t.Fatal("ensureProxyAuthToken() should fail for invalid token format")
	}
	if !strings.Contains(err.Error(), "invalid proxy auth token") {
		t.Fatalf("ensureProxyAuthToken() error = %v, want invalid token failure", err)
	}
}

func TestDaemon_ReloadConfig_HTTPProxy_EnableDisableEnable_KeepsProxyAuthToken(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wrappers.yaml")

	enabledConfig := `
http_proxy:
  enabled: true
  listen: 127.0.0.1:0
tools: {}
`
	if err := os.WriteFile(configPath, []byte(enabledConfig), 0o644); err != nil {
		t.Fatalf("write enabled config: %v", err)
	}

	d := New(WithConfigPath(configPath))
	d.proxyAuthTokenPath = filepath.Join(tmpDir, "proxy-auth-token")
	defer func() {
		if d.httpProxy != nil {
			_ = d.httpProxy.Stop()
		}
	}()

	if err := d.reloadConfig(); err != nil {
		t.Fatalf("reloadConfig() initial enable error = %v", err)
	}
	if d.httpProxy == nil {
		t.Fatal("expected HTTP proxy to be running")
	}
	firstToken := d.proxyAuthToken
	if firstToken == "" {
		t.Fatal("expected proxyAuthToken to be set")
	}

	disabledConfig := `
http_proxy:
  enabled: false
tools: {}
`
	if err := os.WriteFile(configPath, []byte(disabledConfig), 0o644); err != nil {
		t.Fatalf("write disabled config: %v", err)
	}
	if err := d.reloadConfig(); err != nil {
		t.Fatalf("reloadConfig() disable error = %v", err)
	}
	if d.httpProxy != nil {
		t.Fatal("expected HTTP proxy to be stopped")
	}

	if err := os.WriteFile(configPath, []byte(enabledConfig), 0o644); err != nil {
		t.Fatalf("rewrite enabled config: %v", err)
	}
	if err := d.reloadConfig(); err != nil {
		t.Fatalf("reloadConfig() re-enable error = %v", err)
	}
	if d.httpProxy == nil {
		t.Fatal("expected HTTP proxy to be running after re-enable")
	}
	if d.proxyAuthToken != firstToken {
		t.Fatalf("proxyAuthToken changed across disable/enable: got %q, want %q", d.proxyAuthToken, firstToken)
	}
}
