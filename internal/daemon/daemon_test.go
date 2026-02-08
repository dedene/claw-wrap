//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
tools: {}
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	origSetAge := setAgeIdentityFileFunc
	origSetOP := setOPTokenFileFunc
	defer func() {
		setAgeIdentityFileFunc = origSetAge
		setOPTokenFileFunc = origSetOP
	}()

	var seenAge []string
	var seenOP []string
	setAgeIdentityFileFunc = func(path string) {
		seenAge = append(seenAge, path)
	}
	setOPTokenFileFunc = func(path string) {
		seenOP = append(seenOP, path)
	}

	d := New(WithConfigPath(configPath))
	if err := d.reloadConfig(); err != nil {
		t.Fatalf("initial reloadConfig() error = %v", err)
	}

	updatedConfig := `
proxy:
  age_identity_file: /tmp/age-b
  op_token_file: /tmp/op-b
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
}

func TestDaemon_Run_ConfiguresBackendsAndCleansUpOnFailure(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wrappers.yaml")
	cfg := `
proxy:
  age_identity_file: /tmp/startup-age
  op_token_file: /tmp/startup-op
  hmac_secret_file: /this/path/does/not/exist/auth
tools: {}
`
	if err := os.WriteFile(configPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	origSetAge := setAgeIdentityFileFunc
	origSetOP := setOPTokenFileFunc
	origCleanup := cleanupBWSessionFunc
	defer func() {
		setAgeIdentityFileFunc = origSetAge
		setOPTokenFileFunc = origSetOP
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
	if cleanupCalls != 1 {
		t.Fatalf("cleanupBWSessionFunc calls = %d, want 1", cleanupCalls)
	}
}
