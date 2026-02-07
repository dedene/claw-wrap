//go:build linux

package daemon

import (
	"os"
	"path/filepath"
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
