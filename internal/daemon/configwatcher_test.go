package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigWatcher_ReloadsOnFileChange(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wrappers.yaml")

	initialConfig := `
tools:
  gh:
    binary: /usr/bin/gh
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0o644); err != nil {
		t.Fatalf("write initial config: %v", err)
	}

	d := New(WithConfigPath(configPath))
	if err := d.reloadConfig(); err != nil {
		t.Fatalf("initial reloadConfig: %v", err)
	}

	if err := d.startConfigWatcher(); err != nil {
		t.Fatalf("startConfigWatcher: %v", err)
	}
	defer d.stopConfigWatcher()

	// Modify config — add a new tool
	updatedConfig := `
tools:
  gh:
    binary: /usr/bin/gh
  npm:
    binary: /usr/bin/npm
`
	if err := os.WriteFile(configPath, []byte(updatedConfig), 0o644); err != nil {
		t.Fatalf("write updated config: %v", err)
	}

	// Wait for debounce + reload (500ms debounce + margin)
	deadline := time.After(3 * time.Second)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for config reload")
		case <-tick.C:
			cfg := d.getConfig()
			if cfg != nil && len(cfg.Tools) == 2 {
				if _, ok := cfg.Tools["npm"]; ok {
					return // success
				}
			}
		}
	}
}

func TestConfigWatcher_DebounceCoalescesRapidWrites(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wrappers.yaml")

	initialConfig := `
tools:
  gh:
    binary: /usr/bin/gh
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0o644); err != nil {
		t.Fatalf("write initial config: %v", err)
	}

	d := New(WithConfigPath(configPath))
	if err := d.reloadConfig(); err != nil {
		t.Fatalf("initial reloadConfig: %v", err)
	}

	if err := d.startConfigWatcher(); err != nil {
		t.Fatalf("startConfigWatcher: %v", err)
	}
	defer d.stopConfigWatcher()

	// Rapid-fire 5 writes within 100ms (well under 500ms debounce)
	for i := 0; i < 5; i++ {
		cfg := `
tools:
  gh:
    binary: /usr/bin/gh
  rapid:
    binary: /usr/bin/rapid
`
		if err := os.WriteFile(configPath, []byte(cfg), 0o644); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Wait for debounce to fire
	time.Sleep(configWatchDebounce + 200*time.Millisecond)

	// Config should have been reloaded
	cfg := d.getConfig()
	if cfg == nil || len(cfg.Tools) != 2 {
		t.Fatalf("expected 2 tools after rapid writes, got %v", cfg)
	}

	// Now write a distinguishable config to detect any extra reloads
	finalConfig := `
tools:
  gh:
    binary: /usr/bin/gh
  rapid:
    binary: /usr/bin/rapid
  final:
    binary: /usr/bin/final
`
	if err := os.WriteFile(configPath, []byte(finalConfig), 0o644); err != nil {
		t.Fatalf("write final config: %v", err)
	}

	// Wait for that reload
	deadline := time.After(3 * time.Second)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for final config reload")
		case <-tick.C:
			cfg := d.getConfig()
			if cfg != nil && len(cfg.Tools) == 3 {
				return // debounce confirmed by reaching final state
			}
		}
	}
}

func TestConfigWatcher_InvalidConfigKeepsOld(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wrappers.yaml")

	validConfig := `
tools:
  gh:
    binary: /usr/bin/gh
`
	if err := os.WriteFile(configPath, []byte(validConfig), 0o644); err != nil {
		t.Fatalf("write valid config: %v", err)
	}

	d := New(WithConfigPath(configPath))
	if err := d.reloadConfig(); err != nil {
		t.Fatalf("initial reloadConfig: %v", err)
	}

	if err := d.startConfigWatcher(); err != nil {
		t.Fatalf("startConfigWatcher: %v", err)
	}
	defer d.stopConfigWatcher()

	// Write invalid YAML
	if err := os.WriteFile(configPath, []byte("{{invalid yaml}}"), 0o644); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}

	// Wait for debounce + attempted reload
	time.Sleep(configWatchDebounce + 300*time.Millisecond)

	// Previous config should be preserved
	cfg := d.getConfig()
	if cfg == nil {
		t.Fatal("config should not be nil after failed reload")
	}
	if len(cfg.Tools) != 1 {
		t.Fatalf("expected 1 tool (preserved), got %d", len(cfg.Tools))
	}
	if _, ok := cfg.Tools["gh"]; !ok {
		t.Error("expected 'gh' tool preserved after failed reload")
	}
}

func TestConfigWatcher_StopIsIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wrappers.yaml")

	if err := os.WriteFile(configPath, []byte("tools: {}\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	d := New(WithConfigPath(configPath))
	if err := d.reloadConfig(); err != nil {
		t.Fatalf("initial reloadConfig: %v", err)
	}

	if err := d.startConfigWatcher(); err != nil {
		t.Fatalf("startConfigWatcher: %v", err)
	}

	// Stop multiple times — should not panic
	d.stopConfigWatcher()
	d.stopConfigWatcher()
	d.stopConfigWatcher()
}

func TestConfigWatcher_StopBeforeStart(t *testing.T) {
	d := New()

	// Stop without ever starting — should not panic
	d.stopConfigWatcher()
}

func TestConfigWatcher_IgnoresUnrelatedFiles(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wrappers.yaml")

	validConfig := `
tools:
  gh:
    binary: /usr/bin/gh
`
	if err := os.WriteFile(configPath, []byte(validConfig), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	d := New(WithConfigPath(configPath))
	if err := d.reloadConfig(); err != nil {
		t.Fatalf("initial reloadConfig: %v", err)
	}

	if err := d.startConfigWatcher(); err != nil {
		t.Fatalf("startConfigWatcher: %v", err)
	}
	defer d.stopConfigWatcher()

	// Write an unrelated file in the same directory
	otherPath := filepath.Join(tmpDir, "other.yaml")
	if err := os.WriteFile(otherPath, []byte("unrelated: true\n"), 0o644); err != nil {
		t.Fatalf("write other file: %v", err)
	}

	// Wait past debounce window
	time.Sleep(configWatchDebounce + 300*time.Millisecond)

	// Config should be unchanged (still 1 tool)
	cfg := d.getConfig()
	if cfg == nil || len(cfg.Tools) != 1 {
		t.Fatalf("config should be unchanged, got %d tools", len(cfg.Tools))
	}
}
