package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Kubernetes mounts a ConfigMap as symlinks into a timestamped directory:
//
//	wrappers.yaml -> ..data/wrappers.yaml
//	..data        -> ..2026_10_07_10_00_00.000000001
//
// An update writes a new timestamped dir and atomically renames a fresh
// ..data_tmp symlink over ..data. No event names wrappers.yaml itself.
func TestConfigWatcher_ReloadsOnConfigMapSymlinkSwap(t *testing.T) {
	dir := t.TempDir()

	writeVersion := func(name, content string) {
		t.Helper()
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name, "wrappers.yaml"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	writeVersion("..v1", "tools:\n  gh:\n    binary: /usr/bin/gh\n")
	if err := os.Symlink("..v1", filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "wrappers.yaml")
	if err := os.Symlink("..data/wrappers.yaml", configPath); err != nil {
		t.Fatal(err)
	}

	d := New(WithConfigPath(configPath))
	if err := d.reloadConfig(); err != nil {
		t.Fatalf("initial reloadConfig: %v", err)
	}
	if err := d.startConfigWatcher(); err != nil {
		t.Fatalf("startConfigWatcher: %v", err)
	}
	defer d.stopConfigWatcher()

	// Same sequence as kubelet's AtomicWriter.
	writeVersion("..v2", "tools:\n  gh:\n    binary: /usr/bin/gh\n  mcparcel:\n    binary: /usr/local/bin/mcparcel\n")
	if err := os.Symlink("..v2", filepath.Join(dir, "..data_tmp")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "..data_tmp"), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "..v1")); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(3 * time.Second)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline:
			t.Fatal("ConfigMap-style update did not trigger a reload")
		case <-tick.C:
			if cfg := d.getConfig(); cfg != nil {
				if _, ok := cfg.Tools["mcparcel"]; ok {
					return
				}
			}
		}
	}
}
