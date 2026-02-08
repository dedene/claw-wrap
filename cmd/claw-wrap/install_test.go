package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeInstallConfig(t *testing.T, path string) {
	t.Helper()
	content := `tools:
  gh:
    binary: /bin/echo
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func runInstallWithArgs(t *testing.T, args ...string) error {
	t.Helper()
	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	os.Args = args
	return runInstall()
}

func TestRunInstall_ConflictRegularFileWithoutForce(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wrappers.yaml")
	writeInstallConfig(t, configPath)

	target := filepath.Join(tmpDir, "gh")
	if err := os.WriteFile(target, []byte("real-binary"), 0o755); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	err := runInstallWithArgs(t, "claw-wrap", "install", "--config", configPath, "--install-dir", tmpDir)
	if err == nil {
		t.Fatal("runInstall() error = nil, want conflict error")
	}
	if !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("runInstall() error = %q, want conflict hint", err)
	}

	info, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("lstat target: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("target unexpectedly replaced with symlink")
	}
}

func TestRunInstall_ConflictForeignSymlinkWithoutForce(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wrappers.yaml")
	writeInstallConfig(t, configPath)

	target := filepath.Join(tmpDir, "gh")
	if err := os.Symlink("/bin/echo", target); err != nil {
		t.Fatalf("create foreign symlink: %v", err)
	}

	err := runInstallWithArgs(t, "claw-wrap", "install", "--config", configPath, "--install-dir", tmpDir)
	if err == nil {
		t.Fatal("runInstall() error = nil, want conflict error")
	}

	link, err := os.Readlink(target)
	if err != nil {
		t.Fatalf("readlink target: %v", err)
	}
	if link != "/bin/echo" {
		t.Fatalf("symlink target = %q, want %q", link, "/bin/echo")
	}
}

func TestRunInstall_IdempotentWhenAlreadyLinked(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wrappers.yaml")
	writeInstallConfig(t, configPath)

	clawWrapPath, err := selfExePath()
	if err != nil {
		t.Fatalf("selfExePath() error = %v", err)
	}

	target := filepath.Join(tmpDir, "gh")
	if err := os.Symlink(clawWrapPath, target); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	if err := runInstallWithArgs(t, "claw-wrap", "install", "--config", configPath, "--install-dir", tmpDir); err != nil {
		t.Fatalf("runInstall() error = %v, want nil", err)
	}

	ok, err := symlinkPointsTo(target, clawWrapPath)
	if err != nil {
		t.Fatalf("symlinkPointsTo() error = %v", err)
	}
	if !ok {
		t.Fatal("symlink should remain linked to claw-wrap binary")
	}
}

func TestRunInstall_ForceReplacesExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "wrappers.yaml")
	writeInstallConfig(t, configPath)

	target := filepath.Join(tmpDir, "gh")
	if err := os.WriteFile(target, []byte("real-binary"), 0o755); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	if err := runInstallWithArgs(t, "claw-wrap", "install", "--config", configPath, "--install-dir", tmpDir, "--force"); err != nil {
		t.Fatalf("runInstall() error = %v, want nil", err)
	}

	info, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("lstat target: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("target should be replaced with symlink")
	}
}
