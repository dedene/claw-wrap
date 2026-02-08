package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFindTrustedBinary_FindsExecutable(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "pass")
	if err := os.WriteFile(binaryPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	origDirs := trustedBinaryDirs
	defer func() { trustedBinaryDirs = origDirs }()
	trustedBinaryDirs = []string{tmpDir}

	got, err := FindTrustedBinary("pass")
	if err != nil {
		t.Fatalf("FindTrustedBinary() error = %v", err)
	}
	if got != binaryPath {
		t.Fatalf("FindTrustedBinary() = %q, want %q", got, binaryPath)
	}
}

func TestFindTrustedBinary_DoesNotUsePATH(t *testing.T) {
	maliciousDir := t.TempDir()
	maliciousBinary := filepath.Join(maliciousDir, "pass")
	if err := os.WriteFile(maliciousBinary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	origPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", maliciousDir); err != nil {
		t.Fatalf("set PATH: %v", err)
	}
	defer os.Setenv("PATH", origPath)

	origDirs := trustedBinaryDirs
	defer func() { trustedBinaryDirs = origDirs }()
	trustedBinaryDirs = []string{}

	if _, err := FindTrustedBinary("pass"); err == nil {
		t.Fatal("FindTrustedBinary() error = nil, want not found when only PATH has binary")
	}
}

func TestFindTrustedBinary_RejectsPathSeparator(t *testing.T) {
	if _, err := FindTrustedBinary("bin/pass"); err == nil {
		t.Fatal("FindTrustedBinary() error = nil, want error for path separator")
	}
}

func TestDefaultPassBinary_UsesTrustedLookup(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "pass")
	if err := os.WriteFile(binaryPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	origDirs := trustedBinaryDirs
	defer func() { trustedBinaryDirs = origDirs }()
	trustedBinaryDirs = []string{tmpDir}

	if got := DefaultPassBinary(); got != binaryPath {
		t.Fatalf("DefaultPassBinary() = %q, want %q", got, binaryPath)
	}
}

func TestCADir_PlatformSpecific(t *testing.T) {
	got := CADir()

	switch runtime.GOOS {
	case "darwin":
		// macOS should use ~/.claw-wrap/ca
		home, _ := os.UserHomeDir()
		want := filepath.Join(home, ".claw-wrap", "ca")
		if got != want {
			t.Errorf("CADir() = %q, want %q", got, want)
		}
	case "linux":
		// Linux should use /etc/openclaw/ca
		if got != "/etc/openclaw/ca" {
			t.Errorf("CADir() = %q, want /etc/openclaw/ca", got)
		}
	default:
		// Other platforms - just verify it returns a non-empty path
		if got == "" {
			t.Error("CADir() returned empty string")
		}
	}

	// Path should not contain ~ (unexpanded)
	if strings.Contains(got, "~") {
		t.Errorf("CADir() = %q, contains unexpanded ~", got)
	}
}
