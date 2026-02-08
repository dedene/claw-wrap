package paths

import (
	"os"
	"path/filepath"
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
