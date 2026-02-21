package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsAllowedBinary_DirectPath(t *testing.T) {
	tmpDir := t.TempDir()
	bin := filepath.Join(tmpDir, "claw-wrap")
	os.WriteFile(bin, []byte("binary"), 0o755)

	d := &Daemon{allowedBinaries: []string{bin}}
	if !d.isAllowedBinary(bin) {
		t.Fatal("direct path should be allowed")
	}
	if d.isAllowedBinary("/some/other/binary") {
		t.Fatal("unrelated path should be rejected")
	}
}

func TestIsAllowedBinary_SymlinkResolves(t *testing.T) {
	tmpDir := t.TempDir()
	real := filepath.Join(tmpDir, "real-binary")
	link := filepath.Join(tmpDir, "symlink-binary")
	os.WriteFile(real, []byte("binary"), 0o755)
	os.Symlink(real, link)

	// Allowed list has real path; caller comes through symlink.
	d := &Daemon{allowedBinaries: []string{real}}
	if !d.isAllowedBinary(link) {
		t.Fatal("symlink resolving to allowed binary should be accepted")
	}

	// Allowed list has symlink; caller uses real path.
	d2 := &Daemon{allowedBinaries: []string{link}}
	if !d2.isAllowedBinary(real) {
		t.Fatal("real path should match when allowed list contains symlink")
	}
}

func TestIsAllowedBinary_SymlinkRetarget(t *testing.T) {
	// Simulates Homebrew upgrade: symlink changes target after daemon start.
	tmpDir := t.TempDir()

	v1 := filepath.Join(tmpDir, "cellar", "1.0", "bin")
	v2 := filepath.Join(tmpDir, "cellar", "2.0", "bin")
	os.MkdirAll(v1, 0o755)
	os.MkdirAll(v2, 0o755)
	os.WriteFile(filepath.Join(v1, "claw-wrap"), []byte("v1"), 0o755)
	os.WriteFile(filepath.Join(v2, "claw-wrap"), []byte("v2"), 0o755)

	stableLink := filepath.Join(tmpDir, "claw-wrap")
	os.Symlink(filepath.Join(v1, "claw-wrap"), stableLink)

	// Daemon starts: allowedBinaries has both the resolved v1 path AND the
	// stable symlink (simulating the os.Args[0] addition).
	d := &Daemon{allowedBinaries: []string{
		filepath.Join(v1, "claw-wrap"), // resolved at startup
		stableLink,                     // stable symlink from os.Args[0]
	}}

	// Before upgrade: caller through stable link → v1 → allowed.
	if !d.isAllowedBinary(filepath.Join(v1, "claw-wrap")) {
		t.Fatal("v1 binary should be allowed before upgrade")
	}

	// Simulate upgrade: retarget symlink to v2.
	os.Remove(stableLink)
	os.Symlink(filepath.Join(v2, "claw-wrap"), stableLink)

	// After upgrade: caller resolves to v2. The stored v1 path won't match,
	// but the stored stable symlink re-resolves to v2 at check time.
	if !d.isAllowedBinary(filepath.Join(v2, "claw-wrap")) {
		t.Fatal("v2 binary should be allowed after symlink retarget via stable link")
	}
}

func TestNormalizeExecutablePath_Symlink(t *testing.T) {
	tmpDir := t.TempDir()
	real := filepath.Join(tmpDir, "real")
	link := filepath.Join(tmpDir, "link")
	os.WriteFile(real, []byte("x"), 0o755)
	os.Symlink(real, link)

	if normalizeExecutablePath(link) != normalizeExecutablePath(real) {
		t.Fatalf("symlink and real path should normalize to same value: %q vs %q",
			normalizeExecutablePath(link), normalizeExecutablePath(real))
	}
}

func TestNormalizeExecutablePath_Relative(t *testing.T) {
	result := normalizeExecutablePath("./relative/path")
	if !filepath.IsAbs(result) {
		t.Fatalf("normalizeExecutablePath should return absolute path, got %q", result)
	}
}
