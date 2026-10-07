package credentials

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSecretFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseSource_File(t *testing.T) {
	p, err := ParseSource("file:/etc/claw-wrap/secrets/token | .value")
	if err != nil {
		t.Fatal(err)
	}
	if p.Backend != BackendFile || p.Path != "/etc/claw-wrap/secrets/token" || p.JQExpr != ".value" {
		t.Fatalf("parsed = %+v", p)
	}
}

func TestFetch_File(t *testing.T) {
	t.Run("reads value and trims trailing newline", func(t *testing.T) {
		path := writeSecretFile(t, "s3cr3t-value\r\n\n", 0o600)
		got, err := Fetch("file:" + path)
		if err != nil {
			t.Fatalf("Fetch() error = %v", err)
		}
		if got != "s3cr3t-value" {
			t.Fatalf("Fetch() = %q", got)
		}
	})

	t.Run("group-readable is allowed (k8s fsGroup + defaultMode 0440)", func(t *testing.T) {
		path := writeSecretFile(t, "v", 0o440)
		if _, err := Fetch("file:" + path); err != nil {
			t.Fatalf("Fetch() error = %v", err)
		}
	})

	t.Run("follows symlinks (k8s secret volumes use ..data links)", func(t *testing.T) {
		target := writeSecretFile(t, "linked", 0o400)
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		got, err := Fetch("file:" + link)
		if err != nil || got != "linked" {
			t.Fatalf("Fetch() = %q, %v", got, err)
		}
	})

	t.Run("jq extraction", func(t *testing.T) {
		path := writeSecretFile(t, `{"client_secret":"abc"}`, 0o600)
		got, err := Fetch("file:" + path + " | .client_secret")
		if err != nil || got != "abc" {
			t.Fatalf("Fetch() = %q, %v", got, err)
		}
	})

	t.Run("re-reads on every fetch so rotation applies", func(t *testing.T) {
		path := writeSecretFile(t, "one", 0o600)
		if got, _ := Fetch("file:" + path); got != "one" {
			t.Fatalf("first fetch = %q", got)
		}
		if err := os.WriteFile(path, []byte("two"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, _ := Fetch("file:" + path); got != "two" {
			t.Fatalf("second fetch = %q, want rotated value", got)
		}
	})

	errorCases := []struct {
		name    string
		source  func(t *testing.T) string
		wantErr string
	}{
		{"relative path", func(t *testing.T) string { return "file:secrets/token" }, "must be absolute"},
		{"world-readable", func(t *testing.T) string { return "file:" + writeSecretFile(t, "v", 0o644) }, "must not be group-writable or accessible by others"},
		{"group-writable", func(t *testing.T) string { return "file:" + writeSecretFile(t, "v", 0o660) }, "must not be group-writable or accessible by others"},
		{"directory", func(t *testing.T) string { return "file:" + t.TempDir() }, "must be a regular file"},
		{"missing", func(t *testing.T) string { return "file:/nonexistent/claw-wrap/secret" }, "open secret file"},
		{"too large", func(t *testing.T) string {
			return "file:" + writeSecretFile(t, strings.Repeat("x", maxSecretFileSize+1), 0o600)
		}, "exceeds"},
	}
	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Fetch(tc.source(t))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Fetch() error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}

	t.Run("owner must be daemon or root", func(t *testing.T) {
		path := writeSecretFile(t, "v", 0o600)
		orig := currentEUIDFunc
		currentEUIDFunc = func() int { return os.Geteuid() + 4242 }
		t.Cleanup(func() { currentEUIDFunc = orig })

		_, err := Fetch("file:" + path)
		if os.Geteuid() == 0 {
			if err != nil {
				t.Fatalf("root-owned file should be accepted: %v", err)
			}
			return
		}
		if err == nil || !strings.Contains(err.Error(), "owner must be root or the daemon uid") {
			t.Fatalf("Fetch() error = %v", err)
		}
	})

	t.Run("error never contains the secret", func(t *testing.T) {
		path := writeSecretFile(t, "TOPSECRETVALUE", 0o644)
		_, err := Fetch("file:" + path)
		if err == nil || strings.Contains(err.Error(), "TOPSECRETVALUE") {
			t.Fatalf("Fetch() error = %v", err)
		}
	})
}
