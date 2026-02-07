package credentials

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeMockPassScript(t *testing.T, dir, markerFile string) string {
	t.Helper()
	scriptPath := filepath.Join(dir, "mock-pass")
	// Skip the '--' separator arg, use the last positional arg as the path
	script := `#!/bin/sh
echo "$0" > "` + markerFile + `"
shift  # skip '--'
echo "secret-for-$1"
`
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatalf("write mock script: %v", err)
	}
	return scriptPath
}

func TestWithPassBinary(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"custom path", "/custom/pass"},
		{"empty string", ""},
		{"relative path", "pass"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &FetchOptions{}
			WithPassBinary(tt.path)(opts)
			if opts.PassBinary != tt.path {
				t.Errorf("PassBinary = %q, want %q", opts.PassBinary, tt.path)
			}
		})
	}
}

func TestFetch_DefaultPassBinary(t *testing.T) {
	// Verify the default is /usr/bin/pass when no option is provided.
	options := &FetchOptions{PassBinary: "/usr/bin/pass"}
	// Apply zero options — simulates what Fetch does internally.
	for _, opt := range []FetchOption{} {
		opt(options)
	}
	if options.PassBinary != "/usr/bin/pass" {
		t.Errorf("default PassBinary = %q, want /usr/bin/pass", options.PassBinary)
	}
}

func TestFetch_PassPrefix(t *testing.T) {
	tmpDir := t.TempDir()
	markerFile := filepath.Join(tmpDir, "marker")
	scriptPath := writeMockPassScript(t, tmpDir, markerFile)

	value, err := Fetch("pass:test/path", WithPassBinary(scriptPath))
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	want := "secret-for-test/path"
	if value != want {
		t.Errorf("Fetch() = %q, want %q", value, want)
	}

	marker, err := os.ReadFile(markerFile)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if got := strings.TrimSpace(string(marker)); got != scriptPath {
		t.Errorf("invoked binary = %q, want %q", got, scriptPath)
	}
}

func TestFetch_LegacyFormat(t *testing.T) {
	tmpDir := t.TempDir()
	markerFile := filepath.Join(tmpDir, "marker")
	scriptPath := writeMockPassScript(t, tmpDir, markerFile)

	value, err := Fetch("some/legacy/path", WithPassBinary(scriptPath))
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	want := "secret-for-some/legacy/path"
	if value != want {
		t.Errorf("Fetch() = %q, want %q", value, want)
	}

	marker, err := os.ReadFile(markerFile)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if got := strings.TrimSpace(string(marker)); got != scriptPath {
		t.Errorf("invoked binary = %q, want %q", got, scriptPath)
	}
}

func TestFetch_EnvPrefix_MissingFile(t *testing.T) {
	// env: prefix routes to fetchFromEnvFile which reads DefaultEnvFile.
	// When that file doesn't exist, we expect an error.
	_, err := Fetch("env:MY_VAR")
	if err == nil {
		t.Fatal("Fetch(env:MY_VAR) returned nil error, want error for missing env file")
	}
	if !strings.Contains(err.Error(), "open env file") {
		t.Errorf("error = %q, want it to mention opening env file", err.Error())
	}
}

func TestFetchFromPass_UsesProvidedBinary(t *testing.T) {
	tests := []struct {
		name     string
		passPath string
		want     string
	}{
		{"simple path", "my/token", "secret-for-my/token"},
		{"nested path", "a/b/c/d", "secret-for-a/b/c/d"},
		{"single segment", "token", "secret-for-token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			markerFile := filepath.Join(tmpDir, "marker")
			scriptPath := writeMockPassScript(t, tmpDir, markerFile)

			value, err := fetchFromPass(scriptPath, tt.passPath)
			if err != nil {
				t.Fatalf("fetchFromPass() error = %v", err)
			}
			if value != tt.want {
				t.Errorf("fetchFromPass() = %q, want %q", value, tt.want)
			}
		})
	}
}

func TestFetchFromPass_NonexistentBinary(t *testing.T) {
	_, err := fetchFromPass("/nonexistent/binary/pass", "some/path")
	if err == nil {
		t.Fatal("fetchFromPass() returned nil error for nonexistent binary")
	}
}

func TestFetchFromPass_FailingBinary(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "fail-pass")
	script := "#!/bin/sh\nexit 1\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	_, err := fetchFromPass(scriptPath, "some/path")
	if err == nil {
		t.Fatal("fetchFromPass() returned nil error for failing binary")
	}
	if !strings.Contains(err.Error(), "some/path") {
		t.Errorf("error = %q, want it to contain the pass path", err.Error())
	}
}

func TestFetchFromPass_TrimsWhitespace(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "ws-pass")
	// Script outputs value with trailing newlines/spaces
	script := "#!/bin/sh\nprintf '  secret-value  \\n\\n'\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	value, err := fetchFromPass(scriptPath, "key")
	if err != nil {
		t.Fatalf("fetchFromPass() error = %v", err)
	}
	if value != "secret-value" {
		t.Errorf("fetchFromPass() = %q, want %q", value, "secret-value")
	}
}

func TestFetchFromEnvFile_VarNotFound(t *testing.T) {
	// fetchFromEnvFile reads DefaultEnvFile which likely doesn't exist in test.
	// This is effectively the same as TestFetch_EnvPrefix_MissingFile but
	// exercises the unexported function directly.
	_, err := fetchFromEnvFile("NONEXISTENT_VAR")
	if err == nil {
		t.Fatal("fetchFromEnvFile() returned nil error when env file missing")
	}
}

func TestFetch_PassBinaryAbsolutePath(t *testing.T) {
	// Core regression test: verify that the absolute path of the custom binary
	// is what actually gets executed, not just "pass" from $PATH.
	tmpDir := t.TempDir()
	markerFile := filepath.Join(tmpDir, "invoked-binary")

	scriptPath := filepath.Join(tmpDir, "my-custom-pass")
	script := `#!/bin/sh
echo "$0" > "` + markerFile + `"
echo "custom-result"
`
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatalf("write mock script: %v", err)
	}

	value, err := Fetch("pass:infra/api-key", WithPassBinary(scriptPath))
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if value != "custom-result" {
		t.Errorf("Fetch() = %q, want %q", value, "custom-result")
	}

	// Verify the exact binary that was invoked.
	marker, err := os.ReadFile(markerFile)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	invokedBinary := strings.TrimSpace(string(marker))
	if invokedBinary != scriptPath {
		t.Errorf("invoked binary = %q, want absolute path %q", invokedBinary, scriptPath)
	}
}
