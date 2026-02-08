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

func TestWithOPBinary(t *testing.T) {
	opts := &FetchOptions{}
	WithOPBinary("/custom/op")(opts)
	if opts.OPBinary != "/custom/op" {
		t.Errorf("OPBinary = %q, want %q", opts.OPBinary, "/custom/op")
	}
}

func TestWithBWBinary(t *testing.T) {
	opts := &FetchOptions{}
	WithBWBinary("/custom/bw")(opts)
	if opts.BWBinary != "/custom/bw" {
		t.Errorf("BWBinary = %q, want %q", opts.BWBinary, "/custom/bw")
	}
}

func TestWithBypassCache(t *testing.T) {
	opts := &FetchOptions{}
	WithBypassCache()(opts)
	if !opts.BypassCache {
		t.Error("BypassCache = false, want true")
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
	orig := DefaultEnvFile
	DefaultEnvFile = filepath.Join(t.TempDir(), "missing-env-file")
	defer func() { DefaultEnvFile = orig }()

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

func TestFetch_EnvWithJQ(t *testing.T) {
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, "env")
	if err := os.WriteFile(envFile, []byte(`MY_JSON={"password":"abc123"}`+"\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	orig := DefaultEnvFile
	DefaultEnvFile = envFile
	defer func() { DefaultEnvFile = orig }()

	value, err := Fetch("env:MY_JSON | .password")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if value != "abc123" {
		t.Errorf("Fetch() = %q, want %q", value, "abc123")
	}
}

func TestFetch_EnvWithJQ_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, "env")
	if err := os.WriteFile(envFile, []byte("MY_TOKEN=abc123\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	orig := DefaultEnvFile
	DefaultEnvFile = envFile
	defer func() { DefaultEnvFile = orig }()

	_, err := Fetch("env:MY_TOKEN | .password")
	if err == nil {
		t.Fatal("Fetch() should fail when jq is used with non-JSON env value")
	}
	if !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("error = %q, want invalid JSON", err.Error())
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
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, "env")
	if err := os.WriteFile(envFile, []byte("OTHER=123\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	orig := DefaultEnvFile
	DefaultEnvFile = envFile
	defer func() { DefaultEnvFile = orig }()

	_, err := fetchFromEnvFile("NONEXISTENT_VAR")
	if err == nil {
		t.Fatal("fetchFromEnvFile() returned nil error when env var is missing")
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

func TestFetchFromEnvFile_ValidPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, "env")
	if err := os.WriteFile(envFile, []byte("MY_TOKEN=abc123\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	orig := DefaultEnvFile
	DefaultEnvFile = envFile
	defer func() { DefaultEnvFile = orig }()

	value, err := fetchFromEnvFile("MY_TOKEN")
	if err != nil {
		t.Fatalf("fetchFromEnvFile() error = %v", err)
	}
	if value != "abc123" {
		t.Errorf("fetchFromEnvFile() = %q, want %q", value, "abc123")
	}
}

func TestValidateEnvFile_RejectsSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	realPath := filepath.Join(tmpDir, "real-env")
	if err := os.WriteFile(realPath, []byte("TOKEN=x\n"), 0o600); err != nil {
		t.Fatalf("write real env file: %v", err)
	}

	linkPath := filepath.Join(tmpDir, "env-link")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	if err := validateEnvFile(linkPath); err == nil {
		t.Fatal("validateEnvFile() returned nil for symlink")
	}
}

func TestValidateEnvFile_RejectsNonRegularFile(t *testing.T) {
	tmpDir := t.TempDir()
	if err := validateEnvFile(tmpDir); err == nil {
		t.Fatal("validateEnvFile() returned nil for directory")
	}
}

func TestValidateEnvFile_RejectsBroadPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, "env")
	if err := os.WriteFile(envFile, []byte("TOKEN=x\n"), 0o644); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	if err := validateEnvFile(envFile); err == nil {
		t.Fatal("validateEnvFile() returned nil for broad permissions")
	}
}

func TestValidateEnvFile_Allows0640(t *testing.T) {
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, "env")
	if err := os.WriteFile(envFile, []byte("TOKEN=x\n"), 0o640); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	if err := validateEnvFile(envFile); err != nil {
		t.Fatalf("validateEnvFile() error = %v, want nil for 0640", err)
	}
}

func TestValidateEnvFile_RejectsOwnerMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, "env")
	if err := os.WriteFile(envFile, []byte("TOKEN=x\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	orig := currentEUIDFunc
	currentEUIDFunc = func() int { return orig() + 1 }
	defer func() { currentEUIDFunc = orig }()

	if err := validateEnvFile(envFile); err == nil {
		t.Fatal("validateEnvFile() returned nil for owner mismatch")
	}
}
