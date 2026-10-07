package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadYAML(t *testing.T, content string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wrappers.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return Load(path)
}

func TestLoad_WorkingDirAndUseStdin(t *testing.T) {
	cfg, err := loadYAML(t, `
tools:
  batch:
    binary: /usr/bin/true
    working_dir: /tmp
    use_stdin: false
  plain:
    binary: /usr/bin/true
`)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	batch := cfg.Tools["batch"]
	if batch.WorkingDir != "/tmp" {
		t.Errorf("WorkingDir = %q, want /tmp", batch.WorkingDir)
	}
	if batch.GetUseStdin() {
		t.Error("GetUseStdin() = true, want false")
	}
	if batch.GetUsePTY() {
		t.Error("use_stdin: false must imply no PTY when use_pty is unset")
	}

	plain := cfg.Tools["plain"]
	if !plain.GetUseStdin() || !plain.GetUsePTY() {
		t.Error("defaults must keep stdin and PTY enabled")
	}
}

func TestLoad_RequestEnv(t *testing.T) {
	cfg, err := loadYAML(t, `
tools:
  none:
    binary: /usr/bin/true
    request_env: []
  term:
    binary: /usr/bin/true
    request_env: [TERM, COLORTERM]
  legacy:
    binary: /usr/bin/true
`)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.Tools["none"].RequestEnv; got == nil || len(got) != 0 {
		t.Errorf("request_env: [] must load as an empty, non-nil allowlist, got %#v", got)
	}
	if got := cfg.Tools["term"].RequestEnv; len(got) != 2 {
		t.Errorf("request_env = %#v", got)
	}
	if cfg.Tools["legacy"].RequestEnv != nil {
		t.Error("unset request_env must stay nil (legacy behaviour)")
	}
}

func TestValidate_ToolOptionErrors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "relative working_dir",
			yaml: `
tools:
  t:
    binary: /usr/bin/true
    working_dir: tmp
`,
			wantErr: "working_dir must be absolute",
		},
		{
			name: "use_pty true with use_stdin false",
			yaml: `
tools:
  t:
    binary: /usr/bin/true
    use_pty: true
    use_stdin: false
`,
			wantErr: "use_pty: true conflicts with use_stdin: false",
		},
	}

	tests = append(tests, struct {
		name    string
		yaml    string
		wantErr string
	}{
		name: "invalid request_env name",
		yaml: `
tools:
  t:
    binary: /usr/bin/true
    request_env: ["BAD-NAME"]
`,
		wantErr: "invalid request_env name",
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadYAML(t, tt.yaml)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
