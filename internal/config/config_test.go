package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidate_ValidBlockedArgs(t *testing.T) {
	cfg := Config{
		Tools: map[string]ToolDef{
			"gh": {
				Binary: "/usr/bin/gh",
				BlockedArgs: []BlockedArg{
					{Pattern: `repo\s+delete`, Message: "no repo delete"},
					{Pattern: `^auth\s+logout$`, Message: "no logout"},
					{Pattern: `--force`, Message: "no force"},
				},
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}

	for i, b := range cfg.Tools["gh"].BlockedArgs {
		if b.Compiled == nil {
			t.Errorf("BlockedArgs[%d].Compiled is nil after Validate()", i)
		}
	}
}

func TestValidate_InvalidBlockedArgs(t *testing.T) {
	cfg := Config{
		Tools: map[string]ToolDef{
			"gh": {
				Binary: "/usr/bin/gh",
				BlockedArgs: []BlockedArg{
					{Pattern: "[invalid(", Message: "bad pattern"},
				},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil, want error for invalid regex")
	}

	if !strings.Contains(err.Error(), "[invalid(") {
		t.Errorf("error %q does not contain pattern string", err.Error())
	}
	if !strings.Contains(err.Error(), "gh") {
		t.Errorf("error %q does not contain tool name", err.Error())
	}
}

func TestValidate_EmptyBlockedArgs(t *testing.T) {
	cfg := Config{
		Tools: map[string]ToolDef{
			"gh": {
				Binary:      "/usr/bin/gh",
				BlockedArgs: nil,
			},
			"npm": {
				Binary:      "/usr/bin/npm",
				BlockedArgs: []BlockedArg{},
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidate_MixedValidInvalid(t *testing.T) {
	cfg := Config{
		Tools: map[string]ToolDef{
			"gh": {
				Binary: "/usr/bin/gh",
				BlockedArgs: []BlockedArg{
					{Pattern: `repo\s+delete`, Message: "valid"},
					{Pattern: "[broken(", Message: "invalid"},
				},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil, want error for mixed patterns")
	}

	if !strings.Contains(err.Error(), "[broken(") {
		t.Errorf("error %q does not mention invalid pattern", err.Error())
	}
}

func TestValidate_MultipleToolsMixedValidity(t *testing.T) {
	cfg := Config{
		Tools: map[string]ToolDef{
			"gh": {
				Binary: "/usr/bin/gh",
				BlockedArgs: []BlockedArg{
					{Pattern: `--force`, Message: "ok"},
				},
			},
			"npm": {
				Binary: "/usr/bin/npm",
				BlockedArgs: []BlockedArg{
					{Pattern: "***", Message: "bad quantifier"},
				},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil, want error")
	}

	if !strings.Contains(err.Error(), "npm") {
		t.Errorf("error %q does not mention offending tool", err.Error())
	}
}

func TestGetPassBinary(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "nil proxy returns default",
			cfg:  Config{},
			want: "/usr/bin/pass",
		},
		{
			name: "empty pass_binary returns default",
			cfg:  Config{Proxy: &ProxyConfig{}},
			want: "/usr/bin/pass",
		},
		{
			name: "configured path returned",
			cfg:  Config{Proxy: &ProxyConfig{PassBinary: "/custom/pass"}},
			want: "/custom/pass",
		},
		{
			name: "nix store path",
			cfg:  Config{Proxy: &ProxyConfig{PassBinary: "/nix/store/abc123-pass/bin/pass"}},
			want: "/nix/store/abc123-pass/bin/pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.GetPassBinary(); got != tt.want {
				t.Errorf("GetPassBinary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoad_PassBinaryFromYAML(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "pass_binary set",
			yaml: "proxy:\n  pass_binary: /opt/bin/pass\ntools: {}\n",
			want: "/opt/bin/pass",
		},
		{
			name: "no proxy section",
			yaml: "tools: {}\n",
			want: "/usr/bin/pass",
		},
		{
			name: "proxy without pass_binary",
			yaml: "proxy:\n  timeout: 60s\ntools: {}\n",
			want: "/usr/bin/pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(tmpDir, tt.name+".yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0644); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got := cfg.GetPassBinary(); got != tt.want {
				t.Errorf("GetPassBinary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoad_RejectsInvalidConfig(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	defer os.RemoveAll(tmpDir)

	t.Run("invalid regex rejected", func(t *testing.T) {
		yamlContent := `tools:
  gh:
    binary: /usr/bin/gh
    blocked_args:
      - pattern: "[invalid("
        message: "test"
`
		path := filepath.Join(tmpDir, "invalid.yaml")
		if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		_, err := Load(path)
		if err == nil {
			t.Fatal("Load() returned nil error for invalid regex config")
		}

		if !strings.Contains(err.Error(), "[invalid(") {
			t.Errorf("Load() error %q does not contain pattern string", err.Error())
		}
	})

	t.Run("valid config loads", func(t *testing.T) {
		yamlContent := `tools:
  gh:
    binary: /usr/bin/gh
    blocked_args:
      - pattern: "repo\\s+delete"
        message: "no deleting repos"
      - pattern: "--force"
        message: "no force"
`
		path := filepath.Join(tmpDir, "valid.yaml")
		if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}

		tool, ok := cfg.Tools["gh"]
		if !ok {
			t.Fatal("Load() did not produce 'gh' tool")
		}

		if len(tool.BlockedArgs) != 2 {
			t.Fatalf("Load() BlockedArgs count = %d, want 2", len(tool.BlockedArgs))
		}

		for i, b := range tool.BlockedArgs {
			if b.Compiled == nil {
				t.Errorf("BlockedArgs[%d].Compiled is nil after Load()", i)
			}
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := Load(filepath.Join(tmpDir, "nonexistent.yaml"))
		if err == nil {
			t.Fatal("Load() returned nil error for missing file")
		}
	})

	t.Run("invalid yaml", func(t *testing.T) {
		path := filepath.Join(tmpDir, "badyaml.yaml")
		if err := os.WriteFile(path, []byte("{{{{not yaml"), 0644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		_, err := Load(path)
		if err == nil {
			t.Fatal("Load() returned nil error for invalid YAML")
		}
	})
}

func TestValidate_EmptyBinary(t *testing.T) {
	cfg := &Config{
		Tools: map[string]ToolDef{
			"gh": {Binary: ""},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject empty binary")
	}
	if !strings.Contains(err.Error(), "empty binary") {
		t.Errorf("error = %v, want 'empty binary'", err)
	}
}

func TestValidate_MissingCredentialRef(t *testing.T) {
	cfg := &Config{
		Credentials: map[string]CredentialDef{}, // no credentials defined
		Tools: map[string]ToolDef{
			"gh": {
				Binary: "/usr/bin/gh",
				Env:    map[string]string{"GH_TOKEN": "nonexistent-cred"},
			},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject undefined credential ref")
	}
	if !strings.Contains(err.Error(), "undefined credential") {
		t.Errorf("error = %v, want 'undefined credential'", err)
	}
}

func TestValidate_ValidCredentialRef(t *testing.T) {
	cfg := &Config{
		Credentials: map[string]CredentialDef{
			"github-token": {Source: "pass:cli/github/token"},
		},
		Tools: map[string]ToolDef{
			"gh": {
				Binary: "/usr/bin/gh",
				Env:    map[string]string{"GH_TOKEN": "github-token"},
			},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestValidate_MissingConfigFileCredential(t *testing.T) {
	cfg := &Config{
		Credentials: map[string]CredentialDef{},
		Tools: map[string]ToolDef{
			"gh": {
				Binary: "/usr/bin/gh",
				ConfigFile: &ConfigFileDef{
					Credentials: []string{"nonexistent"},
				},
			},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject undefined config_file credential ref")
	}
	if !strings.Contains(err.Error(), "config_file references undefined credential") {
		t.Errorf("error = %v, want 'config_file references undefined credential'", err)
	}
}

func TestValidate_ValidConfigFileCredential(t *testing.T) {
	cfg := &Config{
		Credentials: map[string]CredentialDef{
			"github-token": {Source: "pass:cli/github/token"},
		},
		Tools: map[string]ToolDef{
			"gh": {
				Binary: "/usr/bin/gh",
				ConfigFile: &ConfigFileDef{
					Credentials: []string{"github-token"},
				},
			},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestValidate_FullValidConfig(t *testing.T) {
	cfg := &Config{
		Proxy: &ProxyConfig{
			Timeout:         "300s",
			InlineThreshold: "1MB",
			PassBinary:      "/usr/bin/pass",
		},
		Credentials: map[string]CredentialDef{
			"github-token": {Source: "pass:cli/github/token"},
			"gog-key":      {Source: "env:GOG_KEY"},
		},
		Tools: map[string]ToolDef{
			"gh": {
				Binary:    "/usr/bin/gh",
				Env:       map[string]string{"GH_TOKEN": "github-token"},
				ForcedEnv: map[string]string{"GH_PAGER": ""},
				BlockedArgs: []BlockedArg{
					{Pattern: `repo\s+delete`, Message: "blocked"},
				},
				ConfigFile: &ConfigFileDef{
					Credentials: []string{"github-token"},
				},
			},
			"gog": {
				Binary: "/usr/bin/gog",
				Env:    map[string]string{"GOG_KEY": "gog-key"},
			},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("Validate() unexpected error for full valid config: %v", err)
	}
}
