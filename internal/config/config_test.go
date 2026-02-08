package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"claw-wrap/internal/paths"
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

func TestValidate_BlockedArgsMatchModes(t *testing.T) {
	cfg := Config{
		Tools: map[string]ToolDef{
			"gh": {
				Binary: "/usr/bin/gh",
				BlockedArgs: []BlockedArg{
					{Pattern: `repo\s+delete`, Match: BlockedArgMatchCommand},
					{Pattern: `--force`, Match: BlockedArgMatchArg},
					{Pattern: `delete`}, // default should normalize to arg
				},
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}

	tool := cfg.Tools["gh"]
	if tool.BlockedArgs[0].Match != BlockedArgMatchCommand {
		t.Errorf("BlockedArgs[0].Match = %q, want %q", tool.BlockedArgs[0].Match, BlockedArgMatchCommand)
	}
	if tool.BlockedArgs[1].Match != BlockedArgMatchArg {
		t.Errorf("BlockedArgs[1].Match = %q, want %q", tool.BlockedArgs[1].Match, BlockedArgMatchArg)
	}
	if tool.BlockedArgs[2].Match != BlockedArgMatchArg {
		t.Errorf("BlockedArgs[2].Match = %q, want default %q", tool.BlockedArgs[2].Match, BlockedArgMatchArg)
	}
}

func TestValidate_BlockedArgsInvalidMatchMode(t *testing.T) {
	cfg := Config{
		Tools: map[string]ToolDef{
			"gh": {
				Binary: "/usr/bin/gh",
				BlockedArgs: []BlockedArg{
					{Pattern: `repo\s+delete`, Match: "all"},
				},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil, want error for invalid blocked_args match mode")
	}
	if !strings.Contains(err.Error(), "invalid blocked_args match") {
		t.Errorf("error = %q, want invalid match mode error", err.Error())
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

func TestValidate_InvalidToolName(t *testing.T) {
	tests := []string{
		"../../etc/passwd",
		"gh/repo",
		"gh repo",
		"gh;rm",
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := Config{
				Tools: map[string]ToolDef{
					name: {Binary: "/usr/bin/gh"},
				},
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() returned nil, want error for invalid tool name %q", name)
			}
			if !strings.Contains(err.Error(), "invalid name") {
				t.Errorf("error = %q, want invalid name", err.Error())
			}
		})
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
			want: paths.DefaultPassBinary(),
		},
		{
			name: "empty pass_binary returns default",
			cfg:  Config{Proxy: &ProxyConfig{}},
			want: paths.DefaultPassBinary(),
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

func TestGetOPBinary(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "nil proxy returns empty for PATH lookup",
			cfg:  Config{},
			want: "",
		},
		{
			name: "empty op_binary returns empty",
			cfg:  Config{Proxy: &ProxyConfig{}},
			want: "",
		},
		{
			name: "configured absolute path returned",
			cfg:  Config{Proxy: &ProxyConfig{OPBinary: "/custom/op"}},
			want: "/custom/op",
		},
		{
			name: "relative path rejected",
			cfg:  Config{Proxy: &ProxyConfig{OPBinary: "op"}},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.GetOPBinary(); got != tt.want {
				t.Errorf("GetOPBinary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetBWBinary(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "nil proxy returns empty for PATH lookup",
			cfg:  Config{},
			want: "",
		},
		{
			name: "empty bw_binary returns empty",
			cfg:  Config{Proxy: &ProxyConfig{}},
			want: "",
		},
		{
			name: "configured absolute path returned",
			cfg:  Config{Proxy: &ProxyConfig{BWBinary: "/custom/bw"}},
			want: "/custom/bw",
		},
		{
			name: "relative path rejected",
			cfg:  Config{Proxy: &ProxyConfig{BWBinary: "bw"}},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.GetBWBinary(); got != tt.want {
				t.Errorf("GetBWBinary() = %q, want %q", got, tt.want)
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
			want: paths.DefaultPassBinary(),
		},
		{
			name: "proxy without pass_binary",
			yaml: "proxy:\n  timeout: 60s\ntools: {}\n",
			want: paths.DefaultPassBinary(),
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
					XDGSubdir:   "gh",
					Filename:    "config.yml",
					Template:    "token: {{ .nonexistent }}",
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
					XDGSubdir:   "gh",
					Filename:    "config.yml",
					Template:    "token: {{ .github-token }}",
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
					XDGSubdir:   "gh",
					Filename:    "config.yml",
					Template:    "token: {{ .github-token }}",
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

func TestValidate_ConfigFilePathTraversalRejected(t *testing.T) {
	cfg := &Config{
		Credentials: map[string]CredentialDef{
			"token": {Source: "pass:cli/token"},
		},
		Tools: map[string]ToolDef{
			"gh": {
				Binary: "/usr/bin/gh",
				ConfigFile: &ConfigFileDef{
					XDGSubdir:   "../escape",
					Filename:    "config.yml",
					Template:    "token: {{ .token }}",
					Credentials: []string{"token"},
				},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject xdg_subdir traversal")
	}
	if !strings.Contains(err.Error(), "xdg_subdir") {
		t.Errorf("error = %v, want xdg_subdir validation failure", err)
	}
}

func TestGetProxySecurityDefaults(t *testing.T) {
	cfg := &Config{}

	if got := cfg.GetMaxConnections(); got != DefaultMaxConnections {
		t.Errorf("GetMaxConnections() = %d, want %d", got, DefaultMaxConnections)
	}
	if got := cfg.GetReadHeaderTimeout(); got != DefaultReadHeaderTimeout {
		t.Errorf("GetReadHeaderTimeout() = %v, want %v", got, DefaultReadHeaderTimeout)
	}
	if got := cfg.GetReadMessageTimeout(); got != DefaultReadMessageTimeout {
		t.Errorf("GetReadMessageTimeout() = %v, want %v", got, DefaultReadMessageTimeout)
	}
	if got := cfg.GetMaxStdinMessageSize(); got != DefaultMaxStdinMessageSize {
		t.Errorf("GetMaxStdinMessageSize() = %d, want %d", got, DefaultMaxStdinMessageSize)
	}
	if got := cfg.GetReplayCacheTTL(); got != DefaultReplayCacheTTL {
		t.Errorf("GetReplayCacheTTL() = %v, want %v", got, DefaultReplayCacheTTL)
	}
	if got := cfg.GetReplayCacheMaxEntries(); got != DefaultReplayCacheMaxEntries {
		t.Errorf("GetReplayCacheMaxEntries() = %d, want %d", got, DefaultReplayCacheMaxEntries)
	}
}

func TestGetReplayCacheTTL_Floor(t *testing.T) {
	tests := []struct {
		name string
		ttl  string
		want time.Duration
	}{
		{"below floor", "5s", 10 * time.Second},
		{"at floor", "10s", 10 * time.Second},
		{"above floor", "30s", 30 * time.Second},
		{"well above", "2m", 2 * time.Minute},
		{"1s should clamp", "1s", 10 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Proxy: &ProxyConfig{
					ReplayCacheTTL: tt.ttl,
				},
			}
			if got := cfg.GetReplayCacheTTL(); got != tt.want {
				t.Errorf("GetReplayCacheTTL(%q) = %v, want %v", tt.ttl, got, tt.want)
			}
		})
	}
}

func TestGetMaxOutputSize(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want int64
	}{
		{"nil proxy", &Config{}, 0},
		{"empty value", &Config{Proxy: &ProxyConfig{}}, 0},
		{"100MB", &Config{Proxy: &ProxyConfig{MaxOutputSize: "100MB"}}, 100 * 1024 * 1024},
		{"1G", &Config{Proxy: &ProxyConfig{MaxOutputSize: "1G"}}, 1024 * 1024 * 1024},
		{"plain bytes", &Config{Proxy: &ProxyConfig{MaxOutputSize: "1048576"}}, 1048576},
		{"invalid", &Config{Proxy: &ProxyConfig{MaxOutputSize: "not-a-size"}}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.GetMaxOutputSize(); got != tt.want {
				t.Errorf("GetMaxOutputSize() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestGetWriteTimeout(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want time.Duration
	}{
		{"nil proxy", &Config{}, DefaultWriteTimeout},
		{"empty value", &Config{Proxy: &ProxyConfig{}}, DefaultWriteTimeout},
		{"30s", &Config{Proxy: &ProxyConfig{WriteTimeout: "30s"}}, 30 * time.Second},
		{"1m", &Config{Proxy: &ProxyConfig{WriteTimeout: "1m"}}, time.Minute},
		{"invalid", &Config{Proxy: &ProxyConfig{WriteTimeout: "not-a-duration"}}, DefaultWriteTimeout},
		{"zero", &Config{Proxy: &ProxyConfig{WriteTimeout: "0s"}}, DefaultWriteTimeout},
		{"negative", &Config{Proxy: &ProxyConfig{WriteTimeout: "-5s"}}, DefaultWriteTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.GetWriteTimeout(); got != tt.want {
				t.Errorf("GetWriteTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetPassBinary_AbsolutePathValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want string
	}{
		{"nil proxy", &Config{}, paths.DefaultPassBinary()},
		{"empty", &Config{Proxy: &ProxyConfig{}}, paths.DefaultPassBinary()},
		{"absolute path", &Config{Proxy: &ProxyConfig{PassBinary: "/usr/local/bin/pass"}}, "/usr/local/bin/pass"},
		{"relative path rejected", &Config{Proxy: &ProxyConfig{PassBinary: "pass"}}, paths.DefaultPassBinary()},
		{"relative with dir rejected", &Config{Proxy: &ProxyConfig{PassBinary: "./bin/pass"}}, paths.DefaultPassBinary()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.GetPassBinary(); got != tt.want {
				t.Errorf("GetPassBinary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetMaxConnectionLifetime(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want time.Duration
	}{
		{"nil proxy", &Config{}, 0},
		{"empty value", &Config{Proxy: &ProxyConfig{}}, 0},
		{"10m", &Config{Proxy: &ProxyConfig{MaxConnectionLifetime: "10m"}}, 10 * time.Minute},
		{"1h", &Config{Proxy: &ProxyConfig{MaxConnectionLifetime: "1h"}}, time.Hour},
		{"invalid", &Config{Proxy: &ProxyConfig{MaxConnectionLifetime: "bad"}}, 0},
		{"zero", &Config{Proxy: &ProxyConfig{MaxConnectionLifetime: "0s"}}, 0},
		{"negative", &Config{Proxy: &ProxyConfig{MaxConnectionLifetime: "-5s"}}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.GetMaxConnectionLifetime(); got != tt.want {
				t.Errorf("GetMaxConnectionLifetime() = %v, want %v", got, tt.want)
			}
		})
	}
}

// HTTP Proxy Config Tests

func TestValidate_HTTPProxy_ValidConfig(t *testing.T) {
	cfg := &Config{
		Credentials: map[string]CredentialDef{
			"github-token": {Source: "op://vault/item/token"},
		},
		HTTPProxy: &HTTPProxyConfig{
			Enabled:  true,
			Listen:   "127.0.0.1:8080",
			LogLevel: "info",
			CA: CAConfig{
				Path:         "/tmp/ca",
				ValidityDays: 365,
				Organization: "test",
			},
			Routes: []ProxyRoute{
				{
					Host: "api.github.com",
					Inject: InjectSpec{
						Header: "Authorization",
						Value:  "Bearer {{github-token}}",
					},
				},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	// Verify host regex was compiled
	if cfg.HTTPProxy.Routes[0].HostRegex == nil {
		t.Error("HostRegex not compiled")
	}
}

func TestValidate_HTTPProxy_UnknownCredential(t *testing.T) {
	cfg := &Config{
		Credentials: map[string]CredentialDef{
			"known": {Source: "env:KNOWN"},
		},
		HTTPProxy: &HTTPProxyConfig{
			Enabled: true,
			Routes: []ProxyRoute{
				{
					Host:   "api.example.com",
					Inject: InjectSpec{Header: "X-Test", Value: "Bearer {{unknown}}"},
				},
			},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject unknown credential")
	}
	if !strings.Contains(err.Error(), "unknown credential") {
		t.Errorf("error = %v, want unknown credential error", err)
	}
}

func TestValidate_HTTPProxy_DisabledSkipsValidation(t *testing.T) {
	cfg := &Config{
		HTTPProxy: &HTTPProxyConfig{
			Enabled: false,
			Routes: []ProxyRoute{
				{Host: ""}, // Invalid but should be skipped
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() should skip disabled proxy: %v", err)
	}
}

func TestValidate_HTTPProxy_InvalidLogLevel(t *testing.T) {
	cfg := &Config{
		HTTPProxy: &HTTPProxyConfig{
			Enabled:  true,
			LogLevel: "verbose", // invalid
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject invalid log_level")
	}
	if !strings.Contains(err.Error(), "log_level") {
		t.Errorf("error = %v, want log_level error", err)
	}
}

func TestValidate_HTTPProxy_ValidLogLevels(t *testing.T) {
	levels := []string{"", "none", "errors", "info", "debug"}
	for _, level := range levels {
		t.Run(level, func(t *testing.T) {
			cfg := &Config{
				HTTPProxy: &HTTPProxyConfig{
					Enabled:  true,
					LogLevel: level,
					Routes: []ProxyRoute{
						{
							Host:   "example.com",
							Inject: InjectSpec{Header: "X-Test", Value: "test"},
						},
					},
				},
			}
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate() error for log_level %q: %v", level, err)
			}
		})
	}
}

func TestValidate_HTTPProxy_EmptyRouteHost(t *testing.T) {
	cfg := &Config{
		HTTPProxy: &HTTPProxyConfig{
			Enabled: true,
			Routes: []ProxyRoute{
				{
					Host:   "",
					Inject: InjectSpec{Header: "X-Test", Value: "test"},
				},
			},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject empty host")
	}
	if !strings.Contains(err.Error(), "host is required") {
		t.Errorf("error = %v, want host required error", err)
	}
}

func TestValidate_HTTPProxy_EmptyInjectHeader(t *testing.T) {
	cfg := &Config{
		HTTPProxy: &HTTPProxyConfig{
			Enabled: true,
			Routes: []ProxyRoute{
				{
					Host:   "example.com",
					Inject: InjectSpec{Header: "", Value: "test"},
				},
			},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject empty inject.header")
	}
	if !strings.Contains(err.Error(), "inject.header is required") {
		t.Errorf("error = %v, want inject.header required error", err)
	}
}

func TestValidate_HTTPProxy_EmptyInjectValue(t *testing.T) {
	cfg := &Config{
		HTTPProxy: &HTTPProxyConfig{
			Enabled: true,
			Routes: []ProxyRoute{
				{
					Host:   "example.com",
					Inject: InjectSpec{Header: "X-Test", Value: ""},
				},
			},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject empty inject.value")
	}
	if !strings.Contains(err.Error(), "inject.value is required") {
		t.Errorf("error = %v, want inject.value required error", err)
	}
}

func TestCompileHostPattern(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		want    bool
	}{
		// Exact matches
		{"api.github.com", "api.github.com", true},
		{"api.github.com", "other.github.com", false},
		{"api.github.com", "api.github.com.evil.com", false},

		// Wildcard matches (suffix-anchored)
		{"*.github.com", "api.github.com", true},
		{"*.github.com", "raw.github.com", true},
		{"*.github.com", "github.com", false},              // bare domain doesn't match *.
		{"*.github.com", "evil.github.com.attacker.com", false}, // suffix-anchored

		// Wildcard with subdomain attack prevention
		{"*.example.com", "sub.example.com", true},
		{"*.example.com", "deep.sub.example.com", false}, // only one level
		{"*.example.com", "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.host, func(t *testing.T) {
			re, err := compileHostPattern(tt.pattern)
			if err != nil {
				t.Fatalf("compileHostPattern(%q) error = %v", tt.pattern, err)
			}
			got := re.MatchString(tt.host)
			if got != tt.want {
				t.Errorf("pattern %q match %q = %v, want %v", tt.pattern, tt.host, got, tt.want)
			}
		})
	}
}

func TestCompileHostPattern_Empty(t *testing.T) {
	_, err := compileHostPattern("")
	if err == nil {
		t.Error("compileHostPattern(\"\") should return error")
	}
}

func TestCompilePathRule(t *testing.T) {
	tests := []struct {
		pattern string
		method  string
		path    string
		want    bool
	}{
		// Path only (any method)
		{"/api/**", "GET", "/api/users/123", true},
		{"/api/**", "POST", "/api/users", true},
		{"/api/**", "GET", "/other", false},

		// Method + path
		{"GET /api/users", "GET", "/api/users", true},
		{"GET /api/users", "POST", "/api/users", false},
		{"POST /api/*", "POST", "/api/users", true},
		{"POST /api/*", "POST", "/api/users/123", false}, // * is single segment

		// Wildcards
		{"/users/*/profile", "GET", "/users/123/profile", true},
		{"/users/*/profile", "GET", "/users/abc/profile", true},
		{"/users/*/profile", "GET", "/users/123/settings", false},

		// Double wildcard
		{"/files/**", "GET", "/files/a/b/c/d.txt", true},
		{"DELETE /admin/**", "DELETE", "/admin/users/123", true},
		{"DELETE /admin/**", "GET", "/admin/users/123", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.method+"_"+tt.path, func(t *testing.T) {
			rule, err := compilePathRule(tt.pattern)
			if err != nil {
				t.Fatalf("compilePathRule(%q) error = %v", tt.pattern, err)
			}

			methodMatch := rule.Method == "*" || rule.Method == tt.method
			pathMatch := rule.Pattern.MatchString(tt.path)
			got := methodMatch && pathMatch

			if got != tt.want {
				t.Errorf("rule %q: method=%s path=%s = %v, want %v (methodMatch=%v, pathMatch=%v)",
					tt.pattern, tt.method, tt.path, got, tt.want, methodMatch, pathMatch)
			}
		})
	}
}

func TestCompilePathRule_InvalidMethod(t *testing.T) {
	_, err := compilePathRule("INVALID /path")
	if err == nil {
		t.Error("compilePathRule with invalid method should return error")
	}
	if !strings.Contains(err.Error(), "invalid method") {
		t.Errorf("error = %v, want invalid method error", err)
	}
}

func TestCompilePathRule_Empty(t *testing.T) {
	_, err := compilePathRule("")
	if err == nil {
		t.Error("compilePathRule(\"\") should return error")
	}
}

func TestValidate_HTTPProxy_AllowDenyRules(t *testing.T) {
	cfg := &Config{
		HTTPProxy: &HTTPProxyConfig{
			Enabled: true,
			Routes: []ProxyRoute{
				{
					Host:   "api.example.com",
					Inject: InjectSpec{Header: "Authorization", Value: "Bearer token"},
					Allow:  []string{"GET /api/**", "POST /api/users"},
					Deny:   []string{"DELETE /**"},
				},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	route := cfg.HTTPProxy.Routes[0]
	if len(route.AllowRules) != 2 {
		t.Errorf("AllowRules count = %d, want 2", len(route.AllowRules))
	}
	if len(route.DenyRules) != 1 {
		t.Errorf("DenyRules count = %d, want 1", len(route.DenyRules))
	}
}

func TestValidate_HTTPProxy_InvalidAllowRule(t *testing.T) {
	cfg := &Config{
		HTTPProxy: &HTTPProxyConfig{
			Enabled: true,
			Routes: []ProxyRoute{
				{
					Host:   "api.example.com",
					Inject: InjectSpec{Header: "X-Test", Value: "test"},
					Allow:  []string{"BADMETHOD /path"},
				},
			},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject invalid allow rule")
	}
	if !strings.Contains(err.Error(), "allow[0]") {
		t.Errorf("error = %v, want allow[0] error", err)
	}
}

func TestValidate_HTTPProxy_InvalidDenyRule(t *testing.T) {
	cfg := &Config{
		HTTPProxy: &HTTPProxyConfig{
			Enabled: true,
			Routes: []ProxyRoute{
				{
					Host:   "api.example.com",
					Inject: InjectSpec{Header: "X-Test", Value: "test"},
					Deny:   []string{""},
				},
			},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should reject empty deny rule")
	}
	if !strings.Contains(err.Error(), "deny[0]") {
		t.Errorf("error = %v, want deny[0] error", err)
	}
}

func TestGetHTTPProxyConfig(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		cfg := &Config{}
		if got := cfg.GetHTTPProxyConfig(); got != nil {
			t.Errorf("GetHTTPProxyConfig() = %v, want nil", got)
		}
	})

	t.Run("returns config", func(t *testing.T) {
		httpCfg := &HTTPProxyConfig{Enabled: true}
		cfg := &Config{HTTPProxy: httpCfg}
		if got := cfg.GetHTTPProxyConfig(); got != httpCfg {
			t.Errorf("GetHTTPProxyConfig() = %v, want %v", got, httpCfg)
		}
	})
}

func TestHTTPProxyConfig_GetRequireAuth(t *testing.T) {
	t.Run("nil defaults to true", func(t *testing.T) {
		cfg := &HTTPProxyConfig{}
		if got := cfg.GetRequireAuth(); !got {
			t.Error("GetRequireAuth() = false, want true (default)")
		}
	})

	t.Run("explicit true", func(t *testing.T) {
		v := true
		cfg := &HTTPProxyConfig{RequireAuth: &v}
		if got := cfg.GetRequireAuth(); !got {
			t.Error("GetRequireAuth() = false, want true")
		}
	})

	t.Run("explicit false", func(t *testing.T) {
		v := false
		cfg := &HTTPProxyConfig{RequireAuth: &v}
		if got := cfg.GetRequireAuth(); got {
			t.Error("GetRequireAuth() = true, want false")
		}
	})
}
