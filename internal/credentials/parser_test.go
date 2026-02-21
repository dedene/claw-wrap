package credentials

import (
	"testing"
)

func TestParseSource(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		wantBackend Backend
		wantPath    string
		wantJQ      string
		wantErr     bool
	}{
		// Pass backend
		{
			name:        "pass with prefix",
			source:      "pass:cli/github/token",
			wantBackend: BackendPass,
			wantPath:    "cli/github/token",
		},
		{
			name:        "pass legacy format",
			source:      "some/path/in/store",
			wantBackend: BackendPass,
			wantPath:    "some/path/in/store",
		},

		// Env backend
		{
			name:        "env with prefix",
			source:      "env:MY_TOKEN",
			wantBackend: BackendEnv,
			wantPath:    "MY_TOKEN",
		},

		// 1Password backend
		{
			name:        "1password simple",
			source:      "op://Private/GitHub/token",
			wantBackend: Backend1Password,
			wantPath:    "op://Private/GitHub/token",
		},
		{
			name:        "1password with jq",
			source:      "op://Private/GitHub/credential | .password",
			wantBackend: Backend1Password,
			wantPath:    "op://Private/GitHub/credential",
			wantJQ:      ".password",
		},

		// Bitwarden backend
		{
			name:        "bitwarden simple",
			source:      "bw:a1b2c3d4-uuid",
			wantBackend: BackendBitwarden,
			wantPath:    "a1b2c3d4-uuid",
		},
		{
			name:        "bitwarden with jq",
			source:      "bw:item-uuid | .login.password",
			wantBackend: BackendBitwarden,
			wantPath:    "item-uuid",
			wantJQ:      ".login.password",
		},

		// Keychain backend
		{
			name:        "keychain simple",
			source:      "keychain:my-service",
			wantBackend: BackendKeychain,
			wantPath:    "my-service",
		},
		{
			name:        "keychain with jq",
			source:      "keychain:my-service | .api_key",
			wantBackend: BackendKeychain,
			wantPath:    "my-service",
			wantJQ:      ".api_key",
		},

		// Age backend
		{
			name:        "age simple",
			source:      "age:/etc/secrets/key.age",
			wantBackend: BackendAge,
			wantPath:    "/etc/secrets/key.age",
		},
		{
			name:        "age with jq",
			source:      "age:/path/to/secrets.age | .credentials.token",
			wantBackend: BackendAge,
			wantPath:    "/path/to/secrets.age",
			wantJQ:      ".credentials.token",
		},

		// Vault backend
		{
			name:        "vault simple",
			source:      "vault:secret/myapp/api-key",
			wantBackend: BackendVault,
			wantPath:    "secret/myapp/api-key",
		},
		{
			name:        "vault with jq",
			source:      "vault:secret/myapp/creds | .password",
			wantBackend: BackendVault,
			wantPath:    "secret/myapp/creds",
			wantJQ:      ".password",
		},
		{
			name:    "vault empty path",
			source:  "vault:",
			wantErr: true,
		},

		// Complex jq expressions
		{
			name:        "complex jq filter",
			source:      `bw:item | .fields[] | select(.name=="api_key") | .value`,
			wantBackend: BackendBitwarden,
			wantPath:    "item",
			wantJQ:      `.fields[] | select(.name=="api_key") | .value`,
		},

		// Error cases
		{
			name:    "empty source",
			source:  "",
			wantErr: true,
		},
		{
			name:    "empty path after prefix",
			source:  "pass:",
			wantErr: true,
		},
		{
			name:    "empty jq after pipe",
			source:  "bw:item | ",
			wantErr: true,
		},
		{
			name:    "only whitespace jq",
			source:  "bw:item |   ",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSource(tt.source)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseSource(%q) = %+v, want error", tt.source, result)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseSource(%q) error = %v", tt.source, err)
				return
			}

			if result.Backend != tt.wantBackend {
				t.Errorf("Backend = %q, want %q", result.Backend, tt.wantBackend)
			}
			if result.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", result.Path, tt.wantPath)
			}
			if result.JQExpr != tt.wantJQ {
				t.Errorf("JQExpr = %q, want %q", result.JQExpr, tt.wantJQ)
			}
			if result.Original != tt.source {
				t.Errorf("Original = %q, want %q", result.Original, tt.source)
			}
		})
	}
}

func TestParsedSource_HasJQ(t *testing.T) {
	withJQ, _ := ParseSource("bw:item | .password")
	if !withJQ.HasJQ() {
		t.Error("HasJQ() = false, want true for source with jq")
	}

	withoutJQ, _ := ParseSource("bw:item")
	if withoutJQ.HasJQ() {
		t.Error("HasJQ() = true, want false for source without jq")
	}
}

func TestParsedSource_NeedsJSONOutput(t *testing.T) {
	withJQ, _ := ParseSource("op://vault/item | .password")
	if !withJQ.NeedsJSONOutput() {
		t.Error("NeedsJSONOutput() = false, want true for source with jq")
	}

	withoutJQ, _ := ParseSource("op://vault/item/field")
	if withoutJQ.NeedsJSONOutput() {
		t.Error("NeedsJSONOutput() = true, want false for source without jq")
	}
}
