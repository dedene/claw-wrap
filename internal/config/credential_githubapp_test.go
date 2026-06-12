package config

import (
	"strings"
	"testing"
)

func TestValidate_CredentialGitHubApp(t *testing.T) {
	tests := []struct {
		name    string
		cred    CredentialDef
		wantErr string
	}{
		{
			name: "source only valid",
			cred: CredentialDef{Source: "op://vault/item/field"},
		},
		{
			name: "github-app valid",
			cred: CredentialDef{
				Type:           "github-app",
				AppID:          1,
				InstallationID: 2,
				PrivateKey:     "pass:github/app.pem",
			},
		},
		{
			name: "mutually exclusive",
			cred: CredentialDef{
				Source: "env:TOKEN",
				Type:   "github-app",
			},
			wantErr: "mutually exclusive",
		},
		{
			name:    "empty source and type",
			cred:    CredentialDef{},
			wantErr: "empty source",
		},
		{
			name: "github-app missing app_id",
			cred: CredentialDef{
				Type:           "github-app",
				InstallationID: 2,
				PrivateKey:     "pass:github/app.pem",
			},
			wantErr: "requires app_id",
		},
		{
			name: "github-app missing installation_id",
			cred: CredentialDef{
				Type:       "github-app",
				AppID:      1,
				PrivateKey: "pass:github/app.pem",
			},
			wantErr: "requires installation_id",
		},
		{
			name: "github-app missing private_key",
			cred: CredentialDef{
				Type:           "github-app",
				AppID:          1,
				InstallationID: 2,
			},
			wantErr: "requires private_key",
		},
		{
			name:    "unknown type",
			cred:    CredentialDef{Type: "magic"},
			wantErr: "unknown credential type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Credentials: map[string]CredentialDef{
					"test": tt.cred,
				},
				Tools: map[string]ToolDef{
					"gh": {Binary: "/usr/bin/gh"},
				},
			}
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() error = nil, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
