package credentials

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestParseOPSecretRef(t *testing.T) {
	tests := []struct {
		name      string
		ref       string
		wantVault string
		wantItem  string
		wantErr   bool
	}{
		{
			name:      "vault and item",
			ref:       "op://Private/GitHub",
			wantVault: "Private",
			wantItem:  "GitHub",
		},
		{
			name:      "vault item and field",
			ref:       "op://Private/GitHub/token",
			wantVault: "Private",
			wantItem:  "GitHub",
		},
		{
			name:      "vault item section and field",
			ref:       "op://Work/Database/Credentials/password",
			wantVault: "Work",
			wantItem:  "Database",
		},
		{
			name:    "missing op prefix",
			ref:     "Private/GitHub/token",
			wantErr: true,
		},
		{
			name:    "only vault",
			ref:     "op://Private",
			wantErr: true,
		},
		{
			name:    "empty",
			ref:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vault, item, err := parseOPSecretRef(tt.ref)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseOPSecretRef(%q) = (%q, %q, nil), want error", tt.ref, vault, item)
				}
				return
			}

			if err != nil {
				t.Errorf("parseOPSecretRef(%q) error = %v", tt.ref, err)
				return
			}

			if vault != tt.wantVault {
				t.Errorf("vault = %q, want %q", vault, tt.wantVault)
			}
			if item != tt.wantItem {
				t.Errorf("item = %q, want %q", item, tt.wantItem)
			}
		})
	}
}

func TestReadSecureFile(t *testing.T) {
	t.Run("file not found returns empty", func(t *testing.T) {
		result, err := readSecureFile("/nonexistent/path/file")
		if err != nil {
			t.Errorf("readSecureFile() error = %v, want nil for missing file", err)
		}
		if result != "" {
			t.Errorf("readSecureFile() = %q, want empty string", result)
		}
	})

	t.Run("valid file with correct permissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		tokenPath := filepath.Join(tmpDir, "token")
		if err := os.WriteFile(tokenPath, []byte("  secret-token\n  "), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}

		result, err := readSecureFile(tokenPath)
		if err != nil {
			t.Errorf("readSecureFile() error = %v", err)
		}
		if result != "secret-token" {
			t.Errorf("readSecureFile() = %q, want %q", result, "secret-token")
		}
	})

	t.Run("accepts 0640 permissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		tokenPath := filepath.Join(tmpDir, "token")
		if err := os.WriteFile(tokenPath, []byte("secret-token"), 0o640); err != nil {
			t.Fatalf("write file: %v", err)
		}

		result, err := readSecureFile(tokenPath)
		if err != nil {
			t.Errorf("readSecureFile() error = %v", err)
		}
		if result != "secret-token" {
			t.Errorf("readSecureFile() = %q, want %q", result, "secret-token")
		}
	})

	t.Run("rejects world-readable file", func(t *testing.T) {
		tmpDir := t.TempDir()
		tokenPath := filepath.Join(tmpDir, "token")
		if err := os.WriteFile(tokenPath, []byte("secret"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}

		_, err := readSecureFile(tokenPath)
		if err == nil {
			t.Error("readSecureFile() should reject world-readable file")
		}
	})

	t.Run("rejects symlink", func(t *testing.T) {
		tmpDir := t.TempDir()
		realPath := filepath.Join(tmpDir, "real")
		linkPath := filepath.Join(tmpDir, "link")

		if err := os.WriteFile(realPath, []byte("secret"), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}
		if err := os.Symlink(realPath, linkPath); err != nil {
			t.Fatalf("symlink: %v", err)
		}

		_, err := readSecureFile(linkPath)
		if err == nil {
			t.Error("readSecureFile() should reject symlink")
		}
	})

	t.Run("rejects directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := readSecureFile(tmpDir)
		if err == nil {
			t.Error("readSecureFile() should reject directory")
		}
	})

	t.Run("rejects owner mismatch", func(t *testing.T) {
		tmpDir := t.TempDir()
		tokenPath := filepath.Join(tmpDir, "token")
		if err := os.WriteFile(tokenPath, []byte("secret"), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}

		orig := secureFileCurrentEUID
		secureFileCurrentEUID = func() int { return orig() + 1 }
		defer func() { secureFileCurrentEUID = orig }()

		_, err := readSecureFile(tokenPath)
		if err == nil {
			t.Error("readSecureFile() should reject owner mismatch")
		}
	})
}

func TestGetOPServiceAccountToken(t *testing.T) {
	// Save original env
	origCredDir := os.Getenv("CREDENTIALS_DIRECTORY")
	origToken := os.Getenv(opTokenEnvVar)
	defer func() {
		os.Setenv("CREDENTIALS_DIRECTORY", origCredDir)
		os.Setenv(opTokenEnvVar, origToken)
	}()

	t.Run("from CREDENTIALS_DIRECTORY", func(t *testing.T) {
		tmpDir := t.TempDir()
		tokenPath := filepath.Join(tmpDir, opTokenCredentialName)
		if err := os.WriteFile(tokenPath, []byte("ops_systemd_token"), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}

		os.Setenv("CREDENTIALS_DIRECTORY", tmpDir)
		os.Setenv(opTokenEnvVar, "ops_env_token")

		token, err := getOPServiceAccountToken()
		if err != nil {
			t.Errorf("getOPServiceAccountToken() error = %v", err)
		}
		if token != "ops_systemd_token" {
			t.Errorf("token = %q, want %q (should prefer CREDENTIALS_DIRECTORY)", token, "ops_systemd_token")
		}
	})

	t.Run("from environment variable", func(t *testing.T) {
		os.Setenv("CREDENTIALS_DIRECTORY", "")
		os.Setenv(opTokenEnvVar, "ops_env_token")

		token, err := getOPServiceAccountToken()
		if err != nil {
			t.Errorf("getOPServiceAccountToken() error = %v", err)
		}
		if token != "ops_env_token" {
			t.Errorf("token = %q, want %q", token, "ops_env_token")
		}
	})

	t.Run("invalid systemd file fails closed", func(t *testing.T) {
		tmpDir := t.TempDir()
		tokenPath := filepath.Join(tmpDir, opTokenCredentialName)
		if err := os.WriteFile(tokenPath, []byte("ops_systemd_token"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}

		os.Setenv("CREDENTIALS_DIRECTORY", tmpDir)
		os.Setenv(opTokenEnvVar, "ops_env_token")

		_, err := getOPServiceAccountToken()
		if err == nil {
			t.Error("getOPServiceAccountToken() should fail closed on invalid systemd token file")
		}
	})

	t.Run("no token configured", func(t *testing.T) {
		os.Setenv("CREDENTIALS_DIRECTORY", "")
		os.Setenv(opTokenEnvVar, "")

		_, err := getOPServiceAccountToken()
		if err == nil {
			t.Error("getOPServiceAccountToken() should return error when no token configured")
		}
	})
}

func TestFetchFrom1Password_NoBinary(t *testing.T) {
	// Save and clear PATH to ensure op is not found
	origPath := os.Getenv("PATH")
	os.Setenv("PATH", "/nonexistent")
	defer os.Setenv("PATH", origPath)

	parsed := &ParsedSource{
		Backend: Backend1Password,
		Path:    "op://Private/Item/field",
	}

	_, err := fetchFrom1Password(context.Background(), parsed, "")
	if err == nil {
		t.Error("fetchFrom1Password() should error when op binary not found")
	}
}

func writeMockOPScript(t *testing.T, dir string, output string, exitCode int) string {
	t.Helper()
	scriptPath := filepath.Join(dir, "op")
	var script string
	if exitCode == 0 {
		script = "#!/bin/sh\necho '" + output + "'\n"
	} else {
		script = "#!/bin/sh\nexit " + strconv.Itoa(exitCode) + "\n"
	}
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatalf("write mock script: %v", err)
	}
	return dir
}

func TestFetchFrom1PasswordDirect(t *testing.T) {
	tmpDir := t.TempDir()
	mockPath := writeMockOPScript(t, tmpDir, "my-secret-value", 0)

	// Create mock op binary in PATH
	origPath := os.Getenv("PATH")
	os.Setenv("PATH", mockPath+":"+origPath)
	defer os.Setenv("PATH", origPath)

	result, err := fetchFrom1PasswordDirect(context.Background(), filepath.Join(mockPath, "op"), "test-token", "op://vault/item/field")
	if err != nil {
		t.Errorf("fetchFrom1PasswordDirect() error = %v", err)
	}
	if result != "my-secret-value" {
		t.Errorf("result = %q, want %q", result, "my-secret-value")
	}
}
