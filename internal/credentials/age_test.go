package credentials

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func TestGetAgeIdentityPath(t *testing.T) {
	// Save original values
	origCredDir := os.Getenv("CREDENTIALS_DIRECTORY")
	origIdentityFile := ageIdentityFile
	defer func() {
		os.Setenv("CREDENTIALS_DIRECTORY", origCredDir)
		ageIdentityFile = origIdentityFile
	}()

	t.Run("from CREDENTIALS_DIRECTORY", func(t *testing.T) {
		tmpDir := t.TempDir()
		identityPath := filepath.Join(tmpDir, ageIdentityCredentialName)
		if err := os.WriteFile(identityPath, []byte("identity"), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}

		os.Setenv("CREDENTIALS_DIRECTORY", tmpDir)
		ageIdentityFile = "/different/path"

		path, err := getAgeIdentityPath()
		if err != nil {
			t.Errorf("getAgeIdentityPath() error = %v", err)
		}
		if path != identityPath {
			t.Errorf("path = %q, want %q (should prefer CREDENTIALS_DIRECTORY)", path, identityPath)
		}
	})

	t.Run("fallback to configured path", func(t *testing.T) {
		os.Setenv("CREDENTIALS_DIRECTORY", "")
		ageIdentityFile = "/custom/identity"

		path, err := getAgeIdentityPath()
		if err != nil {
			t.Errorf("getAgeIdentityPath() error = %v", err)
		}
		if path != "/custom/identity" {
			t.Errorf("path = %q, want %q", path, "/custom/identity")
		}
	})
}

func TestDecryptAgeFile(t *testing.T) {
	// Generate a real age identity for testing
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	recipient := identity.Recipient()

	tmpDir := t.TempDir()

	// Write identity file
	identityPath := filepath.Join(tmpDir, "identity")
	if err := os.WriteFile(identityPath, []byte(identity.String()), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}

	t.Run("decrypt valid file", func(t *testing.T) {
		// Create encrypted file
		encPath := filepath.Join(tmpDir, "secret.age")
		plaintext := "my-secret-value"

		encFile, err := os.Create(encPath)
		if err != nil {
			t.Fatalf("create enc file: %v", err)
		}
		writer, err := age.Encrypt(encFile, recipient)
		if err != nil {
			t.Fatalf("create encryptor: %v", err)
		}
		if _, err := writer.Write([]byte(plaintext)); err != nil {
			t.Fatalf("write encrypted: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close encryptor: %v", err)
		}
		encFile.Close()

		// Set secure permissions
		if err := os.Chmod(encPath, 0o600); err != nil {
			t.Fatalf("chmod: %v", err)
		}

		result, err := decryptAgeFile(identityPath, encPath)
		if err != nil {
			t.Errorf("decryptAgeFile() error = %v", err)
		}
		if string(result) != plaintext {
			t.Errorf("result = %q, want %q", string(result), plaintext)
		}
	})

	t.Run("identity file not found", func(t *testing.T) {
		_, err := decryptAgeFile("/nonexistent/identity", "/some/file")
		if err == nil {
			t.Error("decryptAgeFile() should error when identity not found")
		}
	})

	t.Run("encrypted file not found", func(t *testing.T) {
		_, err := decryptAgeFile(identityPath, "/nonexistent/file.age")
		if err == nil {
			t.Error("decryptAgeFile() should error when encrypted file not found")
		}
	})

	t.Run("rejects world-readable identity", func(t *testing.T) {
		badIdentityPath := filepath.Join(tmpDir, "bad-identity")
		if err := os.WriteFile(badIdentityPath, []byte(identity.String()), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}

		_, err := decryptAgeFile(badIdentityPath, "/some/file")
		if err == nil {
			t.Error("decryptAgeFile() should reject world-readable identity")
		}
	})

	t.Run("rejects symlink identity", func(t *testing.T) {
		linkPath := filepath.Join(tmpDir, "link-identity")
		if err := os.Symlink(identityPath, linkPath); err != nil {
			t.Fatalf("symlink: %v", err)
		}

		_, err := decryptAgeFile(linkPath, "/some/file")
		if err == nil {
			t.Error("decryptAgeFile() should reject symlink identity")
		}
	})

	t.Run("wrong identity fails decryption", func(t *testing.T) {
		// Create a different identity
		otherIdentity, _ := age.GenerateX25519Identity()
		otherIdentityPath := filepath.Join(tmpDir, "other-identity")
		if err := os.WriteFile(otherIdentityPath, []byte(otherIdentity.String()), 0o600); err != nil {
			t.Fatalf("write other identity: %v", err)
		}

		// Create encrypted file with original identity
		encPath := filepath.Join(tmpDir, "other-secret.age")
		encFile, _ := os.Create(encPath)
		writer, _ := age.Encrypt(encFile, recipient)
		writer.Write([]byte("secret"))
		writer.Close()
		encFile.Close()
		os.Chmod(encPath, 0o600)

		_, err := decryptAgeFile(otherIdentityPath, encPath)
		if err == nil {
			t.Error("decryptAgeFile() should fail with wrong identity")
		}
	})
}

func TestFetchFromAge(t *testing.T) {
	// Generate identity
	identity, _ := age.GenerateX25519Identity()
	recipient := identity.Recipient()

	tmpDir := t.TempDir()

	// Write identity file
	identityPath := filepath.Join(tmpDir, "identity")
	os.WriteFile(identityPath, []byte(identity.String()), 0o600)

	// Save and set identity path
	origIdentityFile := ageIdentityFile
	ageIdentityFile = identityPath
	defer func() { ageIdentityFile = origIdentityFile }()

	t.Run("simple decryption", func(t *testing.T) {
		encPath := filepath.Join(tmpDir, "simple.age")
		encFile, _ := os.Create(encPath)
		writer, _ := age.Encrypt(encFile, recipient)
		writer.Write([]byte("  simple-secret  \n"))
		writer.Close()
		encFile.Close()
		os.Chmod(encPath, 0o600)

		parsed := &ParsedSource{
			Backend: BackendAge,
			Path:    encPath,
		}

		result, err := fetchFromAge(context.Background(), parsed)
		if err != nil {
			t.Errorf("fetchFromAge() error = %v", err)
		}
		if result != "simple-secret" {
			t.Errorf("result = %q, want %q", result, "simple-secret")
		}
	})

	t.Run("decryption with jq", func(t *testing.T) {
		encPath := filepath.Join(tmpDir, "json.age")
		encFile, _ := os.Create(encPath)
		writer, _ := age.Encrypt(encFile, recipient)
		writer.Write([]byte(`{"password": "json-secret", "username": "user"}`))
		writer.Close()
		encFile.Close()
		os.Chmod(encPath, 0o600)

		parsed := &ParsedSource{
			Backend: BackendAge,
			Path:    encPath,
			JQExpr:  ".password",
		}

		result, err := fetchFromAge(context.Background(), parsed)
		if err != nil {
			t.Errorf("fetchFromAge() error = %v", err)
		}
		if result != "json-secret" {
			t.Errorf("result = %q, want %q", result, "json-secret")
		}
	})

	t.Run("missing encrypted file", func(t *testing.T) {
		parsed := &ParsedSource{
			Backend: BackendAge,
			Path:    "/nonexistent/file.age",
		}

		_, err := fetchFromAge(context.Background(), parsed)
		if err == nil {
			t.Error("fetchFromAge() should error for missing file")
		}
	})
}

func TestSetAgeIdentityFile(t *testing.T) {
	orig := ageIdentityFile
	defer func() { ageIdentityFile = orig }()

	SetAgeIdentityFile("/custom/path")
	if ageIdentityFile != "/custom/path" {
		t.Errorf("ageIdentityFile = %q, want %q", ageIdentityFile, "/custom/path")
	}

	// Empty string should not change
	SetAgeIdentityFile("")
	if ageIdentityFile != "/custom/path" {
		t.Errorf("ageIdentityFile = %q after empty set, want %q", ageIdentityFile, "/custom/path")
	}
}
