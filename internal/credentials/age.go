package credentials

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"filippo.io/age"
)

// Age identity file locations (in precedence order).
const (
	ageIdentityCredentialName = "age-identity"
	ageIdentityDefaultPath    = "/etc/openclaw/age-identity"
)

// ageIdentityFile is set by the config loader; defaults to ageIdentityDefaultPath.
// Protected by ageIdentityMu for concurrent access.
var (
	ageIdentityMu   sync.RWMutex
	ageIdentityFile = ageIdentityDefaultPath
)

// SetAgeIdentityFile configures the age identity file path.
func SetAgeIdentityFile(path string) {
	ageIdentityMu.Lock()
	defer ageIdentityMu.Unlock()
	if path != "" {
		ageIdentityFile = path
	}
}

func getAgeIdentityFile() string {
	ageIdentityMu.RLock()
	defer ageIdentityMu.RUnlock()
	return ageIdentityFile
}

// fetchFromAge retrieves a credential from an age-encrypted file.
func fetchFromAge(ctx context.Context, parsed *ParsedSource) (string, error) {
	// Get identity file path
	identityPath, err := getAgeIdentityPath()
	if err != nil {
		return "", fmt.Errorf("age identity not configured")
	}

	// Decrypt the file
	plaintext, err := decryptAgeFile(identityPath, parsed.Path)
	if err != nil {
		return "", fmt.Errorf("age decryption failed")
	}

	content := strings.TrimSpace(string(plaintext))

	// Apply jq if specified
	if parsed.HasJQ() {
		return ApplyJQ(ctx, []byte(content), parsed.JQExpr)
	}

	return content, nil
}

// getAgeIdentityPath returns the age identity file path.
// Sources checked in order:
// 1. $CREDENTIALS_DIRECTORY/age-identity (systemd)
// 2. Configured or default path
func getAgeIdentityPath() (string, error) {
	// 1. Check systemd credentials directory
	if credDir := os.Getenv("CREDENTIALS_DIRECTORY"); credDir != "" {
		tokenPath := filepath.Join(credDir, ageIdentityCredentialName)
		if _, err := os.Stat(tokenPath); err == nil {
			return tokenPath, nil
		}
	}

	// 2. Use configured path
	return getAgeIdentityFile(), nil
}

// decryptAgeFile decrypts an age-encrypted file using the specified identity.
func decryptAgeFile(identityPath, encryptedPath string) ([]byte, error) {
	// Validate and read identity file with security checks
	identityContent, err := readSecureFile(identityPath)
	if err != nil {
		return nil, fmt.Errorf("reading identity: %w", err)
	}
	if identityContent == "" {
		return nil, fmt.Errorf("identity file not found")
	}

	// Parse identities
	identities, err := age.ParseIdentities(strings.NewReader(identityContent))
	if err != nil {
		return nil, fmt.Errorf("parsing identity: %w", err)
	}

	// Read encrypted file with security checks (binary data)
	encContent, err := readSecureFileBytes(encryptedPath)
	if err != nil {
		return nil, fmt.Errorf("reading encrypted file: %w", err)
	}
	if encContent == nil {
		return nil, fmt.Errorf("encrypted file not found")
	}

	// Decrypt
	reader, err := age.Decrypt(bytes.NewReader(encContent), identities...)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return io.ReadAll(reader)
}
