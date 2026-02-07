// Package auth provides HMAC-SHA256 authentication for claw-wrap tool invocations.
// It implements signature computation and verification with timestamp freshness checking
// to prevent replay attacks.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// MaxTimestampDrift is the maximum allowed time difference between
	// the timestamp in a request and the current time.
	MaxTimestampDrift = 5 * time.Second

	// SecretSize is the size of the HMAC secret in bytes.
	SecretSize = 32
)

var (
	// ErrInvalidTimestamp indicates the timestamp is malformed or expired.
	ErrInvalidTimestamp = errors.New("invalid or expired timestamp")

	// ErrInvalidSignature indicates the HMAC signature verification failed.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrSecretNotFound indicates the secret file could not be read.
	ErrSecretNotFound = errors.New("secret file not found")
)

// GenerateSecret creates a cryptographically random 32-byte secret
// suitable for HMAC-SHA256 authentication.
func GenerateSecret() ([]byte, error) {
	secret := make([]byte, SecretSize)
	_, err := rand.Read(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random secret: %w", err)
	}
	return secret, nil
}

// WriteSecret writes the secret to the specified path with 0600 permissions.
// It uses an atomic write via a temporary file to prevent partial writes.
// It refuses to write if the target path is a symlink (prevents symlink attacks).
func WriteSecret(path string, secret []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Check for symlink at target path to prevent symlink attacks
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write secret: %s is a symlink", path)
		}
	}

	// Create temp file in the same directory for atomic rename
	tmpFile, err := os.CreateTemp(dir, ".auth-secret-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Clean up temp file on error
	defer func() {
		if tmpPath != "" {
			os.Remove(tmpPath)
		}
	}()

	// Set permissions before writing content
	if err := tmpFile.Chmod(0600); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Write the secret as base64 for safe storage
	encoded := base64.StdEncoding.EncodeToString(secret)
	if _, err := tmpFile.WriteString(encoded + "\n"); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write secret: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	tmpPath = "" // Prevent cleanup of successfully renamed file
	return nil
}

// LoadSecret reads and decodes the secret from the specified file path.
// The file is expected to contain a base64-encoded secret.
// It refuses to read if the path is a symlink (prevents symlink attacks).
func LoadSecret(path string) ([]byte, error) {
	// Check for symlink before reading
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to read secret: %s is a symlink", path)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrSecretNotFound
		}
		return nil, fmt.Errorf("failed to read secret file: %w", err)
	}

	// Trim whitespace and decode from base64
	encoded := strings.TrimSpace(string(data))
	secret, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret: %w", err)
	}

	return secret, nil
}

// NonceSize is the size of the request nonce in bytes.
const NonceSize = 16

// GenerateNonce creates a cryptographically random 16-byte nonce
// encoded as base64 for inclusion in requests.
func GenerateNonce() (string, error) {
	nonce := make([]byte, NonceSize)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(nonce), nil
}

// ComputeHMAC computes an HMAC-SHA256 signature over:
// timestamp + tool + json(args) + cwd + json({}) + nonce.
// For env-aware signing, use ComputeHMACWithEnv.
func ComputeHMAC(secret []byte, timestamp, tool, cwd string, args []string, nonce string) (string, error) {
	return ComputeHMACWithEnv(secret, timestamp, tool, cwd, args, nil, nonce)
}

// ComputeHMACWithEnv computes an HMAC-SHA256 signature over:
// timestamp + tool + json(args) + cwd + json(env canonical) + nonce.
// Fields are separated by newlines to prevent boundary confusion.
func ComputeHMACWithEnv(secret []byte, timestamp, tool, cwd string, args []string, env map[string]string, nonce string) (string, error) {
	// Serialize args as JSON for consistent encoding
	argsJSON, err := json.Marshal(args)
	if err != nil {
		return "", fmt.Errorf("failed to marshal args: %w", err)
	}

	envJSON, err := marshalEnvCanonical(env)
	if err != nil {
		return "", fmt.Errorf("failed to marshal env: %w", err)
	}

	// Build the message to sign — fields separated by \n to prevent boundary confusion
	message := timestamp + "\n" + tool + "\n" + string(argsJSON) + "\n" + cwd + "\n" + envJSON + "\n" + nonce

	// Compute HMAC-SHA256
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(message))
	signature := mac.Sum(nil)

	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifyHMAC verifies the provided HMAC signature against a freshly computed one.
// It uses constant-time comparison to prevent timing attacks and validates
// that the timestamp is within the allowed freshness window.
// VerifyHMAC verifies signature using an empty env object.
// For env-aware verification, use VerifyHMACWithEnv.
func VerifyHMAC(secret []byte, timestamp, tool, cwd string, args []string, nonce, providedHMAC string) error {
	return VerifyHMACWithEnv(secret, timestamp, tool, cwd, args, nil, nonce, providedHMAC)
}

// VerifyHMACWithEnv verifies the provided HMAC signature with env included.
func VerifyHMACWithEnv(secret []byte, timestamp, tool, cwd string, args []string, env map[string]string, nonce, providedHMAC string) error {
	// First validate timestamp freshness
	if err := ValidateTimestamp(timestamp); err != nil {
		return err
	}

	// Compute expected HMAC
	expectedHMAC, err := ComputeHMACWithEnv(secret, timestamp, tool, cwd, args, env, nonce)
	if err != nil {
		return fmt.Errorf("failed to compute expected HMAC: %w", err)
	}

	// Decode both HMACs for constant-time comparison
	provided, err := base64.StdEncoding.DecodeString(providedHMAC)
	if err != nil {
		return ErrInvalidSignature
	}

	expected, err := base64.StdEncoding.DecodeString(expectedHMAC)
	if err != nil {
		return fmt.Errorf("failed to decode expected HMAC: %w", err)
	}

	// Constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(provided, expected) != 1 {
		return ErrInvalidSignature
	}

	return nil
}

func marshalEnvCanonical(env map[string]string) (string, error) {
	if len(env) == 0 {
		return "{}", nil
	}

	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return "", err
		}
		vb, err := json.Marshal(env[k])
		if err != nil {
			return "", err
		}
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.String(), nil
}

// ValidateTimestamp checks that the timestamp (Unix seconds as string)
// is within MaxTimestampDrift of the current time.
func ValidateTimestamp(timestamp string) error {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return ErrInvalidTimestamp
	}

	requestTime := time.Unix(ts, 0)
	now := time.Now()
	drift := now.Sub(requestTime)

	// Check absolute value of drift
	if drift < 0 {
		drift = -drift
	}

	if drift > MaxTimestampDrift {
		return ErrInvalidTimestamp
	}

	return nil
}
