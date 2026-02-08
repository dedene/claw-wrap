package credentials

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// 1Password token file locations (in precedence order).
const (
	opTokenCredentialName = "op-service-account-token"
	opTokenEnvVar         = "OP_SERVICE_ACCOUNT_TOKEN"
)

// opTokenFile is set by config loader; defaults to /etc/openclaw/1password.token.
var opTokenFile = "/etc/openclaw/1password.token"

// SetOPTokenFile configures the 1Password token file path.
func SetOPTokenFile(path string) {
	if path != "" {
		opTokenFile = path
	}
}

// opCommandTimeout is the maximum time for 1Password CLI commands.
const opCommandTimeout = 30 * time.Second

var secureFileCurrentEUID = os.Geteuid

// fetchFrom1Password retrieves a credential from 1Password.
// For sources without jq: uses `op read` directly.
// For sources with jq: uses `op item get --format json` and applies jq.
func fetchFrom1Password(ctx context.Context, parsed *ParsedSource, opBinaryOverride string) (string, error) {
	opBinary, err := resolveOPBinary(opBinaryOverride)
	if err != nil {
		return "", fmt.Errorf("1password CLI not found in trusted locations")
	}

	// Get service account token
	token, err := getOPServiceAccountToken()
	if err != nil {
		return "", fmt.Errorf("1password token not configured")
	}

	if parsed.HasJQ() {
		return fetchFrom1PasswordWithJQ(ctx, opBinary, token, parsed)
	}
	return fetchFrom1PasswordDirect(ctx, opBinary, token, parsed.Path)
}

func resolveOPBinary(opBinaryOverride string) (string, error) {
	if opBinaryOverride != "" {
		return opBinaryOverride, nil
	}
	return findTrustedBinaryFunc("op")
}

// fetchFrom1PasswordDirect uses `op read` for direct field access.
func fetchFrom1PasswordDirect(ctx context.Context, opBinary, token, secretRef string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, opCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, opBinary, "read", secretRef)
	cmd.Env = append(os.Environ(), opTokenEnvVar+"="+token)

	output, err := cmd.Output()
	if err != nil {
		log.Printf("[DEBUG] op read failed: %v", err)
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
			log.Printf("[DEBUG] op stderr: %s", string(exitErr.Stderr))
		}
		return "", fmt.Errorf("1password read failed")
	}

	return strings.TrimSpace(string(output)), nil
}

// fetchFrom1PasswordWithJQ uses `op item get --format json` and applies jq.
func fetchFrom1PasswordWithJQ(ctx context.Context, opBinary, token string, parsed *ParsedSource) (string, error) {
	// Parse op:// URI to extract vault and item
	// Format: op://vault/item/field or op://vault/item
	vault, item, err := parseOPSecretRef(parsed.Path)
	if err != nil {
		return "", fmt.Errorf("invalid 1password reference")
	}

	ctx, cancel := context.WithTimeout(ctx, opCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, opBinary, "item", "get", item, "--vault", vault, "--format", "json")
	cmd.Env = append(os.Environ(), opTokenEnvVar+"="+token)

	output, err := cmd.Output()
	if err != nil {
		log.Printf("[DEBUG] op item get failed: %v", err)
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
			log.Printf("[DEBUG] op stderr: %s", string(exitErr.Stderr))
		}
		return "", fmt.Errorf("1password item get failed")
	}

	// Apply jq expression
	return ApplyJQ(ctx, output, parsed.JQExpr)
}

// parseOPSecretRef extracts vault and item from op://vault/item/field format.
func parseOPSecretRef(ref string) (vault, item string, err error) {
	if !strings.HasPrefix(ref, "op://") {
		return "", "", fmt.Errorf("invalid op:// reference")
	}

	// Remove op:// prefix
	path := strings.TrimPrefix(ref, "op://")
	parts := strings.Split(path, "/")

	if len(parts) < 2 {
		return "", "", fmt.Errorf("op:// reference must have at least vault/item")
	}

	return parts[0], parts[1], nil
}

// getOPServiceAccountToken retrieves the 1Password service account token.
// Sources checked in order:
// 1. $CREDENTIALS_DIRECTORY/op-service-account-token (systemd)
// 2. /etc/openclaw/1password.token
// 3. OP_SERVICE_ACCOUNT_TOKEN environment variable
func getOPServiceAccountToken() (string, error) {
	// 1. Check systemd credentials directory
	if credDir := os.Getenv("CREDENTIALS_DIRECTORY"); credDir != "" {
		tokenPath := filepath.Join(credDir, opTokenCredentialName)
		token, exists, err := readSecureCredentialValue(tokenPath)
		if err != nil {
			return "", fmt.Errorf("invalid 1password token file: %w", err)
		}
		if exists {
			return token, nil
		}
	}

	// 2. Check configured file path
	token, exists, err := readSecureCredentialValue(opTokenFile)
	if err != nil {
		return "", fmt.Errorf("invalid 1password token file: %w", err)
	}
	if exists {
		return token, nil
	}

	// 3. Check environment variable
	if token := os.Getenv(opTokenEnvVar); token != "" {
		return token, nil
	}

	return "", fmt.Errorf("no 1password token found")
}

func readSecureCredentialValue(path string) (string, bool, error) {
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("stat file: %w", err)
	}

	value, err := readSecureFile(path)
	if err != nil {
		return "", true, err
	}
	if value == "" {
		return "", true, fmt.Errorf("credential file is empty: %s", path)
	}
	return value, true, nil
}

// readSecureFile reads a file with security validations.
// Returns empty string and nil error if file doesn't exist.
// Returns error if file exists but has security issues.
func readSecureFile(path string) (string, error) {
	// Open with O_NOFOLLOW to prevent symlink attacks
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if err == unix.ENOENT {
			return "", nil // File doesn't exist, not an error
		}
		if err == unix.ELOOP {
			return "", fmt.Errorf("file must not be a symlink: %s", path)
		}
		return "", fmt.Errorf("open file: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return "", fmt.Errorf("failed to create file handle")
	}
	defer file.Close()

	// Validate file properties
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat file: %w", err)
	}

	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("must be a regular file: %s", path)
	}

	perm := info.Mode().Perm()
	if perm != 0o600 && perm != 0o640 {
		return "", fmt.Errorf("file permissions too open: %s has %04o, want 0600 or 0640", path, perm)
	}

	// Validate owner matches daemon UID
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("unsupported file stat type")
	}
	if int(stat.Uid) != secureFileCurrentEUID() {
		return "", fmt.Errorf("file owner must match daemon uid")
	}

	// Read content
	content := make([]byte, info.Size())
	n, err := file.Read(content)
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}

	return strings.TrimSpace(string(content[:n])), nil
}

// readSecureFileBytes reads a file with security validations, returning raw bytes.
// Returns nil and nil error if file doesn't exist.
// Returns error if file exists but has security issues.
func readSecureFileBytes(path string) ([]byte, error) {
	// Open with O_NOFOLLOW to prevent symlink attacks
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if err == unix.ENOENT {
			return nil, nil // File doesn't exist, not an error
		}
		if err == unix.ELOOP {
			return nil, fmt.Errorf("file must not be a symlink: %s", path)
		}
		return nil, fmt.Errorf("open file: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed to create file handle")
	}
	defer file.Close()

	// Validate file properties
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("must be a regular file: %s", path)
	}

	perm := info.Mode().Perm()
	if perm != 0o600 && perm != 0o640 {
		return nil, fmt.Errorf("file permissions too open: %s has %04o, want 0600 or 0640", path, perm)
	}

	// Validate owner matches daemon UID
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("unsupported file stat type")
	}
	if int(stat.Uid) != secureFileCurrentEUID() {
		return nil, fmt.Errorf("file owner must match daemon uid")
	}

	// Read content
	content := make([]byte, info.Size())
	n, err := file.Read(content)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	return content[:n], nil
}
