//go:build darwin

package credentials

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// keychainCommandTimeout is the maximum time for keychain operations.
const keychainCommandTimeout = 10 * time.Second

// keychainAccountName is the account name used for all claw-wrap keychain items.
const keychainAccountName = "claw-wrap"

// fetchFromKeychain retrieves a credential from macOS Keychain.
func fetchFromKeychain(ctx context.Context, parsed *ParsedSource) (string, error) {
	// Read from keychain
	secret, err := readKeychainItem(ctx, parsed.Path)
	if err != nil {
		return "", fmt.Errorf("keychain access failed")
	}

	// Apply jq if specified
	if parsed.HasJQ() {
		return ApplyJQ(ctx, []byte(secret), parsed.JQExpr)
	}

	return secret, nil
}

// readKeychainItem reads a password from the login keychain.
func readKeychainItem(ctx context.Context, serviceName string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, keychainCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "security", "find-generic-password",
		"-s", serviceName,
		"-a", keychainAccountName,
		"-w")

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit code 44 = item not found
			if exitErr.ExitCode() == 44 {
				return "", fmt.Errorf("keychain item not found")
			}
			// Check for interaction not allowed (headless/SSH)
			stderr := string(exitErr.Stderr)
			if strings.Contains(stderr, "interaction is not allowed") {
				return "", fmt.Errorf("keychain locked or running in headless mode")
			}
		}
		return "", fmt.Errorf("keychain read failed")
	}

	return strings.TrimSpace(string(output)), nil
}

// KeychainSetup adds a secret to the keychain with appropriate ACL.
// This is called by the keychain-setup command, not during normal operation.
func KeychainSetup(serviceName, binaryPath string) error {
	// Delete existing item (ignore errors)
	deleteCmd := exec.Command("security", "delete-generic-password",
		"-s", serviceName,
		"-a", keychainAccountName)
	_ = deleteCmd.Run() // Ignore error - item may not exist

	// Add with trusted application. Keep -w last to force prompt mode so
	// secrets are never passed via argv.
	args := []string{"add-generic-password",
		"-s", serviceName,
		"-a", keychainAccountName,
		"-U"}

	// Add trusted application if binary path provided
	if binaryPath != "" {
		args = append(args, "-T", binaryPath)
	}
	args = append(args, "-w")

	cmd := exec.Command("security", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		stderr := strings.ToLower(strings.TrimSpace(string(output)))
		if strings.Contains(stderr, "already exists") {
			return fmt.Errorf("keychain item exists and could not be updated")
		}
		if strings.Contains(stderr, "interaction is not allowed") {
			return fmt.Errorf("keychain locked or running in headless mode")
		}
		if strings.Contains(stderr, "user canceled") || strings.Contains(stderr, "operation canceled") {
			return fmt.Errorf("keychain setup cancelled")
		}
		return fmt.Errorf("failed to add keychain item")
	}

	return nil
}
