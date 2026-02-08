//go:build darwin

package credentials

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func setKeychainSecret(t *testing.T, serviceName, secret string) {
	t.Helper()
	cmd := exec.Command(
		"security",
		"add-generic-password",
		"-s", serviceName,
		"-a", keychainAccountName,
		"-w", secret,
		"-U",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("seed keychain item: %v output=%s", err, strings.TrimSpace(string(output)))
	}
}

func TestReadKeychainItem_NotFound(t *testing.T) {
	// Use a service name that definitely doesn't exist
	_, err := readKeychainItem(context.Background(), "claw-wrap-test-nonexistent-12345")
	if err == nil {
		t.Error("readKeychainItem() should error for non-existent item")
	}
	if err.Error() != "keychain item not found" {
		t.Errorf("error = %q, want %q", err.Error(), "keychain item not found")
	}
}

func TestFetchFromKeychain_NotFound(t *testing.T) {
	parsed := &ParsedSource{
		Backend: BackendKeychain,
		Path:    "claw-wrap-test-nonexistent-12345",
	}

	_, err := fetchFromKeychain(context.Background(), parsed)
	if err == nil {
		t.Error("fetchFromKeychain() should error for non-existent item")
	}
}

// TestKeychainRoundtrip tests actual keychain operations.
// Skipped unless KEYCHAIN_TEST=1 is set, as it modifies the login keychain.
func TestKeychainRoundtrip(t *testing.T) {
	if os.Getenv("KEYCHAIN_TEST") != "1" {
		t.Skip("Set KEYCHAIN_TEST=1 to run keychain integration tests")
	}

	serviceName := "claw-wrap-test-roundtrip"
	secret := "test-secret-value-12345"

	// Clean up before and after
	cleanup := func() {
		exec.Command("security", "delete-generic-password",
			"-s", serviceName,
			"-a", keychainAccountName).Run()
	}
	cleanup()
	defer cleanup()

	setKeychainSecret(t, serviceName, secret)

	// Read back
	result, err := readKeychainItem(context.Background(), serviceName)
	if err != nil {
		t.Fatalf("readKeychainItem() error = %v", err)
	}
	if result != secret {
		t.Errorf("result = %q, want %q", result, secret)
	}

	// Test update (using -U flag)
	newSecret := "updated-secret-value"
	setKeychainSecret(t, serviceName, newSecret)

	result, err = readKeychainItem(context.Background(), serviceName)
	if err != nil {
		t.Fatalf("readKeychainItem() after update error = %v", err)
	}
	if result != newSecret {
		t.Errorf("result = %q, want %q", result, newSecret)
	}
}

// TestFetchFromKeychainWithJQ tests jq extraction from keychain values.
// Skipped unless KEYCHAIN_TEST=1 is set.
func TestFetchFromKeychainWithJQ(t *testing.T) {
	if os.Getenv("KEYCHAIN_TEST") != "1" {
		t.Skip("Set KEYCHAIN_TEST=1 to run keychain integration tests")
	}

	serviceName := "claw-wrap-test-jq"
	secret := `{"username": "user", "password": "secret123"}`

	// Clean up before and after
	cleanup := func() {
		exec.Command("security", "delete-generic-password",
			"-s", serviceName,
			"-a", keychainAccountName).Run()
	}
	cleanup()
	defer cleanup()

	setKeychainSecret(t, serviceName, secret)

	parsed := &ParsedSource{
		Backend: BackendKeychain,
		Path:    serviceName,
		JQExpr:  ".password",
	}

	result, err := fetchFromKeychain(context.Background(), parsed)
	if err != nil {
		t.Fatalf("fetchFromKeychain() error = %v", err)
	}
	if result != "secret123" {
		t.Errorf("result = %q, want %q", result, "secret123")
	}
}
