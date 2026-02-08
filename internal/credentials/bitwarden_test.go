package credentials

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGetBWCredential(t *testing.T) {
	// Save original env
	origCredDir := os.Getenv("CREDENTIALS_DIRECTORY")
	origClientID := os.Getenv(bwClientIDEnvVar)
	defer func() {
		os.Setenv("CREDENTIALS_DIRECTORY", origCredDir)
		os.Setenv(bwClientIDEnvVar, origClientID)
	}()

	t.Run("from CREDENTIALS_DIRECTORY", func(t *testing.T) {
		tmpDir := t.TempDir()
		credPath := filepath.Join(tmpDir, bwClientIDCredentialName)
		if err := os.WriteFile(credPath, []byte("systemd-client-id"), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}

		os.Setenv("CREDENTIALS_DIRECTORY", tmpDir)
		os.Setenv(bwClientIDEnvVar, "env-client-id")

		result, err := getBWCredential(bwClientIDCredentialName, bwClientIDEnvVar)
		if err != nil {
			t.Errorf("getBWCredential() error = %v", err)
		}
		if result != "systemd-client-id" {
			t.Errorf("result = %q, want %q (should prefer CREDENTIALS_DIRECTORY)", result, "systemd-client-id")
		}
	})

	t.Run("from environment variable", func(t *testing.T) {
		os.Setenv("CREDENTIALS_DIRECTORY", "")
		os.Setenv(bwClientIDEnvVar, "env-client-id")

		result, err := getBWCredential(bwClientIDCredentialName, bwClientIDEnvVar)
		if err != nil {
			t.Errorf("getBWCredential() error = %v", err)
		}
		if result != "env-client-id" {
			t.Errorf("result = %q, want %q", result, "env-client-id")
		}
	})

	t.Run("invalid systemd file fails closed", func(t *testing.T) {
		tmpDir := t.TempDir()
		credPath := filepath.Join(tmpDir, bwClientIDCredentialName)
		if err := os.WriteFile(credPath, []byte("systemd-client-id"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}

		os.Setenv("CREDENTIALS_DIRECTORY", tmpDir)
		os.Setenv(bwClientIDEnvVar, "env-client-id")

		_, err := getBWCredential(bwClientIDCredentialName, bwClientIDEnvVar)
		if err == nil {
			t.Error("getBWCredential() should fail closed on invalid systemd credential file")
		}
	})

	t.Run("not configured", func(t *testing.T) {
		os.Setenv("CREDENTIALS_DIRECTORY", "")
		os.Setenv(bwClientIDEnvVar, "")

		_, err := getBWCredential(bwClientIDCredentialName, bwClientIDEnvVar)
		if err == nil {
			t.Error("getBWCredential() should error when not configured")
		}
	})
}

func TestIsAuthError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"not logged in", fmt.Errorf("You are not logged in"), true},
		{"vault locked", fmt.Errorf("Vault is locked"), true},
		{"invalid session", fmt.Errorf("Invalid session key"), true},
		{"auth failed", fmt.Errorf("authorization failed"), true},
		{"not found", fmt.Errorf("Not found"), false},
		{"other error", fmt.Errorf("network timeout"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAuthError(tt.err); got != tt.want {
				t.Errorf("isAuthError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBWEnv(t *testing.T) {
	session := &bwSession{dataDir: "/tmp/test-bw-data"}
	env := bwEnv(session)

	found := false
	for _, e := range env {
		if e == "BITWARDENCLI_APPDATA_DIR=/tmp/test-bw-data" {
			found = true
			break
		}
	}

	if !found {
		t.Error("bwEnv() should include BITWARDENCLI_APPDATA_DIR")
	}
}

func TestFetchFromBitwarden_RetryOnAuthError(t *testing.T) {
	origRetryDelays := bwRetryDelays
	origSleep := bwSleep
	origGetItem := bwGetItemFunc
	origEnsure := bwEnsureFunc
	origCurrent := bwCurrent
	defer func() {
		bwRetryDelays = origRetryDelays
		bwSleep = origSleep
		bwGetItemFunc = origGetItem
		bwEnsureFunc = origEnsure
		bwCurrent = origCurrent
	}()

	bwCurrent = nil
	bwRetryDelays = []time.Duration{0, time.Second, 3 * time.Second}

	var sleepCalls []time.Duration
	bwSleep = func(_ context.Context, d time.Duration) error {
		sleepCalls = append(sleepCalls, d)
		return nil
	}

	ensureCalls := 0
	bwEnsureFunc = func(_ context.Context, bwBinary string) error {
		ensureCalls++
		if bwCurrent == nil {
			bwCurrent = &bwSession{dataDir: t.TempDir(), binary: bwBinary, token: "token"}
		}
		bwCurrent.binary = bwBinary
		bwCurrent.token = "token"
		return nil
	}

	getItemCalls := 0
	bwGetItemFunc = func(_ context.Context, _ *bwSession, _ string) (string, error) {
		getItemCalls++
		if getItemCalls == 1 {
			return "", fmt.Errorf("bitwarden get item failed: invalid session key")
		}
		return `{"password":"secret"}`, nil
	}

	parsed := &ParsedSource{Backend: BackendBitwarden, Path: "item-id", JQExpr: ".password"}
	value, err := fetchFromBitwarden(context.Background(), parsed, "/usr/local/bin/bw")
	if err != nil {
		t.Fatalf("fetchFromBitwarden() error = %v", err)
	}
	if value != "secret" {
		t.Fatalf("fetchFromBitwarden() value = %q, want %q", value, "secret")
	}
	if ensureCalls != 2 {
		t.Fatalf("ensure calls = %d, want 2 (initial + re-auth)", ensureCalls)
	}
	if getItemCalls != 2 {
		t.Fatalf("get item calls = %d, want 2", getItemCalls)
	}
	if len(sleepCalls) != 2 || sleepCalls[0] != 0 || sleepCalls[1] != time.Second {
		t.Fatalf("sleep calls = %v, want [0s 1s]", sleepCalls)
	}
}

func TestFetchFromBitwarden_DoesNotRetryNonAuthErrors(t *testing.T) {
	origRetryDelays := bwRetryDelays
	origSleep := bwSleep
	origGetItem := bwGetItemFunc
	origEnsure := bwEnsureFunc
	origCurrent := bwCurrent
	defer func() {
		bwRetryDelays = origRetryDelays
		bwSleep = origSleep
		bwGetItemFunc = origGetItem
		bwEnsureFunc = origEnsure
		bwCurrent = origCurrent
	}()

	bwCurrent = nil
	bwRetryDelays = []time.Duration{0, time.Second, 3 * time.Second}

	var sleepCalls []time.Duration
	bwSleep = func(_ context.Context, d time.Duration) error {
		sleepCalls = append(sleepCalls, d)
		return nil
	}

	ensureCalls := 0
	bwEnsureFunc = func(_ context.Context, bwBinary string) error {
		ensureCalls++
		if bwCurrent == nil {
			bwCurrent = &bwSession{dataDir: t.TempDir(), binary: bwBinary, token: "token"}
		}
		return nil
	}

	getItemCalls := 0
	bwGetItemFunc = func(_ context.Context, _ *bwSession, _ string) (string, error) {
		getItemCalls++
		return "", fmt.Errorf("bitwarden get item failed: network timeout")
	}

	parsed := &ParsedSource{Backend: BackendBitwarden, Path: "item-id"}
	_, err := fetchFromBitwarden(context.Background(), parsed, "/usr/local/bin/bw")
	if err == nil {
		t.Fatal("fetchFromBitwarden() should return error")
	}
	if ensureCalls != 1 {
		t.Fatalf("ensure calls = %d, want 1", ensureCalls)
	}
	if getItemCalls != 1 {
		t.Fatalf("get item calls = %d, want 1", getItemCalls)
	}
	if len(sleepCalls) != 1 || sleepCalls[0] != 0 {
		t.Fatalf("sleep calls = %v, want [0s]", sleepCalls)
	}
}

func TestFetchFromBitwarden_ContextCancellationInterruptsBackoff(t *testing.T) {
	origRetryDelays := bwRetryDelays
	origSleep := bwSleep
	origGetItem := bwGetItemFunc
	origEnsure := bwEnsureFunc
	origCurrent := bwCurrent
	defer func() {
		bwRetryDelays = origRetryDelays
		bwSleep = origSleep
		bwGetItemFunc = origGetItem
		bwEnsureFunc = origEnsure
		bwCurrent = origCurrent
	}()

	bwCurrent = nil
	bwRetryDelays = []time.Duration{0, time.Second, 3 * time.Second}
	bwSleep = sleepWithContext

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bwEnsureFunc = func(_ context.Context, bwBinary string) error {
		if bwCurrent == nil {
			bwCurrent = &bwSession{dataDir: t.TempDir(), binary: bwBinary, token: "token"}
		}
		return nil
	}

	getItemCalls := 0
	bwGetItemFunc = func(_ context.Context, _ *bwSession, _ string) (string, error) {
		getItemCalls++
		cancel()
		return "", fmt.Errorf("bitwarden get item failed: invalid session")
	}

	parsed := &ParsedSource{Backend: BackendBitwarden, Path: "item-id"}
	_, err := fetchFromBitwarden(ctx, parsed, "/usr/local/bin/bw")
	if err == nil {
		t.Fatal("fetchFromBitwarden() should return error when context is cancelled")
	}
	if getItemCalls != 1 {
		t.Fatalf("get item calls = %d, want 1", getItemCalls)
	}
}

// TestBitwardenRoundtrip tests actual Bitwarden operations.
// Skipped unless BITWARDEN_TEST=1 and credentials are set.
func TestBitwardenRoundtrip(t *testing.T) {
	if os.Getenv("BITWARDEN_TEST") != "1" {
		t.Skip("Set BITWARDEN_TEST=1 and configure BW credentials to run integration tests")
	}

	// Ensure cleanup
	defer CleanupBWSession()

	t.Run("check status", func(t *testing.T) {
		ctx := context.Background()

		// Initialize session
		bwMutex.Lock()
		if bwCurrent == nil {
			dataDir, err := os.MkdirTemp("", "claw-wrap-bw-test-*")
			if err != nil {
				t.Fatalf("create temp dir: %v", err)
			}
			bwCurrent = &bwSession{dataDir: dataDir}
		}
		bwMutex.Unlock()

		status, err := bwCheckStatus(ctx, bwCurrent)
		if err != nil {
			t.Logf("bwCheckStatus() error = %v (expected if not logged in)", err)
		} else {
			t.Logf("bwCheckStatus() = %+v", status)
		}
	})
}
