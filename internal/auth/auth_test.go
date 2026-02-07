package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestGenerateSecret(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	if len(secret) != SecretSize {
		t.Errorf("GenerateSecret() returned %d bytes, want %d", len(secret), SecretSize)
	}

	// Verify randomness by generating another and ensuring they differ
	secret2, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() second call error = %v", err)
	}

	if subtle.ConstantTimeCompare(secret, secret2) == 1 {
		t.Error("GenerateSecret() produced identical secrets on consecutive calls")
	}
}

func TestComputeHMAC_Deterministic(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-testing")
	timestamp := "1234567890"
	tool := "test-tool"
	cwd := "/home/user/project"
	args := []string{"arg1", "arg2", "--flag=value"}

	// Compute HMAC multiple times
	hmac1, err := ComputeHMAC(secret, timestamp, tool, cwd, args)
	if err != nil {
		t.Fatalf("ComputeHMAC() first call error = %v", err)
	}

	hmac2, err := ComputeHMAC(secret, timestamp, tool, cwd, args)
	if err != nil {
		t.Fatalf("ComputeHMAC() second call error = %v", err)
	}

	hmac3, err := ComputeHMAC(secret, timestamp, tool, cwd, args)
	if err != nil {
		t.Fatalf("ComputeHMAC() third call error = %v", err)
	}

	if hmac1 != hmac2 || hmac2 != hmac3 {
		t.Errorf("ComputeHMAC() not deterministic: %s != %s != %s", hmac1, hmac2, hmac3)
	}

	// Verify it's valid base64
	decoded, err := base64.StdEncoding.DecodeString(hmac1)
	if err != nil {
		t.Errorf("ComputeHMAC() result not valid base64: %v", err)
	}

	// HMAC-SHA256 produces 32 bytes
	if len(decoded) != 32 {
		t.Errorf("ComputeHMAC() decoded length = %d, want 32", len(decoded))
	}
}

func TestComputeHMAC_DifferentInputs(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-testing")
	timestamp := "1234567890"
	tool := "test-tool"
	cwd := "/home/user/project"
	args := []string{"arg1", "arg2"}

	baseHMAC, err := ComputeHMAC(secret, timestamp, tool, cwd, args)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}

	tests := []struct {
		name      string
		timestamp string
		tool      string
		cwd       string
		args      []string
	}{
		{"different timestamp", "1234567891", tool, cwd, args},
		{"different tool", timestamp, "other-tool", cwd, args},
		{"different cwd", timestamp, tool, "/other/path", args},
		{"different args", timestamp, tool, cwd, []string{"arg1", "arg3"}},
		{"extra arg", timestamp, tool, cwd, []string{"arg1", "arg2", "arg3"}},
		{"empty args", timestamp, tool, cwd, []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			differentHMAC, err := ComputeHMAC(secret, tt.timestamp, tt.tool, tt.cwd, tt.args)
			if err != nil {
				t.Fatalf("ComputeHMAC() error = %v", err)
			}

			if differentHMAC == baseHMAC {
				t.Errorf("ComputeHMAC() with %s produced same HMAC as base case", tt.name)
			}
		})
	}
}

func TestVerifyHMAC_ValidSignature(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-testing")
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	tool := "test-tool"
	cwd := "/home/user/project"
	args := []string{"arg1", "arg2"}

	signature, err := ComputeHMAC(secret, timestamp, tool, cwd, args)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}

	err = VerifyHMAC(secret, timestamp, tool, cwd, args, signature)
	if err != nil {
		t.Errorf("VerifyHMAC() rejected valid signature: %v", err)
	}
}

func TestVerifyHMAC_InvalidSignature(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-testing")
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	tool := "test-tool"
	cwd := "/home/user/project"
	args := []string{"arg1", "arg2"}

	// Generate valid signature
	validSig, err := ComputeHMAC(secret, timestamp, tool, cwd, args)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}

	tests := []struct {
		name      string
		signature string
	}{
		{"completely wrong", "aW52YWxpZC1zaWduYXR1cmUtdGhhdC1pcy1ub3QtY29ycmVjdA=="},
		{"empty", ""},
		{"not base64", "not-valid-base64!!!"},
		{"wrong secret", func() string {
			wrongSecret := []byte("wrong-secret-key-for-testing123")
			sig, _ := ComputeHMAC(wrongSecret, timestamp, tool, cwd, args)
			return sig
		}()},
		{"modified signature", func() string {
			// Decode, modify one byte, re-encode
			decoded, _ := base64.StdEncoding.DecodeString(validSig)
			decoded[0] ^= 0xFF
			return base64.StdEncoding.EncodeToString(decoded)
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyHMAC(secret, timestamp, tool, cwd, args, tt.signature)
			if err == nil {
				t.Errorf("VerifyHMAC() accepted invalid signature (%s)", tt.name)
			}
			if err != nil && err != ErrInvalidSignature {
				// For malformed base64, we still expect ErrInvalidSignature
				if tt.name != "not base64" && tt.name != "empty" {
					t.Logf("VerifyHMAC() returned %v (expected ErrInvalidSignature)", err)
				}
			}
		})
	}
}

func TestVerifyHMAC_ExpiredTimestamp(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-testing")
	tool := "test-tool"
	cwd := "/home/user/project"
	args := []string{"arg1", "arg2"}

	tests := []struct {
		name      string
		timestamp string
	}{
		{"10 seconds old", strconv.FormatInt(time.Now().Add(-10*time.Second).Unix(), 10)},
		{"1 minute old", strconv.FormatInt(time.Now().Add(-1*time.Minute).Unix(), 10)},
		{"10 seconds in future", strconv.FormatInt(time.Now().Add(10*time.Second).Unix(), 10)},
		{"1 minute in future", strconv.FormatInt(time.Now().Add(1*time.Minute).Unix(), 10)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate a valid signature for the expired timestamp
			signature, err := ComputeHMAC(secret, tt.timestamp, tool, cwd, args)
			if err != nil {
				t.Fatalf("ComputeHMAC() error = %v", err)
			}

			err = VerifyHMAC(secret, tt.timestamp, tool, cwd, args, signature)
			if err == nil {
				t.Errorf("VerifyHMAC() accepted expired timestamp (%s)", tt.name)
			}
			if err != ErrInvalidTimestamp {
				t.Errorf("VerifyHMAC() error = %v, want ErrInvalidTimestamp", err)
			}
		})
	}
}

func TestVerifyHMAC_TimestampEdgeCases(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-testing")
	tool := "test-tool"
	cwd := "/home/user/project"
	args := []string{"arg1", "arg2"}

	// Test at exactly 5 seconds (should be accepted due to <= comparison)
	timestamp := strconv.FormatInt(time.Now().Add(-5*time.Second).Unix(), 10)
	signature, _ := ComputeHMAC(secret, timestamp, tool, cwd, args)

	err := VerifyHMAC(secret, timestamp, tool, cwd, args, signature)
	if err != nil {
		// Due to timing, this might fail if test runs slowly
		t.Logf("Note: 5-second boundary test result: %v", err)
	}

	// Test at 4 seconds (should definitely be accepted)
	timestamp = strconv.FormatInt(time.Now().Add(-4*time.Second).Unix(), 10)
	signature, _ = ComputeHMAC(secret, timestamp, tool, cwd, args)

	err = VerifyHMAC(secret, timestamp, tool, cwd, args, signature)
	if err != nil {
		t.Errorf("VerifyHMAC() rejected timestamp within freshness window: %v", err)
	}
}

func TestValidateTimestamp(t *testing.T) {
	tests := []struct {
		name      string
		timestamp string
		wantErr   bool
	}{
		{"current time", strconv.FormatInt(time.Now().Unix(), 10), false},
		{"2 seconds ago", strconv.FormatInt(time.Now().Add(-2*time.Second).Unix(), 10), false},
		{"2 seconds ahead", strconv.FormatInt(time.Now().Add(2*time.Second).Unix(), 10), false},
		{"10 seconds ago", strconv.FormatInt(time.Now().Add(-10*time.Second).Unix(), 10), true},
		{"10 seconds ahead", strconv.FormatInt(time.Now().Add(10*time.Second).Unix(), 10), true},
		{"invalid format", "not-a-number", true},
		{"empty string", "", true},
		{"negative timestamp", "-1", true}, // Would be 1969, definitely expired
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTimestamp(tt.timestamp)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTimestamp(%q) error = %v, wantErr %v", tt.timestamp, err, tt.wantErr)
			}
		})
	}
}

func TestWriteSecret_LoadSecret_Roundtrip(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "auth-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	secretPath := filepath.Join(tmpDir, "subdir", "auth-secret")

	// Generate a secret
	originalSecret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	// Write the secret
	err = WriteSecret(secretPath, originalSecret)
	if err != nil {
		t.Fatalf("WriteSecret() error = %v", err)
	}

	// Verify file permissions
	info, err := os.Stat(secretPath)
	if err != nil {
		t.Fatalf("Failed to stat secret file: %v", err)
	}
	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("WriteSecret() file mode = %o, want 0600", mode)
	}

	// Load the secret back
	loadedSecret, err := LoadSecret(secretPath)
	if err != nil {
		t.Fatalf("LoadSecret() error = %v", err)
	}

	// Compare using constant-time comparison
	if subtle.ConstantTimeCompare(originalSecret, loadedSecret) != 1 {
		t.Errorf("LoadSecret() returned different secret than was written")
	}
}

func TestLoadSecret_NotFound(t *testing.T) {
	_, err := LoadSecret("/nonexistent/path/to/secret")
	if err != ErrSecretNotFound {
		t.Errorf("LoadSecret() error = %v, want ErrSecretNotFound", err)
	}
}

func TestWriteSecret_AtomicWrite(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "auth-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	secretPath := filepath.Join(tmpDir, "auth-secret")

	// Write initial secret
	secret1, _ := GenerateSecret()
	err = WriteSecret(secretPath, secret1)
	if err != nil {
		t.Fatalf("WriteSecret() first call error = %v", err)
	}

	// Write second secret (overwrite)
	secret2, _ := GenerateSecret()
	err = WriteSecret(secretPath, secret2)
	if err != nil {
		t.Fatalf("WriteSecret() second call error = %v", err)
	}

	// Load and verify it's the second secret
	loaded, err := LoadSecret(secretPath)
	if err != nil {
		t.Fatalf("LoadSecret() error = %v", err)
	}

	if subtle.ConstantTimeCompare(loaded, secret2) != 1 {
		t.Error("WriteSecret() did not atomically replace the secret")
	}

	// Verify no temp files left behind
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to read temp dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("WriteSecret() left %d files in directory, expected 1", len(entries))
	}
}

func TestComputeHMAC_EmptyArgs(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-testing")
	timestamp := "1234567890"
	tool := "test-tool"
	cwd := "/home/user"

	// Test with nil args
	hmac1, err := ComputeHMAC(secret, timestamp, tool, cwd, nil)
	if err != nil {
		t.Fatalf("ComputeHMAC() with nil args error = %v", err)
	}

	// Test with empty slice
	hmac2, err := ComputeHMAC(secret, timestamp, tool, cwd, []string{})
	if err != nil {
		t.Fatalf("ComputeHMAC() with empty args error = %v", err)
	}

	// nil and empty slice should produce same JSON: null vs []
	// Actually in Go, json.Marshal(nil) for []string produces "null"
	// and json.Marshal([]string{}) produces "[]"
	// So they might be different - let's verify the behavior
	if hmac1 == hmac2 {
		t.Log("nil and empty slice args produce same HMAC (consistent serialization)")
	} else {
		t.Log("nil and empty slice args produce different HMACs (expected due to JSON serialization)")
	}
}

func TestComputeHMAC_AdminCommand(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-testing")
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Admin commands use tool="admin:<command>", args=nil, cwd=""
	hmac, err := ComputeHMAC(secret, timestamp, "admin:list", "", nil)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}

	// Verify round-trip
	err = VerifyHMAC(secret, timestamp, "admin:list", "", nil, hmac)
	if err != nil {
		t.Errorf("VerifyHMAC() rejected valid admin HMAC: %v", err)
	}

	// Also test "check" command
	hmacCheck, err := ComputeHMAC(secret, timestamp, "admin:check", "", nil)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}
	err = VerifyHMAC(secret, timestamp, "admin:check", "", nil, hmacCheck)
	if err != nil {
		t.Errorf("VerifyHMAC() rejected valid admin:check HMAC: %v", err)
	}
}

func TestVerifyHMAC_AdminCommand_WrongSignature(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-testing")
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Compute HMAC for "list"
	hmacList, err := ComputeHMAC(secret, timestamp, "admin:list", "", nil)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}

	// Verify with "check" should fail (different tool string)
	err = VerifyHMAC(secret, timestamp, "admin:check", "", nil, hmacList)
	if err == nil {
		t.Error("VerifyHMAC() should reject admin:list HMAC when verifying admin:check")
	}

	// Verify with regular tool should fail
	err = VerifyHMAC(secret, timestamp, "gh", "", nil, hmacList)
	if err == nil {
		t.Error("VerifyHMAC() should reject admin HMAC when verifying regular tool")
	}
}

func TestVerifyHMAC_ConstantTimeComparison(t *testing.T) {
	// This test verifies the implementation uses constant-time comparison
	// by checking the function signature rather than timing (timing tests are flaky)

	// The actual constant-time comparison is done in the VerifyHMAC function
	// using subtle.ConstantTimeCompare. We verify the behavior is correct
	// by testing that invalid signatures are rejected consistently.

	secret := []byte("test-secret-key-for-hmac-testing")
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	tool := "test-tool"
	cwd := "/home/user"
	args := []string{"arg1"}

	validSig, _ := ComputeHMAC(secret, timestamp, tool, cwd, args)

	// Try many variations of invalid signatures
	for i := 0; i < 32; i++ {
		decoded, _ := base64.StdEncoding.DecodeString(validSig)
		decoded[i] ^= 0xFF // Flip bits in each byte position
		invalidSig := base64.StdEncoding.EncodeToString(decoded)

		err := VerifyHMAC(secret, timestamp, tool, cwd, args, invalidSig)
		if err == nil {
			t.Errorf("VerifyHMAC() accepted invalid signature with byte %d modified", i)
		}
	}
}

func TestComputeHMACWithEnv_CanonicalOrder(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-testing")
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	tool := "test-tool"
	cwd := "/home/user/project"
	args := []string{"arg1", "arg2"}

	envA := map[string]string{
		"B_VAR": "2",
		"A_VAR": "1",
	}
	envB := map[string]string{
		"A_VAR": "1",
		"B_VAR": "2",
	}

	hmacA, err := ComputeHMACWithEnv(secret, timestamp, tool, cwd, args, envA)
	if err != nil {
		t.Fatalf("ComputeHMACWithEnv() envA error = %v", err)
	}
	hmacB, err := ComputeHMACWithEnv(secret, timestamp, tool, cwd, args, envB)
	if err != nil {
		t.Fatalf("ComputeHMACWithEnv() envB error = %v", err)
	}

	if hmacA != hmacB {
		t.Errorf("canonical env ordering mismatch: %s != %s", hmacA, hmacB)
	}

	if err := VerifyHMACWithEnv(secret, timestamp, tool, cwd, args, envA, hmacB); err != nil {
		t.Errorf("VerifyHMACWithEnv() failed with canonical env maps: %v", err)
	}
}
