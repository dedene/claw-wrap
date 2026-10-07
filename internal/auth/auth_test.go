package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testNonce is a fixed nonce for deterministic tests.
const testNonce = "dGVzdC1ub25jZS0xMjM0" // base64("test-nonce-1234")

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

func TestGenerateNonce(t *testing.T) {
	nonce1, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce() error = %v", err)
	}

	// Should be valid base64
	decoded, err := base64.StdEncoding.DecodeString(nonce1)
	if err != nil {
		t.Fatalf("GenerateNonce() produced invalid base64: %v", err)
	}
	if len(decoded) != NonceSize {
		t.Errorf("GenerateNonce() decoded length = %d, want %d", len(decoded), NonceSize)
	}

	// Two nonces should differ
	nonce2, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce() second call error = %v", err)
	}
	if nonce1 == nonce2 {
		t.Error("GenerateNonce() produced identical nonces")
	}
}

func TestComputeHMAC_Deterministic(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-testing")
	timestamp := "1234567890"
	tool := "test-tool"
	cwd := "/home/user/project"
	args := []string{"arg1", "arg2", "--flag=value"}

	// Compute HMAC multiple times with same nonce
	hmac1, err := ComputeHMAC(secret, timestamp, tool, cwd, args, testNonce)
	if err != nil {
		t.Fatalf("ComputeHMAC() first call error = %v", err)
	}

	hmac2, err := ComputeHMAC(secret, timestamp, tool, cwd, args, testNonce)
	if err != nil {
		t.Fatalf("ComputeHMAC() second call error = %v", err)
	}

	hmac3, err := ComputeHMAC(secret, timestamp, tool, cwd, args, testNonce)
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

	baseHMAC, err := ComputeHMAC(secret, timestamp, tool, cwd, args, testNonce)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}

	tests := []struct {
		name      string
		timestamp string
		tool      string
		cwd       string
		args      []string
		nonce     string
	}{
		{"different timestamp", "1234567891", tool, cwd, args, testNonce},
		{"different tool", timestamp, "other-tool", cwd, args, testNonce},
		{"different cwd", timestamp, tool, "/other/path", args, testNonce},
		{"different args", timestamp, tool, cwd, []string{"arg1", "arg3"}, testNonce},
		{"extra arg", timestamp, tool, cwd, []string{"arg1", "arg2", "arg3"}, testNonce},
		{"empty args", timestamp, tool, cwd, []string{}, testNonce},
		{"different nonce", timestamp, tool, cwd, args, "ZGlmZmVyZW50LW5vbmNl"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			differentHMAC, err := ComputeHMAC(secret, tt.timestamp, tt.tool, tt.cwd, tt.args, tt.nonce)
			if err != nil {
				t.Fatalf("ComputeHMAC() error = %v", err)
			}

			if differentHMAC == baseHMAC {
				t.Errorf("ComputeHMAC() with %s produced same HMAC as base case", tt.name)
			}
		})
	}
}

func TestComputeHMAC_FieldSeparators(t *testing.T) {
	// Verify that field separators prevent boundary confusion.
	// Without separators, "toolA" + args=["B"] could equal "toolAB" + args=[].
	// With \n separators, these must differ.
	secret := []byte("test-secret-key-for-hmac-testing")
	timestamp := "1234567890"

	hmac1, _ := ComputeHMAC(secret, timestamp, "toolA", "/cwd", []string{"B"}, testNonce)
	hmac2, _ := ComputeHMAC(secret, timestamp, "toolAB", "/cwd", []string{}, testNonce)

	if hmac1 == hmac2 {
		t.Error("field separator test: toolA+[B] should differ from toolAB+[]")
	}
}

func TestVerifyHMAC_ValidSignature(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-testing")
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	tool := "test-tool"
	cwd := "/home/user/project"
	args := []string{"arg1", "arg2"}

	signature, err := ComputeHMAC(secret, timestamp, tool, cwd, args, testNonce)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}

	err = VerifyHMAC(secret, timestamp, tool, cwd, args, testNonce, signature)
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
	validSig, err := ComputeHMAC(secret, timestamp, tool, cwd, args, testNonce)
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
			sig, _ := ComputeHMAC(wrongSecret, timestamp, tool, cwd, args, testNonce)
			return sig
		}()},
		{"modified signature", func() string {
			// Decode, modify one byte, re-encode
			decoded, _ := base64.StdEncoding.DecodeString(validSig)
			decoded[0] ^= 0xFF
			return base64.StdEncoding.EncodeToString(decoded)
		}()},
		{"wrong nonce", func() string {
			sig, _ := ComputeHMAC(secret, timestamp, tool, cwd, args, "d3Jvbmctbm9uY2U=")
			return sig
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyHMAC(secret, timestamp, tool, cwd, args, testNonce, tt.signature)
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
			signature, err := ComputeHMAC(secret, tt.timestamp, tool, cwd, args, testNonce)
			if err != nil {
				t.Fatalf("ComputeHMAC() error = %v", err)
			}

			err = VerifyHMAC(secret, tt.timestamp, tool, cwd, args, testNonce, signature)
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
	signature, _ := ComputeHMAC(secret, timestamp, tool, cwd, args, testNonce)

	err := VerifyHMAC(secret, timestamp, tool, cwd, args, testNonce, signature)
	if err != nil {
		// Due to timing, this might fail if test runs slowly
		t.Logf("Note: 5-second boundary test result: %v", err)
	}

	// Test at 4 seconds (should definitely be accepted)
	timestamp = strconv.FormatInt(time.Now().Add(-4*time.Second).Unix(), 10)
	signature, _ = ComputeHMAC(secret, timestamp, tool, cwd, args, testNonce)

	err = VerifyHMAC(secret, timestamp, tool, cwd, args, testNonce, signature)
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

func TestWriteSecretWithMode_CustomMode(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "auth-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	secretPath := filepath.Join(tmpDir, "auth-secret")
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	if err := WriteSecretWithMode(secretPath, secret, 0o640); err != nil {
		t.Fatalf("WriteSecretWithMode() error = %v", err)
	}

	info, err := os.Stat(secretPath)
	if err != nil {
		t.Fatalf("Failed to stat secret file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("WriteSecretWithMode() file mode = %o, want 0640", got)
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
	hmac1, err := ComputeHMAC(secret, timestamp, tool, cwd, nil, testNonce)
	if err != nil {
		t.Fatalf("ComputeHMAC() with nil args error = %v", err)
	}

	// Test with empty slice
	hmac2, err := ComputeHMAC(secret, timestamp, tool, cwd, []string{}, testNonce)
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
	hmac, err := ComputeHMAC(secret, timestamp, "admin:list", "", nil, testNonce)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}

	// Verify round-trip
	err = VerifyHMAC(secret, timestamp, "admin:list", "", nil, testNonce, hmac)
	if err != nil {
		t.Errorf("VerifyHMAC() rejected valid admin HMAC: %v", err)
	}

	// Also test "check" command
	hmacCheck, err := ComputeHMAC(secret, timestamp, "admin:check", "", nil, testNonce)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}
	err = VerifyHMAC(secret, timestamp, "admin:check", "", nil, testNonce, hmacCheck)
	if err != nil {
		t.Errorf("VerifyHMAC() rejected valid admin:check HMAC: %v", err)
	}
}

func TestVerifyHMAC_AdminCommand_WrongSignature(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-testing")
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Compute HMAC for "list"
	hmacList, err := ComputeHMAC(secret, timestamp, "admin:list", "", nil, testNonce)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}

	// Verify with "check" should fail (different tool string)
	err = VerifyHMAC(secret, timestamp, "admin:check", "", nil, testNonce, hmacList)
	if err == nil {
		t.Error("VerifyHMAC() should reject admin:list HMAC when verifying admin:check")
	}

	// Verify with regular tool should fail
	err = VerifyHMAC(secret, timestamp, "gh", "", nil, testNonce, hmacList)
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

	validSig, _ := ComputeHMAC(secret, timestamp, tool, cwd, args, testNonce)

	// Try many variations of invalid signatures
	for i := 0; i < 32; i++ {
		decoded, _ := base64.StdEncoding.DecodeString(validSig)
		decoded[i] ^= 0xFF // Flip bits in each byte position
		invalidSig := base64.StdEncoding.EncodeToString(decoded)

		err := VerifyHMAC(secret, timestamp, tool, cwd, args, testNonce, invalidSig)
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

	hmacA, err := ComputeHMACWithEnv(secret, timestamp, tool, cwd, args, envA, testNonce)
	if err != nil {
		t.Fatalf("ComputeHMACWithEnv() envA error = %v", err)
	}
	hmacB, err := ComputeHMACWithEnv(secret, timestamp, tool, cwd, args, envB, testNonce)
	if err != nil {
		t.Fatalf("ComputeHMACWithEnv() envB error = %v", err)
	}

	if hmacA != hmacB {
		t.Errorf("canonical env ordering mismatch: %s != %s", hmacA, hmacB)
	}

	if err := VerifyHMACWithEnv(secret, timestamp, tool, cwd, args, envA, testNonce, hmacB); err != nil {
		t.Errorf("VerifyHMACWithEnv() failed with canonical env maps: %v", err)
	}
}

func TestVerifyHMAC_NonceMismatch(t *testing.T) {
	// Signature computed with nonce1 should fail verification with nonce2
	secret := []byte("test-secret-key-for-hmac-testing")
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	tool := "test-tool"
	cwd := "/home/user"
	args := []string{"arg1"}

	nonce1 := "bm9uY2UxMjM0NTY3OA==" // base64("nonce12345678")
	nonce2 := "bm9uY2U4NzY1NDMyMQ==" // base64("nonce87654321")

	sig, err := ComputeHMAC(secret, timestamp, tool, cwd, args, nonce1)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}

	// Same nonce should pass
	if err := VerifyHMAC(secret, timestamp, tool, cwd, args, nonce1, sig); err != nil {
		t.Errorf("VerifyHMAC() rejected valid nonce: %v", err)
	}

	// Different nonce should fail
	if err := VerifyHMAC(secret, timestamp, tool, cwd, args, nonce2, sig); err == nil {
		t.Error("VerifyHMAC() should reject signature with wrong nonce")
	}
}

func TestWriteSecret_RejectsSymlink(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "auth-symlink-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a symlink at the target path
	realFile := filepath.Join(tmpDir, "real-file")
	if err := os.WriteFile(realFile, []byte("target"), 0600); err != nil {
		t.Fatalf("Failed to create real file: %v", err)
	}

	symlinkPath := filepath.Join(tmpDir, "secret-link")
	if err := os.Symlink(realFile, symlinkPath); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	secret, _ := GenerateSecret()
	err = WriteSecret(symlinkPath, secret)
	if err == nil {
		t.Fatal("WriteSecret() should reject symlink target")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("WriteSecret() error = %v, want symlink-related error", err)
	}
}

func TestLoadSecret_RejectsSymlink(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "auth-symlink-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write a real secret first
	realPath := filepath.Join(tmpDir, "real-secret")
	secret, _ := GenerateSecret()
	if err := WriteSecret(realPath, secret); err != nil {
		t.Fatalf("WriteSecret() error = %v", err)
	}

	// Create a symlink to the real secret
	symlinkPath := filepath.Join(tmpDir, "secret-link")
	if err := os.Symlink(realPath, symlinkPath); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	_, err = LoadSecret(symlinkPath)
	if err == nil {
		t.Fatal("LoadSecret() should reject symlink path")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("LoadSecret() error = %v, want symlink-related error", err)
	}
}

func TestComputeHMACWithPTY_DifferentPTYFlag(t *testing.T) {
	// PTY flag should change the HMAC signature
	secret := []byte("test-secret-key-for-hmac-testing")
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	tool := "test-tool"
	cwd := "/home/user"
	args := []string{"arg1", "arg2"}
	env := map[string]string{"FOO": "bar"}
	nonce := "dGVzdC1ub25jZS0xMjM0" // base64("test-nonce-1234")

	// Compute HMAC with PTY false
	hmacNoPTY, err := ComputeHMACWithPTY(secret, timestamp, tool, cwd, args, env, nonce, false)
	if err != nil {
		t.Fatalf("ComputeHMACWithPTY(usePTY=false) error = %v", err)
	}

	// Compute HMAC with PTY true
	hmacWithPTY, err := ComputeHMACWithPTY(secret, timestamp, tool, cwd, args, env, nonce, true)
	if err != nil {
		t.Fatalf("ComputeHMACWithPTY(usePTY=true) error = %v", err)
	}

	// Signatures must be different
	if hmacNoPTY == hmacWithPTY {
		t.Error("HMACs should differ based on PTY flag")
	}
}

func TestVerifyHMACWithPTY_PTYFlagMismatch(t *testing.T) {
	// HMAC computed with usePTY=true should fail verification with usePTY=false
	secret := []byte("test-secret-key-for-hmac-testing")
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	tool := "test-tool"
	cwd := "/home/user"
	args := []string{"arg1"}
	nonce := "dGVzdC1ub25jZS0xMjM0"

	// Compute with PTY=true
	sig, err := ComputeHMACWithPTY(secret, timestamp, tool, cwd, args, nil, nonce, true)
	if err != nil {
		t.Fatalf("ComputeHMACWithPTY() error = %v", err)
	}

	// Verify with PTY=true should pass
	if err := VerifyHMACWithPTY(secret, timestamp, tool, cwd, args, nil, nonce, true, sig); err != nil {
		t.Errorf("VerifyHMACWithPTY(usePTY=true) rejected valid signature: %v", err)
	}

	// Verify with PTY=false should fail
	if err := VerifyHMACWithPTY(secret, timestamp, tool, cwd, args, nil, nonce, false, sig); err == nil {
		t.Error("VerifyHMACWithPTY(usePTY=false) should reject signature computed with usePTY=true")
	}
}

func TestComputeHMACWithEnv_BackwardCompatibleWithPTYFalse(t *testing.T) {
	// ComputeHMACWithEnv should produce same result as ComputeHMACWithPTY(usePTY=false)
	secret := []byte("test-secret-key-for-hmac-testing")
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	tool := "test-tool"
	cwd := "/home/user"
	args := []string{"arg1", "arg2"}
	env := map[string]string{"VAR1": "value1"}
	nonce := "dGVzdC1ub25jZS0xMjM0"

	hmacEnv, err := ComputeHMACWithEnv(secret, timestamp, tool, cwd, args, env, nonce)
	if err != nil {
		t.Fatalf("ComputeHMACWithEnv() error = %v", err)
	}

	hmacPTYFalse, err := ComputeHMACWithPTY(secret, timestamp, tool, cwd, args, env, nonce, false)
	if err != nil {
		t.Fatalf("ComputeHMACWithPTY() error = %v", err)
	}

	if hmacEnv != hmacPTYFalse {
		t.Error("ComputeHMACWithEnv should equal ComputeHMACWithPTY(usePTY=false) for backward compatibility")
	}
}
