package credentials

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func writeMockVaultScript(t *testing.T, dir string, output string, exitCode int) string {
	t.Helper()
	scriptPath := filepath.Join(dir, "vault")
	var script string
	if exitCode == 0 {
		script = "#!/bin/sh\nprintf '%s' '" + output + "'\n"
	} else {
		script = "#!/bin/sh\necho 'Error: permission denied' >&2\nexit " + strconv.Itoa(exitCode) + "\n"
	}
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatalf("write mock script: %v", err)
	}
	return scriptPath
}

func TestResolveVaultBinary(t *testing.T) {
	t.Run("override returns override", func(t *testing.T) {
		got, err := resolveVaultBinary("/custom/vault")
		if err != nil {
			t.Errorf("resolveVaultBinary() error = %v", err)
		}
		if got != "/custom/vault" {
			t.Errorf("resolveVaultBinary() = %q, want %q", got, "/custom/vault")
		}
	})

	t.Run("empty falls through to findTrustedBinary", func(t *testing.T) {
		orig := findTrustedBinaryFunc
		findTrustedBinaryFunc = func(name string) (string, error) {
			if name != "vault" {
				t.Errorf("findTrustedBinaryFunc called with %q, want %q", name, "vault")
			}
			return "/usr/bin/vault", nil
		}
		defer func() { findTrustedBinaryFunc = orig }()

		got, err := resolveVaultBinary("")
		if err != nil {
			t.Errorf("resolveVaultBinary() error = %v", err)
		}
		if got != "/usr/bin/vault" {
			t.Errorf("resolveVaultBinary() = %q, want %q", got, "/usr/bin/vault")
		}
	})
}

func TestFetchFromVault_NoBinary(t *testing.T) {
	orig := findTrustedBinaryFunc
	findTrustedBinaryFunc = func(name string) (string, error) {
		return "", os.ErrNotExist
	}
	defer func() { findTrustedBinaryFunc = orig }()

	parsed := &ParsedSource{
		Backend: BackendVault,
		Path:    "secret/myapp/key",
	}

	_, err := fetchFromVault(context.Background(), parsed, "")
	if err == nil {
		t.Error("fetchFromVault() should error when vault binary not found")
	}
}

func TestFetchFromVault_Success(t *testing.T) {
	tmpDir := t.TempDir()
	kvV2Response := `{"data":{"data":{"password":"s3cret","username":"admin"},"metadata":{"version":1}}}`
	scriptPath := writeMockVaultScript(t, tmpDir, kvV2Response, 0)

	parsed := &ParsedSource{
		Backend:  BackendVault,
		Path:     "secret/myapp/creds",
		Original: "vault:secret/myapp/creds",
	}

	result, err := fetchFromVault(context.Background(), parsed, scriptPath)
	if err != nil {
		t.Fatalf("fetchFromVault() error = %v", err)
	}

	// Should return the inner .data.data JSON
	want := `{"password":"s3cret","username":"admin"}`
	if result != want {
		t.Errorf("result = %q, want %q", result, want)
	}
}

func TestFetchFromVault_WithJQ(t *testing.T) {
	tmpDir := t.TempDir()
	kvV2Response := `{"data":{"data":{"password":"s3cret","username":"admin"},"metadata":{"version":1}}}`
	scriptPath := writeMockVaultScript(t, tmpDir, kvV2Response, 0)

	parsed := &ParsedSource{
		Backend:  BackendVault,
		Path:     "secret/myapp/creds",
		JQExpr:   ".password",
		Original: "vault:secret/myapp/creds | .password",
	}

	result, err := fetchFromVault(context.Background(), parsed, scriptPath)
	if err != nil {
		t.Fatalf("fetchFromVault() error = %v", err)
	}

	if result != "s3cret" {
		t.Errorf("result = %q, want %q", result, "s3cret")
	}
}

func TestFetchFromVault_KVv1Fallback(t *testing.T) {
	tmpDir := t.TempDir()
	// KV-v1 response has data directly at .data (no nested .data.data)
	kvV1Response := `{"data":{"password":"v1secret","username":"admin"}}`
	scriptPath := writeMockVaultScript(t, tmpDir, kvV1Response, 0)

	parsed := &ParsedSource{
		Backend:  BackendVault,
		Path:     "secret/myapp/creds",
		JQExpr:   ".password",
		Original: "vault:secret/myapp/creds | .password",
	}

	result, err := fetchFromVault(context.Background(), parsed, scriptPath)
	if err != nil {
		t.Fatalf("fetchFromVault() error = %v", err)
	}

	if result != "v1secret" {
		t.Errorf("result = %q, want %q", result, "v1secret")
	}
}

func TestFetchFromVault_FailingBinary(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := writeMockVaultScript(t, tmpDir, "", 2)

	parsed := &ParsedSource{
		Backend:  BackendVault,
		Path:     "secret/myapp/creds",
		Original: "vault:secret/myapp/creds",
	}

	_, err := fetchFromVault(context.Background(), parsed, scriptPath)
	if err == nil {
		t.Error("fetchFromVault() should error on non-zero exit")
	}
	if err.Error() != "vault read failed" {
		t.Errorf("error = %q, want generic %q", err.Error(), "vault read failed")
	}
}

func TestFetchFromVault_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := writeMockVaultScript(t, tmpDir, "not-json", 0)

	parsed := &ParsedSource{
		Backend:  BackendVault,
		Path:     "secret/myapp/creds",
		Original: "vault:secret/myapp/creds",
	}

	_, err := fetchFromVault(context.Background(), parsed, scriptPath)
	if err == nil {
		t.Error("fetchFromVault() should error on invalid JSON")
	}
	if err.Error() != "vault read failed" {
		t.Errorf("error = %q, want generic %q", err.Error(), "vault read failed")
	}
}

func boolPtr(v bool) *bool { return &v }

func TestVaultEnv(t *testing.T) {
	// Save originals
	origAddr, origSkip, origCACert, origNs, origTokenFile := getVaultSettings()
	defer func() {
		SetVaultAddr(origAddr)
		SetVaultSkipVerify(origSkip)
		SetVaultCACert(origCACert)
		SetVaultNamespace(origNs)
		SetVaultTokenFile(origTokenFile)
	}()

	SetVaultAddr("https://vault.example.com:8200")
	SetVaultSkipVerify(boolPtr(true))
	SetVaultCACert("/etc/vault/ca.pem")
	SetVaultNamespace("team-a")
	SetVaultTokenFile("/home/bot/.vault-token")

	env := vaultEnv()

	checks := map[string]string{
		"VAULT_ADDR":        "https://vault.example.com:8200",
		"VAULT_SKIP_VERIFY": "1",
		"VAULT_CACERT":      "/etc/vault/ca.pem",
		"VAULT_NAMESPACE":   "team-a",
		"VAULT_TOKEN_FILE":  "/home/bot/.vault-token",
	}

	for key, want := range checks {
		found := false
		for _, e := range env {
			if e == key+"="+want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("vaultEnv() missing %s=%s", key, want)
		}
	}
}

func TestVaultEnv_ExplicitFalse(t *testing.T) {
	origAddr, origSkip, origCACert, origNs, origTokenFile := getVaultSettings()
	defer func() {
		SetVaultAddr(origAddr)
		SetVaultSkipVerify(origSkip)
		SetVaultCACert(origCACert)
		SetVaultNamespace(origNs)
		SetVaultTokenFile(origTokenFile)
	}()

	SetVaultSkipVerify(boolPtr(false))

	env := vaultEnv()
	found := false
	for _, e := range env {
		if e == "VAULT_SKIP_VERIFY=0" {
			found = true
			break
		}
	}
	if !found {
		t.Error("vaultEnv() should set VAULT_SKIP_VERIFY=0 when explicitly false")
	}
}

func TestVaultEnv_NilSkipVerify(t *testing.T) {
	origAddr, origSkip, origCACert, origNs, origTokenFile := getVaultSettings()
	defer func() {
		SetVaultAddr(origAddr)
		SetVaultSkipVerify(origSkip)
		SetVaultCACert(origCACert)
		SetVaultNamespace(origNs)
		SetVaultTokenFile(origTokenFile)
	}()

	SetVaultAddr("")
	SetVaultSkipVerify(nil)
	SetVaultCACert("")
	SetVaultNamespace("")
	SetVaultTokenFile("")

	env := vaultEnv()

	// With nil skip and empty strings, vaultEnv() should not add any VAULT_* keys.
	// Ambient env may already have them, but vaultEnv() shouldn't strip or add.
	baseEnv := os.Environ()
	baseCount := make(map[string]int)
	vaultKeys := []string{"VAULT_ADDR", "VAULT_SKIP_VERIFY", "VAULT_CACERT", "VAULT_NAMESPACE", "VAULT_TOKEN_FILE"}
	for _, e := range baseEnv {
		for _, key := range vaultKeys {
			if len(e) > len(key) && e[:len(key)+1] == key+"=" {
				baseCount[key]++
			}
		}
	}

	envCount := make(map[string]int)
	for _, e := range env {
		for _, key := range vaultKeys {
			if len(e) > len(key) && e[:len(key)+1] == key+"=" {
				envCount[key]++
			}
		}
	}

	for _, key := range vaultKeys {
		if envCount[key] != baseCount[key] {
			t.Errorf("vaultEnv() should not change %s count when unconfigured (base=%d, got=%d)", key, baseCount[key], envCount[key])
		}
	}
}

func TestVaultEnv_OverridesAmbient(t *testing.T) {
	origAddr, origSkip, origCACert, origNs, origTokenFile := getVaultSettings()
	defer func() {
		SetVaultAddr(origAddr)
		SetVaultSkipVerify(origSkip)
		SetVaultCACert(origCACert)
		SetVaultNamespace(origNs)
		SetVaultTokenFile(origTokenFile)
	}()

	// Set ambient VAULT_ADDR, then override via config
	t.Setenv("VAULT_ADDR", "https://old.example.com")
	SetVaultAddr("https://new.example.com")
	SetVaultSkipVerify(nil)
	SetVaultCACert("")
	SetVaultNamespace("")
	SetVaultTokenFile("")

	env := vaultEnv()

	// Should have exactly one VAULT_ADDR with the new value
	count := 0
	for _, e := range env {
		if e == "VAULT_ADDR=https://new.example.com" {
			count++
		}
		if e == "VAULT_ADDR=https://old.example.com" {
			t.Error("vaultEnv() should have stripped ambient VAULT_ADDR")
		}
	}
	if count != 1 {
		t.Errorf("expected 1 VAULT_ADDR entry, got %d", count)
	}
}

func TestExtractVaultData_KVv2(t *testing.T) {
	input := []byte(`{"data":{"data":{"password":"s3cret"},"metadata":{"version":1}}}`)
	result, err := extractVaultData(input)
	if err != nil {
		t.Fatalf("extractVaultData() error = %v", err)
	}
	if result != `{"password":"s3cret"}` {
		t.Errorf("result = %q, want %q", result, `{"password":"s3cret"}`)
	}
}

func TestExtractVaultData_KVv1(t *testing.T) {
	input := []byte(`{"data":{"password":"v1secret"}}`)
	result, err := extractVaultData(input)
	if err != nil {
		t.Fatalf("extractVaultData() error = %v", err)
	}
	if result != `{"password":"v1secret"}` {
		t.Errorf("result = %q, want %q", result, `{"password":"v1secret"}`)
	}
}

func TestExtractVaultData_KVv1WithDataKey(t *testing.T) {
	// KV-v1 secret that happens to have a key named "data" — must NOT be
	// misidentified as KV-v2. The fix checks for both "data" AND "metadata".
	input := []byte(`{"data":{"data":"some-value","other":"field"}}`)
	result, err := extractVaultData(input)
	if err != nil {
		t.Fatalf("extractVaultData() error = %v", err)
	}
	// Should return the full .data object (KV-v1 fallback), not just "some-value"
	want := `{"data":"some-value","other":"field"}`
	if result != want {
		t.Errorf("result = %q, want %q", result, want)
	}
}

func TestExtractVaultData_InvalidJSON(t *testing.T) {
	_, err := extractVaultData([]byte("not-json"))
	if err == nil {
		t.Error("extractVaultData() should error on invalid JSON")
	}
}
