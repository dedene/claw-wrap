package credentials

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const vaultCommandTimeout = 30 * time.Second

// vaultConfig holds Vault CLI environment overrides.
// Protected by vaultMu for concurrent access.
var (
	vaultMu         sync.RWMutex
	vaultAddr       string
	vaultSkipVerify bool
	vaultCACert     string
	vaultNamespace  string
	vaultTokenFile  string
)

// SetVaultAddr configures the Vault server address.
func SetVaultAddr(addr string) {
	vaultMu.Lock()
	defer vaultMu.Unlock()
	vaultAddr = addr
}

// SetVaultSkipVerify configures TLS verification skip.
func SetVaultSkipVerify(skip bool) {
	vaultMu.Lock()
	defer vaultMu.Unlock()
	vaultSkipVerify = skip
}

// SetVaultCACert configures the CA cert path.
func SetVaultCACert(path string) {
	vaultMu.Lock()
	defer vaultMu.Unlock()
	vaultCACert = path
}

// SetVaultNamespace configures the Vault namespace (enterprise).
func SetVaultNamespace(ns string) {
	vaultMu.Lock()
	defer vaultMu.Unlock()
	vaultNamespace = ns
}

// SetVaultTokenFile configures a custom token file path.
func SetVaultTokenFile(path string) {
	vaultMu.Lock()
	defer vaultMu.Unlock()
	vaultTokenFile = path
}

func getVaultSettings() (addr string, skipVerify bool, caCert, namespace, tokenFile string) {
	vaultMu.RLock()
	defer vaultMu.RUnlock()
	return vaultAddr, vaultSkipVerify, vaultCACert, vaultNamespace, vaultTokenFile
}

// fetchFromVault retrieves a credential from HashiCorp Vault using the vault CLI.
func fetchFromVault(ctx context.Context, parsed *ParsedSource, vaultBinaryOverride string) (string, error) {
	vaultBinary, err := resolveVaultBinary(vaultBinaryOverride)
	if err != nil {
		return "", fmt.Errorf("vault CLI not found in trusted locations")
	}

	ctx, cancel := context.WithTimeout(ctx, vaultCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, vaultBinary, "kv", "get", "-format=json", parsed.Path)
	cmd.Env = vaultEnv()

	output, err := cmd.Output()
	if err != nil {
		log.Printf("[DEBUG] vault kv get failed: %v", err)
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
			log.Printf("[DEBUG] vault stderr: %s", string(exitErr.Stderr))
		}
		return "", fmt.Errorf("vault read failed")
	}

	result, err := extractVaultData(output)
	if err != nil {
		return "", err
	}

	if parsed.HasJQ() {
		return ApplyJQ(ctx, []byte(result), parsed.JQExpr)
	}

	return result, nil
}

// extractVaultData parses the vault kv get JSON response.
// KV-v2 format: {"data":{"data":{...},"metadata":{...}}}
// KV-v1 format: {"data":{...}}
func extractVaultData(output []byte) (string, error) {
	var response struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(output, &response); err != nil {
		log.Printf("[DEBUG] vault response parse failed: %v", err)
		return "", fmt.Errorf("vault read failed")
	}

	// Try KV-v2: look for nested .data.data AND .data.metadata.
	// Both must be present to confirm KV-v2 — a KV-v1 secret with a key
	// named "data" would otherwise be misidentified.
	var kvV2 struct {
		Data     json.RawMessage `json:"data"`
		Metadata json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(response.Data, &kvV2); err == nil && kvV2.Data != nil && kvV2.Metadata != nil {
		return strings.TrimSpace(string(kvV2.Data)), nil
	}

	// Fall back to KV-v1: .data is the secret itself
	return strings.TrimSpace(string(response.Data)), nil
}

func resolveVaultBinary(vaultBinaryOverride string) (string, error) {
	if vaultBinaryOverride != "" {
		return vaultBinaryOverride, nil
	}
	return findTrustedBinaryFunc("vault")
}

// vaultEnv returns environment variables for the vault CLI.
func vaultEnv() []string {
	env := os.Environ()
	addr, skipVerify, caCert, namespace, tokenFile := getVaultSettings()

	if addr != "" {
		env = append(env, "VAULT_ADDR="+addr)
	}
	if skipVerify {
		env = append(env, "VAULT_SKIP_VERIFY=1")
	}
	if caCert != "" {
		env = append(env, "VAULT_CACERT="+caCert)
	}
	if namespace != "" {
		env = append(env, "VAULT_NAMESPACE="+namespace)
	}
	if tokenFile != "" {
		env = append(env, "VAULT_TOKEN_FILE="+tokenFile)
	}

	return env
}
