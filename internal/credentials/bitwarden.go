package credentials

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Bitwarden credential sources.
const (
	bwClientIDCredentialName     = "bw-client-id"
	bwClientSecretCredentialName = "bw-client-secret"
	bwPasswordCredentialName     = "bw-master-password"
	bwClientIDEnvVar             = "BW_CLIENTID"
	bwClientSecretEnvVar         = "BW_CLIENTSECRET"
	bwPasswordEnvVar             = "BW_PASSWORD"
)

// Bitwarden timeouts and retry settings.
const (
	bwCommandTimeout = 30 * time.Second
)

// bwSession holds the current Bitwarden session state.
// Protected by bwMutex for thread safety.
type bwSession struct {
	token    string
	dataDir  string
	binary   string
	loggedIn bool
}

var (
	bwMutex       sync.Mutex
	bwCurrent     *bwSession
	bwRetryDelays = []time.Duration{0, 1 * time.Second, 3 * time.Second}
	bwSleep       = sleepWithContext
	bwGetItemFunc = bwGetItem
	bwEnsureFunc  = ensureBWSession
)

// bwStatus represents the status returned by `bw status`.
type bwStatus struct {
	Status    string `json:"status"`
	UserEmail string `json:"userEmail"`
}

// fetchFromBitwarden retrieves a credential from Bitwarden.
func fetchFromBitwarden(ctx context.Context, parsed *ParsedSource, bwBinaryOverride string) (string, error) {
	bwBinary, err := resolveBWBinary(bwBinaryOverride)
	if err != nil {
		return "", fmt.Errorf("bitwarden CLI not found in trusted locations")
	}

	bwMutex.Lock()
	defer bwMutex.Unlock()

	if bwCurrent != nil {
		bwCurrent.binary = bwBinary
	}

	// Ensure session is valid
	if err := bwEnsureFunc(ctx, bwBinary); err != nil {
		return "", fmt.Errorf("bitwarden session failed")
	}

	for attempt := 0; attempt < len(bwRetryDelays); attempt++ {
		if err := bwSleep(ctx, bwRetryDelays[attempt]); err != nil {
			return "", fmt.Errorf("bitwarden fetch failed")
		}

		result, err := bwGetItemFunc(ctx, bwCurrent, parsed.Path)
		if err == nil {
			if parsed.HasJQ() {
				return ApplyJQ(ctx, []byte(result), parsed.JQExpr)
			}
			return result, nil
		}

		// Check if we need to re-authenticate
		if isAuthError(err) {
			bwCurrent.loggedIn = false
			bwCurrent.token = ""
			if err := bwEnsureFunc(ctx, bwBinary); err != nil {
				return "", fmt.Errorf("bitwarden re-auth failed")
			}
			continue
		}

		// For other errors, don't retry
		break
	}

	return "", fmt.Errorf("bitwarden fetch failed")
}

func resolveBWBinary(bwBinaryOverride string) (string, error) {
	if bwBinaryOverride != "" {
		return bwBinaryOverride, nil
	}
	return findTrustedBinaryFunc("bw")
}

// ensureBWSession ensures we have a valid Bitwarden session.
func ensureBWSession(ctx context.Context, bwBinary string) error {
	// Initialize session if needed
	if bwCurrent == nil {
		dataDir, err := os.MkdirTemp("", "claw-wrap-bw-*")
		if err != nil {
			return fmt.Errorf("creating bw data dir: %w", err)
		}
		bwCurrent = &bwSession{dataDir: dataDir, binary: bwBinary}
	} else if bwCurrent.binary == "" {
		bwCurrent.binary = bwBinary
	}

	// Check current status
	status, err := bwCheckStatus(ctx, bwCurrent)
	if err != nil {
		// Status check failed, try fresh login
		status = &bwStatus{Status: "unauthenticated"}
	}

	switch status.Status {
	case "unlocked":
		return nil // Ready to use

	case "locked":
		// Need to unlock
		return bwUnlock(ctx, bwCurrent)

	case "unauthenticated":
		// Need full login + unlock
		if err := bwLogin(ctx, bwCurrent); err != nil {
			return err
		}
		return bwUnlock(ctx, bwCurrent)

	default:
		return fmt.Errorf("unknown bitwarden status: %s", status.Status)
	}
}

// bwCheckStatus runs `bw status` to check session state.
func bwCheckStatus(ctx context.Context, session *bwSession) (*bwStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, bwCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, session.binary, "status")
	cmd.Env = bwEnv(session)

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var status bwStatus
	if err := json.Unmarshal(output, &status); err != nil {
		return nil, err
	}

	return &status, nil
}

// bwLogin performs API key login.
func bwLogin(ctx context.Context, session *bwSession) error {
	clientID, err := getBWCredential(bwClientIDCredentialName, bwClientIDEnvVar)
	if err != nil {
		return fmt.Errorf("bitwarden client ID not configured")
	}

	clientSecret, err := getBWCredential(bwClientSecretCredentialName, bwClientSecretEnvVar)
	if err != nil {
		return fmt.Errorf("bitwarden client secret not configured")
	}

	ctx, cancel := context.WithTimeout(ctx, bwCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, session.binary, "login", "--apikey")
	cmd.Env = append(bwEnv(session),
		bwClientIDEnvVar+"="+clientID,
		bwClientSecretEnvVar+"="+clientSecret)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("bitwarden login failed")
	}

	session.loggedIn = true
	return nil
}

// bwUnlock unlocks the vault and stores session token.
func bwUnlock(ctx context.Context, session *bwSession) error {
	password, err := getBWCredential(bwPasswordCredentialName, bwPasswordEnvVar)
	if err != nil {
		return fmt.Errorf("bitwarden password not configured")
	}

	ctx, cancel := context.WithTimeout(ctx, bwCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, session.binary, "unlock", "--raw", "--passwordenv", "BW_UNLOCK_PASSWORD")
	cmd.Env = append(bwEnv(session), "BW_UNLOCK_PASSWORD="+password)

	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("bitwarden unlock failed")
	}

	session.token = strings.TrimSpace(string(output))
	return nil
}

// bwGetItem fetches an item from Bitwarden.
func bwGetItem(ctx context.Context, session *bwSession, itemID string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, bwCommandTimeout)
	defer cancel()

	// Use BW_SESSION env var instead of --session CLI arg to avoid process list exposure
	cmd := exec.CommandContext(ctx, session.binary, "get", "item", itemID)
	cmd.Env = append(bwEnv(session), "BW_SESSION="+session.token)

	output, err := cmd.Output()
	if err != nil {
		stderr := bitwardenStderr(err)
		if isNotFoundError(stderr) {
			return "", fmt.Errorf("bitwarden item not found")
		}
		return "", fmt.Errorf("bitwarden get item failed: %s", stderr)
	}

	return strings.TrimSpace(string(output)), nil
}

// bwEnv returns environment variables for bw CLI.
func bwEnv(session *bwSession) []string {
	env := os.Environ()
	if session.dataDir != "" {
		env = append(env, "BITWARDENCLI_APPDATA_DIR="+session.dataDir)
	}
	return env
}

// getBWCredential retrieves a Bitwarden credential from systemd or env.
func getBWCredential(credName, envVar string) (string, error) {
	// 1. Check systemd credentials directory
	if credDir := os.Getenv("CREDENTIALS_DIRECTORY"); credDir != "" {
		tokenPath := filepath.Join(credDir, credName)
		token, exists, err := readSecureCredentialValue(tokenPath)
		if err != nil {
			return "", fmt.Errorf("invalid bitwarden credential file: %w", err)
		}
		if exists {
			return token, nil
		}
	}

	// 2. Check environment variable
	if token := os.Getenv(envVar); token != "" {
		return token, nil
	}

	return "", fmt.Errorf("credential not configured")
}

// isAuthError checks if error indicates auth/session issue.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not logged in") ||
		strings.Contains(msg, "vault is locked") ||
		strings.Contains(msg, "invalid session") ||
		strings.Contains(msg, "session key") ||
		strings.Contains(msg, "authorization failed")
}

// CleanupBWSession cleans up the Bitwarden session data directory.
// Should be called on daemon shutdown.
func CleanupBWSession() {
	bwMutex.Lock()
	defer bwMutex.Unlock()

	if bwCurrent != nil && bwCurrent.dataDir != "" {
		bwBinary := bwCurrent.binary
		if bwBinary == "" {
			bwBinary = "bw"
		}
		// Logout first
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bwBinary, "logout")
		cmd.Env = bwEnv(bwCurrent)
		_ = cmd.Run()

		// Remove temp directory
		_ = os.RemoveAll(bwCurrent.dataDir)
		bwCurrent = nil
	}
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func bitwardenStderr(err error) string {
	if exitErr, ok := err.(*exec.ExitError); ok {
		if stderr := strings.TrimSpace(string(exitErr.Stderr)); stderr != "" {
			return stderr
		}
	}
	return strings.TrimSpace(err.Error())
}

func isNotFoundError(stderr string) bool {
	return strings.Contains(strings.ToLower(stderr), "not found")
}
