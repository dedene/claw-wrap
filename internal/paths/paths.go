// Package paths provides platform-aware default paths for claw-wrap.
package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// RuntimeDirEnv overrides the runtime directory (socket, HMAC auth file,
// proxy auth token) for both the daemon and the wrapper. Containers use it to
// point both sides at a directory inside a shared volume. Must be absolute.
const RuntimeDirEnv = "CLAW_WRAP_RUNTIME_DIR"

// RuntimeDir returns the runtime directory: $CLAW_WRAP_RUNTIME_DIR when set to
// an absolute path, otherwise the platform default.
//   - Linux: /run/openclaw (created by systemd RuntimeDirectory=)
//   - macOS: $TMPDIR/openclaw (per-user, permission-restricted)
func RuntimeDir() string {
	if dir := os.Getenv(RuntimeDirEnv); dir != "" && filepath.IsAbs(dir) {
		return filepath.Clean(dir)
	}
	return defaultRuntimeDir()
}

// ValidateRuntimeDirEnv reports a set but unusable $CLAW_WRAP_RUNTIME_DIR, which
// RuntimeDir would otherwise silently ignore.
func ValidateRuntimeDirEnv() error {
	if dir := os.Getenv(RuntimeDirEnv); dir != "" && !filepath.IsAbs(dir) {
		return fmt.Errorf("%s must be an absolute path, got %q", RuntimeDirEnv, dir)
	}
	return nil
}

func defaultRuntimeDir() string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(os.TempDir(), "openclaw")
	}
	return "/run/openclaw"
}

// SocketPath returns the default Unix socket path.
func SocketPath() string {
	return filepath.Join(RuntimeDir(), "secrets.sock")
}

// AuthPath returns the default HMAC secret file path.
func AuthPath() string {
	return filepath.Join(RuntimeDir(), "auth")
}

// EnvFile returns the default env credential file path. It deliberately ignores
// $CLAW_WRAP_RUNTIME_DIR: an overridden runtime dir may be shared with the
// client, and credentials must never live there.
func EnvFile() string {
	return filepath.Join(defaultRuntimeDir(), "env")
}

// ProxyAuthTokenPath returns the default HTTP proxy auth token file path.
func ProxyAuthTokenPath() string {
	return filepath.Join(RuntimeDir(), "proxy-auth-token")
}

// ConfigPath returns the default config file path.
func ConfigPath() string {
	return "/etc/openclaw/wrappers.yaml"
}

// RestartHint returns a platform-appropriate daemon restart command.
func RestartHint() string {
	if runtime.GOOS == "darwin" {
		return "launchctl kickstart -k gui/$(id -u)/com.openclaw.claw-wrap"
	}
	return "sudo systemctl restart claw-wrap"
}

// DefaultAgeIdentityFile returns the default age identity file path.
func DefaultAgeIdentityFile() string {
	return "/etc/openclaw/age-identity"
}

// DefaultOPTokenFile returns the default 1Password token file path.
func DefaultOPTokenFile() string {
	return "/etc/openclaw/1password.token"
}

// CADir returns the default CA certificate directory.
//   - Linux: /etc/openclaw/ca (system-wide, matches systemd deployment)
//   - macOS: ~/.claw-wrap/ca (user-writable, no sudo needed)
func CADir() string {
	if runtime.GOOS == "darwin" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "/tmp/claw-wrap/ca"
		}
		return filepath.Join(home, ".claw-wrap", "ca")
	}
	return "/etc/openclaw/ca"
}

// DefaultPassBinary returns the default pass binary path.
// Auto-detect is restricted to trusted install directories.
func DefaultPassBinary() string {
	if p, err := FindTrustedBinary("pass"); err == nil {
		return p
	}
	return defaultPassBinaryForPlatform()
}

func defaultPassBinaryForPlatform() string {
	if runtime.GOOS == "darwin" {
		return "/opt/homebrew/bin/pass"
	}
	return "/usr/bin/pass"
}

var trustedBinaryDirs = []string{
	"/usr/bin",
	"/usr/local/bin",
	"/opt/homebrew/bin",
	"/home/linuxbrew/.linuxbrew/bin",
}

var statPath = os.Stat

// FindTrustedBinary returns the first executable found in trustedBinaryDirs.
func FindTrustedBinary(file string) (string, error) {
	if file == "" {
		return "", fmt.Errorf("empty binary name")
	}
	if strings.Contains(file, "/") {
		return "", fmt.Errorf("%s: must be a base name", file)
	}

	for _, dir := range trustedBinaryDirs {
		path := filepath.Join(dir, file)
		info, err := statPath(path)
		if err == nil && !info.IsDir() && info.Mode()&0111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s: not found in trusted locations", file)
}
