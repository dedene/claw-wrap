// Package paths provides platform-aware default paths for claw-wrap.
package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// RuntimeDir returns the platform-appropriate runtime directory.
//   - Linux: /run/openclaw (created by systemd RuntimeDirectory=)
//   - macOS: $TMPDIR/openclaw (per-user, permission-restricted)
func RuntimeDir() string {
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

// EnvFile returns the default env credential file path.
func EnvFile() string {
	return filepath.Join(RuntimeDir(), "env")
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

// DefaultPassBinary returns the default pass binary path.
// On macOS, Homebrew installs to /opt/homebrew/bin; on Linux, /usr/bin.
func DefaultPassBinary() string {
	// Prefer PATH lookup for portability.
	if p, err := lookPath("pass"); err == nil {
		return p
	}
	if runtime.GOOS == "darwin" {
		return "/opt/homebrew/bin/pass"
	}
	return "/usr/bin/pass"
}

// lookPath is a variable so tests can stub it. Defaults to exec.LookPath.
var lookPath = defaultLookPath

func defaultLookPath(file string) (string, error) {
	// Import exec only at call time to avoid init-order issues.
	// We inline the lookup to keep the package dependency light.
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			dir = "."
		}
		path := filepath.Join(dir, file)
		if info, err := os.Stat(path); err == nil && !info.IsDir() && info.Mode()&0111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s: not found in PATH", file)
}
