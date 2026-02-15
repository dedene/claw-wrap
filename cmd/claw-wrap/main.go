// claw-wrap is a credential wrapper for CLI tools.
//
// It can run in two modes:
//   - Wrapper mode: Invoked as a symlink (e.g., "bird", "gog"), requests credentials
//     from the daemon and executes the wrapped tool.
//   - Daemon mode: Runs as "claw-wrap daemon", serving credentials over a Unix socket.
//
// Usage:
//
//	claw-wrap daemon              # Start the secrets daemon
//	claw-wrap list                # List configured tools
//	claw-wrap check               # Verify credentials are accessible
//	claw-wrap install             # Create symlinks for all tools
//	bird whoami                   # Run bird with credentials (via symlink)
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"claw-wrap/internal/config"
	"claw-wrap/internal/daemon"
	"claw-wrap/internal/paths"
	"claw-wrap/internal/wrapper"
)

var version = "dev"
var safeToolNameRegex = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func main() {
	execName := filepath.Base(os.Args[0])

	// If invoked as a tool symlink, run the wrapper
	if execName != "claw-wrap" {
		if err := runAsTool(execName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Handle subcommands
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}

	var err error
	switch os.Args[1] {
	case "daemon":
		err = runDaemon()
	case "list":
		err = runList()
	case "check":
		err = runCheck()
	case "install":
		err = runInstall()
	case "keychain-setup":
		if !keychainSetupAvailable {
			fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
			printHelp()
			os.Exit(1)
		}
		err = runKeychainSetup()
	case "version", "-v", "--version":
		fmt.Printf("claw-wrap %s\n", version)
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printHelp()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runAsTool(toolName string) error {
	w := wrapper.New()
	return w.RunTool(toolName, os.Args[1:])
}

func runDaemon() error {
	// Parse daemon-specific flags
	opts := []daemon.Option{}

	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
		case arg == "--socket" && i+1 < len(os.Args):
			opts = append(opts, daemon.WithSocketPath(os.Args[i+1]))
			i++
		case arg == "--config" && i+1 < len(os.Args):
			opts = append(opts, daemon.WithConfigPath(os.Args[i+1]))
			i++
		case arg == "--uid" && i+1 < len(os.Args):
			var uid uint32
			fmt.Sscanf(os.Args[i+1], "%d", &uid)
			opts = append(opts, daemon.WithAllowedUID(uid))
			i++
		case arg == "-h" || arg == "--help":
			fmt.Printf(`claw-wrap daemon - Start the secrets daemon

Usage:
  claw-wrap daemon [options]

Options:
  --socket PATH   Socket path (default: %s)
  --config PATH   Config path (default: %s)
  --uid UID       Allowed UID (default: %d)
  -h, --help      Show this help
`, paths.SocketPath(), paths.ConfigPath(), os.Getuid())
			return nil
		}
	}

	opts = append(opts, daemon.WithVersion(version))
	d := daemon.New(opts...)
	return d.Run()
}

func runList() error {
	w := wrapper.New()
	resp, err := w.List()
	if err != nil {
		return err
	}

	warnVersionMismatch(resp.Version)

	fmt.Println("Configured tools:")
	fmt.Println()
	for name, info := range resp.Tools {
		fmt.Printf("  %-12s %s (%s)\n", name, info.Binary, info.Mode)
	}

	return nil
}

func runCheck() error {
	w := wrapper.New()
	resp, err := w.Check()
	if err != nil {
		return err
	}

	warnVersionMismatch(resp.Version)

	fmt.Println("Checking credentials...")
	fmt.Println()

	allOk := true
	for name, info := range resp.Credentials {
		if info.Status == "ok" {
			fmt.Printf("  %-24s OK (%s)\n", name, info.Preview)
		} else {
			fmt.Printf("  %-24s FAILED\n", name)
			allOk = false
		}
	}

	if !allOk {
		return fmt.Errorf("some credentials failed")
	}

	// Show HTTP proxy info if enabled
	if resp.HTTPProxy != nil && resp.HTTPProxy.Enabled {
		fmt.Println()
		fmt.Println("HTTP Proxy:")
		fmt.Printf("  Listen:     %s\n", resp.HTTPProxy.Listen)
		fmt.Printf("  CA cert:    %s\n", resp.HTTPProxy.CACertPath)
		if resp.HTTPProxy.AuthTokenPath != "" {
			fmt.Printf("  Auth token: %s\n", resp.HTTPProxy.AuthTokenPath)
		}
		fmt.Println()
		fmt.Println("Usage:")
		if resp.HTTPProxy.AuthTokenPath != "" {
			fmt.Printf("  export HTTPS_PROXY=\"http://claw:$(cat %s)@%s\"\n", resp.HTTPProxy.AuthTokenPath, resp.HTTPProxy.Listen)
		} else {
			fmt.Printf("  export HTTPS_PROXY=\"http://%s\"\n", resp.HTTPProxy.Listen)
		}
		fmt.Printf("  export SSL_CERT_FILE=\"%s\"\n", resp.HTTPProxy.CACertPath)
	}

	return nil
}

func runInstall() error {
	// Parse flags
	var installDir, configPath string
	force := false
	for i := 2; i < len(os.Args); i++ {
		switch {
		case os.Args[i] == "--install-dir" && i+1 < len(os.Args):
			installDir = os.Args[i+1]
			i++
		case os.Args[i] == "--config" && i+1 < len(os.Args):
			configPath = os.Args[i+1]
			i++
		case os.Args[i] == "--force":
			force = true
		}
	}

	// Read tool list directly from config (no daemon needed)
	if configPath == "" {
		configPath = config.DefaultConfigPath
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	if len(cfg.Tools) == 0 {
		return fmt.Errorf("no tools configured in %s", configPath)
	}

	// Auto-detect claw-wrap binary path (symlink target)
	clawWrapPath, err := selfExePath()
	if err != nil {
		return err
	}

	// Symlink directory: explicit flag or /usr/local/bin default
	if installDir == "" {
		installDir = "/usr/local/bin"
	}

	// Check if we need elevated privileges
	if !canWriteDir(installDir) {
		if isRoot() {
			return fmt.Errorf("cannot write to %s even as root", installDir)
		}
		return reexecWithSudo()
	}

	fmt.Printf("Installing symlinks in %s -> %s\n", installDir, clawWrapPath)

	var created, replaced, unchanged, failed, conflicts int
	for toolName := range cfg.Tools {
		if !safeToolNameRegex.MatchString(toolName) {
			fmt.Printf("  %-12s FAILED (invalid tool name)\n", toolName)
			failed++
			continue
		}

		linkPath := filepath.Join(installDir, toolName)
		replacing := false

		if info, err := os.Lstat(linkPath); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				alreadyLinked, err := symlinkPointsTo(linkPath, clawWrapPath)
				if err != nil {
					fmt.Printf("  %-12s FAILED (read symlink: %v)\n", toolName, err)
					failed++
					continue
				}
				if alreadyLinked {
					fmt.Printf("  %-12s OK (already linked)\n", toolName)
					unchanged++
					continue
				}
			}

			if !force {
				fmt.Printf("  %-12s FAILED (conflict: %s exists, re-run with --force)\n", toolName, linkPath)
				conflicts++
				failed++
				continue
			}

			if err := removeInstallTarget(linkPath, info); err != nil {
				fmt.Printf("  %-12s FAILED (remove: %v)\n", toolName, err)
				failed++
				continue
			}
			replacing = true
		} else if !os.IsNotExist(err) {
			fmt.Printf("  %-12s FAILED (lstat: %v)\n", toolName, err)
			failed++
			continue
		}

		// Create symlink
		if err := os.Symlink(clawWrapPath, linkPath); err != nil {
			fmt.Printf("  %-12s FAILED (symlink: %v)\n", toolName, err)
			failed++
			continue
		}

		if replacing {
			fmt.Printf("  %-12s replaced -> claw-wrap\n", toolName)
			replaced++
		} else {
			fmt.Printf("  %-12s -> claw-wrap\n", toolName)
			created++
		}
	}

	total := created + replaced + unchanged + failed
	if failed > 0 {
		if conflicts > 0 && !force {
			return fmt.Errorf("%d/%d symlinks failed (%d conflicts) — re-run with --force to replace existing targets", failed, total, conflicts)
		}
		return fmt.Errorf("%d/%d symlinks failed", failed, total)
	}
	fmt.Printf("Done. %d created, %d replaced, %d unchanged.\n", created, replaced, unchanged)
	return nil
}

func removeInstallTarget(path string, info os.FileInfo) error {
	if info.IsDir() {
		return fmt.Errorf("%s exists and is a directory (will not remove)", path)
	}
	return os.Remove(path)
}

// canWriteDir checks if the current process can write to the given directory.
func canWriteDir(dir string) bool {
	testFile := filepath.Join(dir, ".claw-wrap-test")
	f, err := os.Create(testFile)
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(testFile)
	return true
}

func symlinkPointsTo(linkPath, targetPath string) (bool, error) {
	actualTarget, err := os.Readlink(linkPath)
	if err != nil {
		return false, err
	}
	if !filepath.IsAbs(actualTarget) {
		actualTarget = filepath.Join(filepath.Dir(linkPath), actualTarget)
	}
	return normalizeInstallPath(actualTarget) == normalizeInstallPath(targetPath), nil
}

func normalizeInstallPath(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	return filepath.Clean(path)
}

func warnVersionMismatch(daemonVersion string) {
	if daemonVersion != "" && daemonVersion != version {
		fmt.Fprintf(os.Stderr, "Warning: daemon is %s, client is %s — restart daemon:\n  %s\n\n", daemonVersion, version, paths.RestartHint())
	}
}

// selfExePath returns the absolute path of the running binary without resolving symlinks.
// This preserves stable paths (e.g., homebrew's bin/claw-wrap) rather than resolving
// to versioned paths (e.g., Cellar/claw-wrap/x.y.z/bin/claw-wrap) that break on upgrade.
func selfExePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("detect executable path: %w", err)
	}
	abs, err := filepath.Abs(exe)
	if err != nil {
		return "", fmt.Errorf("resolve absolute path: %w", err)
	}
	return filepath.Clean(abs), nil
}

func printHelp() {
	keychainLine := ""
	if keychainSetupAvailable {
		keychainLine = "  keychain-setup  Add credential to macOS Keychain\n"
	}
	fmt.Printf(`claw-wrap %s - OpenClaw credential wrapper

Usage:
  claw-wrap <command> [options]
  <toolname> [args...]    (when invoked via symlink)

Commands:
  daemon          Start the secrets daemon
  list            List configured tools
  check           Verify all credentials are accessible
  install         Create symlinks for all tools
                  --install-dir PATH  Install location (default: /usr/local/bin)
                  --config PATH       Config file path
                  --force             Replace existing files
%s  version         Show version
  help            Show this help

Examples:
  claw-wrap daemon         # Start daemon
  claw-wrap list           # Show tools
  sudo claw-wrap install   # Create symlinks
  bird whoami              # Run bird with credentials (via symlink)
`, version, keychainLine)
}
