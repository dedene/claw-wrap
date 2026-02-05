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

	"claw-wrap/internal/daemon"
	"claw-wrap/internal/wrapper"
)

var version = "dev"

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
			fmt.Println(`claw-wrap daemon - Start the secrets daemon

Usage:
  claw-wrap daemon [options]

Options:
  --socket PATH   Socket path (default: /run/openclaw/secrets.sock)
  --config PATH   Config path (default: /etc/openclaw/wrappers.yaml)
  --uid UID       Allowed UID (default: 1000)
  -h, --help      Show this help`)
			return nil
		}
	}

	d := daemon.New(opts...)
	return d.Run()
}

func runList() error {
	w := wrapper.New()
	resp, err := w.List()
	if err != nil {
		return err
	}

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
	return nil
}

func runInstall() error {
	w := wrapper.New()
	resp, err := w.List()
	if err != nil {
		return err
	}

	installDir := "/usr/local/bin"
	clawWrapPath := filepath.Join(installDir, "claw-wrap")

	if _, err := os.Stat(clawWrapPath); os.IsNotExist(err) {
		return fmt.Errorf("claw-wrap not installed at %s", clawWrapPath)
	}

	fmt.Println("Installing symlinks...")

	for toolName := range resp.Tools {
		linkPath := filepath.Join(installDir, toolName)

		// Remove existing file/symlink
		if _, err := os.Lstat(linkPath); err == nil {
			if err := os.Remove(linkPath); err != nil {
				fmt.Printf("  %-12s FAILED (remove: %v)\n", toolName, err)
				continue
			}
		}

		// Create symlink
		if err := os.Symlink(clawWrapPath, linkPath); err != nil {
			fmt.Printf("  %-12s FAILED (symlink: %v)\n", toolName, err)
			continue
		}

		fmt.Printf("  %-12s -> claw-wrap\n", toolName)
	}

	fmt.Println("Done.")
	return nil
}

func printHelp() {
	fmt.Printf(`claw-wrap %s - OpenClaw credential wrapper

Usage:
  claw-wrap <command> [options]
  <toolname> [args...]    (when invoked via symlink)

Commands:
  daemon     Start the secrets daemon
  list       List configured tools
  check      Verify all credentials are accessible
  install    Create symlinks for all configured tools
  version    Show version
  help       Show this help

Examples:
  claw-wrap daemon         # Start daemon (replaces Python daemon)
  claw-wrap list           # Show tools
  sudo claw-wrap install   # Create symlinks
  bird whoami              # Run bird with credentials (via symlink)
`, version)
}
