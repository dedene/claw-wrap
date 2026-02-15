//go:build unix

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// reexecWithSudo re-executes the current process with sudo.
// Uses syscall.Exec to replace the current process entirely.
func reexecWithSudo() error {
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return fmt.Errorf("sudo not found: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot find executable: %w", err)
	}
	fmt.Println("Requesting sudo access...")
	argv := append([]string{sudo, exe}, os.Args[1:]...)
	return syscall.Exec(sudo, argv, os.Environ())
}

// isRoot returns true if running as root.
func isRoot() bool {
	return os.Getuid() == 0
}
