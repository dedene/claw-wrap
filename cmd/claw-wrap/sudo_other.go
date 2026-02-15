//go:build !unix

package main

import "fmt"

// reexecWithSudo is not supported on non-Unix platforms.
func reexecWithSudo() error {
	return fmt.Errorf("automatic sudo elevation not supported on this platform; please run as administrator")
}

// isRoot returns true if running with elevated privileges.
// On non-Unix platforms, we assume not elevated (user will get permission error).
func isRoot() bool {
	return false
}
