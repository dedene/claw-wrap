//go:build !darwin

package main

// keychainSetupAvailable indicates the command is not available on this platform.
const keychainSetupAvailable = false

func runKeychainSetup() error {
	panic("keychain-setup not available on this platform")
}
