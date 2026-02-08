//go:build darwin

package main

import (
	"fmt"
	"os"

	"claw-wrap/internal/credentials"
)

// keychainSetupAvailable indicates the command is available on this platform.
const keychainSetupAvailable = true

func runKeychainSetup() error {
	// Check for help
	if len(os.Args) >= 3 && (os.Args[2] == "-h" || os.Args[2] == "--help") {
		fmt.Println(`claw-wrap keychain-setup - Add credential to macOS Keychain

Usage:
  claw-wrap keychain-setup <service-name>

	This command:
	  1. Opens macOS keychain prompt for the secret value
	  2. Stores it in the login keychain
	  3. Sets ACL to allow claw-wrap access without prompts

Example:
  claw-wrap keychain-setup my-api-token`)
		return nil
	}

	// Require service name
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: claw-wrap keychain-setup <service-name>")
	}
	serviceName := os.Args[2]

	// Get binary path for ACL
	binaryPath, err := selfExePath()
	if err != nil {
		return fmt.Errorf("detect binary path: %w", err)
	}

	// Add to keychain
	fmt.Printf("Opening keychain prompt for '%s' with ACL for %s...\n", serviceName, binaryPath)
	if err := credentials.KeychainSetup(serviceName, binaryPath); err != nil {
		return err
	}

	fmt.Println("Success! Credential stored in keychain.")
	fmt.Printf("Use in config: keychain:%s\n", serviceName)
	return nil
}
