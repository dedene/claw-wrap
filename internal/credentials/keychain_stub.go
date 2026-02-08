//go:build !darwin

package credentials

import (
	"context"
	"fmt"
)

// fetchFromKeychain is not supported on non-darwin platforms.
func fetchFromKeychain(_ context.Context, _ *ParsedSource) (string, error) {
	return "", fmt.Errorf("keychain backend only available on macOS")
}

// KeychainSetup is not supported on non-darwin platforms.
func KeychainSetup(_, _ string) error {
	return fmt.Errorf("keychain backend only available on macOS")
}
