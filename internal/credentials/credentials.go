// Package credentials handles fetching secrets from various sources.
package credentials

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// DefaultEnvFile is the path to the env file with service credentials.
const DefaultEnvFile = "/run/openclaw/env"

// FetchOptions holds configuration for credential fetching.
type FetchOptions struct {
	PassBinary string
}

// FetchOption configures credential fetching.
type FetchOption func(*FetchOptions)

// WithPassBinary sets the path to the pass binary.
func WithPassBinary(path string) FetchOption {
	return func(o *FetchOptions) {
		o.PassBinary = path
	}
}

// Fetch retrieves a credential from the specified source.
// Source formats:
//   - pass:path/in/store - fetch from password store
//   - env:VAR_NAME - fetch from env file
//   - path/in/store - legacy format, assumed to be pass
func Fetch(source string, opts ...FetchOption) (string, error) {
	options := &FetchOptions{
		PassBinary: "/usr/bin/pass",
	}
	for _, opt := range opts {
		opt(options)
	}

	switch {
	case strings.HasPrefix(source, "env:"):
		envName := strings.TrimPrefix(source, "env:")
		return fetchFromEnvFile(envName)
	case strings.HasPrefix(source, "pass:"):
		passPath := strings.TrimPrefix(source, "pass:")
		return fetchFromPass(options.PassBinary, passPath)
	default:
		// Legacy format: assume pass
		return fetchFromPass(options.PassBinary, source)
	}
}

// fetchFromEnvFile reads a credential from the env file.
func fetchFromEnvFile(envName string) (string, error) {
	file, err := os.Open(DefaultEnvFile)
	if err != nil {
		return "", fmt.Errorf("open env file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	prefix := envName + "="
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix), nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read env file: %w", err)
	}

	return "", fmt.Errorf("env var %s not found", envName)
}

// fetchFromPass retrieves a credential from the password store.
func fetchFromPass(binary, path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, "--", path)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("pass %s: %w", path, err)
	}

	return strings.TrimSpace(string(output)), nil
}
