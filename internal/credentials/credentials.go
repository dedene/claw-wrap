// Package credentials handles fetching secrets from various sources.
package credentials

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"claw-wrap/internal/paths"
	"golang.org/x/sys/unix"
)

// DefaultEnvFile is the path to the env file with service credentials.
var DefaultEnvFile = paths.EnvFile()
var currentEUIDFunc = os.Geteuid

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
		PassBinary: paths.DefaultPassBinary(),
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
	file, err := openValidatedEnvFile(DefaultEnvFile)
	if err != nil {
		return "", err
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

func validateEnvFile(path string) error {
	file, err := openValidatedEnvFile(path)
	if err != nil {
		return err
	}
	return file.Close()
}

func openValidatedEnvFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if err == unix.ELOOP {
			return nil, fmt.Errorf("env file must not be a symlink: %s", path)
		}
		return nil, fmt.Errorf("open env file: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open env file: failed to create file handle")
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat env file: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("env file must be a regular file: %s", path)
	}

	perm := info.Mode().Perm()
	if perm != 0o600 && perm != 0o640 {
		_ = file.Close()
		return nil, fmt.Errorf("env file permissions must be 0600 or 0640: %s has %04o", path, perm)
	}

	ownerUID, err := envFileOwnerUID(info)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("failed to read env file owner metadata: %w", err)
	}
	if ownerUID != currentEUIDFunc() {
		_ = file.Close()
		return nil, fmt.Errorf("env file owner must match daemon uid: %s owner=%d daemon=%d", path, ownerUID, currentEUIDFunc())
	}

	return file, nil
}

func envFileOwnerUID(info os.FileInfo) (int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unsupported file stat type")
	}
	return int(stat.Uid), nil
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
