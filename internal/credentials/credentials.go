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
var findTrustedBinaryFunc = paths.FindTrustedBinary

// Credential is a fetched secret with an optional absolute expiry.
// Zero ExpiresAt means the value has no inherent expiry (static backends).
type Credential struct {
	Value     string
	ExpiresAt time.Time
}

// FetchOptions holds configuration for credential fetching.
type FetchOptions struct {
	PassBinary  string
	OPBinary    string
	BWBinary    string
	VaultBinary string
	BypassCache bool
}

// FetchOption configures credential fetching.
type FetchOption func(*FetchOptions)

// WithPassBinary sets the path to the pass binary.
func WithPassBinary(path string) FetchOption {
	return func(o *FetchOptions) {
		o.PassBinary = path
	}
}

// WithOPBinary sets the path to the 1Password CLI binary.
func WithOPBinary(path string) FetchOption {
	return func(o *FetchOptions) {
		o.OPBinary = path
	}
}

// WithBWBinary sets the path to the Bitwarden CLI binary.
func WithBWBinary(path string) FetchOption {
	return func(o *FetchOptions) {
		o.BWBinary = path
	}
}

// WithVaultBinary sets the path to the HashiCorp Vault CLI binary.
func WithVaultBinary(path string) FetchOption {
	return func(o *FetchOptions) {
		o.VaultBinary = path
	}
}

// WithBypassCache forces live credential fetches and bypasses result caching.
func WithBypassCache() FetchOption {
	return func(o *FetchOptions) {
		o.BypassCache = true
	}
}

// Fetch retrieves a credential from the specified source.
// Source formats:
//   - pass:path/in/store - fetch from password store
//   - env:VAR_NAME - fetch from env file
//   - op://vault/item/field - fetch from 1Password
//   - age:/path/to/file.age - decrypt age-encrypted file
//   - keychain:service-name - fetch from macOS Keychain
//   - bw:item-uuid - fetch from Bitwarden
//   - vault:secret/path - fetch from HashiCorp Vault
//   - path/in/store - legacy format, assumed to be pass
//
// All sources optionally support jq extraction: "source | .jq_expr"
func Fetch(source string, opts ...FetchOption) (string, error) {
	cred, err := FetchCredential(source, opts...)
	if err != nil {
		return "", err
	}
	return cred.Value, nil
}

// FetchCredential retrieves a credential and its expiry metadata from the specified source.
func FetchCredential(source string, opts ...FetchOption) (Credential, error) {
	options := &FetchOptions{
		PassBinary: paths.DefaultPassBinary(),
	}
	for _, opt := range opts {
		opt(options)
	}

	parsed, err := ParseSource(source)
	if err != nil {
		return Credential{}, fmt.Errorf("invalid credential source")
	}

	cacheEligible := isCredentialCacheableBackend(parsed.Backend) && !options.BypassCache
	now := credentialCacheNow()
	if cacheEligible {
		cacheKey := credentialCacheKey(parsed)
		return credentialResultCache.fetchCached(cacheKey, now, func() (Credential, error) {
			return fetchCredentialFromBackend(parsed, options)
		})
	}

	return fetchCredentialFromBackend(parsed, options)
}

func fetchCredentialFromBackend(parsed *ParsedSource, options *FetchOptions) (Credential, error) {
	ctx := context.Background()

	var result string
	var err error
	switch parsed.Backend {
	case BackendEnv:
		result, err = fetchFromEnvFile(parsed.Path)
		if err != nil {
			return Credential{}, err
		}
		if parsed.HasJQ() {
			result, err = ApplyJQ(ctx, []byte(result), parsed.JQExpr)
			if err != nil {
				return Credential{}, err
			}
		}

	case BackendPass:
		result, err = fetchFromPass(options.PassBinary, parsed.Path)
		if err != nil {
			return Credential{}, err
		}
		if parsed.HasJQ() {
			result, err = ApplyJQ(ctx, []byte(result), parsed.JQExpr)
			if err != nil {
				return Credential{}, err
			}
		}

	case Backend1Password:
		result, err = fetchFrom1Password(ctx, parsed, options.OPBinary)
		if err != nil {
			return Credential{}, err
		}

	case BackendAge:
		result, err = fetchFromAge(ctx, parsed)
		if err != nil {
			return Credential{}, err
		}

	case BackendKeychain:
		result, err = fetchFromKeychain(ctx, parsed)
		if err != nil {
			return Credential{}, err
		}

	case BackendBitwarden:
		result, err = fetchFromBitwarden(ctx, parsed, options.BWBinary)
		if err != nil {
			return Credential{}, err
		}

	case BackendVault:
		result, err = fetchFromVault(ctx, parsed, options.VaultBinary)
		if err != nil {
			return Credential{}, err
		}

	default:
		return Credential{}, fmt.Errorf("unknown credential backend")
	}

	return Credential{Value: result}, nil
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
