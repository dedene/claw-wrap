// Package config handles loading and parsing the wrappers.yaml configuration.
package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"claw-wrap/internal/paths"
	"gopkg.in/yaml.v3"
)

const (
	// DefaultTimeout is the default proxy timeout.
	DefaultTimeout = 5 * time.Minute
	// DefaultInlineThreshold is the default inline threshold (1MB).
	DefaultInlineThreshold int64 = 1 << 20
	// DefaultMaxConnections is the default max concurrent daemon connections.
	DefaultMaxConnections = 64
	// DefaultReadHeaderTimeout is the timeout for reading the first request frame.
	DefaultReadHeaderTimeout = 3 * time.Second
	// DefaultReadMessageTimeout is the timeout for per-message stdin/control reads.
	DefaultReadMessageTimeout = 15 * time.Second
	// DefaultMaxStdinMessageSize is the default max size for wrapper->daemon NDJSON messages.
	DefaultMaxStdinMessageSize = 1 << 20 // 1MB
	// DefaultReplayCacheTTL is the default TTL for replay entries.
	DefaultReplayCacheTTL = 2 * time.Minute
	// DefaultReplayCacheMaxEntries is the default replay cache size cap.
	DefaultReplayCacheMaxEntries = 10000
	// DefaultWriteTimeout is the default write deadline for daemon→client writes.
	DefaultWriteTimeout = 30 * time.Second
)

// DefaultConfigPath returns the default location for wrappers.yaml.
var DefaultConfigPath = paths.ConfigPath()

// ProxyConfig holds proxy-related configuration.
type ProxyConfig struct {
	Timeout               string `yaml:"timeout"`                 // e.g., "300s"
	InlineThreshold       string `yaml:"inline_threshold"`        // e.g., "1MB"
	HMACSecretFile        string `yaml:"hmac_secret_file"`        // e.g., "/run/openclaw/auth"
	PassBinary            string `yaml:"pass_binary"`             // e.g., "/usr/bin/pass"
	MaxConnections        int    `yaml:"max_connections"`         // e.g., 64
	ReadHeaderTimeout     string `yaml:"read_header_timeout"`     // e.g., "3s"
	ReadMessageTimeout    string `yaml:"read_message_timeout"`    // e.g., "15s"
	MaxStdinMessageSize   string `yaml:"max_stdin_message_size"`  // e.g., "1MB"
	MaxOutputSize         string `yaml:"max_output_size"`         // e.g., "100MB" (0 = unlimited)
	WriteTimeout          string `yaml:"write_timeout"`           // e.g., "30s"
	MaxConnectionLifetime string `yaml:"max_connection_lifetime"` // e.g., "10m" (0 = unlimited)
	ReplayCacheTTL        string `yaml:"replay_cache_ttl"`        // e.g., "2m"
	ReplayCacheMax        int    `yaml:"replay_cache_max_entries"`
}

// SecurityConfig holds security policy flags.
type SecurityConfig struct {
	// DenyUnverifiedCallerExe rejects connections when /proc/<pid>/exe
	// cannot be read (e.g. inside firejail). Default: false (allow).
	DenyUnverifiedCallerExe bool `yaml:"deny_unverified_caller_exe"`
}

// Config is the root configuration structure.
type Config struct {
	Proxy       *ProxyConfig             `yaml:"proxy,omitempty"`
	Security    *SecurityConfig          `yaml:"security,omitempty"`
	Credentials map[string]CredentialDef `yaml:"credentials"`
	Tools       map[string]ToolDef       `yaml:"tools"`
}

// CredentialDef defines a credential source.
type CredentialDef struct {
	Source string `yaml:"source"`
}

// ToolDef defines a wrapped tool.
type ToolDef struct {
	Binary      string            `yaml:"binary"`
	Timeout     string            `yaml:"timeout,omitempty"`
	Env         map[string]string `yaml:"env,omitempty"`
	ForcedEnv   map[string]string `yaml:"forced_env,omitempty"`
	BlockedArgs []BlockedArg      `yaml:"blocked_args,omitempty"`
	ConfigFile  *ConfigFileDef    `yaml:"config_file,omitempty"`
}

// BlockedArg defines a blocked argument pattern.
type BlockedArg struct {
	Pattern  string         `yaml:"pattern"`
	Message  string         `yaml:"message"`
	Match    string         `yaml:"match,omitempty"` // arg (default) or command
	Compiled *regexp.Regexp `yaml:"-"`               // compiled at validation time
}

// ConfigFileDef defines a temporary config file to generate.
type ConfigFileDef struct {
	XDGSubdir   string   `yaml:"xdg_subdir"`
	Filename    string   `yaml:"filename"`
	Template    string   `yaml:"template"`
	Credentials []string `yaml:"credentials"`
}

const (
	// BlockedArgMatchArg matches each arg independently (default, safer).
	BlockedArgMatchArg = "arg"
	// BlockedArgMatchCommand matches against strings.Join(args, " ").
	BlockedArgMatchCommand = "command"
)

var (
	envVarNameRegex = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	toolNameRegex   = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// Load reads and parses the configuration from the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &config, nil
}

// Validate checks the configuration for errors and compiles regex patterns.
func (c *Config) Validate() error {
	if c.Credentials == nil {
		c.Credentials = map[string]CredentialDef{}
	}
	if c.Tools == nil {
		c.Tools = map[string]ToolDef{}
	}

	for name, cred := range c.Credentials {
		if strings.TrimSpace(cred.Source) == "" {
			return fmt.Errorf("credential %q: empty source", name)
		}
	}

	for toolName, tool := range c.Tools {
		if !toolNameRegex.MatchString(toolName) {
			return fmt.Errorf("tool %q: invalid name (allowed: letters, digits, dot, underscore, hyphen)", toolName)
		}

		// Binary must be non-empty and absolute.
		if tool.Binary == "" {
			return fmt.Errorf("tool %q: empty binary path", toolName)
		}
		if !filepath.IsAbs(tool.Binary) {
			return fmt.Errorf("tool %q: binary path must be absolute: %q", toolName, tool.Binary)
		}

		// Warn (don't error) if binary doesn't exist on disk.
		if _, err := os.Stat(tool.Binary); err != nil {
			log.Printf("[WARN] tool %q: binary %q not found on disk: %v", toolName, tool.Binary, err)
		}

		for envVar, credName := range tool.Env {
			if !envVarNameRegex.MatchString(envVar) {
				return fmt.Errorf("tool %q: invalid env var name %q", toolName, envVar)
			}
			if _, ok := c.Credentials[credName]; !ok {
				return fmt.Errorf("tool %q: references undefined credential %q", toolName, credName)
			}
		}

		for envVar := range tool.ForcedEnv {
			if !envVarNameRegex.MatchString(envVar) {
				return fmt.Errorf("tool %q: invalid forced_env var name %q", toolName, envVar)
			}
		}

		if tool.ConfigFile != nil {
			if err := validateConfigFileDef(tool.ConfigFile); err != nil {
				return fmt.Errorf("tool %q: invalid config_file: %w", toolName, err)
			}

			for _, credName := range tool.ConfigFile.Credentials {
				if _, ok := c.Credentials[credName]; !ok {
					return fmt.Errorf("tool %q: config_file references undefined credential %q", toolName, credName)
				}
			}
		}

		// Compile blocked_args regex patterns.
		for i, b := range tool.BlockedArgs {
			matchMode := strings.TrimSpace(b.Match)
			if matchMode == "" {
				matchMode = BlockedArgMatchArg
			}
			switch matchMode {
			case BlockedArgMatchArg, BlockedArgMatchCommand:
			default:
				return fmt.Errorf("tool %q: invalid blocked_args match %q (must be %q or %q)", toolName, b.Match, BlockedArgMatchArg, BlockedArgMatchCommand)
			}

			re, err := regexp.Compile(b.Pattern)
			if err != nil {
				return fmt.Errorf("tool %q: invalid blocked_args pattern %q: %w", toolName, b.Pattern, err)
			}
			c.Tools[toolName].BlockedArgs[i].Match = matchMode
			c.Tools[toolName].BlockedArgs[i].Compiled = re
		}
	}
	return nil
}

func validateConfigFileDef(def *ConfigFileDef) error {
	if def == nil {
		return nil
	}
	if err := validateSafeRelativePath(def.XDGSubdir, true); err != nil {
		return fmt.Errorf("xdg_subdir: %w", err)
	}
	if err := validateSafeRelativePath(def.Filename, false); err != nil {
		return fmt.Errorf("filename: %w", err)
	}
	if strings.TrimSpace(def.Template) == "" {
		return fmt.Errorf("template must not be empty")
	}
	return nil
}

func validateSafeRelativePath(value string, allowNested bool) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("must not be empty")
	}
	if strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("contains NUL byte")
	}
	if filepath.IsAbs(value) {
		return fmt.Errorf("must be relative")
	}
	if strings.Contains(value, "\\") {
		return fmt.Errorf("must use forward slashes")
	}
	if strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return fmt.Errorf("must not start or end with slash")
	}

	parts := strings.Split(value, "/")
	if !allowNested && len(parts) > 1 {
		return fmt.Errorf("must not contain path separators")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("contains invalid path segment %q", part)
		}
	}

	clean := filepath.Clean(value)
	if clean != value {
		return fmt.Errorf("must be normalized")
	}

	return nil
}

// LoadDefault loads the configuration from the default path.
func LoadDefault() (*Config, error) {
	return Load(DefaultConfigPath)
}

// ParseDuration parses a duration string like "300s", "5m", etc.
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty duration string")
	}
	return time.ParseDuration(s)
}

// byteSizeRegex matches byte size strings like "1MB", "512kb", "1G".
var byteSizeRegex = regexp.MustCompile(`(?i)^(\d+)\s*(k|m|g)b?$`)

// ParseByteSize parses a byte size string like "1MB", "512KB", "1G".
// Supports KB, MB, GB (case insensitive), with or without trailing 'B'.
func ParseByteSize(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty byte size string")
	}

	s = strings.TrimSpace(s)

	// Try parsing as plain number first
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}

	matches := byteSizeRegex.FindStringSubmatch(s)
	if matches == nil {
		return 0, fmt.Errorf("invalid byte size format: %q", s)
	}

	value, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number in byte size: %w", err)
	}

	unit := strings.ToUpper(matches[2])
	switch unit {
	case "K":
		return value * 1024, nil
	case "M":
		return value * 1024 * 1024, nil
	case "G":
		return value * 1024 * 1024 * 1024, nil
	default:
		return 0, fmt.Errorf("unknown unit: %s", unit)
	}
}

// GetTimeout returns the proxy timeout or the default (5 minutes).
func (c *Config) GetTimeout() time.Duration {
	if c.Proxy == nil || c.Proxy.Timeout == "" {
		return DefaultTimeout
	}
	d, err := ParseDuration(c.Proxy.Timeout)
	if err != nil {
		return DefaultTimeout
	}
	return d
}

// GetInlineThreshold returns the proxy inline threshold or the default (1MB).
func (c *Config) GetInlineThreshold() int64 {
	if c.Proxy == nil || c.Proxy.InlineThreshold == "" {
		return DefaultInlineThreshold
	}
	size, err := ParseByteSize(c.Proxy.InlineThreshold)
	if err != nil {
		return DefaultInlineThreshold
	}
	return size
}

// GetHMACSecretFile returns the HMAC secret file path or the default.
func (c *Config) GetHMACSecretFile() string {
	if c.Proxy == nil || c.Proxy.HMACSecretFile == "" {
		return paths.AuthPath()
	}
	return c.Proxy.HMACSecretFile
}

// GetPassBinary returns the configured pass binary path or the default.
// The returned path is always absolute.
func (c *Config) GetPassBinary() string {
	if c.Proxy != nil && c.Proxy.PassBinary != "" {
		if !filepath.IsAbs(c.Proxy.PassBinary) {
			log.Printf("[WARN] pass_binary %q is not absolute, using default", c.Proxy.PassBinary)
			return paths.DefaultPassBinary()
		}
		return c.Proxy.PassBinary
	}
	return paths.DefaultPassBinary()
}

// DenyUnverifiedCallerExe returns whether to reject connections when
// /proc/<pid>/exe is unreadable. Default: false (allow).
func (c *Config) DenyUnverifiedCallerExe() bool {
	return c.Security != nil && c.Security.DenyUnverifiedCallerExe
}

// GetMaxConnections returns the max concurrent daemon connections.
func (c *Config) GetMaxConnections() int {
	if c.Proxy == nil || c.Proxy.MaxConnections <= 0 {
		return DefaultMaxConnections
	}
	return c.Proxy.MaxConnections
}

// GetReadHeaderTimeout returns header read timeout.
func (c *Config) GetReadHeaderTimeout() time.Duration {
	if c.Proxy == nil || c.Proxy.ReadHeaderTimeout == "" {
		return DefaultReadHeaderTimeout
	}
	d, err := ParseDuration(c.Proxy.ReadHeaderTimeout)
	if err != nil || d <= 0 {
		return DefaultReadHeaderTimeout
	}
	return d
}

// GetReadMessageTimeout returns per-message read timeout.
func (c *Config) GetReadMessageTimeout() time.Duration {
	if c.Proxy == nil || c.Proxy.ReadMessageTimeout == "" {
		return DefaultReadMessageTimeout
	}
	d, err := ParseDuration(c.Proxy.ReadMessageTimeout)
	if err != nil || d <= 0 {
		return DefaultReadMessageTimeout
	}
	return d
}

// GetMaxStdinMessageSize returns max wrapper->daemon NDJSON message size.
func (c *Config) GetMaxStdinMessageSize() int {
	if c.Proxy == nil || c.Proxy.MaxStdinMessageSize == "" {
		return DefaultMaxStdinMessageSize
	}
	size, err := ParseByteSize(c.Proxy.MaxStdinMessageSize)
	if err != nil || size <= 0 {
		return DefaultMaxStdinMessageSize
	}
	if size > int64(^uint(0)>>1) {
		return DefaultMaxStdinMessageSize
	}
	return int(size)
}

// GetMaxOutputSize returns the max output size limit in bytes.
// Returns 0 (unlimited) by default — this is opt-in only.
func (c *Config) GetMaxOutputSize() int64 {
	if c.Proxy == nil || c.Proxy.MaxOutputSize == "" {
		return 0
	}
	size, err := ParseByteSize(c.Proxy.MaxOutputSize)
	if err != nil || size <= 0 {
		return 0
	}
	return size
}

// GetReplayCacheTTL returns replay cache TTL.
// Enforces a minimum of 10 seconds to prevent trivially short replay windows.
func (c *Config) GetReplayCacheTTL() time.Duration {
	if c.Proxy == nil || c.Proxy.ReplayCacheTTL == "" {
		return DefaultReplayCacheTTL
	}
	d, err := ParseDuration(c.Proxy.ReplayCacheTTL)
	if err != nil || d <= 0 {
		return DefaultReplayCacheTTL
	}
	const minTTL = 10 * time.Second
	if d < minTTL {
		return minTTL
	}
	return d
}

// GetReplayCacheMaxEntries returns replay cache max size.
func (c *Config) GetReplayCacheMaxEntries() int {
	if c.Proxy == nil || c.Proxy.ReplayCacheMax <= 0 {
		return DefaultReplayCacheMaxEntries
	}
	return c.Proxy.ReplayCacheMax
}

// GetWriteTimeout returns the write deadline for daemon→client responses.
func (c *Config) GetWriteTimeout() time.Duration {
	if c.Proxy == nil || c.Proxy.WriteTimeout == "" {
		return DefaultWriteTimeout
	}
	d, err := ParseDuration(c.Proxy.WriteTimeout)
	if err != nil || d <= 0 {
		return DefaultWriteTimeout
	}
	return d
}

// GetMaxConnectionLifetime returns the maximum lifetime for a single connection.
// Returns 0 (unlimited) by default — this is opt-in only.
func (c *Config) GetMaxConnectionLifetime() time.Duration {
	if c.Proxy == nil || c.Proxy.MaxConnectionLifetime == "" {
		return 0
	}
	d, err := ParseDuration(c.Proxy.MaxConnectionLifetime)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// GetTimeout returns the tool-specific timeout or falls back to the global default.
func (t *ToolDef) GetTimeout(globalDefault time.Duration) time.Duration {
	if t.Timeout == "" {
		return globalDefault
	}
	d, err := ParseDuration(t.Timeout)
	if err != nil {
		return globalDefault
	}
	return d
}
