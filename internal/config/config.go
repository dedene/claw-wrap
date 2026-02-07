// Package config handles loading and parsing the wrappers.yaml configuration.
package config

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultTimeout is the default proxy timeout.
	DefaultTimeout = 5 * time.Minute
	// DefaultInlineThreshold is the default inline threshold (1MB).
	DefaultInlineThreshold int64 = 1 << 20
	// DefaultHMACSecretFile is the default HMAC secret file path.
	DefaultHMACSecretFile = "/run/openclaw/auth"
)

// DefaultConfigPath is the default location for wrappers.yaml.
const DefaultConfigPath = "/etc/openclaw/wrappers.yaml"

// ProxyConfig holds proxy-related configuration.
type ProxyConfig struct {
	Timeout         string `yaml:"timeout"`           // e.g., "300s"
	InlineThreshold string `yaml:"inline_threshold"`  // e.g., "1MB"
	HMACSecretFile  string `yaml:"hmac_secret_file"`  // e.g., "/run/openclaw/auth"
	PassBinary      string `yaml:"pass_binary"`       // e.g., "/usr/bin/pass"
}

// Config is the root configuration structure.
type Config struct {
	Proxy       *ProxyConfig             `yaml:"proxy,omitempty"`
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
	Compiled *regexp.Regexp `yaml:"-"` // compiled at validation time
}

// ConfigFileDef defines a temporary config file to generate.
type ConfigFileDef struct {
	XDGSubdir   string   `yaml:"xdg_subdir"`
	Filename    string   `yaml:"filename"`
	Template    string   `yaml:"template"`
	Credentials []string `yaml:"credentials"`
}

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
	for toolName, tool := range c.Tools {
		// Binary must be non-empty.
		if tool.Binary == "" {
			return fmt.Errorf("tool %q: empty binary path", toolName)
		}

		// Warn (don't error) if binary doesn't exist on disk.
		if _, err := os.Stat(tool.Binary); err != nil {
			log.Printf("[WARN] tool %q: binary %q not found on disk: %v", toolName, tool.Binary, err)
		}

		// Env credential references must exist in config.Credentials.
		for _, credName := range tool.Env {
			if _, ok := c.Credentials[credName]; !ok {
				return fmt.Errorf("tool %q: references undefined credential %q", toolName, credName)
			}
		}

		// ConfigFile credential references must exist in config.Credentials.
		if tool.ConfigFile != nil {
			for _, credName := range tool.ConfigFile.Credentials {
				if _, ok := c.Credentials[credName]; !ok {
					return fmt.Errorf("tool %q: config_file references undefined credential %q", toolName, credName)
				}
			}
		}

		// Compile blocked_args regex patterns.
		for i, b := range tool.BlockedArgs {
			re, err := regexp.Compile(b.Pattern)
			if err != nil {
				return fmt.Errorf("tool %q: invalid blocked_args pattern %q: %w", toolName, b.Pattern, err)
			}
			c.Tools[toolName].BlockedArgs[i].Compiled = re
		}
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
		return DefaultHMACSecretFile
	}
	return c.Proxy.HMACSecretFile
}

// GetPassBinary returns the configured pass binary path or the default.
func (c *Config) GetPassBinary() string {
	if c.Proxy != nil && c.Proxy.PassBinary != "" {
		return c.Proxy.PassBinary
	}
	return "/usr/bin/pass"
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
