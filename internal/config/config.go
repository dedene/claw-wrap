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
	OPBinary              string `yaml:"op_binary"`               // e.g., "/usr/local/bin/op"
	OPTokenFile           string `yaml:"op_token_file"`           // e.g., "/etc/openclaw/1password.token"
	BWBinary              string `yaml:"bw_binary"`               // e.g., "/usr/local/bin/bw"
	AgeIdentityFile       string `yaml:"age_identity_file"`       // e.g., "/etc/openclaw/age-identity"
	MaxConnections        int    `yaml:"max_connections"`         // e.g., 64
	ReadHeaderTimeout     string `yaml:"read_header_timeout"`     // e.g., "3s"
	ReadMessageTimeout    string `yaml:"read_message_timeout"`    // e.g., "15s"
	MaxStdinMessageSize   string `yaml:"max_stdin_message_size"`  // e.g., "1MB"
	MaxOutputSize         string `yaml:"max_output_size"`         // e.g., "100MB" (0 = unlimited)
	WriteTimeout          string `yaml:"write_timeout"`           // e.g., "30s"
	MaxConnectionLifetime string `yaml:"max_connection_lifetime"` // e.g., "10m" (0 = unlimited)
	ReplayCacheTTL        string `yaml:"replay_cache_ttl"`        // e.g., "2m"
	ReplayCacheMax        int    `yaml:"replay_cache_max_entries"`
	CredentialCacheTTL    string `yaml:"credential_cache_ttl"` // e.g., "30s" (0/empty disables)
}

// SecurityConfig holds security policy flags.
type SecurityConfig struct {
	// DenyUnverifiedCallerExe rejects connections when /proc/<pid>/exe
	// cannot be read (e.g. inside firejail). Default: false (allow).
	DenyUnverifiedCallerExe bool `yaml:"deny_unverified_caller_exe"`
}

// HTTPProxyConfig holds HTTP proxy configuration.
type HTTPProxyConfig struct {
	Enabled              bool         `yaml:"enabled"`
	Listen               string       `yaml:"listen"`
	RequireAuth          *bool        `yaml:"require_auth"` // default true
	LogLevel             string       `yaml:"log_level"`    // none, errors, info, debug
	CA                   CAConfig     `yaml:"ca"`
	StripResponseHeaders []string     `yaml:"strip_response_headers"`
	Routes               []ProxyRoute `yaml:"routes"`
}

// GetRequireAuth returns whether proxy auth is required (default: true).
func (c *HTTPProxyConfig) GetRequireAuth() bool {
	if c.RequireAuth == nil {
		return true
	}
	return *c.RequireAuth
}

// CAConfig holds CA certificate configuration for MITM proxy.
type CAConfig struct {
	Path         string `yaml:"path"`
	ValidityDays int    `yaml:"validity_days"`
	Organization string `yaml:"organization"`
}

// ProxyRoute defines a route for credential injection.
type ProxyRoute struct {
	Host   string     `yaml:"host"`
	Inject InjectSpec `yaml:"inject"`
	Allow  []string   `yaml:"allow,omitempty"`
	Deny   []string   `yaml:"deny,omitempty"`

	// Compiled at validation time (not serialized)
	HostRegex  *regexp.Regexp `yaml:"-"`
	AllowRules []PathRule     `yaml:"-"`
	DenyRules  []PathRule     `yaml:"-"`
}

// PathRule represents a compiled method/path pattern.
type PathRule struct {
	Method  string         // HTTP method or "*" for any
	Pattern *regexp.Regexp // Compiled path pattern
}

// InjectSpec defines which header to inject and its value template.
type InjectSpec struct {
	Header string `yaml:"header"`
	Value  string `yaml:"value"`
}

// AuditConfig holds audit logging configuration.
type AuditConfig struct {
	Enabled           bool   `yaml:"enabled"`
	File              string `yaml:"file"`
	IncludeArgs       *bool  `yaml:"include_args"`
	IncludeOutputHash *bool  `yaml:"include_output_hash"`
	IncludeDuration   *bool  `yaml:"include_duration"`
	Syslog            bool   `yaml:"syslog"`
	SyslogFacility    string `yaml:"syslog_facility"`
}

// GetIncludeArgs returns whether to include args in audit entries (default true).
func (a *AuditConfig) GetIncludeArgs() bool {
	if a.IncludeArgs == nil {
		return true
	}
	return *a.IncludeArgs
}

// GetIncludeOutputHash returns whether to include output hash (default true).
func (a *AuditConfig) GetIncludeOutputHash() bool {
	if a.IncludeOutputHash == nil {
		return true
	}
	return *a.IncludeOutputHash
}

// GetIncludeDuration returns whether to include duration (default true).
func (a *AuditConfig) GetIncludeDuration() bool {
	if a.IncludeDuration == nil {
		return true
	}
	return *a.IncludeDuration
}

// Config is the root configuration structure.
type Config struct {
	Proxy       *ProxyConfig             `yaml:"proxy,omitempty"`
	Security    *SecurityConfig          `yaml:"security,omitempty"`
	HTTPProxy   *HTTPProxyConfig         `yaml:"http_proxy,omitempty"`
	Audit       *AuditConfig             `yaml:"audit,omitempty"`
	Credentials map[string]CredentialDef `yaml:"credentials"`
	Tools       map[string]ToolDef       `yaml:"tools"`
}

// CredentialDef defines a credential source.
type CredentialDef struct {
	Source string `yaml:"source"`
}

// ToolDef defines a wrapped tool.
type ToolDef struct {
	Binary   string            `yaml:"binary"`
	Timeout  string            `yaml:"timeout,omitempty"`
	Env      map[string]string `yaml:"env,omitempty"` // Unified env: credential refs, {{ interpolation }}, or literals
	// Deprecated: Use Env instead. ForcedEnv values are always treated as literals.
	// Will be removed in a future version.
	ForcedEnv    map[string]string `yaml:"forced_env,omitempty"`
	Mode         string            `yaml:"mode,omitempty"` // "blocklist" (default) or "allowlist"
	BlockedArgs  []BlockedArg      `yaml:"blocked_args,omitempty"`
	AllowedArgs  []BlockedArg      `yaml:"allowed_args,omitempty"`
	RedactOutput []ToolRedactRule  `yaml:"redact_output,omitempty"`
	ConfigFile   *ConfigFileDef    `yaml:"config_file,omitempty"`
	UseProxy     bool              `yaml:"use_proxy,omitempty"` // Enable HTTP proxy for this tool
	UsePTY       bool              `yaml:"use_pty,omitempty"`   // Enable PTY mode for interactive TUI apps
}

// ToolRedactRule defines an output redaction rule for tool stdout/stderr.
type ToolRedactRule struct {
	Pattern  string         `yaml:"pattern"`
	Replace  string         `yaml:"replace,omitempty"`
	Compiled *regexp.Regexp `yaml:"-"`
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

	// ToolModeBlocklist rejects commands matching blocked_args (default).
	ToolModeBlocklist = "blocklist"
	// ToolModeAllowlist requires commands to match at least one allowed_args pattern.
	ToolModeAllowlist = "allowlist"

	// DefaultRedactReplacement is used when redact_output.replace is omitted.
	DefaultRedactReplacement = "[REDACTED]"
	// Limits to keep redact_output processing bounded.
	maxRedactOutputRulesPerTool = 64
	maxRedactPatternLength      = 1024
	maxRedactReplaceLength      = 256
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

		// Build credential names set for validation
		credNames := CredentialNamesSet(c.Credentials)

		// Validate env entries (unified: credential refs, {{ interpolation }}, or literals)
		for envVar, value := range tool.Env {
			if !envVarNameRegex.MatchString(envVar) {
				return fmt.Errorf("tool %q: invalid env var name %q", toolName, envVar)
			}
			// Validate any credential references in the value
			if missing := ValidateEnvRefs(value, credNames); len(missing) > 0 {
				return fmt.Errorf("tool %q: env %q references undefined credential(s): %v", toolName, envVar, missing)
			}
		}

		// Validate forced_env (deprecated) - emit warning and validate var names
		if len(tool.ForcedEnv) > 0 {
			log.Printf("[WARN] tool %q: forced_env is deprecated, use env instead (values without credential refs are treated as literals)", toolName)
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

		// Validate and normalize mode.
		mode := strings.TrimSpace(tool.Mode)
		if mode == "" {
			mode = ToolModeBlocklist
		}
		switch mode {
		case ToolModeBlocklist, ToolModeAllowlist:
		default:
			return fmt.Errorf("tool %q: invalid mode %q (must be %q or %q)", toolName, tool.Mode, ToolModeBlocklist, ToolModeAllowlist)
		}

		// Cross-validation: allowed_args requires mode: allowlist.
		if mode == ToolModeBlocklist && len(tool.AllowedArgs) > 0 {
			return fmt.Errorf("tool %q: allowed_args requires mode: allowlist", toolName)
		}

		// Allowlist mode requires allowed_args (fail-closed: nothing would pass).
		if mode == ToolModeAllowlist && len(tool.AllowedArgs) == 0 {
			return fmt.Errorf("tool %q: mode %q requires allowed_args", toolName, ToolModeAllowlist)
		}

		// Compile allowed_args regex patterns.
		for i, a := range tool.AllowedArgs {
			matchMode := strings.TrimSpace(a.Match)
			if matchMode == "" {
				matchMode = BlockedArgMatchArg
			}
			switch matchMode {
			case BlockedArgMatchArg, BlockedArgMatchCommand:
			default:
				return fmt.Errorf("tool %q: invalid allowed_args match %q (must be %q or %q)", toolName, a.Match, BlockedArgMatchArg, BlockedArgMatchCommand)
			}

			re, err := regexp.Compile(a.Pattern)
			if err != nil {
				return fmt.Errorf("tool %q: invalid allowed_args pattern %q: %w", toolName, a.Pattern, err)
			}
			c.Tools[toolName].AllowedArgs[i].Match = matchMode
			c.Tools[toolName].AllowedArgs[i].Compiled = re
		}

		// Store normalized mode.
		t := c.Tools[toolName]
		t.Mode = mode
		c.Tools[toolName] = t

		// Validate and compile redact_output regex patterns.
		if len(tool.RedactOutput) > maxRedactOutputRulesPerTool {
			return fmt.Errorf("tool %q: too many redact_output rules (%d > %d)", toolName, len(tool.RedactOutput), maxRedactOutputRulesPerTool)
		}
		for i, r := range tool.RedactOutput {
			if strings.TrimSpace(r.Pattern) == "" {
				return fmt.Errorf("tool %q: redact_output[%d]: pattern must not be empty", toolName, i)
			}
			pattern := r.Pattern
			if len(pattern) > maxRedactPatternLength {
				return fmt.Errorf("tool %q: redact_output[%d]: pattern too long (%d > %d)", toolName, i, len(pattern), maxRedactPatternLength)
			}

			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("tool %q: invalid redact_output pattern %q: %w", toolName, pattern, err)
			}
			if re.MatchString("") {
				return fmt.Errorf("tool %q: redact_output[%d]: pattern must not match empty string", toolName, i)
			}

			replace := r.Replace
			if replace == "" {
				replace = DefaultRedactReplacement
			}
			if len(replace) > maxRedactReplaceLength {
				return fmt.Errorf("tool %q: redact_output[%d]: replace too long (%d > %d)", toolName, i, len(replace), maxRedactReplaceLength)
			}

			c.Tools[toolName].RedactOutput[i].Pattern = pattern
			c.Tools[toolName].RedactOutput[i].Replace = replace
			c.Tools[toolName].RedactOutput[i].Compiled = re
		}
	}
	// Validate HTTP proxy configuration
	if c.HTTPProxy != nil && c.HTTPProxy.Enabled {
		if err := c.validateHTTPProxy(); err != nil {
			return fmt.Errorf("http_proxy: %w", err)
		}
	}

	// Validate audit configuration
	if c.Audit != nil && c.Audit.Enabled {
		if err := c.validateAudit(); err != nil {
			return fmt.Errorf("audit: %w", err)
		}
	}

	return nil
}

func (c *Config) validateHTTPProxy() error {
	cfg := c.HTTPProxy

	// Validate log level
	switch cfg.LogLevel {
	case "", "none", "errors", "info", "debug":
	default:
		return fmt.Errorf("invalid log_level %q (must be none, errors, info, or debug)", cfg.LogLevel)
	}

	// Normalize empty log_level to documented default
	if cfg.LogLevel == "" {
		c.HTTPProxy.LogLevel = "errors"
	}

	// Validate CA config
	if cfg.CA.ValidityDays < 0 {
		return fmt.Errorf("ca.validity_days must be non-negative")
	}

	// Validate and compile routes
	for i := range cfg.Routes {
		route := &cfg.Routes[i]

		if route.Host == "" {
			return fmt.Errorf("route[%d]: host is required", i)
		}

		// Compile host pattern
		hostRegex, err := compileHostPattern(route.Host)
		if err != nil {
			return fmt.Errorf("route[%d]: invalid host pattern %q: %w", i, route.Host, err)
		}
		route.HostRegex = hostRegex

		// Validate inject spec
		if route.Inject.Header == "" {
			return fmt.Errorf("route[%d]: inject.header is required", i)
		}
		if route.Inject.Value == "" {
			return fmt.Errorf("route[%d]: inject.value is required", i)
		}

		// Validate credential references exist
		refs := extractCredentialRefs(route.Inject.Value)
		for _, ref := range refs {
			if _, ok := c.Credentials[ref]; !ok {
				return fmt.Errorf("route[%d]: unknown credential %q in inject.value", i, ref)
			}
		}

		// Compile allow rules
		for j, pattern := range route.Allow {
			rule, err := compilePathRule(pattern)
			if err != nil {
				return fmt.Errorf("route[%d].allow[%d]: %w", i, j, err)
			}
			route.AllowRules = append(route.AllowRules, rule)
		}

		// Compile deny rules
		for j, pattern := range route.Deny {
			rule, err := compilePathRule(pattern)
			if err != nil {
				return fmt.Errorf("route[%d].deny[%d]: %w", i, j, err)
			}
			route.DenyRules = append(route.DenyRules, rule)
		}
	}

	return nil
}

// compileHostPattern compiles a host pattern (exact or *.suffix) to regex.
// Suffix-anchored to prevent subdomain attacks.
// Patterns are normalized to lowercase since hostnames are case-insensitive.
func compileHostPattern(pattern string) (*regexp.Regexp, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, fmt.Errorf("empty pattern")
	}

	// Reject empty wildcard suffix (e.g. "*.")
	if pattern == "*." {
		return nil, fmt.Errorf("invalid wildcard pattern: empty suffix")
	}

	// Normalize to lowercase (hostnames are case-insensitive)
	pattern = strings.ToLower(pattern)
	// Trim trailing dot (FQDN normalization)
	pattern = strings.TrimSuffix(pattern, ".")

	if pattern == "" {
		return nil, fmt.Errorf("empty pattern after normalization")
	}

	// Handle wildcard prefix *.
	if strings.HasPrefix(pattern, "*.") {
		// *.example.com -> matches sub.example.com but NOT example.com
		// Suffix-anchored: must end with .example.com
		suffix := regexp.QuoteMeta(pattern[2:]) // Skip "*."
		return regexp.Compile(`^[^.]+\.` + suffix + `$`)
	}

	// Exact match
	escaped := regexp.QuoteMeta(pattern)
	return regexp.Compile(`^` + escaped + `$`)
}

// compilePathRule compiles a "METHOD /path/pattern" string.
// Supports * for single path segment and ** for rest of path.
func compilePathRule(pattern string) (PathRule, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return PathRule{}, fmt.Errorf("empty pattern")
	}

	parts := strings.SplitN(pattern, " ", 2)
	method := "*"
	pathPattern := pattern

	if len(parts) == 2 {
		method = strings.ToUpper(parts[0])
		pathPattern = parts[1]
	}

	// Validate method
	switch method {
	case "*", "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
	default:
		return PathRule{}, fmt.Errorf("invalid method %q", method)
	}

	// Compile path pattern
	// Escape special regex chars
	escaped := regexp.QuoteMeta(pathPattern)

	// Replace ** first (matches rest of path)
	escaped = strings.ReplaceAll(escaped, `\*\*`, `.*`)
	// Replace * (matches single segment)
	escaped = strings.ReplaceAll(escaped, `\*`, `[^/]+`)

	re, err := regexp.Compile(`^` + escaped + `$`)
	if err != nil {
		return PathRule{}, fmt.Errorf("invalid path pattern: %w", err)
	}

	return PathRule{Method: method, Pattern: re}, nil
}

// credentialRefRe matches {{name}} template placeholders for named credentials.
var credentialRefRe = regexp.MustCompile(`\{\{([^}]+)\}\}`)

// extractCredentialRefs extracts all credential reference names from a template string.
func extractCredentialRefs(template string) []string {
	matches := credentialRefRe.FindAllStringSubmatch(template, -1)
	refs := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) > 1 {
			ref := strings.TrimSpace(m[1])
			if ref != "" {
				refs = append(refs, ref)
			}
		}
	}
	return refs
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

// GetOPBinary returns the configured 1Password CLI binary path or empty for trusted-directory lookup.
// If configured, the returned path must be absolute.
func (c *Config) GetOPBinary() string {
	if c.Proxy != nil && c.Proxy.OPBinary != "" {
		if !filepath.IsAbs(c.Proxy.OPBinary) {
			log.Printf("[WARN] op_binary %q is not absolute, using trusted-directory lookup", c.Proxy.OPBinary)
			return ""
		}
		return c.Proxy.OPBinary
	}
	return ""
}

// GetBWBinary returns the configured Bitwarden CLI binary path or empty for trusted-directory lookup.
// If configured, the returned path must be absolute.
func (c *Config) GetBWBinary() string {
	if c.Proxy != nil && c.Proxy.BWBinary != "" {
		if !filepath.IsAbs(c.Proxy.BWBinary) {
			log.Printf("[WARN] bw_binary %q is not absolute, using trusted-directory lookup", c.Proxy.BWBinary)
			return ""
		}
		return c.Proxy.BWBinary
	}
	return ""
}

// GetOPTokenFile returns the configured 1Password token file path or the default.
// The returned path is always absolute.
func (c *Config) GetOPTokenFile() string {
	if c.Proxy != nil && c.Proxy.OPTokenFile != "" {
		if !filepath.IsAbs(c.Proxy.OPTokenFile) {
			log.Printf("[WARN] op_token_file %q is not absolute, using default", c.Proxy.OPTokenFile)
			return paths.DefaultOPTokenFile()
		}
		return c.Proxy.OPTokenFile
	}
	return paths.DefaultOPTokenFile()
}

// GetAgeIdentityFile returns the configured age identity file path or the default.
// The returned path is always absolute.
func (c *Config) GetAgeIdentityFile() string {
	if c.Proxy != nil && c.Proxy.AgeIdentityFile != "" {
		if !filepath.IsAbs(c.Proxy.AgeIdentityFile) {
			log.Printf("[WARN] age_identity_file %q is not absolute, using default", c.Proxy.AgeIdentityFile)
			return paths.DefaultAgeIdentityFile()
		}
		return c.Proxy.AgeIdentityFile
	}
	return paths.DefaultAgeIdentityFile()
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

// GetCredentialCacheTTL returns credential cache TTL.
// Returns 0 (disabled) when unset, invalid, or non-positive.
func (c *Config) GetCredentialCacheTTL() time.Duration {
	if c.Proxy == nil || c.Proxy.CredentialCacheTTL == "" {
		return 0
	}
	d, err := ParseDuration(c.Proxy.CredentialCacheTTL)
	if err != nil || d <= 0 {
		return 0
	}
	return d
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

// GetHTTPProxyConfig returns the HTTP proxy configuration.
func (c *Config) GetHTTPProxyConfig() *HTTPProxyConfig {
	return c.HTTPProxy
}

// GetHTTPProxyEnabled returns whether HTTP proxy is enabled.
func (c *Config) GetHTTPProxyEnabled() bool {
	return c.HTTPProxy != nil && c.HTTPProxy.Enabled
}

// GetHTTPProxyListen returns the HTTP proxy listen address.
func (c *Config) GetHTTPProxyListen() string {
	if c.HTTPProxy == nil || c.HTTPProxy.Listen == "" {
		return "127.0.0.1:8080"
	}
	return c.HTTPProxy.Listen
}

// GetHTTPProxyCAPath returns the CA directory path.
func (c *Config) GetHTTPProxyCAPath() string {
	if c.HTTPProxy == nil {
		return ""
	}
	return c.HTTPProxy.CA.Path
}

// GetHTTPProxyRequireAuth returns whether proxy authentication is required.
func (c *Config) GetHTTPProxyRequireAuth() bool {
	if c.HTTPProxy == nil {
		return true // default
	}
	return c.HTTPProxy.GetRequireAuth()
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

// validSyslogFacilities lists valid syslog facility names.
var validSyslogFacilities = map[string]bool{
	"local0": true, "local1": true, "local2": true, "local3": true,
	"local4": true, "local5": true, "local6": true, "local7": true,
}

func (c *Config) validateAudit() error {
	a := c.Audit

	if a.File == "" && !a.Syslog {
		return fmt.Errorf("at least one output (file or syslog) must be configured")
	}
	if a.File != "" && !filepath.IsAbs(a.File) {
		return fmt.Errorf("file path must be absolute: %q", a.File)
	}
	if a.SyslogFacility != "" && !validSyslogFacilities[a.SyslogFacility] {
		return fmt.Errorf("invalid syslog_facility %q (must be local0..local7)", a.SyslogFacility)
	}
	return nil
}

// GetAuditConfig returns the audit configuration.
func (c *Config) GetAuditConfig() *AuditConfig {
	if c == nil {
		return nil
	}
	return c.Audit
}

// GetAuditEnabled returns whether audit logging is enabled.
func (c *Config) GetAuditEnabled() bool {
	return c.Audit != nil && c.Audit.Enabled
}
