// Package credentials handles fetching secrets from various sources.
package credentials

import (
	"fmt"
	"strings"
)

// Backend represents a credential source type.
type Backend string

const (
	BackendPass      Backend = "pass"
	BackendEnv       Backend = "env"
	Backend1Password Backend = "op"
	BackendAge       Backend = "age"
	BackendKeychain  Backend = "keychain"
	BackendBitwarden Backend = "bw"
	BackendVault     Backend = "vault"
	BackendExecJSON  Backend = "exec-json"
)

// ParsedSource represents a parsed credential source URI.
type ParsedSource struct {
	Backend  Backend
	Path     string // The path/reference after the prefix
	JQExpr   string // Optional jq expression (empty if none)
	Original string // Original source string for error messages
}

// ParseSource parses a credential source string into its components.
// Formats:
//   - pass:path/in/store
//   - env:VAR_NAME
//   - op://vault/item/field
//   - op://vault/item/field | .jq_expr
//   - bw:item-uuid
//   - bw:item-uuid | .jq_expr
//   - keychain:service-name
//   - keychain:service-name | .jq_expr
//   - age:/path/to/file.age
//   - age:/path/to/file.age | .jq_expr
//   - vault:secret/myapp/api-key
//   - vault:secret/myapp/api-key | .password
//   - path/in/store (legacy, assumed pass)
func ParseSource(source string) (*ParsedSource, error) {
	if source == "" {
		return nil, fmt.Errorf("empty credential source")
	}

	original := source

	// Split on " | " for jq expression
	var jqExpr string
	if idx := strings.Index(source, " | "); idx != -1 {
		jqExpr = strings.TrimSpace(source[idx+3:])
		source = strings.TrimSpace(source[:idx])
		if jqExpr == "" {
			return nil, fmt.Errorf("empty jq expression after pipe in %q", original)
		}
	}

	// Determine backend from prefix
	var backend Backend
	var path string

	switch {
	case strings.HasPrefix(source, "op://"):
		backend = Backend1Password
		path = source // Keep full URI for op read
	case strings.HasPrefix(source, "bw:"):
		backend = BackendBitwarden
		path = strings.TrimPrefix(source, "bw:")
	case strings.HasPrefix(source, "keychain:"):
		backend = BackendKeychain
		path = strings.TrimPrefix(source, "keychain:")
	case strings.HasPrefix(source, "age:"):
		backend = BackendAge
		path = strings.TrimPrefix(source, "age:")
	case strings.HasPrefix(source, "pass:"):
		backend = BackendPass
		path = strings.TrimPrefix(source, "pass:")
	case strings.HasPrefix(source, "env:"):
		backend = BackendEnv
		path = strings.TrimPrefix(source, "env:")
	case strings.HasPrefix(source, "vault:"):
		backend = BackendVault
		path = strings.TrimPrefix(source, "vault:")
	case strings.HasPrefix(source, "exec-json:"):
		backend = BackendExecJSON
		path = strings.TrimPrefix(source, "exec-json:")
	default:
		// Legacy format: assume pass
		backend = BackendPass
		path = source
	}

	if path == "" {
		return nil, fmt.Errorf("empty path in credential source %q", original)
	}

	if backend == BackendExecJSON && jqExpr != "" {
		return nil, fmt.Errorf("exec-json backend does not support jq extraction in %q", original)
	}

	return &ParsedSource{
		Backend:  backend,
		Path:     path,
		JQExpr:   jqExpr,
		Original: original,
	}, nil
}

// HasJQ returns true if this source has a jq expression.
func (p *ParsedSource) HasJQ() bool {
	return p.JQExpr != ""
}

// NeedsJSONOutput returns true if backend should return JSON for jq processing.
func (p *ParsedSource) NeedsJSONOutput() bool {
	return p.HasJQ()
}
