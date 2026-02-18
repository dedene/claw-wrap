// Package config handles loading and parsing the wrappers.yaml configuration.
package config

import (
	"fmt"
	"regexp"
	"strings"
)

// credentialNameRe matches valid credential names in {{ name }} templates.
// More restrictive than the existing credentialRefRe: only allows valid credential name chars.
var credentialNameRe = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_-]+)\s*\}\}`)

// FindCredentialRefs extracts all credential reference names from a template string.
// Returns unique names in order of first appearance.
// Example: "prefix:{{ foo }}:{{ bar }}:{{ foo }}" → ["foo", "bar"]
func FindCredentialRefs(value string) []string {
	matches := credentialNameRe.FindAllStringSubmatch(value, -1)
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	refs := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) > 1 {
			name := m[1]
			if !seen[name] {
				seen[name] = true
				refs = append(refs, name)
			}
		}
	}
	return refs
}

// HasCredentialRefs returns true if the value contains any {{ name }} templates.
func HasCredentialRefs(value string) bool {
	return credentialNameRe.MatchString(value)
}

// Interpolate replaces all {{ name }} templates in value with resolved credentials.
// The resolver function is called for each unique credential name.
// Returns error if any credential resolution fails.
func Interpolate(value string, resolver func(name string) (string, error)) (string, error) {
	refs := FindCredentialRefs(value)
	if len(refs) == 0 {
		return value, nil
	}

	// Resolve all unique credentials first
	resolved := make(map[string]string, len(refs))
	for _, name := range refs {
		secret, err := resolver(name)
		if err != nil {
			return "", fmt.Errorf("credential %q: %w", name, err)
		}
		resolved[name] = secret
	}

	// Replace all occurrences
	result := credentialNameRe.ReplaceAllStringFunc(value, func(match string) string {
		// Extract name from match (handles whitespace)
		m := credentialNameRe.FindStringSubmatch(match)
		if len(m) > 1 {
			return resolved[m[1]]
		}
		return match
	})

	return result, nil
}

// IsExactCredentialRef returns true if value is exactly a credential name (no template syntax).
// Used to detect direct credential references vs interpolation vs literal values.
func IsExactCredentialRef(value string, credentialNames map[string]struct{}) bool {
	_, exists := credentialNames[value]
	return exists
}

// ClassifyEnvValue determines how an env value should be resolved:
//   - "credential": value is an exact credential name → fetch entire value
//   - "interpolate": value contains {{ refs }} → interpolate
//   - "literal": no credential refs → use as-is
func ClassifyEnvValue(value string, credentialNames map[string]struct{}) string {
	// Check exact match first
	if _, exists := credentialNames[value]; exists {
		return "credential"
	}
	// Check for template refs
	if HasCredentialRefs(value) {
		return "interpolate"
	}
	return "literal"
}

// ValidateEnvRefs validates that all credential references in an env value exist.
// For exact credential matches, checks the value itself.
// For interpolated values, checks all {{ name }} refs.
// Returns list of missing credential names, or nil if all valid.
func ValidateEnvRefs(value string, credentialNames map[string]struct{}) []string {
	classification := ClassifyEnvValue(value, credentialNames)

	switch classification {
	case "credential":
		// Already validated by ClassifyEnvValue returning "credential"
		return nil
	case "interpolate":
		refs := FindCredentialRefs(value)
		var missing []string
		for _, ref := range refs {
			if _, exists := credentialNames[ref]; !exists {
				missing = append(missing, ref)
			}
		}
		return missing
	default:
		return nil
	}
}

// ResolveEnvValue resolves an env value to its final string.
// Handles all three cases: exact credential, interpolated, and literal.
func ResolveEnvValue(value string, credentialNames map[string]struct{}, resolver func(name string) (string, error)) (string, error) {
	classification := ClassifyEnvValue(value, credentialNames)

	switch classification {
	case "credential":
		return resolver(value)
	case "interpolate":
		return Interpolate(value, resolver)
	default:
		return value, nil
	}
}

// CredentialNamesSet builds a set of credential names from a credentials map.
// Helper to avoid repeatedly building this set.
func CredentialNamesSet(credentials map[string]CredentialDef) map[string]struct{} {
	names := make(map[string]struct{}, len(credentials))
	for name := range credentials {
		names[name] = struct{}{}
	}
	return names
}

// NormalizeCredentialRef trims whitespace from a credential ref.
// "{{  foo  }}" → "foo"
func NormalizeCredentialRef(ref string) string {
	return strings.TrimSpace(ref)
}
