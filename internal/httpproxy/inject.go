package httpproxy

import (
	"fmt"
	"regexp"
	"strings"

	"claw-wrap/internal/config"
	"claw-wrap/internal/credentials"
)

// credentialRefRe matches {{name}} template placeholders for named credentials.
// Names must reference credentials defined in the config's credentials section.
var credentialRefRe = regexp.MustCompile(`\{\{([^}]+)\}\}`)

// resolveHeaderValue resolves named credential references in a header value template.
// All references must be named credentials defined in the config's credentials map.
// Returns the resolved value or an error if any credential resolution fails.
func resolveHeaderValue(template string, creds map[string]config.CredentialDef, opts []credentials.FetchOption) (string, error) {
	var resolveErr error

	result := credentialRefRe.ReplaceAllStringFunc(template, func(match string) string {
		if resolveErr != nil {
			return "" // Already have an error, skip remaining
		}

		// Extract the name from {{name}}
		name := strings.TrimPrefix(match, "{{")
		name = strings.TrimSuffix(name, "}}")
		name = strings.TrimSpace(name)

		if name == "" {
			resolveErr = fmt.Errorf("empty credential reference")
			return ""
		}

		// Look up named credential
		cred, ok := creds[name]
		if !ok {
			resolveErr = fmt.Errorf("unknown credential %q", name)
			return ""
		}

		value, err := credentials.Fetch(cred.Source, opts...)
		if err != nil {
			resolveErr = fmt.Errorf("resolve credential %q: %w", name, err)
			return ""
		}

		return value
	})

	if resolveErr != nil {
		return "", resolveErr
	}

	return result, nil
}

// hasCredentialRef checks if a string contains credential template references.
func hasCredentialRef(s string) bool {
	return credentialRefRe.MatchString(s)
}
