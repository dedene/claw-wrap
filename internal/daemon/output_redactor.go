package daemon

import (
	"regexp"
	"sort"

	"claw-wrap/internal/config"
)

const defaultRedactionOverlapBytes = 128

type outputRedactionRule struct {
	replace []byte
	re      *regexp.Regexp
}

// OutputRedactor applies regex-based output redaction with bounded overlap
// so matches can be detected across chunk boundaries.
type OutputRedactor struct {
	rules   []outputRedactionRule
	carry   []byte
	overlap int
}

// NewOutputRedactor builds a streaming redactor from validated tool rules.
func NewOutputRedactor(rules []config.ToolRedactRule) *OutputRedactor {
	if len(rules) == 0 {
		return nil
	}

	compiled := make([]outputRedactionRule, 0, len(rules))
	for _, r := range rules {
		if r.Compiled == nil {
			continue
		}
		compiled = append(compiled, outputRedactionRule{
			re:      r.Compiled,
			replace: []byte(r.Replace),
		})
	}

	if len(compiled) == 0 {
		return nil
	}

	return &OutputRedactor{
		rules:   compiled,
		overlap: defaultRedactionOverlapBytes,
	}
}

// minSecretRedactLength is the shortest injected credential value that is
// redacted literally. Shorter values ("1", "true") would mangle unrelated output.
const minSecretRedactLength = 8

// NewOutputRedactorWithSecrets builds a redactor from the tool's rules plus a
// literal rule for every injected credential value, so a tool that echoes its
// own secret (debug output, error messages) cannot hand it to the caller.
func NewOutputRedactorWithSecrets(rules []config.ToolRedactRule, secrets []string) *OutputRedactor {
	r := NewOutputRedactor(rules)

	seen := make(map[string]bool, len(secrets))
	literals := make([]string, 0, len(secrets))
	for _, s := range secrets {
		if len(s) < minSecretRedactLength || seen[s] {
			continue
		}
		seen[s] = true
		literals = append(literals, s)
	}
	if len(literals) == 0 {
		return r
	}
	// Longest first, so a secret containing another is replaced whole.
	sort.Slice(literals, func(i, j int) bool { return len(literals[i]) > len(literals[j]) })

	if r == nil {
		r = &OutputRedactor{overlap: defaultRedactionOverlapBytes}
	}
	// Literal secrets run before the tool's own rules: a user regex that
	// rewrites part of a secret would otherwise leave a fragment the literal
	// no longer matches.
	replace := []byte(config.DefaultRedactReplacement)
	secretRules := make([]outputRedactionRule, 0, len(literals))
	for _, s := range literals {
		secretRules = append(secretRules, outputRedactionRule{
			re:      regexp.MustCompile(regexp.QuoteMeta(s)),
			replace: replace,
		})
		// The carry must hold all but the last byte of a secret for matches
		// that span chunk boundaries.
		if len(s) > r.overlap {
			r.overlap = len(s)
		}
	}
	r.rules = append(secretRules, r.rules...)
	return r
}

// RedactChunk redacts one output chunk. When finalize is false it keeps a
// bounded carry to catch matches that span chunk boundaries.
func (r *OutputRedactor) RedactChunk(data []byte, finalize bool) []byte {
	if r == nil {
		return data
	}

	if len(data) == 0 && !finalize {
		return nil
	}

	combinedLen := len(r.carry) + len(data)
	if combinedLen == 0 {
		return nil
	}

	combined := make([]byte, 0, combinedLen)
	combined = append(combined, r.carry...)
	combined = append(combined, data...)

	redacted := combined
	for _, rule := range r.rules {
		if len(redacted) == 0 {
			break
		}
		if !rule.re.Match(redacted) {
			continue
		}
		redacted = rule.re.ReplaceAll(redacted, rule.replace)
	}

	if finalize {
		r.carry = r.carry[:0]
		return redacted
	}

	if len(redacted) <= r.overlap {
		r.carry = append(r.carry[:0], redacted...)
		return nil
	}

	emitLen := len(redacted) - r.overlap
	r.carry = append(r.carry[:0], redacted[emitLen:]...)
	return redacted[:emitLen]
}
