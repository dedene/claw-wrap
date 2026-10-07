package daemon

import (
	"bytes"
	"regexp"
	"sort"

	"claw-wrap/internal/config"
)

const defaultRedactionOverlapBytes = 128

type outputRedactionRule struct {
	replace []byte
	re      *regexp.Regexp
}

// OutputRedactor redacts streamed tool output in two stages:
//
//  1. Literal secrets (injected credential values). Only the trailing bytes
//     that could still be the start of a secret are held back; everything
//     else is released at once, so prompts without a newline stay visible.
//  2. Regex rules from redact_output, with a bounded overlap carry so matches
//     spanning chunks are found. They only see stage-1 output, which never
//     contains part of a secret that is still arriving.
type OutputRedactor struct {
	secrets     [][]byte // longest first
	secretCarry []byte

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
		r = &OutputRedactor{}
	}
	for _, lit := range literals {
		r.secrets = append(r.secrets, []byte(lit))
	}
	return r
}

// RedactChunk redacts one output chunk. When finalize is false it may keep
// a carry to catch matches that span chunk boundaries.
func (r *OutputRedactor) RedactChunk(data []byte, finalize bool) []byte {
	if r == nil {
		return data
	}

	if len(r.secrets) > 0 {
		data = r.redactSecrets(data, finalize)
	}
	if len(r.rules) == 0 {
		return data
	}
	return r.redactRules(data, finalize)
}

// redactSecrets replaces literal secrets and holds back only a trailing
// partial match.
func (r *OutputRedactor) redactSecrets(data []byte, finalize bool) []byte {
	buf := append(r.secretCarry, data...)
	r.secretCarry = nil
	if len(buf) == 0 {
		return nil
	}

	replace := []byte(config.DefaultRedactReplacement)
	out := make([]byte, 0, len(buf))
	for i := 0; i < len(buf); {
		rest := buf[i:]
		// A tail that is a proper prefix of a secret might complete in the
		// next chunk. Wait for it, even if a shorter secret already matches.
		if !finalize && r.isSecretPrefix(rest) {
			r.secretCarry = append([]byte(nil), rest...)
			break
		}
		if n := r.matchSecret(rest); n > 0 {
			out = append(out, replace...)
			i += n
			continue
		}
		out = append(out, buf[i])
		i++
	}
	return out
}

// isSecretPrefix reports whether b is a proper prefix of any secret.
func (r *OutputRedactor) isSecretPrefix(b []byte) bool {
	for _, s := range r.secrets {
		if len(b) < len(s) && bytes.HasPrefix(s, b) {
			return true
		}
	}
	return false
}

// matchSecret returns the length of the longest secret b starts with, or 0.
func (r *OutputRedactor) matchSecret(b []byte) int {
	for _, s := range r.secrets { // longest first
		if bytes.HasPrefix(b, s) {
			return len(s)
		}
	}
	return 0
}

// redactRules applies the regex rules with a bounded overlap carry.
func (r *OutputRedactor) redactRules(data []byte, finalize bool) []byte {
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
