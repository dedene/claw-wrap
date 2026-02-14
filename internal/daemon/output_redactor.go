package daemon

import (
	"regexp"

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
