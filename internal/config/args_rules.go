package config

import (
	"fmt"
	"regexp"
	"strings"
)

// compileArgRule normalizes the match mode of a blocked_args/allowed_args rule
// and compiles its patterns. field names the list for error messages.
func compileArgRule(rule *BlockedArg, field string, allowArgv bool) error {
	matchMode := strings.TrimSpace(rule.Match)
	if matchMode == "" {
		matchMode = BlockedArgMatchArg
	}

	switch matchMode {
	case BlockedArgMatchArg, BlockedArgMatchCommand:
		if len(rule.Argv) > 0 {
			return fmt.Errorf("%s: argv is only valid with match: argv", field)
		}
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return fmt.Errorf("invalid %s pattern %q: %w", field, rule.Pattern, err)
		}
		rule.Compiled = re

	case BlockedArgMatchArgv:
		if !allowArgv {
			return fmt.Errorf("%s: match %q is only supported in allowed_args", field, BlockedArgMatchArgv)
		}
		if rule.Pattern != "" {
			return fmt.Errorf("%s: use either pattern or argv, not both", field)
		}
		if len(rule.Argv) == 0 {
			return fmt.Errorf("%s: match %q requires a non-empty argv list", field, BlockedArgMatchArgv)
		}
		compiled := make([]*regexp.Regexp, len(rule.Argv))
		for i, p := range rule.Argv {
			// Compile the bare pattern first: only a pattern that is valid on
			// its own is a closed group, so wrapping cannot be escaped with
			// unbalanced parens (e.g. "a)|(.*").
			if _, err := regexp.Compile(p); err != nil {
				return fmt.Errorf("invalid %s argv[%d] %q: %w", field, i, p, err)
			}
			// Anchor every position so a pattern can never match a prefix,
			// suffix, or an argument that smuggles extra words or newlines.
			re, err := regexp.Compile(`^(?:` + p + `)$`)
			if err != nil {
				return fmt.Errorf("invalid %s argv[%d] %q: %w", field, i, p, err)
			}
			compiled[i] = re
		}
		rule.CompiledArgv = compiled

	default:
		valid := fmt.Sprintf("%q or %q", BlockedArgMatchArg, BlockedArgMatchCommand)
		if allowArgv {
			valid = fmt.Sprintf("%q, %q or %q", BlockedArgMatchArg, BlockedArgMatchCommand, BlockedArgMatchArgv)
		}
		return fmt.Errorf("invalid %s match %q (must be %s)", field, rule.Match, valid)
	}

	rule.Match = matchMode
	return nil
}
