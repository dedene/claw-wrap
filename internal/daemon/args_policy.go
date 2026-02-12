package daemon

import (
	"log"
	"strings"

	"claw-wrap/internal/config"
)

// checkToolArgs is the unified entry point for arg policy enforcement.
// It checks blocked_args first (deny-first), then allowed_args if in allowlist mode.
func checkToolArgs(args []string, tool *config.ToolDef) (bool, string) {
	// Step 1: always check blocked_args (any match → deny).
	if allowed, msg := checkBlockedArgs(args, tool.BlockedArgs); !allowed {
		return false, msg
	}

	// Step 2: if allowlist mode, require at least one allowed_args match.
	if tool.Mode == config.ToolModeAllowlist && len(tool.AllowedArgs) > 0 {
		if allowed, msg := checkAllowedArgs(args, tool.AllowedArgs); !allowed {
			return false, msg
		}
	}

	return true, ""
}

func checkBlockedArgs(args []string, blocked []config.BlockedArg) (bool, string) {
	if len(blocked) == 0 {
		return true, ""
	}

	joinedArgs := strings.Join(args, " ")

	for _, b := range blocked {
		if b.Compiled == nil {
			log.Printf("[ERROR] nil compiled pattern for %q - fail-closed", b.Pattern)
			return false, "internal error: invalid security pattern"
		}

		switch b.Match {
		case "", config.BlockedArgMatchArg:
			for _, arg := range args {
				if b.Compiled.MatchString(arg) {
					return false, blockedArgMessage(b.Message)
				}
			}
		case config.BlockedArgMatchCommand:
			if b.Compiled.MatchString(joinedArgs) {
				return false, blockedArgMessage(b.Message)
			}
		default:
			log.Printf("[ERROR] invalid blocked_args match mode %q - fail-closed", b.Match)
			return false, "internal error: invalid security pattern"
		}
	}

	return true, ""
}

func blockedArgMessage(msg string) string {
	if msg == "" {
		return "operation blocked by security policy"
	}
	return msg
}

// checkAllowedArgs returns (true, "") if ANY pattern matches; (false, msg) if none match.
func checkAllowedArgs(args []string, allowed []config.BlockedArg) (bool, string) {
	if len(allowed) == 0 {
		return true, ""
	}

	joinedArgs := strings.Join(args, " ")

	for _, a := range allowed {
		if a.Compiled == nil {
			log.Printf("[ERROR] nil compiled pattern for allowed_args %q - fail-closed", a.Pattern)
			return false, "internal error: invalid security pattern"
		}

		switch a.Match {
		case "", config.BlockedArgMatchArg:
			for _, arg := range args {
				if a.Compiled.MatchString(arg) {
					return true, ""
				}
			}
		case config.BlockedArgMatchCommand:
			if a.Compiled.MatchString(joinedArgs) {
				return true, ""
			}
		default:
			log.Printf("[ERROR] invalid allowed_args match mode %q - fail-closed", a.Match)
			return false, "internal error: invalid security pattern"
		}
	}

	// No allowed pattern matched.
	return false, allowedArgMessage(allowed)
}

func allowedArgMessage(allowed []config.BlockedArg) string {
	for _, a := range allowed {
		if a.Message != "" {
			return a.Message
		}
	}
	return "operation not in allowlist"
}
