package daemon

import (
	"regexp"
	"testing"

	"claw-wrap/internal/config"
)

func TestCheckBlockedArgs_Matches(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		blocked     []config.BlockedArg
		wantAllowed bool
		wantMsg     string
	}{
		{
			name: "exact arg match blocks",
			args: []string{"repo", "delete", "my-repo"},
			blocked: []config.BlockedArg{
				{Pattern: `^delete$`, Message: "no repo delete", Compiled: regexp.MustCompile(`^delete$`)},
			},
			wantAllowed: false,
			wantMsg:     "no repo delete",
		},
		{
			name: "no match allows",
			args: []string{"repo", "list"},
			blocked: []config.BlockedArg{
				{Pattern: `^delete$`, Message: "no repo delete", Compiled: regexp.MustCompile(`^delete$`)},
			},
			wantAllowed: true,
			wantMsg:     "",
		},
		{
			name: "flag pattern blocks",
			args: []string{"push", "--force"},
			blocked: []config.BlockedArg{
				{Pattern: `--force`, Message: "no force push", Compiled: regexp.MustCompile(`--force`)},
			},
			wantAllowed: false,
			wantMsg:     "no force push",
		},
		{
			name: "default message when empty",
			args: []string{"repo", "delete"},
			blocked: []config.BlockedArg{
				{Pattern: `^delete$`, Message: "", Compiled: regexp.MustCompile(`^delete$`)},
			},
			wantAllowed: false,
			wantMsg:     "operation blocked by security policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, msg := checkBlockedArgs(tt.args, tt.blocked)
			if allowed != tt.wantAllowed {
				t.Errorf("checkBlockedArgs() allowed = %v, want %v", allowed, tt.wantAllowed)
			}
			if msg != tt.wantMsg {
				t.Errorf("checkBlockedArgs() msg = %q, want %q", msg, tt.wantMsg)
			}
		})
	}
}

func TestCheckBlockedArgs_NoPatterns(t *testing.T) {
	allowed, msg := checkBlockedArgs([]string{"anything", "goes"}, nil)
	if !allowed {
		t.Error("checkBlockedArgs() blocked with nil patterns")
	}
	if msg != "" {
		t.Errorf("checkBlockedArgs() msg = %q, want empty", msg)
	}

	allowed, msg = checkBlockedArgs([]string{"anything"}, []config.BlockedArg{})
	if !allowed {
		t.Error("checkBlockedArgs() blocked with empty patterns")
	}
	if msg != "" {
		t.Errorf("checkBlockedArgs() msg = %q, want empty", msg)
	}
}

func TestCheckBlockedArgs_MultiplePatterns(t *testing.T) {
	blocked := []config.BlockedArg{
		{Pattern: `^delete$`, Message: "no delete", Compiled: regexp.MustCompile(`^delete$`)},
		{Pattern: `--force`, Message: "no force", Compiled: regexp.MustCompile(`--force`)},
	}

	t.Run("second pattern matches", func(t *testing.T) {
		allowed, msg := checkBlockedArgs([]string{"push", "--force"}, blocked)
		if allowed {
			t.Error("checkBlockedArgs() allowed, want blocked by second pattern")
		}
		if msg != "no force" {
			t.Errorf("checkBlockedArgs() msg = %q, want %q", msg, "no force")
		}
	})

	t.Run("first pattern matches", func(t *testing.T) {
		allowed, msg := checkBlockedArgs([]string{"repo", "delete", "foo"}, blocked)
		if allowed {
			t.Error("checkBlockedArgs() allowed, want blocked by first pattern")
		}
		if msg != "no delete" {
			t.Errorf("checkBlockedArgs() msg = %q, want %q", msg, "no delete")
		}
	})

	t.Run("neither matches", func(t *testing.T) {
		allowed, msg := checkBlockedArgs([]string{"repo", "list"}, blocked)
		if !allowed {
			t.Error("checkBlockedArgs() blocked, want allowed")
		}
		if msg != "" {
			t.Errorf("checkBlockedArgs() msg = %q, want empty", msg)
		}
	})
}

func TestCheckBlockedArgs_EmptyArgs(t *testing.T) {
	blocked := []config.BlockedArg{
		{Pattern: `--force`, Message: "no force", Compiled: regexp.MustCompile(`--force`)},
	}

	allowed, msg := checkBlockedArgs([]string{}, blocked)
	if !allowed {
		t.Error("checkBlockedArgs() blocked with empty args")
	}
	if msg != "" {
		t.Errorf("checkBlockedArgs() msg = %q, want empty", msg)
	}

	allowed, msg = checkBlockedArgs(nil, blocked)
	if !allowed {
		t.Error("checkBlockedArgs() blocked with nil args")
	}
	if msg != "" {
		t.Errorf("checkBlockedArgs() msg = %q, want empty", msg)
	}
}

func TestCheckBlockedArgs_SpecialChars(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		pattern     string
		wantAllowed bool
	}{
		{
			name:        "args with double quotes",
			args:        []string{"--message", `"hello world"`},
			pattern:     `"hello`,
			wantAllowed: false,
		},
		{
			name:        "args with backslash",
			args:        []string{"--path", `C:\Users\test`},
			pattern:     `C:\\Users`,
			wantAllowed: false,
		},
		{
			name:        "args with unicode",
			args:        []string{"--name", "caf\u00e9"},
			pattern:     `caf\x{00e9}`,
			wantAllowed: false,
		},
		{
			name:        "args with single quotes",
			args:        []string{"--eval", "'rm -rf /'"},
			pattern:     `rm\s+-rf`,
			wantAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked := []config.BlockedArg{
				{Pattern: tt.pattern, Message: "blocked", Compiled: regexp.MustCompile(tt.pattern)},
			}
			allowed, _ := checkBlockedArgs(tt.args, blocked)
			if allowed != tt.wantAllowed {
				t.Errorf("checkBlockedArgs() allowed = %v, want %v", allowed, tt.wantAllowed)
			}
		})
	}
}

func TestCheckBlockedArgs_FailClosed(t *testing.T) {
	// Key security test: nil Compiled field must block (fail-closed)
	blocked := []config.BlockedArg{
		{Pattern: "anything", Message: "should block", Compiled: nil},
	}

	allowed, msg := checkBlockedArgs([]string{"harmless", "args"}, blocked)
	if allowed {
		t.Fatal("checkBlockedArgs() allowed with nil Compiled - SECURITY BUG: must fail-closed")
	}
	if msg == "" {
		t.Error("checkBlockedArgs() returned empty message for nil Compiled")
	}
}

func TestCheckBlockedArgs_FailClosed_MixedNilCompiled(t *testing.T) {
	// Valid pattern first, nil pattern second - nil should still block
	blocked := []config.BlockedArg{
		{Pattern: `zzz-no-match`, Message: "won't match", Compiled: regexp.MustCompile(`zzz-no-match`)},
		{Pattern: "broken", Message: "nil compiled", Compiled: nil},
	}

	allowed, msg := checkBlockedArgs([]string{"some", "args"}, blocked)
	if allowed {
		t.Fatal("checkBlockedArgs() allowed with nil Compiled in second entry - must fail-closed")
	}
	if msg == "" {
		t.Error("checkBlockedArgs() returned empty message for nil Compiled")
	}
}

// TestCheckBlockedArgs_PerArgMatching verifies per-arg matching prevents
// bypass via embedded spaces (the old join-with-space vulnerability).
func TestCheckBlockedArgs_PerArgMatching(t *testing.T) {
	blocked := []config.BlockedArg{
		{Pattern: `--force`, Message: "no force", Compiled: regexp.MustCompile(`--force`)},
	}

	t.Run("embedded space bypass attempt", func(t *testing.T) {
		// Old code: strings.Join(["safe --force"], " ") = "safe --force" → matched
		// New code: each arg checked individually → "safe --force" still matches (contains --force)
		allowed, _ := checkBlockedArgs([]string{"safe --force"}, blocked)
		if allowed {
			t.Error("per-arg matching should still detect --force within a single arg")
		}
	})

	t.Run("cross-boundary pattern no longer falsely matches", func(t *testing.T) {
		// Pattern matching across arg boundaries should NOT work with per-arg.
		// e.g., pattern `foo bar` should not match args ["foo", "bar"]
		crossBoundary := []config.BlockedArg{
			{Pattern: `foo bar`, Message: "cross", Compiled: regexp.MustCompile(`foo bar`)},
		}
		allowed, _ := checkBlockedArgs([]string{"foo", "bar"}, crossBoundary)
		if !allowed {
			t.Error("per-arg matching should NOT match pattern across arg boundaries")
		}
	})

	t.Run("pattern within single arg still matches", func(t *testing.T) {
		crossBoundary := []config.BlockedArg{
			{Pattern: `foo bar`, Message: "cross", Compiled: regexp.MustCompile(`foo bar`)},
		}
		// Single arg containing the full pattern should match
		allowed, _ := checkBlockedArgs([]string{"foo bar"}, crossBoundary)
		if allowed {
			t.Error("per-arg matching should match when full pattern is in one arg")
		}
	})
}

func TestCheckBlockedArgs_CommandMode(t *testing.T) {
	blocked := []config.BlockedArg{
		{
			Pattern:  `repo\s+delete`,
			Message:  "no repo delete",
			Match:    config.BlockedArgMatchCommand,
			Compiled: regexp.MustCompile(`repo\s+delete`),
		},
	}

	allowed, msg := checkBlockedArgs([]string{"repo", "delete", "my-repo"}, blocked)
	if allowed {
		t.Fatal("checkBlockedArgs() allowed command mode match; want blocked")
	}
	if msg != "no repo delete" {
		t.Errorf("checkBlockedArgs() msg = %q, want %q", msg, "no repo delete")
	}
}

func TestCheckBlockedArgs_InvalidMatchModeFailClosed(t *testing.T) {
	blocked := []config.BlockedArg{
		{
			Pattern:  `delete`,
			Message:  "blocked",
			Match:    "invalid",
			Compiled: regexp.MustCompile(`delete`),
		},
	}

	allowed, msg := checkBlockedArgs([]string{"delete"}, blocked)
	if allowed {
		t.Fatal("checkBlockedArgs() allowed invalid match mode; must fail-closed")
	}
	if msg == "" {
		t.Error("checkBlockedArgs() returned empty message for invalid match mode")
	}
}
