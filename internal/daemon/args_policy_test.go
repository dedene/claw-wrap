package daemon

import (
	"regexp"
	"testing"

	"claw-wrap/internal/config"
)

// --- checkAllowedArgs tests ---

func TestCheckAllowedArgs_MatchAllows(t *testing.T) {
	allowed := []config.BlockedArg{
		{Pattern: `^(repo|issue|pr)\s+(list|view|status)`, Match: config.BlockedArgMatchCommand, Compiled: regexp.MustCompile(`^(repo|issue|pr)\s+(list|view|status)`)},
	}

	ok, msg := checkAllowedArgs([]string{"repo", "list"}, allowed)
	if !ok {
		t.Fatalf("checkAllowedArgs() denied, want allowed; msg=%s", msg)
	}
}

func TestCheckAllowedArgs_NoMatchDenies(t *testing.T) {
	allowed := []config.BlockedArg{
		{Pattern: `^(repo|issue|pr)\s+(list|view|status)`, Match: config.BlockedArgMatchCommand, Message: "Only read operations allowed", Compiled: regexp.MustCompile(`^(repo|issue|pr)\s+(list|view|status)`)},
	}

	ok, msg := checkAllowedArgs([]string{"repo", "delete", "my-repo"}, allowed)
	if ok {
		t.Fatal("checkAllowedArgs() allowed, want denied")
	}
	if msg != "Only read operations allowed" {
		t.Errorf("msg = %q, want %q", msg, "Only read operations allowed")
	}
}

func TestCheckAllowedArgs_DefaultMessage(t *testing.T) {
	allowed := []config.BlockedArg{
		{Pattern: `^safe$`, Compiled: regexp.MustCompile(`^safe$`)},
	}

	ok, msg := checkAllowedArgs([]string{"dangerous"}, allowed)
	if ok {
		t.Fatal("checkAllowedArgs() allowed, want denied")
	}
	if msg != "operation not in allowlist" {
		t.Errorf("msg = %q, want %q", msg, "operation not in allowlist")
	}
}

func TestCheckAllowedArgs_EmptyArgs(t *testing.T) {
	allowed := []config.BlockedArg{
		{Pattern: `^list$`, Compiled: regexp.MustCompile(`^list$`)},
	}

	ok, _ := checkAllowedArgs([]string{}, allowed)
	if ok {
		t.Fatal("checkAllowedArgs() allowed empty args, want denied")
	}

	ok, _ = checkAllowedArgs(nil, allowed)
	if ok {
		t.Fatal("checkAllowedArgs() allowed nil args, want denied")
	}
}

func TestCheckAllowedArgs_NoPatterns(t *testing.T) {
	ok, _ := checkAllowedArgs([]string{"anything"}, nil)
	if !ok {
		t.Fatal("checkAllowedArgs() denied with nil patterns, want allowed")
	}

	ok, _ = checkAllowedArgs([]string{"anything"}, []config.BlockedArg{})
	if !ok {
		t.Fatal("checkAllowedArgs() denied with empty patterns, want allowed")
	}
}

func TestCheckAllowedArgs_MultiplePatterns(t *testing.T) {
	allowed := []config.BlockedArg{
		{Pattern: `^list$`, Message: "read only", Compiled: regexp.MustCompile(`^list$`)},
		{Pattern: `^view$`, Message: "read only", Compiled: regexp.MustCompile(`^view$`)},
	}

	t.Run("first matches", func(t *testing.T) {
		ok, _ := checkAllowedArgs([]string{"list"}, allowed)
		if !ok {
			t.Error("want allowed by first pattern")
		}
	})

	t.Run("second matches", func(t *testing.T) {
		ok, _ := checkAllowedArgs([]string{"view"}, allowed)
		if !ok {
			t.Error("want allowed by second pattern")
		}
	})

	t.Run("neither matches", func(t *testing.T) {
		ok, _ := checkAllowedArgs([]string{"delete"}, allowed)
		if ok {
			t.Error("want denied, no pattern matches")
		}
	})
}

func TestCheckAllowedArgs_CommandMode(t *testing.T) {
	allowed := []config.BlockedArg{
		{Pattern: `^pr\s+view`, Match: config.BlockedArgMatchCommand, Compiled: regexp.MustCompile(`^pr\s+view`)},
	}

	ok, _ := checkAllowedArgs([]string{"pr", "view", "123"}, allowed)
	if !ok {
		t.Fatal("checkAllowedArgs() denied command mode match, want allowed")
	}
}

func TestCheckAllowedArgs_ArgMode(t *testing.T) {
	allowed := []config.BlockedArg{
		{Pattern: `^(list|view|status)$`, Match: config.BlockedArgMatchArg, Compiled: regexp.MustCompile(`^(list|view|status)$`)},
	}

	t.Run("matching arg present", func(t *testing.T) {
		ok, _ := checkAllowedArgs([]string{"repo", "list"}, allowed)
		if !ok {
			t.Error("want allowed — 'list' matches pattern")
		}
	})

	t.Run("no matching arg", func(t *testing.T) {
		ok, _ := checkAllowedArgs([]string{"repo", "delete"}, allowed)
		if ok {
			t.Error("want denied — no arg matches pattern")
		}
	})
}

func TestCheckAllowedArgs_FailClosed_NilCompiled(t *testing.T) {
	allowed := []config.BlockedArg{
		{Pattern: "anything", Compiled: nil},
	}

	ok, msg := checkAllowedArgs([]string{"safe"}, allowed)
	if ok {
		t.Fatal("checkAllowedArgs() allowed with nil Compiled - SECURITY BUG: must fail-closed")
	}
	if msg == "" {
		t.Error("want non-empty message for nil Compiled")
	}
}

func TestCheckAllowedArgs_FailClosed_InvalidMatchMode(t *testing.T) {
	allowed := []config.BlockedArg{
		{Pattern: `safe`, Match: "invalid", Compiled: regexp.MustCompile(`safe`)},
	}

	ok, msg := checkAllowedArgs([]string{"safe"}, allowed)
	if ok {
		t.Fatal("checkAllowedArgs() allowed invalid match mode; must fail-closed")
	}
	if msg == "" {
		t.Error("want non-empty message for invalid match mode")
	}
}

// --- checkToolArgs tests ---

func TestCheckToolArgs_BlocklistModeDefault(t *testing.T) {
	tool := &config.ToolDef{
		Mode: config.ToolModeBlocklist,
		BlockedArgs: []config.BlockedArg{
			{Pattern: `^delete$`, Message: "no delete", Compiled: regexp.MustCompile(`^delete$`)},
		},
	}

	t.Run("blocked", func(t *testing.T) {
		ok, msg := checkToolArgs([]string{"delete"}, tool)
		if ok {
			t.Fatal("want denied")
		}
		if msg != "no delete" {
			t.Errorf("msg = %q, want %q", msg, "no delete")
		}
	})

	t.Run("allowed", func(t *testing.T) {
		ok, _ := checkToolArgs([]string{"list"}, tool)
		if !ok {
			t.Fatal("want allowed")
		}
	})
}

func TestCheckToolArgs_AllowlistOnly(t *testing.T) {
	tool := &config.ToolDef{
		Mode: config.ToolModeAllowlist,
		AllowedArgs: []config.BlockedArg{
			{Pattern: `^(repo|issue|pr)\s+(list|view|status)`, Match: config.BlockedArgMatchCommand, Message: "Only read ops", Compiled: regexp.MustCompile(`^(repo|issue|pr)\s+(list|view|status)`)},
		},
	}

	t.Run("allowed", func(t *testing.T) {
		ok, _ := checkToolArgs([]string{"repo", "list"}, tool)
		if !ok {
			t.Fatal("want allowed")
		}
	})

	t.Run("denied", func(t *testing.T) {
		ok, msg := checkToolArgs([]string{"repo", "delete"}, tool)
		if ok {
			t.Fatal("want denied")
		}
		if msg != "Only read ops" {
			t.Errorf("msg = %q, want %q", msg, "Only read ops")
		}
	})
}

func TestCheckToolArgs_Layered_BlockedTakesPrecedence(t *testing.T) {
	tool := &config.ToolDef{
		Mode: config.ToolModeAllowlist,
		BlockedArgs: []config.BlockedArg{
			{Pattern: `--include-sensitive`, Message: "sensitive flag blocked", Compiled: regexp.MustCompile(`--include-sensitive`)},
		},
		AllowedArgs: []config.BlockedArg{
			{Pattern: `^(repo|issue|pr)\s+(list|view)`, Match: config.BlockedArgMatchCommand, Compiled: regexp.MustCompile(`^(repo|issue|pr)\s+(list|view)`)},
		},
	}

	// Matches allowlist but also matches blocklist → deny
	ok, msg := checkToolArgs([]string{"repo", "list", "--include-sensitive"}, tool)
	if ok {
		t.Fatal("want denied — blocklist takes precedence")
	}
	if msg != "sensitive flag blocked" {
		t.Errorf("msg = %q, want %q", msg, "sensitive flag blocked")
	}
}

func TestCheckToolArgs_Layered_BothPass(t *testing.T) {
	tool := &config.ToolDef{
		Mode: config.ToolModeAllowlist,
		BlockedArgs: []config.BlockedArg{
			{Pattern: `--include-sensitive`, Message: "blocked", Compiled: regexp.MustCompile(`--include-sensitive`)},
		},
		AllowedArgs: []config.BlockedArg{
			{Pattern: `^(repo|issue|pr)\s+(list|view)`, Match: config.BlockedArgMatchCommand, Compiled: regexp.MustCompile(`^(repo|issue|pr)\s+(list|view)`)},
		},
	}

	ok, _ := checkToolArgs([]string{"repo", "list"}, tool)
	if !ok {
		t.Fatal("want allowed — passes both lists")
	}
}

func TestCheckToolArgs_Layered_AllowedRequired(t *testing.T) {
	tool := &config.ToolDef{
		Mode: config.ToolModeAllowlist,
		BlockedArgs: []config.BlockedArg{
			{Pattern: `--include-sensitive`, Message: "blocked", Compiled: regexp.MustCompile(`--include-sensitive`)},
		},
		AllowedArgs: []config.BlockedArg{
			{Pattern: `^(repo|issue|pr)\s+(list|view)`, Match: config.BlockedArgMatchCommand, Message: "read only", Compiled: regexp.MustCompile(`^(repo|issue|pr)\s+(list|view)`)},
		},
	}

	// Passes blocklist, fails allowlist
	ok, msg := checkToolArgs([]string{"repo", "delete"}, tool)
	if ok {
		t.Fatal("want denied — not in allowlist")
	}
	if msg != "read only" {
		t.Errorf("msg = %q, want %q", msg, "read only")
	}
}
