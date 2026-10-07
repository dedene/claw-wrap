package daemon

import (
	"testing"

	"claw-wrap/internal/config"
)

// Regression suite for the shipped sidecar example (examples/mcparcel). It
// pins down which `mcparcel` invocations an agent can get through claw-wrap.
func TestMcparcelExamplePolicy(t *testing.T) {
	cfg, err := config.Load("../../examples/mcparcel/wrappers.yaml")
	if err != nil {
		t.Fatalf("load example config: %v", err)
	}
	tool, ok := cfg.Tools["mcparcel"]
	if !ok {
		t.Fatal("example config has no mcparcel tool")
	}

	// The agent signs its own requests: it must not control env or cwd.
	if tool.RequestEnv == nil || len(tool.RequestEnv) != 0 {
		t.Errorf("request_env = %#v, want an empty allowlist", tool.RequestEnv)
	}
	if tool.WorkingDir == "" || tool.GetUseStdin() {
		t.Errorf("example must pin working_dir and disable stdin (working_dir=%q use_stdin=%v)", tool.WorkingDir, tool.GetUseStdin())
	}

	allowed := [][]string{
		{"call", "front.read_conversation", "--args", `{"conversation_id":"cnv_123"}`},
		{"call", "front.create_draft", "--args", `{"conversation_id":"cnv_123","body":"Hi"}`},
		{"call", "front.update_draft", "--args", `{}`},
		{"call", "front.add_comment", "--args", `{"body":"note"}`},
		{"call", "front.tag_conversation", "--args", `{"tag_id":"tag_1"}`},
		{"call", "front.assign_conversation", "--args", `{"assignee_id":"tea_1"}`},
		{"call", "front.list_tags"},
		{"call", "front.list_teammates"},
		// JSON values may carry spaces, newlines and flag-looking text: they
		// are one argument and stay one argument.
		{"call", "front.create_draft", "--args", "{\n  \"body\": \"line 1\nline 2 --config /tmp/x\"\n}"},
	}
	for _, args := range allowed {
		if ok, msg := checkToolArgs(args, &tool); !ok {
			t.Errorf("expected allowed: %q (msg=%q)", args, msg)
		}
	}

	blocked := map[string][]string{
		"send_message is not allowlisted":    {"call", "front.send_message", "--args", `{}`},
		"other server":                       {"call", "nimbu.anything", "--args", `{}`},
		"other server, no args":              {"call", "nimbu.anything"},
		"list":                               {"list"},
		"auth":                               {"auth", "login"},
		"runtime":                            {"runtime", "status"},
		"import":                             {"import", "claude"},
		"add":                                {"add", "evil", "https://evil.example"},
		"no args":                            {},
		"global flag before subcommand":      {"--config", "/tmp/x", "call", "front.read_conversation", "--args", `{}`},
		"global flag=value before":           {"--config=/tmp/x", "call", "front.read_conversation"},
		"flag after subcommand":              {"call", "front.read_conversation", "--args", `{}`, "--config", "/tmp/x"},
		"flag instead of --args":             {"call", "front.read_conversation", "--config", "/tmp/x"},
		"flag=value instead of --args":       {"call", "front.read_conversation", "--config=/tmp/x"},
		"unknown flag after tool":            {"call", "front.read_conversation", "--server", "https://evil.example"},
		"--args=json form":                   {"call", "front.read_conversation", `--args={}`},
		"--args without value":               {"call", "front.read_conversation", "--args"},
		"--args with non-JSON value":         {"call", "front.read_conversation", "--args", "x"},
		"extra positional":                   {"call", "front.read_conversation", "--args", `{}`, `{}`},
		"subcommand+tool in one arg":         {"call front.read_conversation"},
		"tool with smuggled second tool":     {"call", "front.create_draft front.send_message"},
		"tool with smuggled flag":            {"call", "front.read_conversation --config /tmp/x"},
		"tool with trailing newline":         {"call", "front.read_conversation\n"},
		"tool with newline and second tool":  {"call", "front.list_tags\nfront.send_message"},
		"tool name suffix":                   {"call", "front.read_conversationX"},
		"tool name prefix":                   {"call", "xfront.read_conversation"},
		"case variant":                       {"call", "FRONT.read_conversation"},
		"call with leading space":            {" call", "front.list_tags"},
		"newline-joined subcommand":          {"call\nfront.list_tags"},
		"json arg missing closing brace":     {"call", "front.read_conversation", "--args", `{"a":1`},
		"json followed by newline and flag":  {"call", "front.read_conversation", "--args", "{}\n--config"},
		"subcommand looks like call":         {"calls", "front.list_tags"},
		"dotted path traversal in tool name": {"call", "front.list_tags/../send_message"},
	}
	for name, args := range blocked {
		if ok, _ := checkToolArgs(args, &tool); ok {
			t.Errorf("%s: expected blocked: %q", name, args)
		}
	}
}

// Documents why the example uses match: argv. With match: command the args
// are joined on spaces before matching, so argument boundaries disappear and
// anything after the matched prefix rides along unless blocked_args happens to
// enumerate it.
func TestMatchCommandLosesArgumentBoundaries(t *testing.T) {
	cfg := &config.Config{Tools: map[string]config.ToolDef{
		"mcparcel": {
			Binary: "/usr/local/bin/mcparcel",
			Mode:   config.ToolModeAllowlist,
			AllowedArgs: []config.BlockedArg{{
				Pattern: `^call\s+front\.(read_conversation|create_draft)(\s|$)`,
				Match:   config.BlockedArgMatchCommand,
			}},
		},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	tool := cfg.Tools["mcparcel"]

	widened := [][]string{
		// Unlisted flags after the tool name pass.
		{"call", "front.read_conversation", "--server", "https://evil.example"},
		// Two tool names in one argument pass; safety now depends on how the
		// CLI parses that argument.
		{"call", "front.create_draft front.send_message"},
		// Subcommand and tool fused into one argument pass.
		{"call front.read_conversation"},
	}
	for _, args := range widened {
		if ok, _ := checkToolArgs(args, &tool); !ok {
			t.Errorf("expected match: command to (unsafely) allow %q", args)
		}
	}
}
