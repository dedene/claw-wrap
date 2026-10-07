package daemon

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"claw-wrap/internal/config"
	"claw-wrap/internal/protocol"
)

// In a sidecar the caller's cwd usually does not exist in the daemon's
// filesystem; working_dir pins the tool's cwd instead.
func TestExecutor_WorkingDirOverridesRequestCwd(t *testing.T) {
	workDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tool := helperTool("pwd")
	tool.WorkingDir = workDir

	cfg := &config.Config{Audit: &config.AuditConfig{Enabled: true, Stdout: true}}
	logger := &captureAudit{}
	res := runHelperToolWith(t, tool, protocol.ProxyRequest{Cwd: "/nonexistent/caller/cwd"}, cfg, logger)
	if res.errMsg != "" {
		t.Fatalf("executor error: %s", res.errMsg)
	}
	if res.stdout != workDir {
		t.Fatalf("tool cwd = %q, want %q", res.stdout, workDir)
	}
	// The audit log records where the tool actually ran.
	if len(logger.entries) != 1 || logger.entries[0].Cwd != workDir {
		t.Fatalf("audit entries = %+v, want cwd %q", logger.entries, workDir)
	}
}

func TestExecutor_MissingRequestCwdRejectedWithoutWorkingDir(t *testing.T) {
	res := runHelperTool(t, helperTool("pwd"), protocol.ProxyRequest{Cwd: "/nonexistent/caller/cwd"})
	if res.errMsg != "invalid working directory" {
		t.Fatalf("errMsg = %q, want %q", res.errMsg, "invalid working directory")
	}
}

// With use_stdin: false a tool that prompts gets EOF immediately, even though
// the wrapper connection (and thus the stdin stream) stays open.
func TestExecutor_UseStdinFalseFailsFastOnPrompt(t *testing.T) {
	tool := helperTool("read-stdin")
	noStdin := false
	tool.UseStdin = &noStdin
	tool.UsePTY = nil

	res := runHelperTool(t, tool, protocol.ProxyRequest{UsePTY: true})
	if res.timeout {
		t.Fatal("tool timed out; stdin should have been /dev/null")
	}
	if res.exitCode != 3 || res.stderr != "no input available" {
		t.Fatalf("exit=%d stderr=%q, want exit 3 with EOF message", res.exitCode, res.stderr)
	}
	if res.elapsed > 2*time.Second {
		t.Fatalf("took %v, want immediate failure", res.elapsed)
	}
}

// Without use_stdin: false a prompting tool waits for input, but the tool
// timeout still bounds it.
func TestExecutor_PromptingToolHitsTimeout(t *testing.T) {
	tool := helperTool("read-stdin")
	tool.Timeout = "1s"

	res := runHelperTool(t, tool, protocol.ProxyRequest{})
	if !res.timeout {
		t.Fatalf("expected timeout, got exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	if res.elapsed > 8*time.Second {
		t.Fatalf("timeout handling took %v", res.elapsed)
	}
}

// The caller signs its own requests, so request env is caller-controlled.
// request_env limits which variables it may set.
func TestExecutor_RequestEnvAllowlist(t *testing.T) {
	req := protocol.ProxyRequest{
		Args: []string{"MCP_SERVER_URL"},
		Env:  map[string]string{"MCP_SERVER_URL": "https://evil.example", "TERM": "xterm"},
	}

	legacy := runHelperTool(t, helperTool("env"), req)
	if legacy.stdout != "https://evil.example" {
		t.Fatalf("without request_env the caller's env passes through (legacy), got %q", legacy.stdout)
	}

	tool := helperTool("env")
	tool.RequestEnv = []string{"TERM"}
	res := runHelperTool(t, tool, req)
	if res.stdout != "" {
		t.Fatalf("MCP_SERVER_URL leaked into the tool: %q", res.stdout)
	}

	req.Args = []string{"TERM"}
	res = runHelperTool(t, tool, req)
	if res.stdout != "xterm" {
		t.Fatalf("allowlisted TERM = %q, want xterm", res.stdout)
	}
}

// Output still buffered in the pipe when the tool exits must survive a client
// that reads slower than the post-exit drain grace.
func TestExecutor_SlowClientDoesNotTruncateOutput(t *testing.T) {
	const size = 90 * 1024
	clientReadDelay = 2 * outputDrainGrace
	t.Cleanup(func() { clientReadDelay = 0 })

	res := runHelperTool(t, helperTool("big-output"), protocol.ProxyRequest{Args: []string{strconv.Itoa(size)}})
	if res.exitCode != 0 {
		t.Fatalf("exit=%d stderr=%q err=%q", res.exitCode, res.stderr, res.errMsg)
	}
	if len(res.stdout) != size {
		t.Fatalf("got %d stdout bytes, want %d", len(res.stdout), size)
	}
}
