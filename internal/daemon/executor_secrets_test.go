package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"claw-wrap/internal/audit"
	"claw-wrap/internal/config"
	"claw-wrap/internal/protocol"
)

type captureAudit struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (c *captureAudit) Log(e audit.Entry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, e)
	return nil
}

func (c *captureAudit) Close() error { return nil }

// A credential mapped into the tool env reaches the tool, but never the
// wrapper's output or the audit log, even when the tool prints it.
func TestExecutor_CredentialEnvIsRedactedAndNotAudited(t *testing.T) {
	const secret = "front-client-secret-0123456789"
	secretPath := filepath.Join(t.TempDir(), "front-client-secret")
	if err := os.WriteFile(secretPath, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Credentials: map[string]config.CredentialDef{
			"front_client_secret": {Source: "file:" + secretPath},
		},
		Audit: &config.AuditConfig{Enabled: true, Stdout: true},
	}
	tool := helperTool("env")
	tool.Env["FRONT_CLIENT_SECRET"] = "front_client_secret"

	logger := &captureAudit{}
	res := runHelperToolWith(t, tool, protocol.ProxyRequest{Args: []string{"FRONT_CLIENT_SECRET"}}, cfg, logger)

	if res.errMsg != "" || res.exitCode != 0 {
		t.Fatalf("exit=%d err=%q stderr=%q", res.exitCode, res.errMsg, res.stderr)
	}
	if res.stdout != config.DefaultRedactReplacement {
		t.Fatalf("stdout = %q, want the secret redacted", res.stdout)
	}

	if len(logger.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(logger.entries))
	}
	raw, _ := json.Marshal(logger.entries[0])
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "FRONT_CLIENT_SECRET=") {
		t.Fatalf("audit entry leaks the credential: %s", raw)
	}
}

func TestOutputRedactor_SecretAcrossChunkBoundary(t *testing.T) {
	secret := strings.Repeat("s3cr3t", 50) // 300 bytes, longer than the default overlap
	r := NewOutputRedactorWithSecrets(nil, []string{secret})

	input := "head " + secret + " tail"
	var out strings.Builder
	// Feed in small chunks so the secret is split across many of them.
	for i := 0; i < len(input); i += 7 {
		end := i + 7
		if end > len(input) {
			end = len(input)
		}
		out.Write(r.RedactChunk([]byte(input[i:end]), false))
	}
	out.Write(r.RedactChunk(nil, true))

	if got := out.String(); got != "head [REDACTED] tail" {
		t.Fatalf("redacted output = %q", got)
	}
}

func TestOutputRedactor_IgnoresShortSecrets(t *testing.T) {
	// Very short values (e.g. "1", "true") would mangle unrelated output.
	if r := NewOutputRedactorWithSecrets(nil, []string{"abc", ""}); r != nil {
		t.Fatal("expected no redactor for values below the minimum length")
	}
}

// A tool rule that rewrites part of a secret must not leave a fragment behind.
func TestOutputRedactor_SecretsBeforeToolRules(t *testing.T) {
	cfg := &config.Config{Tools: map[string]config.ToolDef{
		"t": {Binary: "/usr/bin/true", RedactOutput: []config.ToolRedactRule{{Pattern: "tok", Replace: "***"}}},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	r := NewOutputRedactorWithSecrets(cfg.Tools["t"].RedactOutput, []string{"tok_live_123456"})
	got := string(r.RedactChunk([]byte("key=tok_live_123456"), true))
	if got != "key=[REDACTED]" {
		t.Fatalf("redacted = %q, want key=[REDACTED]", got)
	}
}
