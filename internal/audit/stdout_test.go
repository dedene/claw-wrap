package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"claw-wrap/internal/config"
)

func TestNew_StdoutLoggerWritesJSONL(t *testing.T) {
	var buf bytes.Buffer
	orig := stdoutWriter
	stdoutWriter = &buf
	t.Cleanup(func() { stdoutWriter = orig })

	l, err := New(&config.AuditConfig{Enabled: true, Stdout: true})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := l.Log(Entry{Tool: "gh", Args: []string{"<b>"}}); err != nil {
		t.Fatalf("Log() error = %v", err)
	}
	// Closing must not close the process's stdout.
	if err := l.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	line := strings.TrimSpace(buf.String())
	var got Entry
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("stdout is not one JSON line: %q: %v", line, err)
	}
	if got.Tool != "gh" || got.Args[0] != "<b>" {
		t.Fatalf("entry = %+v", got)
	}
}

func TestValidateAudit_StdoutIsAnOutput(t *testing.T) {
	cfg := &config.Config{Audit: &config.AuditConfig{Enabled: true, Stdout: true}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}
