package daemon

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"claw-wrap/internal/config"
	"claw-wrap/internal/protocol"
)

// mockSendFn captures messages sent by OutputBuffer.
func mockSendFn(messages *[]interface{}) func(interface{}) error {
	return func(msg interface{}) error {
		*messages = append(*messages, msg)
		return nil
	}
}

func decodeInlineOutput(t *testing.T, msgs []interface{}) string {
	t.Helper()

	var out bytes.Buffer
	for _, raw := range msgs {
		msg, ok := raw.(protocol.ResponseMessage)
		if !ok {
			continue
		}
		if msg.Type != protocol.MsgTypeStdout && msg.Type != protocol.MsgTypeStderr {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(msg.Data)
		if err != nil {
			t.Fatalf("DecodeString() error = %v", err)
		}
		out.Write(decoded)
	}

	return out.String()
}

func compiledRedactRule(pattern, replace string) config.ToolRedactRule {
	return config.ToolRedactRule{
		Pattern:  pattern,
		Replace:  replace,
		Compiled: regexp.MustCompile(pattern),
	}
}

func TestOutputBuffer_TempFilePermissions(t *testing.T) {
	// Key security test: temp files must be 0600
	var msgs []interface{}
	buf := NewOutputBuffer("stdout", 10, 0, mockSendFn(&msgs))

	// Write enough to trigger file mode (> 10 bytes threshold)
	data := []byte("this exceeds the threshold definitely")
	if err := buf.Write(data); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	path, err := buf.Finalize()
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	if path == "" {
		t.Fatal("Finalize() returned empty path, expected file mode")
	}
	defer buf.Cleanup()

	// Check file permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v", path, err)
	}
	mode := info.Mode().Perm()
	if mode != 0o600 {
		t.Errorf("temp file mode = %o, want 0600", mode)
	}
}

func TestOutputBuffer_InlineMode(t *testing.T) {
	var msgs []interface{}
	buf := NewOutputBuffer("stdout", 1024, 0, mockSendFn(&msgs))

	// Write small data (stays inline)
	if err := buf.Write([]byte("hello")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	path, err := buf.Finalize()
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	if path != "" {
		t.Errorf("Finalize() returned path %q, want empty (inline mode)", path)
	}

	// Should have sent a message
	if len(msgs) == 0 {
		t.Error("expected at least one inline message sent")
	}

	// Verify the message is a ResponseMessage with correct stream type
	if msg, ok := msgs[0].(protocol.ResponseMessage); ok {
		if msg.Type != "stdout" {
			t.Errorf("message type = %q, want stdout", msg.Type)
		}
	}
}

func TestOutputBuffer_SwitchToFileMode(t *testing.T) {
	var msgs []interface{}
	buf := NewOutputBuffer("stderr", 10, 0, mockSendFn(&msgs))

	// Write data exceeding threshold
	if err := buf.Write([]byte("exceeds threshold")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	path, err := buf.Finalize()
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	if path == "" {
		t.Fatal("expected file path after exceeding threshold")
	}
	defer buf.Cleanup()

	// Verify file exists and has content
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	if string(content) != "exceeds threshold" {
		t.Errorf("file content = %q, want %q", content, "exceeds threshold")
	}
}

func TestOutputBuffer_Cleanup(t *testing.T) {
	var msgs []interface{}
	buf := NewOutputBuffer("stdout", 10, 0, mockSendFn(&msgs))

	buf.Write([]byte("exceeds threshold"))
	path, _ := buf.Finalize()

	// File should exist
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file should exist before cleanup: %v", err)
	}

	// First cleanup
	buf.Cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file should be removed after cleanup")
	}

	// Second cleanup should not panic (idempotent)
	buf.Cleanup()
}

func TestOutputBuffer_EmptyWrite(t *testing.T) {
	var msgs []interface{}
	buf := NewOutputBuffer("stdout", 1024, 0, mockSendFn(&msgs))

	// Empty write should be a no-op
	if err := buf.Write([]byte{}); err != nil {
		t.Fatalf("Write(empty) error = %v", err)
	}
	if err := buf.Write(nil); err != nil {
		t.Fatalf("Write(nil) error = %v", err)
	}

	if len(msgs) != 0 {
		t.Errorf("expected no messages for empty writes, got %d", len(msgs))
	}
}

func TestOutputBuffer_MaxOutputSize_Exceeded(t *testing.T) {
	var msgs []interface{}
	buf := NewOutputBuffer("stdout", 1024, 50, mockSendFn(&msgs))

	// First write under limit
	if err := buf.Write([]byte("hello")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	// Second write exceeds 50-byte limit
	err := buf.Write(make([]byte, 50))
	if err == nil {
		t.Fatal("Write() should return error when limit exceeded")
	}
	if !errors.Is(err, ErrOutputLimitExceeded) {
		t.Errorf("Write() error = %v, want ErrOutputLimitExceeded", err)
	}
}

func TestOutputBuffer_MaxOutputSize_ExactLimit(t *testing.T) {
	var msgs []interface{}
	buf := NewOutputBuffer("stdout", 1024, 10, mockSendFn(&msgs))

	// Write exactly at limit — should succeed
	if err := buf.Write([]byte("0123456789")); err != nil {
		t.Fatalf("Write() error = %v (should succeed at exact limit)", err)
	}

	// One more byte should fail
	err := buf.Write([]byte("x"))
	if !errors.Is(err, ErrOutputLimitExceeded) {
		t.Errorf("Write() error = %v, want ErrOutputLimitExceeded", err)
	}
}

func TestOutputBuffer_MaxOutputSize_Zero_Unlimited(t *testing.T) {
	var msgs []interface{}
	buf := NewOutputBuffer("stdout", 1024, 0, mockSendFn(&msgs))

	// With maxOutputSize=0, no limit — large writes should succeed
	if err := buf.Write(make([]byte, 500)); err != nil {
		t.Fatalf("Write() error = %v, want nil (unlimited)", err)
	}
	if err := buf.Write(make([]byte, 500)); err != nil {
		t.Fatalf("Write() error = %v, want nil (unlimited)", err)
	}
}

func TestOutputBuffer_MaxOutputSize_FileMode(t *testing.T) {
	var msgs []interface{}
	// threshold=10, maxOutputSize=30 → first write triggers file mode, second exceeds limit
	buf := NewOutputBuffer("stdout", 10, 30, mockSendFn(&msgs))

	// First write exceeds inline threshold (10) but under output limit (30)
	if err := buf.Write([]byte("twenty chars here!!!")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	// Second write pushes past 30-byte output limit
	err := buf.Write([]byte("more data here"))
	if !errors.Is(err, ErrOutputLimitExceeded) {
		t.Errorf("Write() error = %v, want ErrOutputLimitExceeded", err)
	}

	buf.Cleanup()
}

func TestOutputBuffer_Tee_InlineMode(t *testing.T) {
	var msgs []interface{}
	var teeBuf bytes.Buffer
	buf := NewOutputBuffer("stdout", 1024, 0, mockSendFn(&msgs))
	buf.SetTee(&teeBuf)

	buf.Write([]byte("hello"))
	buf.Write([]byte(" world"))

	if got := teeBuf.String(); got != "hello world" {
		t.Errorf("tee got %q, want %q", got, "hello world")
	}
}

func TestOutputBuffer_Tee_FileMode(t *testing.T) {
	var msgs []interface{}
	var teeBuf bytes.Buffer
	buf := NewOutputBuffer("stdout", 10, 0, mockSendFn(&msgs))
	buf.SetTee(&teeBuf)

	data := []byte("this exceeds the threshold definitely")
	buf.Write(data)

	if got := teeBuf.Bytes(); !bytes.Equal(got, data) {
		t.Errorf("tee got %d bytes, want %d", len(got), len(data))
	}
	buf.Cleanup()
}

func TestOutputBuffer_Tee_SHA256(t *testing.T) {
	var msgs []interface{}
	h := sha256.New()
	buf := NewOutputBuffer("stdout", 1024, 0, mockSendFn(&msgs))
	buf.SetTee(h)

	buf.Write([]byte("hello"))
	buf.Write([]byte(" world"))

	expected := sha256.Sum256([]byte("hello world"))
	if got := h.Sum(nil); !bytes.Equal(got, expected[:]) {
		t.Error("SHA256 hash mismatch")
	}
}

func TestOutputBuffer_Accumulated(t *testing.T) {
	var msgs []interface{}
	buf := NewOutputBuffer("stdout", 1024, 0, mockSendFn(&msgs))

	if got := buf.Accumulated(); got != 0 {
		t.Errorf("Accumulated() = %d, want 0", got)
	}

	buf.Write([]byte("hello"))
	if got := buf.Accumulated(); got != 5 {
		t.Errorf("Accumulated() = %d, want 5", got)
	}

	buf.Write([]byte(" world"))
	if got := buf.Accumulated(); got != 11 {
		t.Errorf("Accumulated() = %d, want 11", got)
	}
}

func TestOutputBuffer_RedactOutput_Inline(t *testing.T) {
	var msgs []interface{}
	buf := NewOutputBuffer("stdout", 1024, 0, mockSendFn(&msgs))
	buf.SetRedactor(NewOutputRedactor([]config.ToolRedactRule{
		compiledRedactRule(`ghp_[A-Za-z0-9]{36}`, "[REDACTED:github-pat]"),
	}))

	secret := "ghp_" + strings.Repeat("A", 36)
	if err := buf.Write([]byte("token=" + secret + "\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if _, err := buf.Finalize(); err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}

	got := decodeInlineOutput(t, msgs)
	if got != "token=[REDACTED:github-pat]\n" {
		t.Fatalf("inline redaction output = %q", got)
	}
}

func TestOutputBuffer_RedactOutput_FileMode(t *testing.T) {
	var msgs []interface{}
	buf := NewOutputBuffer("stdout", 10, 0, mockSendFn(&msgs))
	buf.SetRedactor(NewOutputRedactor([]config.ToolRedactRule{
		compiledRedactRule(`sk-[A-Za-z0-9]{48}`, "[REDACTED:openai-key]"),
	}))

	secret := "sk-" + strings.Repeat("A", 48)
	if err := buf.Write([]byte("api_key=" + secret + "\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	path, err := buf.Finalize()
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	if path == "" {
		t.Fatal("Finalize() returned empty path, expected file mode")
	}
	defer buf.Cleanup()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if got := string(content); got != "api_key=[REDACTED:openai-key]\n" {
		t.Fatalf("file redaction output = %q", got)
	}
}

func TestOutputBuffer_RedactOutput_AcrossChunks(t *testing.T) {
	var msgs []interface{}
	buf := NewOutputBuffer("stdout", 4096, 0, mockSendFn(&msgs))
	buf.SetRedactor(NewOutputRedactor([]config.ToolRedactRule{
		compiledRedactRule(`ghp_[A-Za-z0-9]{36}`, "[REDACTED:github-pat]"),
	}))

	part1 := "ghp_ABCDEFGHIJKLMN"
	part2 := "OPQRSTUVWXYZ0123456789"

	if err := buf.Write([]byte("token=" + part1)); err != nil {
		t.Fatalf("first Write() error = %v", err)
	}
	if err := buf.Write([]byte(part2 + "\n")); err != nil {
		t.Fatalf("second Write() error = %v", err)
	}
	if _, err := buf.Finalize(); err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}

	got := decodeInlineOutput(t, msgs)
	if got != "token=[REDACTED:github-pat]\n" {
		t.Fatalf("cross-chunk redaction output = %q", got)
	}
}

func TestOutputBuffer_RedactOutput_NoLeakAtEmitBoundary(t *testing.T) {
	var msgs []interface{}
	buf := NewOutputBuffer("stdout", 4096, 0, mockSendFn(&msgs))
	buf.SetRedactor(NewOutputRedactor([]config.ToolRedactRule{
		compiledRedactRule(`ghp_[A-Za-z0-9]{36}`, "[REDACTED:github-pat]"),
	}))

	secret := "ghp_" + strings.Repeat("A", 36)
	payload := strings.Repeat("A", 70) + secret + strings.Repeat("B", 80) + "\n"

	if err := buf.Write([]byte(payload)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if _, err := buf.Finalize(); err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}

	got := decodeInlineOutput(t, msgs)
	if strings.Contains(got, "ghp_") {
		t.Fatalf("output leaked PAT marker: %q", got)
	}
	if strings.Count(got, "[REDACTED:github-pat]") != 1 {
		t.Fatalf("output replacement count mismatch: %q", got)
	}
}
