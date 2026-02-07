//go:build linux

package daemon

import (
	"os"
	"testing"

	"claw-wrap/internal/protocol"
)

// mockSendFn captures messages sent by OutputBuffer.
func mockSendFn(messages *[]interface{}) func(interface{}) error {
	return func(msg interface{}) error {
		*messages = append(*messages, msg)
		return nil
	}
}

func TestOutputBuffer_TempFilePermissions(t *testing.T) {
	// Key security test: temp files must be 0600
	var msgs []interface{}
	buf := NewOutputBuffer("stdout", 10, mockSendFn(&msgs))

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
	buf := NewOutputBuffer("stdout", 1024, mockSendFn(&msgs))

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
	buf := NewOutputBuffer("stderr", 10, mockSendFn(&msgs))

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
	buf := NewOutputBuffer("stdout", 10, mockSendFn(&msgs))

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
	buf := NewOutputBuffer("stdout", 1024, mockSendFn(&msgs))

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
