//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"claw-wrap/internal/protocol"
)

func TestHandleWrapperMessage_CleanupIsNoop(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "keep.txt")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	executor := &ToolExecutor{}
	msg := &protocol.WrapperMessage{Type: protocol.MsgTypeCleanup, Files: []string{target}}
	if err := executor.handleWrapperMessage(msg); err != nil {
		t.Fatalf("handleWrapperMessage cleanup: %v", err)
	}

	if _, err := os.Stat(target); err != nil {
		t.Fatalf("cleanup must not remove arbitrary paths: %v", err)
	}
}
