package daemon

import (
	"encoding/base64"
	"fmt"
	"os"
	"sync"

	"claw-wrap/internal/protocol"
)

// OutputBuffer handles streaming output with threshold-based file fallback.
// When output is below the threshold, data is streamed as base64-encoded chunks.
// When output exceeds the threshold, data is written to a temp file instead.
type OutputBuffer struct {
	stream      string                  // "stdout" or "stderr"
	threshold   int64                   // switch to file above this
	accumulated int64                   // bytes seen so far
	inlineMode  bool                    // true if still streaming inline
	tempFile    *os.File                // nil until threshold exceeded
	tempPath    string                  // path for cleanup/response
	sendFn      func(interface{}) error // sends length-prefixed message
	mu          sync.Mutex
}

// NewOutputBuffer creates a new OutputBuffer for the given stream.
// The stream parameter should be "stdout" or "stderr".
// The threshold specifies the byte limit before switching to file mode.
// The sendFn is called to send ResponseMessage chunks for inline data.
func NewOutputBuffer(stream string, threshold int64, sendFn func(interface{}) error) *OutputBuffer {
	return &OutputBuffer{
		stream:     stream,
		threshold:  threshold,
		inlineMode: true,
		sendFn:     sendFn,
	}
}

// Write handles incoming data.
// If still under threshold: send as base64 chunk immediately.
// If exceeds threshold: switch to temp file mode, write all subsequent data to file.
func (b *OutputBuffer) Write(data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(data) == 0 {
		return nil
	}

	// Check if this write would exceed the threshold
	if b.inlineMode && b.accumulated+int64(len(data)) > b.threshold {
		// Switch to file mode
		if err := b.switchToFileMode(); err != nil {
			return fmt.Errorf("switch to file mode: %w", err)
		}
	}

	if b.inlineMode {
		// Send data as base64-encoded chunk
		msg := protocol.ResponseMessage{
			Type: b.stream,
			Data: base64.StdEncoding.EncodeToString(data),
		}
		if err := b.sendFn(msg); err != nil {
			return fmt.Errorf("send chunk: %w", err)
		}
		b.accumulated += int64(len(data))
	} else {
		// Write to temp file
		if _, err := b.tempFile.Write(data); err != nil {
			return fmt.Errorf("write to temp file: %w", err)
		}
		b.accumulated += int64(len(data))
	}

	return nil
}

// switchToFileMode transitions from inline streaming to file-based buffering.
// This is called when the accumulated data exceeds the threshold.
func (b *OutputBuffer) switchToFileMode() error {
	// Create temp file
	pattern := fmt.Sprintf("claw-wrap-%s-*", b.stream)
	f, err := os.CreateTemp(os.TempDir(), pattern)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	b.tempFile = f
	b.tempPath = f.Name()
	b.inlineMode = false

	return nil
}

// Finalize completes the buffer.
// If inline mode: nothing to do (all data already sent).
// If file mode: close file, return path for "file" message.
// Returns (tempFilePath, error) - tempFilePath is empty if inline mode was used.
func (b *OutputBuffer) Finalize() (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.inlineMode {
		// All data already sent as chunks
		return "", nil
	}

	// Close the temp file
	if b.tempFile != nil {
		if err := b.tempFile.Close(); err != nil {
			return "", fmt.Errorf("close temp file: %w", err)
		}
		b.tempFile = nil
	}

	return b.tempPath, nil
}

// Cleanup removes any temp file.
// Call on error or after wrapper confirms cleanup.
func (b *OutputBuffer) Cleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.tempFile != nil {
		b.tempFile.Close()
		b.tempFile = nil
	}

	if b.tempPath != "" {
		os.Remove(b.tempPath)
		b.tempPath = ""
	}
}
