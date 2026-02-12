package daemon

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"claw-wrap/internal/protocol"
)

// ErrOutputLimitExceeded is returned when output exceeds the configured max size.
var ErrOutputLimitExceeded = errors.New("output size limit exceeded")

// OutputBuffer handles streaming output with threshold-based file fallback.
// When output is below the threshold, data is streamed as base64-encoded chunks.
// When output exceeds the threshold, data is written to a temp file instead.
// If maxOutputSize > 0, total output is capped and ErrOutputLimitExceeded returned.
type OutputBuffer struct {
	stream        string                  // "stdout" or "stderr"
	threshold     int64                   // switch to file above this
	maxOutputSize int64                   // 0 = unlimited
	accumulated   int64                   // bytes seen so far
	inlineMode    bool                    // true if still streaming inline
	tempFile      *os.File                // nil until threshold exceeded
	tempPath      string                  // path for cleanup/response
	sendFn        func(interface{}) error // sends length-prefixed message
	tee           io.Writer              // optional; receives copy of all raw bytes
	mu            sync.Mutex
}

// NewOutputBuffer creates a new OutputBuffer for the given stream.
// The stream parameter should be "stdout" or "stderr".
// The threshold specifies the byte limit before switching to file mode.
// The maxOutputSize caps total output (0 = unlimited).
// The sendFn is called to send ResponseMessage chunks for inline data.
func NewOutputBuffer(stream string, threshold int64, maxOutputSize int64, sendFn func(interface{}) error) *OutputBuffer {
	return &OutputBuffer{
		stream:        stream,
		threshold:     threshold,
		maxOutputSize: maxOutputSize,
		inlineMode:    true,
		sendFn:        sendFn,
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

	// Check output size limit before feeding tee/hash — rejected data must not
	// affect the hash so that output_hash and output_bytes stay consistent.
	if b.maxOutputSize > 0 && b.accumulated+int64(len(data)) > b.maxOutputSize {
		return ErrOutputLimitExceeded
	}

	// Feed tee writer (e.g. SHA256 hasher) before inline/file branching
	if b.tee != nil {
		if _, err := b.tee.Write(data); err != nil {
			return fmt.Errorf("tee write: %w", err)
		}
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

	// Restrict permissions regardless of umask
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		os.Remove(f.Name())
		return fmt.Errorf("chmod temp file: %w", err)
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

// SetTee sets an optional writer that receives a copy of all raw bytes.
// Must be called before any Write calls (before pumpers start).
func (b *OutputBuffer) SetTee(w io.Writer) {
	b.tee = w
}

// Accumulated returns the total bytes written so far.
func (b *OutputBuffer) Accumulated() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.accumulated
}
