// Package framing implements length-prefixed and NDJSON message encoding
// for communication between the claw-wrap wrapper and daemon.
//
// Protocol:
// - Daemon responses use length-prefixed format: [4 bytes big-endian length][JSON payload]
// - Wrapper requests use NDJSON format: JSON + newline
package framing

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxMessageSize is the maximum allowed message size (16 MB).
// Output is already chunked, so individual frames don't need to be huge.
// 16 MB is generous for any single response frame.
const MaxMessageSize = 16 * 1024 * 1024

// ErrMessageTooLarge is returned when a message exceeds MaxMessageSize.
var ErrMessageTooLarge = errors.New("message exceeds maximum size")

// ErrEmptyMessage is returned when attempting to decode an empty message.
var ErrEmptyMessage = errors.New("empty message")

// Encoder writes length-prefixed JSON messages (for daemon responses).
type Encoder struct {
	w io.Writer
}

// NewEncoder creates a new Encoder that writes to w.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

// Encode marshals v to JSON and writes it with a 4-byte big-endian length prefix.
func (e *Encoder) Encode(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	if len(data) > MaxMessageSize {
		return ErrMessageTooLarge
	}

	// Write 4-byte big-endian length prefix
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

	if _, err := e.w.Write(lenBuf); err != nil {
		return fmt.Errorf("write length: %w", err)
	}

	if _, err := e.w.Write(data); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}

	return nil
}

// Decoder reads length-prefixed JSON messages (for wrapper reading responses).
type Decoder struct {
	r io.Reader
}

// NewDecoder creates a new Decoder that reads from r.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r: r}
}

// Decode reads a length-prefixed message and unmarshals it into v.
func (d *Decoder) Decode(v interface{}) error {
	// Read 4-byte length prefix
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(d.r, lenBuf); err != nil {
		if err == io.EOF {
			return io.EOF
		}
		return fmt.Errorf("read length: %w", err)
	}

	length := binary.BigEndian.Uint32(lenBuf)

	if length == 0 {
		return ErrEmptyMessage
	}

	if length > MaxMessageSize {
		return fmt.Errorf("message exceeds maximum size (got %d bytes, max is %d bytes)", length, MaxMessageSize)
	}

	// Read payload
	data := make([]byte, length)
	if _, err := io.ReadFull(d.r, data); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return fmt.Errorf("truncated message: expected %d bytes", length)
		}
		return fmt.Errorf("read payload: %w", err)
	}

	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	return nil
}

// NDJSONWriter writes newline-delimited JSON (for wrapper requests).
type NDJSONWriter struct {
	w io.Writer
}

// NewNDJSONWriter creates a new NDJSONWriter that writes to w.
func NewNDJSONWriter(w io.Writer) *NDJSONWriter {
	return &NDJSONWriter{w: w}
}

// Write marshals v to JSON and writes it followed by a newline.
func (n *NDJSONWriter) Write(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	if len(data) > MaxMessageSize {
		return ErrMessageTooLarge
	}

	// Write JSON followed by newline
	if _, err := n.w.Write(data); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	if _, err := n.w.Write([]byte{'\n'}); err != nil {
		return fmt.Errorf("write newline: %w", err)
	}

	return nil
}

// NDJSONReader reads newline-delimited JSON (for daemon reading stdin messages).
type NDJSONReader struct {
	scanner *bufio.Scanner
}

// NewNDJSONReader creates a new NDJSONReader that reads from r.
func NewNDJSONReader(r io.Reader) *NDJSONReader {
	return NewNDJSONReaderWithLimit(r, MaxMessageSize)
}

// NewNDJSONReaderWithLimit creates a new NDJSONReader with a custom max token size.
func NewNDJSONReaderWithLimit(r io.Reader, maxTokenSize int) *NDJSONReader {
	if maxTokenSize <= 0 || maxTokenSize > MaxMessageSize {
		maxTokenSize = MaxMessageSize
	}

	scanner := bufio.NewScanner(r)
	// Set max token size to handle large messages
	initial := 64 * 1024
	if maxTokenSize < initial {
		initial = maxTokenSize
	}
	scanner.Buffer(make([]byte, initial), maxTokenSize)
	return &NDJSONReader{scanner: scanner}
}

// Read reads a line and unmarshals it into v.
func (n *NDJSONReader) Read(v interface{}) error {
	if !n.scanner.Scan() {
		if err := n.scanner.Err(); err != nil {
			if errors.Is(err, bufio.ErrTooLong) {
				return ErrMessageTooLarge
			}
			return fmt.Errorf("scan: %w", err)
		}
		return io.EOF
	}

	line := n.scanner.Bytes()
	if len(line) == 0 {
		return ErrEmptyMessage
	}

	if err := json.Unmarshal(line, v); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	return nil
}
