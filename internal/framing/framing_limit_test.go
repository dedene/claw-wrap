package framing

import (
	"bytes"
	"testing"
)

func TestNDJSONReaderWithLimit_RejectsOversize(t *testing.T) {
	var buf bytes.Buffer
	payload := bytes.Repeat([]byte("a"), 2048)
	buf.Write(payload)
	buf.WriteByte('\n')

	reader := NewNDJSONReaderWithLimit(&buf, 1024)
	var v map[string]any
	err := reader.Read(&v)
	if err != ErrMessageTooLarge {
		t.Fatalf("Read() error = %v, want ErrMessageTooLarge", err)
	}
}
