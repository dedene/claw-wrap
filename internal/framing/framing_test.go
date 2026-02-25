package framing

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

// testMessage is a simple struct for testing encoding/decoding.
type testMessage struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Count   int    `json:"count"`
}

func TestEncoderDecoder_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		msg  testMessage
	}{
		{
			name: "small message",
			msg:  testMessage{Type: "test", Payload: "hello", Count: 42},
		},
		{
			name: "empty strings",
			msg:  testMessage{Type: "", Payload: "", Count: 0},
		},
		{
			name: "unicode content",
			msg:  testMessage{Type: "unicode", Payload: "Hello, 世界! 🚀", Count: 123},
		},
		{
			name: "large payload",
			msg:  testMessage{Type: "large", Payload: strings.Repeat("x", 100000), Count: 1},
		},
		{
			name: "special characters",
			msg:  testMessage{Type: "special", Payload: `{"nested": "json", "quotes": "\""}`, Count: -1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			// Encode
			enc := NewEncoder(&buf)
			if err := enc.Encode(tt.msg); err != nil {
				t.Fatalf("Encode() error = %v", err)
			}

			// Decode
			dec := NewDecoder(&buf)
			var got testMessage
			if err := dec.Decode(&got); err != nil {
				t.Fatalf("Decode() error = %v", err)
			}

			// Compare
			if got.Type != tt.msg.Type || got.Payload != tt.msg.Payload || got.Count != tt.msg.Count {
				t.Errorf("Decode() = %+v, want %+v", got, tt.msg)
			}
		})
	}
}

func TestEncoderDecoder_MultipleMessages(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	messages := []testMessage{
		{Type: "first", Payload: "one", Count: 1},
		{Type: "second", Payload: "two", Count: 2},
		{Type: "third", Payload: "three", Count: 3},
	}

	// Encode all messages
	for _, msg := range messages {
		if err := enc.Encode(msg); err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
	}

	// Decode all messages
	dec := NewDecoder(&buf)
	for i, want := range messages {
		var got testMessage
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("Decode() message %d error = %v", i, err)
		}
		if got.Type != want.Type || got.Payload != want.Payload || got.Count != want.Count {
			t.Errorf("Decode() message %d = %+v, want %+v", i, got, want)
		}
	}

	// Should get EOF on next read
	var extra testMessage
	if err := dec.Decode(&extra); err != io.EOF {
		t.Errorf("Decode() after all messages error = %v, want io.EOF", err)
	}
}

func TestDecoder_TruncatedLength(t *testing.T) {
	// Only 2 bytes instead of 4
	buf := bytes.NewBuffer([]byte{0x00, 0x00})
	dec := NewDecoder(buf)

	var msg testMessage
	err := dec.Decode(&msg)
	if err == nil {
		t.Error("Decode() expected error for truncated length, got nil")
	}
}

func TestDecoder_TruncatedPayload(t *testing.T) {
	var buf bytes.Buffer

	// Write length indicating 100 bytes
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, 100)
	buf.Write(lenBuf)

	// Write only 10 bytes of payload
	buf.Write([]byte("short data"))

	dec := NewDecoder(&buf)
	var msg testMessage
	err := dec.Decode(&msg)
	if err == nil {
		t.Error("Decode() expected error for truncated payload, got nil")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("Decode() error = %v, want error containing 'truncated'", err)
	}
}

func TestDecoder_OversizedMessage(t *testing.T) {
	var buf bytes.Buffer

	// Write length exceeding DefaultMaxMessageSize
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(DefaultMaxMessageSize+1))
	buf.Write(lenBuf)

	dec := NewDecoder(&buf)
	var msg testMessage
	err := dec.Decode(&msg)
	if err == nil {
		t.Errorf("Decode() expected error")
	}
	if !strings.Contains(err.Error(), "message exceeds maximum size") {
		t.Errorf("Decode() error message doesn't contain expected text: %v", err)
	}
}

func TestEncoder_OversizedMessage(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// Create a message larger than DefaultMaxMessageSize
	msg := testMessage{
		Type:    "oversized",
		Payload: strings.Repeat("x", DefaultMaxMessageSize),
		Count:   1,
	}

	err := enc.Encode(msg)
	if err == nil {
		t.Errorf("Encode() expected error")
	}
	if !strings.Contains(err.Error(), "message exceeds maximum size") {
		t.Errorf("Encode() error message doesn't contain expected text: %v", err)
	}
}

func TestDecoder_EmptyMessage(t *testing.T) {
	var buf bytes.Buffer

	// Write length of 0
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, 0)
	buf.Write(lenBuf)

	dec := NewDecoder(&buf)
	var msg testMessage
	err := dec.Decode(&msg)
	if err != ErrEmptyMessage {
		t.Errorf("Decode() error = %v, want ErrEmptyMessage", err)
	}
}

func TestDecoder_EOF(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	dec := NewDecoder(buf)

	var msg testMessage
	err := dec.Decode(&msg)
	if err != io.EOF {
		t.Errorf("Decode() error = %v, want io.EOF", err)
	}
}

func TestNDJSONWriterReader_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		msg  testMessage
	}{
		{
			name: "small message",
			msg:  testMessage{Type: "test", Payload: "hello", Count: 42},
		},
		{
			name: "empty strings",
			msg:  testMessage{Type: "", Payload: "", Count: 0},
		},
		{
			name: "unicode content",
			msg:  testMessage{Type: "unicode", Payload: "Hello, 世界! 🚀", Count: 123},
		},
		{
			name: "large payload",
			msg:  testMessage{Type: "large", Payload: strings.Repeat("x", 100000), Count: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			// Write
			writer := NewNDJSONWriter(&buf)
			if err := writer.Write(tt.msg); err != nil {
				t.Fatalf("Write() error = %v", err)
			}

			// Read
			reader := NewNDJSONReader(&buf)
			var got testMessage
			if err := reader.Read(&got); err != nil {
				t.Fatalf("Read() error = %v", err)
			}

			// Compare
			if got.Type != tt.msg.Type || got.Payload != tt.msg.Payload || got.Count != tt.msg.Count {
				t.Errorf("Read() = %+v, want %+v", got, tt.msg)
			}
		})
	}
}

func TestNDJSONWriterReader_MultipleMessages(t *testing.T) {
	var buf bytes.Buffer
	writer := NewNDJSONWriter(&buf)

	messages := []testMessage{
		{Type: "first", Payload: "one", Count: 1},
		{Type: "second", Payload: "two", Count: 2},
		{Type: "third", Payload: "three", Count: 3},
	}

	// Write all messages
	for _, msg := range messages {
		if err := writer.Write(msg); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}

	// Read all messages
	reader := NewNDJSONReader(&buf)
	for i, want := range messages {
		var got testMessage
		if err := reader.Read(&got); err != nil {
			t.Fatalf("Read() message %d error = %v", i, err)
		}
		if got.Type != want.Type || got.Payload != want.Payload || got.Count != want.Count {
			t.Errorf("Read() message %d = %+v, want %+v", i, got, want)
		}
	}

	// Should get EOF on next read
	var extra testMessage
	if err := reader.Read(&extra); err != io.EOF {
		t.Errorf("Read() after all messages error = %v, want io.EOF", err)
	}
}

func TestNDJSONReader_EmptyLine(t *testing.T) {
	// Buffer with an empty line
	buf := bytes.NewBufferString("\n")
	reader := NewNDJSONReader(buf)

	var msg testMessage
	err := reader.Read(&msg)
	if err != ErrEmptyMessage {
		t.Errorf("Read() error = %v, want ErrEmptyMessage", err)
	}
}

func TestNDJSONReader_EOF(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	reader := NewNDJSONReader(buf)

	var msg testMessage
	err := reader.Read(&msg)
	if err != io.EOF {
		t.Errorf("Read() error = %v, want io.EOF", err)
	}
}

func TestNDJSONReader_InvalidJSON(t *testing.T) {
	buf := bytes.NewBufferString("not valid json\n")
	reader := NewNDJSONReader(buf)

	var msg testMessage
	err := reader.Read(&msg)
	if err == nil {
		t.Error("Read() expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("Read() error = %v, want error containing 'unmarshal'", err)
	}
}

func TestNDJSONWriter_OversizedMessage(t *testing.T) {
	var buf bytes.Buffer
	writer := NewNDJSONWriter(&buf)

	// Create a message larger than DefaultMaxMessageSize
	msg := testMessage{
		Type:    "oversized",
		Payload: strings.Repeat("x", DefaultMaxMessageSize),
		Count:   1,
	}

	err := writer.Write(msg)
	if err == nil {
		t.Errorf("Write() expected error")
	}
	if !strings.Contains(err.Error(), "message exceeds maximum size") {
		t.Errorf("Write() error message doesn't contain expected text: %v", err)
	}
}

func TestEncoder_InvalidJSON(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	// Channels cannot be marshaled to JSON
	ch := make(chan int)
	err := enc.Encode(ch)
	if err == nil {
		t.Error("Encode() expected error for non-marshalable value, got nil")
	}
}

func TestNDJSONWriter_InvalidJSON(t *testing.T) {
	var buf bytes.Buffer
	writer := NewNDJSONWriter(&buf)

	// Channels cannot be marshaled to JSON
	ch := make(chan int)
	err := writer.Write(ch)
	if err == nil {
		t.Error("Write() expected error for non-marshalable value, got nil")
	}
}

func TestDecoder_InvalidJSON(t *testing.T) {
	var buf bytes.Buffer

	// Write valid length but invalid JSON
	payload := []byte("not valid json")
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(payload)))
	buf.Write(lenBuf)
	buf.Write(payload)

	dec := NewDecoder(&buf)
	var msg testMessage
	err := dec.Decode(&msg)
	if err == nil {
		t.Error("Decode() expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("Decode() error = %v, want error containing 'unmarshal'", err)
	}
}

// Benchmark tests
func BenchmarkEncoder(b *testing.B) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	msg := testMessage{Type: "bench", Payload: strings.Repeat("x", 1000), Count: 42}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		enc.Encode(msg)
	}
}

func BenchmarkDecoder(b *testing.B) {
	var encoded bytes.Buffer
	enc := NewEncoder(&encoded)
	msg := testMessage{Type: "bench", Payload: strings.Repeat("x", 1000), Count: 42}
	enc.Encode(msg)
	data := encoded.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dec := NewDecoder(bytes.NewReader(data))
		var got testMessage
		dec.Decode(&got)
	}
}

func BenchmarkNDJSONWriter(b *testing.B) {
	var buf bytes.Buffer
	writer := NewNDJSONWriter(&buf)
	msg := testMessage{Type: "bench", Payload: strings.Repeat("x", 1000), Count: 42}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		writer.Write(msg)
	}
}

func BenchmarkNDJSONReader(b *testing.B) {
	var encoded bytes.Buffer
	writer := NewNDJSONWriter(&encoded)
	msg := testMessage{Type: "bench", Payload: strings.Repeat("x", 1000), Count: 42}
	writer.Write(msg)
	data := encoded.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := NewNDJSONReader(bytes.NewReader(data))
		var got testMessage
		reader.Read(&got)
	}
}
