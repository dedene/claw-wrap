package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"claw-wrap/internal/config"
)

func TestNopLogger(t *testing.T) {
	l := Nop()
	if err := l.Log(Entry{Tool: "gh"}); err != nil {
		t.Errorf("Nop.Log() error = %v", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("Nop.Close() error = %v", err)
	}
}

func TestFileLogger_WritesJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger() error = %v", err)
	}

	entries := []Entry{
		{Timestamp: "2026-02-08T10:30:00Z", Tool: "gh", Args: []string{"repo", "list"}, ExitCode: 0, OutputBytes: 100},
		{Timestamp: "2026-02-08T10:31:00Z", Tool: "npm", Args: []string{"install"}, ExitCode: 1, Timeout: true},
	}
	for _, e := range entries {
		if err := l.Log(e); err != nil {
			t.Fatalf("Log() error = %v", err)
		}
	}
	l.Close()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	i := 0
	for scanner.Scan() {
		var got Entry
		if err := json.Unmarshal(scanner.Bytes(), &got); err != nil {
			t.Errorf("line %d: invalid JSON: %v", i, err)
			continue
		}
		if got.Tool != entries[i].Tool {
			t.Errorf("line %d: tool = %q, want %q", i, got.Tool, entries[i].Tool)
		}
		i++
	}
	if i != len(entries) {
		t.Errorf("read %d lines, want %d", i, len(entries))
	}
}

func TestFileLogger_Permissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger() error = %v", err)
	}
	l.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file permissions = %04o, want 0600", perm)
	}
}

func TestFileLogger_CreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "dir", "audit.jsonl")
	l, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger() error = %v", err)
	}
	l.Close()

	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

func TestFileLogger_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.jsonl")
	os.WriteFile(target, nil, 0600)

	link := filepath.Join(dir, "audit.jsonl")
	os.Symlink(target, link)

	_, err := NewFileLogger(link)
	if err == nil {
		t.Fatal("NewFileLogger() should reject symlink")
	}
}

func TestFileLogger_ConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger() error = %v", err)
	}

	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			l.Log(Entry{Tool: "gh", ExitCode: i})
		}(i)
	}
	wg.Wait()
	l.Close()

	f, _ := os.Open(path)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Errorf("line %d: invalid JSON: %v", count, err)
		}
		count++
	}
	if count != n {
		t.Errorf("wrote %d lines, want %d", count, n)
	}
}

func TestMultiLogger(t *testing.T) {
	dir := t.TempDir()
	path1 := filepath.Join(dir, "a.jsonl")
	path2 := filepath.Join(dir, "b.jsonl")
	l1, _ := NewFileLogger(path1)
	l2, _ := NewFileLogger(path2)

	ml := &MultiLogger{loggers: []Logger{l1, l2}}
	ml.Log(Entry{Tool: "gh"})
	ml.Close()

	for _, p := range []string{path1, path2} {
		data, _ := os.ReadFile(p)
		var e Entry
		if err := json.Unmarshal(data, &e); err != nil {
			t.Errorf("%s: invalid JSON: %v", p, err)
		}
		if e.Tool != "gh" {
			t.Errorf("%s: tool = %q, want gh", p, e.Tool)
		}
	}
}

func TestNew_DisabledReturnsNop(t *testing.T) {
	l, err := New(nil)
	if err != nil {
		t.Fatalf("New(nil) error = %v", err)
	}
	if _, ok := l.(nopLogger); !ok {
		t.Errorf("New(nil) returned %T, want nopLogger", l)
	}

	l2, err := New(&config.AuditConfig{Enabled: false})
	if err != nil {
		t.Fatalf("New(disabled) error = %v", err)
	}
	if _, ok := l2.(nopLogger); !ok {
		t.Errorf("New(disabled) returned %T, want nopLogger", l2)
	}
}

func TestNew_EnabledCreatesFileLogger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(&config.AuditConfig{
		Enabled: true,
		File:    path,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer l.Close()

	if _, ok := l.(*FileLogger); !ok {
		t.Errorf("New() returned %T, want *FileLogger", l)
	}
}

func TestEntry_JSONFieldNames(t *testing.T) {
	e := Entry{
		Timestamp:   "2026-02-08T10:30:00Z",
		Tool:        "gh",
		Args:        []string{"repo", "list"},
		Cwd:         "/home/user",
		CallerPID:   12345,
		CallerExe:   "/usr/local/bin/claw-wrap",
		ExitCode:    0,
		DurationMs:  1234,
		OutputHash:  "sha256:abc123",
		OutputBytes: 4567,
	}

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var m map[string]interface{}
	json.Unmarshal(data, &m)

	required := []string{"ts", "tool", "args", "cwd", "caller_pid", "caller_exe", "exit_code", "duration_ms", "output_hash", "output_bytes"}
	for _, key := range required {
		if _, ok := m[key]; !ok {
			t.Errorf("missing JSON field %q", key)
		}
	}
}
