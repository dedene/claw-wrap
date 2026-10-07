// Package audit provides opt-in JSONL audit logging for proxied tool executions.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"

	"claw-wrap/internal/config"
)

// Entry is a single audit log record written as one JSONL line.
type Entry struct {
	Timestamp   string   `json:"ts"`
	Tool        string   `json:"tool"`
	Args        []string `json:"args,omitempty"`
	Cwd         string   `json:"cwd"`
	CallerPID   int32    `json:"caller_pid"`
	CallerExe   string   `json:"caller_exe"`
	ExitCode    int      `json:"exit_code"`
	Timeout     bool     `json:"timeout,omitempty"`
	DurationMs  int64    `json:"duration_ms,omitempty"`
	OutputHash  string   `json:"output_hash,omitempty"`
	OutputBytes int64    `json:"output_bytes"`
}

// Logger writes audit entries. Implementations must be safe for concurrent use.
type Logger interface {
	Log(entry Entry) error
	Close() error
}

// nopLogger is a zero-cost no-op logger used when auditing is disabled.
type nopLogger struct{}

func (nopLogger) Log(Entry) error { return nil }
func (nopLogger) Close() error    { return nil }

// Nop returns a no-op Logger.
func Nop() Logger { return nopLogger{} }

// FileLogger writes JSONL entries to a file with mutex-protected writes.
type FileLogger struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

// NewFileLogger opens or creates the audit file with 0600 permissions.
func NewFileLogger(path string) (*FileLogger, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}

	// Refuse to write through symlinks
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("audit file must not be a symlink: %s", path)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit file: %w", err)
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return nil, fmt.Errorf("chmod audit file: %w", err)
	}

	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	return &FileLogger{file: f, enc: enc}, nil
}

// Log writes an entry as a single JSONL line.
func (l *FileLogger) Log(entry Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enc.Encode(entry)
}

// Close closes the underlying file.
func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

// stdoutWriter is the destination of the stdout logger (swapped in tests).
var stdoutWriter io.Writer = os.Stdout

// StreamLogger writes JSONL entries to a stream it does not own, such as the
// daemon's stdout in a container where logs are collected from the stream.
type StreamLogger struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewStreamLogger returns a logger that writes JSONL to w.
func NewStreamLogger(w io.Writer) *StreamLogger {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &StreamLogger{enc: enc}
}

// Log writes an entry as a single JSONL line.
func (l *StreamLogger) Log(entry Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enc.Encode(entry)
}

// Close is a no-op: the stream belongs to the caller.
func (l *StreamLogger) Close() error { return nil }

// MultiLogger fans out to multiple loggers.
type MultiLogger struct {
	loggers []Logger
}

// Log writes the entry to all underlying loggers.
func (m *MultiLogger) Log(entry Entry) error {
	var firstErr error
	for _, l := range m.loggers {
		if err := l.Log(entry); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close closes all underlying loggers.
func (m *MultiLogger) Close() error {
	var firstErr error
	for _, l := range m.loggers {
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// New creates an audit Logger based on config. Returns Nop() when disabled.
func New(cfg *config.AuditConfig) (Logger, error) {
	if cfg == nil || !cfg.Enabled {
		return Nop(), nil
	}

	var loggers []Logger

	if cfg.File != "" {
		fl, err := NewFileLogger(cfg.File)
		if err != nil {
			return nil, fmt.Errorf("audit file logger: %w", err)
		}
		loggers = append(loggers, fl)
	}

	if cfg.Stdout {
		loggers = append(loggers, NewStreamLogger(stdoutWriter))
	}

	if cfg.Syslog {
		sl, err := newSyslogLogger(cfg.SyslogFacility)
		if err != nil {
			// Syslog failure is non-fatal if file is also configured
			if len(loggers) > 0 {
				log.Printf("[WARN] audit syslog failed, using file only: %v", err)
			} else {
				return nil, fmt.Errorf("audit syslog logger: %w", err)
			}
		} else {
			loggers = append(loggers, sl)
		}
	}

	if len(loggers) == 0 {
		return Nop(), nil
	}
	if len(loggers) == 1 {
		return loggers[0], nil
	}
	return &MultiLogger{loggers: loggers}, nil
}
