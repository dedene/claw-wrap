//go:build !windows

package audit

import (
	"encoding/json"
	"fmt"
	"log/syslog"
)

// syslogLogger writes audit entries to syslog.
type syslogLogger struct {
	writer *syslog.Writer
}

func newSyslogLogger(facility string) (*syslogLogger, error) {
	f := parseFacility(facility)
	w, err := syslog.New(f|syslog.LOG_INFO, "claw-wrap-audit")
	if err != nil {
		return nil, fmt.Errorf("connect to syslog: %w", err)
	}
	return &syslogLogger{writer: w}, nil
}

func (l *syslogLogger) Log(entry Entry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}
	return l.writer.Info(string(data))
}

func (l *syslogLogger) Close() error {
	return l.writer.Close()
}

func parseFacility(name string) syslog.Priority {
	switch name {
	case "local1":
		return syslog.LOG_LOCAL1
	case "local2":
		return syslog.LOG_LOCAL2
	case "local3":
		return syslog.LOG_LOCAL3
	case "local4":
		return syslog.LOG_LOCAL4
	case "local5":
		return syslog.LOG_LOCAL5
	case "local6":
		return syslog.LOG_LOCAL6
	case "local7":
		return syslog.LOG_LOCAL7
	default:
		return syslog.LOG_LOCAL0
	}
}
