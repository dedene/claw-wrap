package main

import (
	"os"
	"strings"
	"testing"
)

func TestSafeToolNameRegex(t *testing.T) {
	valid := []string{"gh", "my-tool", "tool.v2", "tool_name"}
	for _, name := range valid {
		if !safeToolNameRegex.MatchString(name) {
			t.Errorf("safeToolNameRegex rejected valid name %q", name)
		}
	}

	invalid := []string{"../../etc/passwd", "gh/repo", "gh repo", "gh;rm", ""}
	for _, name := range invalid {
		if safeToolNameRegex.MatchString(name) {
			t.Errorf("safeToolNameRegex accepted invalid name %q", name)
		}
	}
}

func TestRunDaemon_InvalidFlags(t *testing.T) {
	t.Run("invalid uid", func(t *testing.T) {
		orig := os.Args
		defer func() { os.Args = orig }()
		os.Args = []string{"claw-wrap", "daemon", "--uid", "nope"}
		err := runDaemon()
		if err == nil || !strings.Contains(err.Error(), "invalid --uid") {
			t.Fatalf("runDaemon() error = %v, want invalid --uid", err)
		}
	})

	t.Run("invalid auth mode", func(t *testing.T) {
		orig := os.Args
		defer func() { os.Args = orig }()
		os.Args = []string{"claw-wrap", "daemon", "--auth-mode", "0666"}
		err := runDaemon()
		if err == nil || !strings.Contains(err.Error(), "invalid --auth-mode") {
			t.Fatalf("runDaemon() error = %v, want invalid --auth-mode", err)
		}
	})

	t.Run("invalid socket mode", func(t *testing.T) {
		orig := os.Args
		defer func() { os.Args = orig }()
		os.Args = []string{"claw-wrap", "daemon", "--socket-mode", "0640"}
		err := runDaemon()
		if err == nil || !strings.Contains(err.Error(), "invalid --socket-mode") {
			t.Fatalf("runDaemon() error = %v, want invalid --socket-mode", err)
		}
	})

	t.Run("invalid runtime gid", func(t *testing.T) {
		orig := os.Args
		defer func() { os.Args = orig }()
		os.Args = []string{"claw-wrap", "daemon", "--runtime-gid", "-1"}
		err := runDaemon()
		if err == nil || !strings.Contains(err.Error(), "invalid --runtime-gid") {
			t.Fatalf("runDaemon() error = %v, want invalid --runtime-gid", err)
		}
	})
}
