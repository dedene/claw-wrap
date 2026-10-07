package daemon

import (
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"claw-wrap/internal/audit"
	"claw-wrap/internal/config"
	"claw-wrap/internal/framing"
	"claw-wrap/internal/protocol"
)

// clientReadDelay makes the test client stall once, after the first message,
// to simulate a slow consumer.
var clientReadDelay time.Duration

// clientAnswer, when set, makes the test client send "y\n" on stdin as soon as
// the given prompt text has arrived on stdout.
var clientAnswer string

type execResult struct {
	stdout   string
	stderr   string
	exitCode int
	timeout  bool
	errMsg   string
	elapsed  time.Duration
}

// runHelperTool executes the test binary as a wrapped tool through a real
// ToolExecutor and collects everything the wrapper would receive.
func runHelperTool(t *testing.T, tool config.ToolDef, req protocol.ProxyRequest) execResult {
	t.Helper()
	return runHelperToolWith(t, tool, req, &config.Config{}, nil)
}

func runHelperToolWith(t *testing.T, tool config.ToolDef, req protocol.ProxyRequest, cfg *config.Config, auditLogger audit.Logger) execResult {
	t.Helper()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	tool.Binary = exe
	if req.Tool == "" {
		req.Tool = "helper"
	}
	if req.Cwd == "" {
		req.Cwd = t.TempDir()
	}

	daemonSide, clientSide := net.Pipe()
	defer clientSide.Close()

	ex, err := NewToolExecutor(daemonSide, &req, &tool, cfg, "", auditLogger, 0, "")
	if err != nil {
		t.Fatalf("NewToolExecutor: %v", err)
	}

	start := time.Now()
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = ex.Run()
		daemonSide.Close()
	}()

	var res execResult
	var stdout, stderr strings.Builder
	dec := framing.NewDecoder(clientSide)
	answered := false
	answer := func() {
		msg := protocol.WrapperMessage{Type: protocol.MsgTypeStdin, Data: base64.StdEncoding.EncodeToString([]byte("y\n"))}
		if err := framing.NewNDJSONWriter(clientSide).Write(&msg); err != nil {
			t.Errorf("send stdin: %v", err)
		}
	}
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		stalled := false
		for {
			var msg protocol.ResponseMessage
			if err := dec.Decode(&msg); err != nil {
				return
			}
			if clientReadDelay > 0 && !stalled {
				stalled = true
				time.Sleep(clientReadDelay)
			}
			switch msg.Type {
			case protocol.MsgTypeStdout, protocol.MsgTypeStderr:
				data, err := base64.StdEncoding.DecodeString(msg.Data)
				if err != nil {
					t.Errorf("decode %s: %v", msg.Type, err)
					return
				}
				if msg.Type == protocol.MsgTypeStdout {
					stdout.Write(data)
					if clientAnswer != "" && !answered && strings.Contains(stdout.String(), clientAnswer) {
						answered = true
						go answer()
					}
				} else {
					stderr.Write(data)
				}
			case protocol.MsgTypeDone:
				res.exitCode = msg.ExitCode
				res.timeout = msg.Timeout
			case protocol.MsgTypeError:
				res.errMsg = msg.Message
			}
		}
	}()

	select {
	case <-runDone:
	case <-time.After(30 * time.Second):
		t.Fatal("executor did not finish within 30s")
	}
	res.elapsed = time.Since(start)
	<-readDone
	res.stdout = stdout.String()
	res.stderr = stderr.String()
	return res
}

func helperTool(mode string) config.ToolDef {
	noPTY := false
	return config.ToolDef{
		Timeout: "20s",
		Env:     map[string]string{helperEnv: mode},
		UsePTY:  &noPTY,
	}
}

func readPID(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pidfile: %v", err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatalf("parse pid: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	return pid
}

// processAlive reports whether pid still exists after giving a just-signalled
// process a moment to be reaped.
func processAlive(pid int) bool {
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := syscall.Kill(pid, 0); err != nil {
			return false
		}
		if time.Now().After(deadline) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestExecutor_DetachedDaemonChild(t *testing.T) {
	tests := []struct {
		name      string
		session   string
		stdio     string
		wantAlive bool
	}{
		// Well-behaved: new session, stdio detached. The contract we document.
		{name: "setsid devnull", session: "setsid", stdio: "devnull", wantAlive: true},
		// Sloppy: new session but stdout/stderr inherited. Must not hang claw-wrap.
		{name: "setsid inherited stdio", session: "setsid", stdio: "inherit", wantAlive: true},
		// Background child left in the tool's process group: cleanup kills it.
		{name: "same process group", session: "same-pgrp", stdio: "devnull", wantAlive: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "daemon.pid")
			res := runHelperTool(t, helperTool("spawn-daemon"), protocol.ProxyRequest{
				Args: []string{tt.session, tt.stdio, pidFile},
			})

			if res.errMsg != "" {
				t.Fatalf("executor error: %s", res.errMsg)
			}
			if res.exitCode != 0 || res.timeout {
				t.Fatalf("exit=%d timeout=%v stderr=%q", res.exitCode, res.timeout, res.stderr)
			}
			if res.stdout != "daemon started" {
				t.Fatalf("stdout = %q, want %q", res.stdout, "daemon started")
			}
			if res.elapsed > 3*time.Second {
				t.Fatalf("executor took %v; a detached child must not hold the call open", res.elapsed)
			}

			pid := readPID(t, pidFile)
			if alive := processAlive(pid); alive != tt.wantAlive {
				t.Fatalf("daemon alive = %v, want %v", alive, tt.wantAlive)
			}
		})
	}
}

// Wait() on an exec.Cmd closes StdoutPipe readers as soon as the process
// exits, which can drop output the pumpers have not read yet.
func TestExecutor_NoOutputTruncationOnExit(t *testing.T) {
	const size = 200 * 1024
	for i := 0; i < 25; i++ {
		res := runHelperTool(t, helperTool("big-output"), protocol.ProxyRequest{
			Args: []string{strconv.Itoa(size)},
		})
		if res.exitCode != 0 {
			t.Fatalf("run %d: exit=%d stderr=%q", i, res.exitCode, res.stderr)
		}
		if len(res.stdout) != size {
			t.Fatalf("run %d: got %d stdout bytes, want %d", i, len(res.stdout), size)
		}
	}
}
