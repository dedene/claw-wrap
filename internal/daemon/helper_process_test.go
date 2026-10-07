package daemon

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// helperEnv selects a helper mode when the test binary is re-executed as a
// wrapped tool. Executor tests point ToolDef.Binary at os.Executable() and set
// this variable through ToolDef.Env, so the "tool" is this very binary.
const helperEnv = "CLAW_WRAP_TEST_HELPER"

func TestMain(m *testing.M) {
	mode := os.Getenv(helperEnv)
	if mode == "" {
		os.Exit(m.Run())
	}
	os.Exit(runHelper(mode, os.Args[1:]))
}

func runHelper(mode string, args []string) int {
	switch mode {
	case "echo":
		fmt.Fprint(os.Stdout, strings.Join(args, " "))
		return 0

	case "pwd":
		wd, _ := os.Getwd()
		fmt.Fprint(os.Stdout, wd)
		return 0

	case "env":
		fmt.Fprint(os.Stdout, os.Getenv(args[0]))
		return 0

	case "big-output":
		// args: <bytes>
		n, _ := strconv.Atoi(args[0])
		w := bufio.NewWriterSize(os.Stdout, 64*1024)
		for i := 0; i < n; i++ {
			_ = w.WriteByte('a' + byte(i%26))
		}
		_ = w.Flush()
		return 0

	case "prompt":
		// Interactive confirmation: no trailing newline, then wait for input.
		fmt.Fprint(os.Stdout, "Continue? [y/N] ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return 3
		}
		fmt.Fprint(os.Stdout, "answer:"+line)
		return 0

	case "read-stdin":
		// Mimics a CLI that prompts for input; EOF means "non-interactive".
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			fmt.Fprint(os.Stderr, "no input available")
			return 3
		}
		fmt.Fprint(os.Stdout, "got:"+line)
		return 0

	case "spawn-daemon":
		// args: <setsid|same-pgrp> <inherit|devnull> <pidfile>
		// Mimics a CLI whose first invocation starts a long-lived background
		// daemon and then exits.
		cmd := exec.Command(os.Args[0])
		cmd.Env = append(os.Environ(), helperEnv+"=daemon")
		if args[0] == "setsid" {
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		}
		if args[1] == "inherit" {
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "start daemon: %v", err)
			return 1
		}
		if err := os.WriteFile(args[2], []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "write pidfile: %v", err)
			return 1
		}
		fmt.Fprint(os.Stdout, "daemon started")
		return 0

	case "daemon":
		time.Sleep(60 * time.Second)
		return 0
	}

	fmt.Fprintf(os.Stderr, "unknown helper mode %q", mode)
	return 2
}
