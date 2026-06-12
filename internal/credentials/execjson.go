package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var execJSONCommandTimeout = 10 * time.Second

const maxExecJSONStderrLen = 1024

type execJSONResponse struct {
	Value     string `json:"value"`
	ExpiresAt string `json:"expires_at"`
}

func fetchFromExecJSON(parsed *ParsedSource) (Credential, error) {
	commandPath := parsed.Path
	if err := validateExecJSONCommand(commandPath); err != nil {
		return Credential{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), execJSONCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, commandPath)
	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return Credential{}, fmt.Errorf("exec-json %s: timed out after %s", commandPath, execJSONCommandTimeout)
		}
		return Credential{}, execJSONCommandError(commandPath, err)
	}

	return parseExecJSONOutput(output)
}

func validateExecJSONCommand(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("exec-json command path must be absolute: %s", path)
	}

	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if err == unix.ELOOP {
			return fmt.Errorf("exec-json command must not be a symlink: %s", path)
		}
		return fmt.Errorf("open exec-json command: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("open exec-json command: failed to create file handle")
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat exec-json command: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("exec-json command must be a regular file: %s", path)
	}
	if info.Mode()&0111 == 0 {
		return fmt.Errorf("exec-json command must be executable: %s", path)
	}

	perm := info.Mode().Perm()
	if perm&0022 != 0 {
		return fmt.Errorf("exec-json command must not be group or world writable: %s has %04o", path, perm)
	}

	ownerUID, err := execJSONCommandOwnerUID(info)
	if err != nil {
		return fmt.Errorf("read exec-json command owner metadata: %w", err)
	}
	euid := currentEUIDFunc()
	if ownerUID != euid && ownerUID != 0 {
		return fmt.Errorf("exec-json command owner must match daemon uid or root: %s owner=%d daemon=%d", path, ownerUID, euid)
	}

	return nil
}

func execJSONCommandOwnerUID(info os.FileInfo) (int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unsupported file stat type")
	}
	return int(stat.Uid), nil
}

func execJSONCommandError(commandPath string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("exec-json %s: timed out after %s", commandPath, execJSONCommandTimeout)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if len(exitErr.Stderr) > 0 {
			stderr := truncateExecJSONStderr(exitErr.Stderr)
			return fmt.Errorf("exec-json %s: exit status %d: %s", commandPath, exitErr.ExitCode(), stderr)
		}
		return fmt.Errorf("exec-json %s: exit status %d", commandPath, exitErr.ExitCode())
	}
	return fmt.Errorf("exec-json %s: %w", commandPath, err)
}

func truncateExecJSONStderr(stderr []byte) string {
	if len(stderr) <= maxExecJSONStderrLen {
		return string(stderr)
	}
	return string(stderr[:maxExecJSONStderrLen])
}

func parseExecJSONOutput(output []byte) (Credential, error) {
	var parsed execJSONResponse
	if err := json.Unmarshal(output, &parsed); err != nil {
		return Credential{}, fmt.Errorf("exec-json: decode helper output: %w", err)
	}
	if strings.TrimSpace(parsed.Value) == "" {
		return Credential{}, fmt.Errorf("exec-json: helper output missing value")
	}

	cred := Credential{Value: parsed.Value}
	expiresRaw := strings.TrimSpace(parsed.ExpiresAt)
	if expiresRaw == "" {
		return cred, nil
	}

	expiresAt, err := time.Parse(time.RFC3339, expiresRaw)
	if err != nil {
		return Credential{}, fmt.Errorf("exec-json: parse expires_at: %w", err)
	}
	cred.ExpiresAt = expiresAt.UTC()
	return cred, nil
}
