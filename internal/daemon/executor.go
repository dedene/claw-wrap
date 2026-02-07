// Package daemon implements the secrets daemon that serves credentials over a Unix socket.
package daemon

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"claw-wrap/internal/config"
	"claw-wrap/internal/credentials"
	"claw-wrap/internal/framing"
	"claw-wrap/internal/protocol"
)

// deniedEnvVars contains environment variable names that must never be
// injected via request env. These could be used to hijack tool execution.
var deniedEnvVars = map[string]bool{
	"LD_PRELOAD":            true,
	"LD_LIBRARY_PATH":       true,
	"BASH_ENV":              true,
	"ENV":                   true,
	"DYLD_INSERT_LIBRARIES": true,
	"DYLD_LIBRARY_PATH":     true,
	"DYLD_FRAMEWORK_PATH":   true,
	"PYTHONPATH":            true,
	"PYTHONSTARTUP":         true,
	"PERL5LIB":              true,
	"RUBYLIB":               true,
	"NODE_OPTIONS":          true,
	"GIT_SSH_COMMAND":       true,
	"EDITOR":                true,
	"VISUAL":                true,
	"PAGER":                 true,
}

// isDeniedEnvVar checks if an environment variable name is in the denylist.
// Also blocks BASH_FUNC_* prefix (bash function exports).
func isDeniedEnvVar(key string) bool {
	if deniedEnvVars[key] {
		return true
	}
	if strings.HasPrefix(key, "BASH_FUNC_") {
		return true
	}
	return false
}

// ToolExecutor handles proxy mode execution of a tool.
type ToolExecutor struct {
	conn net.Conn
	req  *protocol.ProxyRequest
	tool *config.ToolDef
	cfg  *config.Config

	cmd       *exec.Cmd
	pgid      int
	stdinPipe io.WriteCloser

	ctx       context.Context
	cancel    context.CancelFunc
	timeout   time.Duration
	threshold int64
	readMsgTO time.Duration
	msgSize   int

	encoder *framing.Encoder
	sendMu  sync.Mutex

	configDir string // temp dir for config file injection

	stdoutBuf *OutputBuffer
	stderrBuf *OutputBuffer

	pumperWg sync.WaitGroup // WaitGroup for I/O pumpers
}

// NewToolExecutor creates a new ToolExecutor for the given request.
func NewToolExecutor(conn net.Conn, req *protocol.ProxyRequest, tool *config.ToolDef, cfg *config.Config) *ToolExecutor {
	timeout := tool.GetTimeout(cfg.GetTimeout())
	threshold := cfg.GetInlineThreshold()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	return &ToolExecutor{
		conn:      conn,
		req:       req,
		tool:      tool,
		cfg:       cfg,
		ctx:       ctx,
		cancel:    cancel,
		timeout:   timeout,
		threshold: threshold,
		readMsgTO: cfg.GetReadMessageTimeout(),
		msgSize:   cfg.GetMaxStdinMessageSize(),
		encoder:   framing.NewEncoder(conn),
	}
}

// Run is the main entry point that executes the tool and handles I/O.
func (e *ToolExecutor) Run() error {
	defer e.cleanup()

	// Verify working directory exists
	if _, err := os.Stat(e.req.Cwd); os.IsNotExist(err) {
		e.sendError(fmt.Sprintf("working directory does not exist: %s", e.req.Cwd))
		return err
	}

	// Setup config file if needed
	if err := e.setupConfigFile(); err != nil {
		e.sendError(fmt.Sprintf("setup config file: %v", err))
		return err
	}

	// Build environment
	env, err := e.buildEnvironment()
	if err != nil {
		e.sendError(fmt.Sprintf("build environment: %v", err))
		return err
	}

	// Start the process
	if err := e.startProcess(env); err != nil {
		e.sendError(fmt.Sprintf("start process: %v", err))
		return err
	}

	// Run I/O loop
	if err := e.runIOLoop(); err != nil {
		// Don't send error here, runIOLoop handles its own error reporting
		return err
	}

	return nil
}

// buildEnvironment constructs the environment for the tool.
// Order: minimal base + credentials + forced_env + req.Env (cannot override forced_env)
func (e *ToolExecutor) buildEnvironment() ([]string, error) {
	envMap := make(map[string]string)

	// Start with minimal base environment
	envMap["PATH"] = os.Getenv("PATH")
	if envMap["PATH"] == "" {
		envMap["PATH"] = "/usr/local/bin:/usr/bin:/bin"
	}

	if home := os.Getenv("HOME"); home != "" {
		envMap["HOME"] = home
	} else if u, err := user.Current(); err == nil {
		envMap["HOME"] = u.HomeDir
	}

	if username := os.Getenv("USER"); username != "" {
		envMap["USER"] = username
	} else if u, err := user.Current(); err == nil {
		envMap["USER"] = u.Username
	}

	if term := os.Getenv("TERM"); term != "" {
		envMap["TERM"] = term
	} else {
		envMap["TERM"] = "dumb"
	}

	// Add credentials from tool.Env
	for envVar, credName := range e.tool.Env {
		credDef, ok := e.cfg.Credentials[credName]
		if !ok {
			return nil, fmt.Errorf("missing credential config: %s", credName)
		}
		value, err := credentials.Fetch(credDef.Source, credentials.WithPassBinary(e.cfg.GetPassBinary()))
		if err != nil {
			return nil, fmt.Errorf("fetch credential %s: %w", credName, err)
		}
		if value == "" {
			return nil, fmt.Errorf("empty credential: %s", credName)
		}
		envMap[envVar] = value
	}

	// Add forced_env (these cannot be overridden)
	forcedKeys := make(map[string]bool)
	for k, v := range e.tool.ForcedEnv {
		envMap[k] = v
		forcedKeys[k] = true
	}

	// Add request env (cannot override forced_env, blocked dangerous vars)
	for k, v := range e.req.Env {
		if isDeniedEnvVar(k) {
			log.Printf("[WARN] Request attempted to set denied env var %q, ignoring", k)
			continue
		}
		if forcedKeys[k] {
			log.Printf("[WARN] Request attempted to override forced_env key %q, ignoring", k)
			continue
		}
		envMap[k] = v
	}

	// If we have a config dir, set XDG_CONFIG_HOME
	if e.configDir != "" {
		envMap["XDG_CONFIG_HOME"] = e.configDir
	}

	// Convert map to slice
	env := make([]string, 0, len(envMap))
	for k, v := range envMap {
		env = append(env, k+"="+v)
	}

	return env, nil
}

// setupConfigFile creates a temp config file if the tool requires one.
func (e *ToolExecutor) setupConfigFile() error {
	if e.tool.ConfigFile == nil {
		return nil
	}

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "claw-wrap-config-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	e.configDir = tempDir

	// Create XDG subdir
	configPath := filepath.Join(tempDir, e.tool.ConfigFile.XDGSubdir)
	if err := os.MkdirAll(configPath, 0700); err != nil {
		return fmt.Errorf("create config subdir: %w", err)
	}

	// Fetch credentials for template
	credValues := make(map[string]string)
	for _, credName := range e.tool.ConfigFile.Credentials {
		credDef, ok := e.cfg.Credentials[credName]
		if !ok {
			return fmt.Errorf("missing credential config: %s", credName)
		}
		value, err := credentials.Fetch(credDef.Source, credentials.WithPassBinary(e.cfg.GetPassBinary()))
		if err != nil {
			return fmt.Errorf("fetch credential %s: %w", credName, err)
		}
		if value == "" {
			return fmt.Errorf("empty credential: %s", credName)
		}
		credValues[credName] = value
	}

	// Render template
	content := renderTemplate(e.tool.ConfigFile.Template, credValues)

	// Write config file
	configFile := filepath.Join(configPath, e.tool.ConfigFile.Filename)
	if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

// startProcess spawns the tool in a new process group.
func (e *ToolExecutor) startProcess(env []string) error {
	e.cmd = exec.CommandContext(e.ctx, e.tool.Binary, e.req.Args...)
	e.cmd.Dir = e.req.Cwd
	e.cmd.Env = env

	// Create new process group so we can kill all children
	e.cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}

	// Set up pipes
	stdout, err := e.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	stderr, err := e.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	stdin, err := e.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	e.stdinPipe = stdin

	// Create output buffers
	e.stdoutBuf = NewOutputBuffer("stdout", e.threshold, e.sendMessage)
	e.stderrBuf = NewOutputBuffer("stderr", e.threshold, e.sendMessage)

	// Start the process
	if err := e.cmd.Start(); err != nil {
		return fmt.Errorf("start: %w", err)
	}

	// Get the process group ID
	e.pgid = e.cmd.Process.Pid

	// Start I/O pumpers
	e.pumperWg.Add(2) // Only stdout and stderr pumpers, not stdin

	go e.stdoutPumper(stdout)
	go e.stderrPumper(stderr)
	go e.stdinPumper() // stdin pumper runs independently

	return nil
}

// runIOLoop waits for the process to complete and handles timeout.
func (e *ToolExecutor) runIOLoop() error {
	// Wait for process in a goroutine
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- e.cmd.Wait()
	}()

	// Wait for either completion or context cancellation
	select {
	case err := <-waitDone:
		// Process completed normally
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				// Some other error
				e.sendError(fmt.Sprintf("process error: %v", err))
				return err
			}
		}

		// Wait for output pumpers to finish draining pipes
		// Use a channel with timeout to avoid blocking forever
		pumpersDone := make(chan struct{})
		go func() {
			e.pumperWg.Wait()
			close(pumpersDone)
		}()

		select {
		case <-pumpersDone:
			// Pumpers finished normally
		case <-time.After(5 * time.Second):
			// Pumpers taking too long, proceed anyway
			log.Printf("[WARN] Output pumpers did not finish within 5 seconds")
		}

		// Finalize output buffers and send file messages if needed
		if err := e.finalizeOutput(); err != nil {
			log.Printf("[WARN] Finalize output: %v", err)
		}

		e.sendDone(exitCode, false)
		return nil

	case <-e.ctx.Done():
		// Timeout or cancellation
		e.handleTimeout()
		return e.ctx.Err()
	}
}

// stdoutPumper reads from stdout and writes to the output buffer.
func (e *ToolExecutor) stdoutPumper(r io.Reader) {
	defer e.pumperWg.Done()

	buf := make([]byte, 32*1024) // 32KB buffer
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if writeErr := e.stdoutBuf.Write(buf[:n]); writeErr != nil {
				log.Printf("[WARN] stdout write: %v", writeErr)
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[DEBUG] stdout read: %v", err)
			}
			return
		}
	}
}

// stderrPumper reads from stderr and writes to the output buffer.
func (e *ToolExecutor) stderrPumper(r io.Reader) {
	defer e.pumperWg.Done()

	buf := make([]byte, 32*1024) // 32KB buffer
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if writeErr := e.stderrBuf.Write(buf[:n]); writeErr != nil {
				log.Printf("[WARN] stderr write: %v", writeErr)
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[DEBUG] stderr read: %v", err)
			}
			return
		}
	}
}

// stdinPumper reads WrapperMessages from the connection and forwards stdin/signals.
func (e *ToolExecutor) stdinPumper() {
	reader := framing.NewNDJSONReaderWithLimit(e.conn, e.msgSize)

	for {
		if e.readMsgTO > 0 {
			_ = e.conn.SetReadDeadline(time.Now().Add(e.readMsgTO))
		}

		var msg protocol.WrapperMessage
		if err := reader.Read(&msg); err != nil {
			_ = e.conn.SetReadDeadline(time.Time{})
			if err != io.EOF {
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					log.Printf("[WARN] stdin/control read timeout after %v", e.readMsgTO)
				}
				log.Printf("[DEBUG] stdin read: %v", err)
			}
			// Connection closed or error, close stdin
			if e.stdinPipe != nil {
				e.stdinPipe.Close()
			}
			return
		}
		_ = e.conn.SetReadDeadline(time.Time{})

		if err := e.handleWrapperMessage(&msg); err != nil {
			log.Printf("[WARN] handle wrapper message: %v", err)
		}
	}
}

// handleWrapperMessage processes a message from the wrapper.
func (e *ToolExecutor) handleWrapperMessage(msg *protocol.WrapperMessage) error {
	switch msg.Type {
	case protocol.MsgTypeStdin:
		if msg.EOF {
			// Close stdin pipe
			if e.stdinPipe != nil {
				if err := e.stdinPipe.Close(); err != nil {
					return fmt.Errorf("close stdin: %w", err)
				}
				e.stdinPipe = nil
			}
		} else {
			// Decode and write data
			data, err := base64.StdEncoding.DecodeString(msg.Data)
			if err != nil {
				return fmt.Errorf("decode stdin: %w", err)
			}
			if e.stdinPipe != nil {
				if _, err := e.stdinPipe.Write(data); err != nil {
					return fmt.Errorf("write stdin: %w", err)
				}
			}
		}

	case protocol.MsgTypeSignal:
		if err := e.forwardSignal(msg.Signal); err != nil {
			return fmt.Errorf("forward signal: %w", err)
		}

	case protocol.MsgTypeCleanup:
		// Compatibility no-op. Daemon-only cleanup is enforced server-side.
		log.Printf("[DEBUG] ignoring client cleanup request (%d files)", len(msg.Files))

	default:
		log.Printf("[WARN] unknown wrapper message type: %s", msg.Type)
	}

	return nil
}

// forwardSignal sends a signal to the process group.
func (e *ToolExecutor) forwardSignal(sig string) error {
	// Validate signal
	if !protocol.ValidSignals[sig] {
		return fmt.Errorf("invalid signal: %s", sig)
	}

	// Map signal name to syscall signal
	var signal syscall.Signal
	switch sig {
	case "SIGINT":
		signal = syscall.SIGINT
	case "SIGTERM":
		signal = syscall.SIGTERM
	case "SIGHUP":
		signal = syscall.SIGHUP
	default:
		return fmt.Errorf("unhandled signal: %s", sig)
	}

	return e.killProcessGroup(signal)
}

// sendMessage sends a ResponseMessage to the wrapper (thread-safe).
func (e *ToolExecutor) sendMessage(msg interface{}) error {
	e.sendMu.Lock()
	defer e.sendMu.Unlock()

	return e.encoder.Encode(msg)
}

// sendError sends an error message to the wrapper.
func (e *ToolExecutor) sendError(message string) {
	msg := protocol.ResponseMessage{
		Type:    protocol.MsgTypeError,
		Message: message,
	}
	if err := e.sendMessage(msg); err != nil {
		log.Printf("[WARN] send error message: %v", err)
	}
}

// sendDone sends a completion message to the wrapper.
func (e *ToolExecutor) sendDone(exitCode int, timeout bool) {
	msg := protocol.ResponseMessage{
		Type:     protocol.MsgTypeDone,
		ExitCode: exitCode,
		Timeout:  timeout,
	}
	if err := e.sendMessage(msg); err != nil {
		log.Printf("[WARN] send done message: %v", err)
	}
}

// finalizeOutput closes output buffers and streams any file-buffered output.
func (e *ToolExecutor) finalizeOutput() error {
	// Finalize stdout buffer
	if stdoutPath, err := e.stdoutBuf.Finalize(); err != nil {
		return fmt.Errorf("finalize stdout: %w", err)
	} else if stdoutPath != "" {
		if err := e.streamFile(stdoutPath, protocol.MsgTypeStdout); err != nil {
			return fmt.Errorf("stream stdout file: %w", err)
		}
		if err := os.Remove(stdoutPath); err != nil && !os.IsNotExist(err) {
			log.Printf("[WARN] cleanup stdout temp file %s: %v", stdoutPath, err)
		}
	}

	// Finalize stderr buffer
	if stderrPath, err := e.stderrBuf.Finalize(); err != nil {
		return fmt.Errorf("finalize stderr: %w", err)
	} else if stderrPath != "" {
		if err := e.streamFile(stderrPath, protocol.MsgTypeStderr); err != nil {
			return fmt.Errorf("stream stderr file: %w", err)
		}
		if err := os.Remove(stderrPath); err != nil && !os.IsNotExist(err) {
			log.Printf("[WARN] cleanup stderr temp file %s: %v", stderrPath, err)
		}
	}

	return nil
}

func (e *ToolExecutor) streamFile(path string, streamType string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := make([]byte, 32*1024)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			msg := protocol.ResponseMessage{
				Type: streamType,
				Data: base64.StdEncoding.EncodeToString(buf[:n]),
			}
			if err := e.sendMessage(msg); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

// killProcessGroup sends a signal to the entire process group.
func (e *ToolExecutor) killProcessGroup(sig syscall.Signal) error {
	if e.pgid == 0 {
		return nil
	}

	// Negative PID means send to process group
	return syscall.Kill(-e.pgid, sig)
}

// handleTimeout gracefully terminates the process on timeout.
// Sends SIGTERM first, waits 5 seconds, then SIGKILL if still running.
func (e *ToolExecutor) handleTimeout() {
	log.Printf("[INFO] Tool timeout after %v", e.timeout)

	// Send SIGTERM to process group
	if err := e.killProcessGroup(syscall.SIGTERM); err != nil {
		log.Printf("[WARN] SIGTERM to process group: %v", err)
	}

	// Wait up to 5 seconds for graceful shutdown
	gracePeriod := 5 * time.Second
	deadline := time.Now().Add(gracePeriod)

	for time.Now().Before(deadline) {
		// Check if process has exited
		if e.cmd.ProcessState != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// If still running, send SIGKILL
	if e.cmd.ProcessState == nil {
		log.Printf("[INFO] Process still running after SIGTERM, sending SIGKILL")
		if err := e.killProcessGroup(syscall.SIGKILL); err != nil {
			log.Printf("[WARN] SIGKILL to process group: %v", err)
		}
	}

	// Wait for output pumpers to finish (with timeout)
	pumpersDone := make(chan struct{})
	go func() {
		e.pumperWg.Wait()
		close(pumpersDone)
	}()

	select {
	case <-pumpersDone:
		// Pumpers finished
	case <-time.After(2 * time.Second):
		// Don't wait too long on timeout path
		log.Printf("[WARN] Output pumpers did not finish within 2 seconds")
	}

	// Finalize output buffers
	if err := e.finalizeOutput(); err != nil {
		log.Printf("[WARN] Finalize output: %v", err)
	}

	// Send done with timeout flag
	e.sendDone(-1, true)
}

// cleanup removes temp files and ensures the process group is terminated.
func (e *ToolExecutor) cleanup() {
	// Cancel context
	e.cancel()

	// Close stdin pipe if still open
	if e.stdinPipe != nil {
		e.stdinPipe.Close()
		e.stdinPipe = nil
	}

	// Kill process group if still running
	if e.pgid != 0 {
		// Best effort kill
		_ = e.killProcessGroup(syscall.SIGKILL)
	}

	// Cleanup output buffers
	if e.stdoutBuf != nil {
		e.stdoutBuf.Cleanup()
	}
	if e.stderrBuf != nil {
		e.stderrBuf.Cleanup()
	}

	// Remove config dir
	if e.configDir != "" {
		if err := os.RemoveAll(e.configDir); err != nil {
			log.Printf("[WARN] cleanup config dir: %v", err)
		}
	}

}

// NOTE: renderTemplate is defined in daemon.go and shared by this file
