// Package wrapper implements the client side that executes wrapped tools.
package wrapper

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/term"

	"claw-wrap/internal/auth"
	"claw-wrap/internal/framing"
	"claw-wrap/internal/paths"
	"claw-wrap/internal/protocol"
)

// Wrapper is the client that communicates with the daemon.
type Wrapper struct {
	socketPath string
	authPath   string
}

// Option configures the wrapper.
type Option func(*Wrapper)

// WithSocketPath sets the socket path.
func WithSocketPath(path string) Option {
	return func(w *Wrapper) { w.socketPath = path }
}

// WithAuthPath sets the auth file path.
func WithAuthPath(path string) Option {
	return func(w *Wrapper) { w.authPath = path }
}

// New creates a new wrapper with the given options.
func New(opts ...Option) *Wrapper {
	w := &Wrapper{
		socketPath: paths.SocketPath(),
		authPath:   paths.AuthPath(),
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// RunTool requests execution from the daemon and relays I/O.
func (w *Wrapper) RunTool(toolName string, args []string) error {
	// 1. Load HMAC secret
	secret, err := auth.LoadSecret(w.authPath)
	if err != nil {
		return fmt.Errorf("load secret: %w", err)
	}

	// 2. Get working directory
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get cwd: %w", err)
	}

	// 3. Detect terminal and request PTY if available
	// Always request PTY when stdin is a terminal - daemon decides based on tool config
	usePTY := false
	var winSize *protocol.WinSize
	stdinFd := int(os.Stdin.Fd())
	if term.IsTerminal(stdinFd) {
		usePTY = true
		cols, rows, _ := term.GetSize(stdinFd)
		if cols > 0 && rows > 0 {
			winSize = &protocol.WinSize{
				Rows: uint16(rows),
				Cols: uint16(cols),
			}
		}
	}

	// 4. Compute timestamp, nonce, and HMAC (includes PTY flag in signature)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce, err := auth.GenerateNonce()
	if err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	var reqEnv map[string]string
	hmac, err := auth.ComputeHMACWithPTY(secret, timestamp, toolName, cwd, args, reqEnv, nonce, usePTY)
	if err != nil {
		return fmt.Errorf("compute hmac: %w", err)
	}

	// 5. Connect to socket
	conn, err := net.Dial("unix", w.socketPath)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	// 6. Send ProxyRequest (NDJSON)
	req := &protocol.ProxyRequest{
		Version:    protocol.ProtocolVersion,
		Tool:       toolName,
		Args:       args,
		Cwd:        cwd,
		Timestamp:  timestamp,
		Nonce:      nonce,
		HMAC:       hmac,
		Env:        reqEnv,
		UsePTY:     usePTY,
		WindowSize: winSize,
	}
	ndjson := framing.NewNDJSONWriter(conn)
	if err := ndjson.Write(req); err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	// 7. Enter I/O loop (PTY mode uses raw terminal)
	if usePTY {
		return w.ioLoopPTY(conn, ndjson, stdinFd)
	}
	return w.ioLoop(conn, ndjson)
}

func (w *Wrapper) ioLoop(conn net.Conn, ndjson *framing.NDJSONWriter) error {
	decoder := framing.NewDecoder(conn)

	// Channels for coordination
	stdinCh := make(chan []byte, 16)
	stdinEOF := make(chan struct{})
	signalCh := make(chan os.Signal, 1)
	doneCh := make(chan struct{})
	var exitCode int

	// Start stdin reader goroutine
	go func() {
		buf := make([]byte, 32*1024) // 32KB chunks
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				select {
				case stdinCh <- chunk:
				case <-doneCh:
					return
				}
			}
			if err != nil {
				close(stdinEOF)
				return
			}
		}
	}()

	// Register signal handlers
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signalCh)

	// Main loop
	responseCh := make(chan *protocol.ResponseMessage)
	errCh := make(chan error)

	// Response reader goroutine
	go func() {
		for {
			var msg protocol.ResponseMessage
			if err := decoder.Decode(&msg); err != nil {
				if err != io.EOF {
					errCh <- err
				}
				return
			}
			select {
			case responseCh <- &msg:
			case <-doneCh:
				return
			}
		}
	}()

	for {
		select {
		case msg := <-responseCh:
			done, err := w.handleResponse(msg)
			if err != nil {
				return err
			}
			if done {
				exitCode = msg.ExitCode
				close(doneCh)
				os.Exit(exitCode)
			}

		case err := <-errCh:
			close(doneCh)
			return fmt.Errorf("read response: %w", err)

		case chunk := <-stdinCh:
			msg := &protocol.WrapperMessage{
				Type: protocol.MsgTypeStdin,
				Data: base64.StdEncoding.EncodeToString(chunk),
			}
			if err := ndjson.Write(msg); err != nil {
				return fmt.Errorf("send stdin: %w", err)
			}

		case <-stdinEOF:
			msg := &protocol.WrapperMessage{
				Type: protocol.MsgTypeStdin,
				EOF:  true,
			}
			ndjson.Write(msg)
			stdinEOF = nil // Disable this case

		case sig := <-signalCh:
			sigName := "SIGTERM"
			switch sig {
			case syscall.SIGINT:
				sigName = "SIGINT"
			case syscall.SIGHUP:
				sigName = "SIGHUP"
			}
			msg := &protocol.WrapperMessage{
				Type:   protocol.MsgTypeSignal,
				Signal: sigName,
			}
			ndjson.Write(msg)
		}
	}
}

// ioLoopPTY handles I/O in PTY mode with raw terminal and SIGWINCH forwarding.
func (w *Wrapper) ioLoopPTY(conn net.Conn, ndjson *framing.NDJSONWriter, stdinFd int) error {
	// Put terminal in raw mode
	oldState, err := term.MakeRaw(stdinFd)
	if err != nil {
		// Fall back to regular mode if raw mode fails
		return w.ioLoop(conn, ndjson)
	}
	// Restore terminal on all exit paths. Note: os.Exit() doesn't run defers,
	// so we call Restore explicitly before os.Exit and use defer for error returns.
	defer term.Restore(stdinFd, oldState)

	decoder := framing.NewDecoder(conn)

	// Channels for coordination
	stdinCh := make(chan []byte, 16)
	stdinEOF := make(chan struct{})
	signalCh := make(chan os.Signal, 1)
	winSizeCh := make(chan os.Signal, 1)
	doneCh := make(chan struct{})
	var exitCode int

	// Start stdin reader goroutine
	go func() {
		buf := make([]byte, 32*1024) // 32KB chunks
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				select {
				case stdinCh <- chunk:
				case <-doneCh:
					return
				}
			}
			if err != nil {
				close(stdinEOF)
				return
			}
		}
	}()

	// Register signal handlers
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	signal.Notify(winSizeCh, syscall.SIGWINCH)
	defer signal.Stop(signalCh)
	defer signal.Stop(winSizeCh)

	// Main loop
	responseCh := make(chan *protocol.ResponseMessage)
	errCh := make(chan error)

	// Response reader goroutine
	go func() {
		for {
			var msg protocol.ResponseMessage
			if err := decoder.Decode(&msg); err != nil {
				if err != io.EOF {
					errCh <- err
				}
				return
			}
			select {
			case responseCh <- &msg:
			case <-doneCh:
				return
			}
		}
	}()

	for {
		select {
		case msg := <-responseCh:
			done, err := w.handleResponse(msg)
			if err != nil {
				return err
			}
			if done {
				exitCode = msg.ExitCode
				close(doneCh)
				// Restore terminal before os.Exit (defers don't run on os.Exit)
				term.Restore(stdinFd, oldState)
				os.Exit(exitCode)
			}

		case err := <-errCh:
			close(doneCh)
			return fmt.Errorf("read response: %w", err)

		case chunk := <-stdinCh:
			msg := &protocol.WrapperMessage{
				Type: protocol.MsgTypeStdin,
				Data: base64.StdEncoding.EncodeToString(chunk),
			}
			if err := ndjson.Write(msg); err != nil {
				return fmt.Errorf("send stdin: %w", err)
			}

		case <-stdinEOF:
			msg := &protocol.WrapperMessage{
				Type: protocol.MsgTypeStdin,
				EOF:  true,
			}
			ndjson.Write(msg)
			stdinEOF = nil // Disable this case

		case sig := <-signalCh:
			sigName := "SIGTERM"
			switch sig {
			case syscall.SIGINT:
				sigName = "SIGINT"
			case syscall.SIGHUP:
				sigName = "SIGHUP"
			}
			msg := &protocol.WrapperMessage{
				Type:   protocol.MsgTypeSignal,
				Signal: sigName,
			}
			ndjson.Write(msg)

		case <-winSizeCh:
			// Get new window size and forward to daemon
			cols, rows, _ := term.GetSize(stdinFd)
			if cols > 0 && rows > 0 {
				msg := &protocol.WrapperMessage{
					Type: protocol.MsgTypeWinSize,
					Rows: uint16(rows),
					Cols: uint16(cols),
				}
				ndjson.Write(msg)
			}
		}
	}
}

func (w *Wrapper) handleResponse(msg *protocol.ResponseMessage) (done bool, err error) {
	switch msg.Type {
	case protocol.MsgTypeStdout:
		data, err := base64.StdEncoding.DecodeString(msg.Data)
		if err != nil {
			return false, fmt.Errorf("decode stdout: %w", err)
		}
		os.Stdout.Write(data)

	case protocol.MsgTypeStderr:
		data, err := base64.StdEncoding.DecodeString(msg.Data)
		if err != nil {
			return false, fmt.Errorf("decode stderr: %w", err)
		}
		os.Stderr.Write(data)

	case protocol.MsgTypeFile:
		// Backward-compatible safety: ignore file-path based responses.
		// Modern daemon versions stream output directly and never expose paths.
		return false, fmt.Errorf("daemon returned deprecated file response")

	case protocol.MsgTypeDone:
		return true, nil

	case protocol.MsgTypeError:
		return true, fmt.Errorf("daemon error: %s", msg.Message)
	}
	return false, nil
}

// List requests the list of configured tools.
func (w *Wrapper) List() (*protocol.AdminListResponse, error) {
	req, err := w.buildAdminRequest("list")
	if err != nil {
		return nil, err
	}
	data, err := w.sendAdminRequest(req)
	if err != nil {
		return nil, err
	}

	var resp protocol.AdminListResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &resp, nil
}

// Check requests credential verification.
func (w *Wrapper) Check() (*protocol.AdminCheckResponse, error) {
	req, err := w.buildAdminRequest("check")
	if err != nil {
		return nil, err
	}
	data, err := w.sendAdminRequest(req)
	if err != nil {
		return nil, err
	}

	var resp protocol.AdminCheckResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &resp, nil
}

// buildAdminRequest creates a signed admin request.
func (w *Wrapper) buildAdminRequest(command string) (*protocol.AdminRequest, error) {
	secret, err := auth.LoadSecret(w.authPath)
	if err != nil {
		return nil, fmt.Errorf("load secret: %w", err)
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce, err := auth.GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	hmac, err := auth.ComputeHMAC(secret, timestamp, "admin:"+command, "", nil, nonce)
	if err != nil {
		return nil, fmt.Errorf("compute hmac: %w", err)
	}

	return &protocol.AdminRequest{
		Version:   protocol.ProtocolVersion,
		Admin:     command,
		Timestamp: timestamp,
		Nonce:     nonce,
		HMAC:      hmac,
	}, nil
}

// sendAdminRequest sends an admin request to the daemon and returns the response.
func (w *Wrapper) sendAdminRequest(request interface{}) ([]byte, error) {
	conn, err := net.Dial("unix", w.socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to socket: %w", err)
	}
	defer conn.Close()

	data, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	data = buf[:n]
	var adminErr map[string]string
	if err := json.Unmarshal(data, &adminErr); err == nil {
		if msg, ok := adminErr["error"]; ok && msg != "" {
			return nil, fmt.Errorf("daemon error: %s", msg)
		}
	}

	return data, nil
}
