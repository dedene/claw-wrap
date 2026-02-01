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

	"claw-wrap/internal/auth"
	"claw-wrap/internal/framing"
	"claw-wrap/internal/protocol"
)

const (
	// DefaultSocketPath is the default daemon socket path.
	DefaultSocketPath = "/run/openclaw/secrets.sock"
	// DefaultAuthPath is the default HMAC secret path.
	DefaultAuthPath = "/run/openclaw/auth"
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
		socketPath: DefaultSocketPath,
		authPath:   DefaultAuthPath,
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

	// 3. Compute timestamp and HMAC
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	hmac, err := auth.ComputeHMAC(secret, timestamp, toolName, cwd, args)
	if err != nil {
		return fmt.Errorf("compute hmac: %w", err)
	}

	// 4. Connect to socket
	conn, err := net.Dial("unix", w.socketPath)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	// 5. Send ProxyRequest (NDJSON)
	req := &protocol.ProxyRequest{
		Tool:      toolName,
		Args:      args,
		Cwd:       cwd,
		Timestamp: timestamp,
		HMAC:      hmac,
	}
	ndjson := framing.NewNDJSONWriter(conn)
	if err := ndjson.Write(req); err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	// 6. Enter I/O loop
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
	var tempFiles []string

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
			done, err := w.handleResponse(msg, &tempFiles)
			if err != nil {
				return err
			}
			if done {
				exitCode = msg.ExitCode
				close(doneCh)
				w.sendCleanup(ndjson, tempFiles)
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

func (w *Wrapper) handleResponse(msg *protocol.ResponseMessage, tempFiles *[]string) (done bool, err error) {
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
		*tempFiles = append(*tempFiles, msg.Path)
		data, err := os.ReadFile(msg.Path)
		if err != nil {
			return false, fmt.Errorf("read temp file: %w", err)
		}
		if msg.Stream == "stdout" {
			os.Stdout.Write(data)
		} else {
			os.Stderr.Write(data)
		}

	case protocol.MsgTypeDone:
		return true, nil

	case protocol.MsgTypeError:
		return true, fmt.Errorf("daemon error: %s", msg.Message)
	}
	return false, nil
}

func (w *Wrapper) sendCleanup(ndjson *framing.NDJSONWriter, files []string) {
	if len(files) == 0 {
		return
	}
	msg := &protocol.WrapperMessage{
		Type:  protocol.MsgTypeCleanup,
		Files: files,
	}
	ndjson.Write(msg)
}

// List requests the list of configured tools.
func (w *Wrapper) List() (*protocol.AdminListResponse, error) {
	data, err := w.sendAdminRequest(protocol.AdminRequest{Admin: "list"})
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
	data, err := w.sendAdminRequest(protocol.AdminRequest{Admin: "check"})
	if err != nil {
		return nil, err
	}

	var resp protocol.AdminCheckResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &resp, nil
}

// sendAdminRequest sends an admin request to the daemon and returns the response.
// Admin requests use simple JSON request/response pattern (no HMAC required).
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

	return buf[:n], nil
}
