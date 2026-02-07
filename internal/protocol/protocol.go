// Package protocol defines the socket communication types between claw-wrap and the daemon.
package protocol

// ProtocolVersion is the wire protocol version for wrapper/daemon requests.
const ProtocolVersion = 3

// ProxyRequest is sent by wrapper to request tool execution (NDJSON format)
type ProxyRequest struct {
	Version   int               `json:"version,omitempty"`
	Tool      string            `json:"tool"`
	Args      []string          `json:"args"`
	Cwd       string            `json:"cwd"`
	Timestamp string            `json:"timestamp"`
	Nonce     string            `json:"nonce"`
	HMAC      string            `json:"hmac"`
	Env       map[string]string `json:"env,omitempty"`
}

// ResponseMessage is sent by daemon during execution (length-prefixed)
type ResponseMessage struct {
	Type     string `json:"type"`                // stdout, stderr, done, error, file
	Data     string `json:"data,omitempty"`      // base64 for stdout/stderr
	ExitCode int    `json:"exit_code,omitempty"` // for done
	Timeout  bool   `json:"timeout,omitempty"`   // for done with timeout
	Message  string `json:"message,omitempty"`   // for error
	Stream   string `json:"stream,omitempty"`    // for file: stdout or stderr
	Path     string `json:"path,omitempty"`      // for file: temp path
}

// WrapperMessage is sent by wrapper during execution (NDJSON format)
type WrapperMessage struct {
	Type   string   `json:"type"`             // stdin, signal, cleanup
	Data   string   `json:"data,omitempty"`   // base64 for stdin
	EOF    bool     `json:"eof,omitempty"`    // stdin EOF
	Signal string   `json:"signal,omitempty"` // SIGINT, SIGTERM, SIGHUP
	Files  []string `json:"files,omitempty"`  // cleanup paths
}

// Message type constants
const (
	MsgTypeStdout  = "stdout"
	MsgTypeStderr  = "stderr"
	MsgTypeDone    = "done"
	MsgTypeError   = "error"
	MsgTypeFile    = "file"
	MsgTypeStdin   = "stdin"
	MsgTypeSignal  = "signal"
	MsgTypeCleanup = "cleanup"
)

// ValidSignals for signal forwarding
var ValidSignals = map[string]bool{
	"SIGINT":  true,
	"SIGTERM": true,
	"SIGHUP":  true,
}

// AdminRequest is sent for administrative commands.
type AdminRequest struct {
	Version   int    `json:"version,omitempty"`
	Admin     string `json:"admin"`
	Timestamp string `json:"timestamp"`
	Nonce     string `json:"nonce"`
	HMAC      string `json:"hmac"`
}

// AdminListResponse contains the list of configured tools.
type AdminListResponse struct {
	Tools   map[string]ToolInfo `json:"tools"`
	Version string              `json:"version,omitempty"`
}

// ToolInfo describes a configured tool.
type ToolInfo struct {
	Binary string `json:"binary"`
	Mode   string `json:"mode"`
}

// AdminCheckResponse contains credential check results.
type AdminCheckResponse struct {
	Credentials map[string]CredentialInfo `json:"credentials"`
	Version     string                    `json:"version,omitempty"`
}

// CredentialInfo describes a credential check result.
type CredentialInfo struct {
	Status  string `json:"status"`
	Preview string `json:"preview,omitempty"`
}
