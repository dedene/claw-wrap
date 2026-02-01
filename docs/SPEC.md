# claw-wrap Proxy Mode Specification

This document specifies the proxy mode implementation for claw-wrap, designed to prevent credential exfiltration from sandboxed environments.

## 1. Overview

### 1.1 Problem Statement

The original architecture returns credentials to the wrapper inside the sandbox:

```
Sandbox → {tool: "gog", args: [...]} → Daemon
Daemon → {env: {GOG_KEYRING_PASSWORD: "secret"}} → Sandbox
Sandbox → exec(gog) with credentials in environment
```

**Vulnerability**: Any process inside the sandbox can connect to `/run/openclaw/secrets.sock` and extract credentials directly, bypassing the intended security model.

### 1.2 Solution: Proxy Mode

In proxy mode, the daemon executes tools on behalf of the sandbox. Credentials never enter the sandbox:

```
Sandbox → {tool: "gog", args: [...], cwd: "/path", hmac: "..."} → Daemon
Daemon → spawns gog with credentials, captures output
Daemon → {stdout: "...", stderr: "...", exit_code: 0} → Sandbox
```

### 1.3 Design Decisions

| Decision | Choice |
|----------|--------|
| Mode selection | Proxy-only (direct-exec removed) |
| Large output handling | Temp file for >threshold, inline otherwise |
| Stdin support | Full duplex forwarding |
| Interactive/PTY | Not supported |
| Legacy protocol | Removed entirely |

## 2. Authentication

### 2.1 HMAC Token

All requests must include an HMAC signature for authentication.

**Secret provisioning**:
- Daemon generates random 32-byte secret on startup
- Written to `/run/openclaw/auth` with mode 0640
- Bind-mounted read-only into sandbox by firejail

**Signature scope**:
```
HMAC-SHA256(secret, timestamp + tool + args_json + cwd)
```

Where:
- `timestamp`: Unix epoch seconds as string
- `tool`: Tool name (e.g., "gog")
- `args_json`: JSON-encoded args array (e.g., `["gmail","list"]`)
- `cwd`: Working directory path

**Validation**:
- Daemon rejects requests where `|now - timestamp| > 5 seconds`
- Daemon rejects requests with invalid HMAC
- Combined with SO_PEERCRED UID verification (existing)

### 2.2 Request Authentication Flow

```
1. Wrapper reads secret from /run/openclaw/auth
2. Wrapper computes HMAC(secret, timestamp + tool + args + cwd)
3. Request includes: {tool, args, cwd, timestamp, hmac}
4. Daemon verifies UID via SO_PEERCRED
5. Daemon verifies timestamp freshness (±5s)
6. Daemon verifies HMAC signature
7. If any check fails: {error: "authentication failed"}
```

## 3. Wire Protocol

### 3.1 Request Format (NDJSON)

Requests are newline-delimited JSON (one JSON object per line):

```json
{
  "tool": "gog",
  "args": ["gmail", "list"],
  "cwd": "/home/user/project",
  "timestamp": "1706745600",
  "hmac": "base64-encoded-hmac",
  "env": {
    "EXTRA_VAR": "value"
  }
}
```

**Fields**:
- `tool` (required): Tool name as defined in wrappers.yaml
- `args` (required): Array of string arguments
- `cwd` (required): Working directory for tool execution
- `timestamp` (required): Unix epoch seconds for HMAC
- `hmac` (required): Base64-encoded HMAC-SHA256 signature
- `env` (optional): Additional environment variables to set

### 3.2 Response Format (Length-Prefixed)

Responses use length-prefixed framing for binary safety:

```
[4 bytes: big-endian length][JSON payload]
```

**Message types**:

#### Error Response
```json
{"type": "error", "message": "authentication failed"}
```

#### Stdout Chunk
```json
{"type": "stdout", "data": "base64-encoded-bytes"}
```

#### Stderr Chunk
```json
{"type": "stderr", "data": "base64-encoded-bytes"}
```

#### Completion
```json
{"type": "done", "exit_code": 0}
```

#### Large Output (Temp File)
```json
{"type": "file", "stream": "stdout", "path": "/run/openclaw/out-abc123"}
```

### 3.3 Stdin Forwarding

Wrapper can send stdin to the running tool:

```json
{"type": "stdin", "data": "base64-encoded-bytes"}
```

EOF signaled by:
```json
{"type": "stdin", "eof": true}
```

### 3.4 Signal Forwarding

Wrapper can forward signals (e.g., when user presses Ctrl+C):

```json
{"type": "signal", "signal": "SIGINT"}
```

Supported signals: SIGINT, SIGTERM, SIGHUP

## 4. Execution Model

### 4.1 Environment Variables

Tools execute with a minimal environment:
- `PATH`: Standard system PATH
- `HOME`: User's home directory
- `USER`: Username
- `TERM`: Terminal type (from daemon)
- Credentials from wrappers.yaml `env:` section
- Forced env vars from wrappers.yaml `forced_env:` section
- Extra vars from request `env:` field (cannot override forced_env)

### 4.2 Working Directory

Tool runs in the `cwd` specified by the request. Daemon verifies the path exists.

### 4.3 Process Groups

- Tool spawned in new process group (`setpgid`)
- On timeout or signal, entire process group killed (`kill(-pgid, sig)`)
- Ensures child processes are cleaned up

### 4.4 Timeouts

- Global default: 300 seconds (5 minutes)
- Per-tool override via `timeout:` in tool config
- On timeout: SIGTERM to process group, wait 5s, SIGKILL if still running

### 4.5 Output Handling

**Inline mode** (default):
- Stdout/stderr sent as chunks over socket
- Chunks sent as they arrive (best-effort ordering)
- Interleaving between stdout/stderr reflects execution order

**Temp file mode** (for large output):
- If accumulated output exceeds `inline_threshold`, switch to temp file
- Temp file written to daemon's PrivateTmp (`/tmp`)
- Path returned in `{"type": "file", ...}` message
- Sandbox reads file directly (bind-mounted)

**Cleanup**:
- Wrapper sends `{"type": "cleanup", "files": ["/path1", "/path2"]}`
- Daemon deletes files on socket disconnect (fallback)

### 4.6 Config File Injection

For tools using `config_file:`:
- Daemon creates temp dir in PrivateTmp
- Renders template with credentials
- Sets `XDG_CONFIG_HOME` to temp dir
- Cleans up after tool exits

## 5. Configuration

### 5.1 Global Proxy Settings

New `proxy:` section in wrappers.yaml:

```yaml
proxy:
  timeout: 300s              # Global default timeout
  inline_threshold: 1MB      # Switch to temp file above this
  hmac_secret_file: /run/openclaw/auth  # Path to HMAC secret
```

### 5.2 Per-Tool Configuration

```yaml
tools:
  gog:
    binary: /home/linuxbrew/.linuxbrew/bin/gog
    timeout: 600s            # Override global timeout
    env:
      GOG_KEYRING_PASSWORD: gog-keyring-password  # Credential name
    forced_env:
      GOG_ENABLE_COMMANDS: "gmail,calendar,drive"  # Cannot be overridden
    blocked_args:
      - pattern: "gmail\\s+(send|delete)"
        message: "Email modifications blocked"
```

### 5.3 Full Example

```yaml
proxy:
  timeout: 300s
  inline_threshold: 1MB
  hmac_secret_file: /run/openclaw/auth

credentials:
  gog-keyring-password:
    source: pass:cli/gog/keyring-password
  openhue-bridge:
    source: pass:cli/openhue/bridge
  openhue-key:
    source: pass:cli/openhue/key

tools:
  gog:
    binary: /home/linuxbrew/.linuxbrew/bin/gog
    timeout: 600s
    env:
      GOG_KEYRING_PASSWORD: gog-keyring-password
    forced_env:
      GOG_ENABLE_COMMANDS: "gmail,calendar,drive,tasks,contacts,keep,time"
    blocked_args:
      - pattern: "gmail\\s+(send|delete|trash)"
        message: "Email send/delete operations are blocked"
      - pattern: "drive\\s+(delete|trash|remove)"
        message: "Drive delete operations are blocked"

  openhue:
    binary: /home/linuxbrew/.linuxbrew/bin/openhue
    config_file:
      xdg_subdir: openhue
      filename: config.yaml
      template: |
        bridge: {{ .openhue-bridge }}
        key: {{ .openhue-key }}
      credentials:
        - openhue-bridge
        - openhue-key
```

## 6. Daemon Behavior

### 6.1 Startup

1. Load configuration from `/etc/openclaw/wrappers.yaml`
2. Generate random 32-byte HMAC secret
3. Write secret to `hmac_secret_file` (mode 0640)
4. Create Unix socket at `/run/openclaw/secrets.sock`
5. Accept connections

### 6.2 Request Handling

1. Accept connection
2. Verify UID via SO_PEERCRED
3. Read NDJSON request
4. Verify timestamp freshness (±5s)
5. Verify HMAC signature
6. Validate tool exists in config
7. Check blocked_args patterns
8. Resolve credentials from sources
9. Spawn tool in new process group
10. Stream stdout/stderr to client
11. Forward stdin from client
12. Handle signals from client
13. Send exit code on completion
14. Clean up temp files on disconnect

### 6.3 Logging

Structured log format (redacted):

```
[INFO] Request: tool=gog args_hash=a1b2c3 peer_uid=1000
[INFO] Completed: tool=gog duration=1.23s exit_code=0
[WARN] Blocked: tool=gog pattern="gmail send" message="Email send blocked"
[ERROR] Auth failed: peer_uid=1000 reason="invalid hmac"
```

- Tool name logged
- Args hashed (not logged in plain text)
- Timing and exit codes logged
- Blocked operations logged with pattern

### 6.4 Error Handling

| Condition | Response |
|-----------|----------|
| UID mismatch | `{"type": "error", "message": "unauthorized uid"}` |
| Invalid timestamp | `{"type": "error", "message": "authentication failed"}` |
| Invalid HMAC | `{"type": "error", "message": "authentication failed"}` |
| Unknown tool | `{"type": "error", "message": "unknown tool: xxx"}` |
| Blocked args | `{"type": "error", "message": "blocked: <message>"}` |
| Credential fetch failed | `{"type": "error", "message": "credential error: xxx"}` |
| Timeout | SIGTERM + 5s + SIGKILL, `{"type": "done", "exit_code": -1, "timeout": true}` |

## 7. Wrapper Behavior

### 7.1 Invocation

When invoked as a symlink (e.g., `gog gmail list`):

1. Determine tool name from argv[0]
2. Read HMAC secret from `/run/openclaw/auth`
3. Compute HMAC signature
4. Connect to `/run/openclaw/secrets.sock`
5. Send request with tool, args, cwd, timestamp, hmac
6. Enter I/O loop

### 7.2 I/O Loop

```
while connection open:
    select on:
        - socket readable: read response, handle by type
        - stdin readable: read chunk, send as stdin message
        - signals: forward as signal message
```

### 7.3 Output Handling

- `stdout` messages: write data to os.Stdout
- `stderr` messages: write data to os.Stderr
- `file` messages: read temp file, write to appropriate fd
- `done` message: exit with provided exit_code

### 7.4 Signal Handling

- Catch SIGINT, SIGTERM, SIGHUP
- Forward as `{"type": "signal", "signal": "SIGINT"}`
- Continue I/O loop (don't exit until `done` received)

### 7.5 Cleanup

On exit (normal or error):
- Send cleanup message for any temp files received
- Close socket connection

### 7.6 Error Handling

- Connection refused: exit 1 with error message
- Connection reset: exit 1 with error message
- No retry on daemon restart

## 8. Security Considerations

### 8.1 Threat Model

**Protected against**:
- Malicious code in sandbox extracting credentials
- Replay attacks (5-second timestamp window)
- Request tampering (HMAC covers full request)
- Unauthorized tools (blocked_args enforcement)

**Not protected against**:
- Compromised daemon (has full credential access)
- Compromised pass/GPG (credential source)
- Side-channel timing attacks on HMAC verification
- Memory dumps of daemon process

### 8.2 Defense in Depth

1. **UID verification**: Only configured user can connect
2. **HMAC authentication**: Prevents unauthorized requests
3. **Blocked args**: Server-side enforcement of restrictions
4. **Forced env**: Agent cannot override security settings
5. **No credential exposure**: Credentials never enter sandbox
6. **Process isolation**: Tools run in separate process groups

### 8.3 Secret File Permissions

```
/run/openclaw/auth: 0640 <user>:<user>
/run/openclaw/secrets.sock: 0666 root:root
```

The socket is world-writable but protected by UID verification via SO_PEERCRED.
Firejail profile must bind-mount `/run/openclaw/auth` as read-only.

## 9. Testing

### 9.1 Unit Tests

- Protocol parsing (request/response)
- HMAC computation and verification
- Config loading and validation
- Blocked args pattern matching
- Credential resolution (mock sources)

### 9.2 Manual Testing

```bash
# Verify daemon starts
sudo systemctl start claw-wrap
sudo systemctl status claw-wrap

# Verify auth file created
ls -la /run/openclaw/auth

# Test tool execution
gog time now
bird whoami

# Test blocked args
gog gmail send test@example.com  # Should fail

# Test stdin forwarding
echo "test" | some-tool-that-reads-stdin

# Test large output
gog drive list  # May trigger temp file mode

# Test timeout
some-slow-tool  # Should timeout after configured duration

# Test signal forwarding
gog gmail list &
kill -INT $!  # Should forward signal and exit
```

## 10. Migration

### 10.1 Breaking Changes

1. Legacy credential protocol removed
2. Direct-exec mode removed
3. New `proxy:` config section required
4. HMAC secret file must be bind-mounted into sandbox

### 10.2 Migration Steps

1. Update wrappers.yaml with `proxy:` section
2. Update firejail profile to bind-mount `/run/openclaw/auth`
3. Rebuild and install new claw-wrap binary
4. Restart daemon: `sudo systemctl restart claw-wrap`
5. Restart gateway: `sudo systemctl restart openclaw-gateway`
6. Test tool execution from within sandbox

## 11. Future Considerations

### 11.1 Not Implemented

- PTY allocation for interactive tools
- Metrics/stats endpoint
- Retry on daemon restart
- Per-tool concurrency limits

### 11.2 Potential Enhancements

- Cgroup-based process isolation
- Rate limiting per tool/caller
- Audit log to separate file
- Tool execution quotas
