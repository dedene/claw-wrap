# claw-wrap Protocol Specification

Wire protocol and security model for communication between the claw-wrap wrapper and daemon.

For configuration options, see [CONFIG.md](CONFIG.md).

## 1. Overview

In proxy mode, the daemon executes tools on behalf of the sandbox. Credentials never enter the sandbox:

```
Sandbox → {tool: "gog", args: [...], cwd: "/path", hmac: "..."} → Daemon
Daemon → spawns gog with credentials, captures output
Daemon → {stdout: "...", stderr: "...", exit_code: 0} → Sandbox
```

## 2. Authentication

### 2.1 HMAC Token

All requests must include an HMAC-SHA256 signature with a unique nonce.

**Secret provisioning**:
- Daemon generates random 32-byte secret on startup
- Written to `/run/openclaw/auth` with mode 0600
- Bind-mounted read-only into sandbox by firejail

**Signature scope** (v3):
```
HMAC-SHA256(secret, timestamp + "\n" + tool + "\n" + args_json + "\n" + cwd + "\n" + env_json + "\n" + nonce)
```

Fields are separated by `\n` to prevent concatenation ambiguity attacks. Each field:
- `timestamp`: Unix epoch seconds as string
- `tool`: Tool name (e.g., "gog")
- `args_json`: JSON-encoded args array (e.g., `["gmail","list"]`)
- `cwd`: Working directory path (must be absolute)
- `env_json`: Canonical JSON object of request env (keys sorted)
- `nonce`: 16-byte hex-encoded random value (unique per request)

**Validation**:
- Daemon rejects requests where `|now - timestamp| > 5 seconds`
- Daemon rejects requests with invalid HMAC
- Replay cache prevents duplicate authenticated requests (keyed on HMAC+UID)
- Combined with SO_PEERCRED UID verification
- Replay cache TTL is enforced with a minimum floor of 10 seconds

### 2.2 Request Authentication Flow

```
1. Wrapper reads secret from /run/openclaw/auth
2. Wrapper generates 16-byte random nonce
3. Wrapper computes HMAC(secret, timestamp\ntool\nargs\ncwd\nenv\nnonce)
4. Request includes: {version, tool, args, cwd, timestamp, hmac, nonce, env}
5. Daemon verifies UID via SO_PEERCRED
6. Daemon verifies caller binary path against allowlist
7. Daemon verifies timestamp freshness (±5s)
8. Daemon verifies HMAC signature (including nonce)
9. Daemon checks replay cache (UID + HMAC as key)
10. If any check fails: generic error (no internal details leaked)
```

## 3. Wire Protocol

### 3.1 Request Format (NDJSON)

Requests are newline-delimited JSON (one JSON object per line):

```json
{
  "version": 3,
  "tool": "gog",
  "args": ["gmail", "list"],
  "cwd": "/home/user/project",
  "timestamp": "1706745600",
  "hmac": "base64-encoded-hmac",
  "nonce": "hex-encoded-16-byte-nonce",
  "env": {
    "EXTRA_VAR": "value"
  }
}
```

**Fields**:
- `version` (required): Protocol version (currently `3`)
- `tool` (required): Tool name as defined in wrappers.yaml
- `args` (required): Array of string arguments
- `cwd` (required): Absolute working directory for tool execution
- `timestamp` (required): Unix epoch seconds for HMAC
- `hmac` (required): Base64-encoded HMAC-SHA256 signature
- `nonce` (required): Hex-encoded 16-byte random nonce
- `env` (optional): Additional environment variables to set

### 3.2 Response Format (Length-Prefixed)

Responses use length-prefixed framing for binary safety:

```
[4 bytes: big-endian length][JSON payload]
```

Maximum frame size: 16 MB. Output is chunked, so individual frames stay well within this limit.

**Message types**:

#### Stdout/Stderr Chunk
```json
{"type": "stdout", "data": "base64-encoded-bytes"}
{"type": "stderr", "data": "base64-encoded-bytes"}
```

#### Completion
```json
{"type": "done", "exit_code": 0}
```

#### Error
```json
{"type": "error", "message": "authentication failed"}
```

Error messages are sanitized — internal details (paths, versions, tool names) are logged server-side only.

### 3.3 Stdin Forwarding

```json
{"type": "stdin", "data": "base64-encoded-bytes"}
{"type": "stdin", "eof": true}
```

### 3.4 Signal Forwarding

```json
{"type": "signal", "signal": "SIGINT"}
```

Supported signals: SIGINT, SIGTERM, SIGHUP

### 3.5 Admin Requests

Admin commands (`list`, `check`) use the same NDJSON format with nonce:

```json
{"version": 3, "admin": "list", "timestamp": "...", "hmac": "...", "nonce": "..."}
```

Responses include the daemon's build version for mismatch detection:

```json
{"tools": {...}, "version": "0.1.3"}
```

## 4. Execution Model

### 4.1 Environment Variables

Tools execute with a minimal environment:
- `PATH`, `HOME`, `USER`, `TERM`
- Credentials from `env:` section (resolved from pass/etc)
- Forced env from `forced_env:` section (cannot be overridden by request)
- Extra vars from request `env:` field

**Denied environment variables** are stripped from requests to prevent injection:
- Prefix-blocked: `LD_*`, `DYLD_*`, `BASH_FUNC_*`
- Explicit deny: shell injection vectors (`IFS`, `CDPATH`, `PROMPT_COMMAND`, etc.), language runtime hijack (`PYTHONPATH`, `NODE_OPTIONS`, `RUBYOPT`, etc.), proxy/TLS hijack (`http_proxy`, `SSL_CERT_FILE`, etc.), git hijack (`GIT_PROXY_COMMAND`, `GIT_CONFIG_GLOBAL`, etc.)

### 4.2 Process Groups

- Tool spawned in new process group (`setpgid`)
- On timeout or signal, entire process group killed
- Ensures child processes are cleaned up

### 4.3 Timeouts

- Global default: 300 seconds
- Per-tool override via `timeout:` in tool config
- On timeout: SIGTERM → wait 5s → SIGKILL
- Write timeout (default 30s) on all daemon→client writes
- Optional connection lifetime limit (`max_connection_lifetime`)

### 4.4 Output Handling

- Stdout/stderr streamed as chunks over socket
- Large output buffered in daemon temp files and re-streamed
- Temp files managed server-side, never exposed to wrapper
- Optional `max_output_size` limit — process killed if exceeded
- Stale temp directories swept on daemon startup

### 4.5 Config File Injection

For tools using `config_file:`:
- Daemon creates temp dir with restrictive umask (0o177)
- Renders template with YAML-escaped credential values
- Sets `XDG_CONFIG_HOME` to temp dir
- Cleans up after tool exits

Credential values are single-quoted in YAML templates to prevent special characters from breaking template structure.

## 5. Security Model

### 5.1 Threat Model

**Protected against**:
- Malicious code in sandbox extracting credentials
- Replay attacks (nonce + replay cache + 5-second window)
- Request tampering (HMAC covers args/cwd/env/nonce with field separators)
- Unauthorized tool operations (blocked_args, per-argument matching)
- Environment variable injection (comprehensive denylist)
- YAML template injection (values single-quoted/escaped)
- Path traversal (absolute CWD validation, symlink checks on secret files)
- Output flooding (optional max_output_size)
- Connection exhaustion (max_connections, optional max_connection_lifetime)

**Not protected against**:
- Compromised daemon process
- Compromised pass/GPG credential source
- Memory dumps of daemon process

### 5.2 Defense in Depth

1. **UID verification**: Only configured user can connect
2. **Binary allowlist**: Caller exe path checked via /proc/PID/exe
3. **HMAC authentication**: Field-separated signature with per-request nonce
4. **Replay cache**: Duplicate requests rejected (UID-scoped, min 10s TTL)
5. **Blocked args**: Server-side command restrictions (per-argument matching)
6. **Forced env**: Agent cannot override security settings
7. **No credential exposure**: Credentials never enter sandbox
8. **Process isolation**: Tools in separate process groups
9. **Environment denylist**: Dangerous env vars stripped from requests
10. **Error sanitization**: Internal details logged server-side only
11. **Write deadlines**: Prevent slow-client resource exhaustion
12. **Symlink protection**: Secret file read/write refuses symlinks
13. **Absolute path validation**: CWD must be absolute; pass binary must be absolute
14. **YAML escaping**: Credential values safely quoted in templates
15. **Frame size limit**: Max 16 MB per response frame

### 5.3 File Permissions

```
/run/openclaw/auth:         0600 <user>:<user>
/run/openclaw/secrets.sock: 0600 <user>:<user>
```

Firejail profile must bind-mount `/run/openclaw/auth` as read-only.
