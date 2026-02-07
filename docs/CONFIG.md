# Configuration Reference

claw-wrap reads its configuration from `/etc/openclaw/wrappers.yaml`.

## Minimal Example

A single tool (`gh`) with one credential:

```yaml
proxy:
  timeout: 300s
  inline_threshold: 1MB
  hmac_secret_file: /run/openclaw/auth
  max_connections: 64
  read_header_timeout: 3s
  read_message_timeout: 15s
  max_stdin_message_size: 1MB
  replay_cache_ttl: 2m
  replay_cache_max_entries: 10000

security:
  allow_unverified_caller_exe: false

credentials:
  github-token:
    source: pass:cli/github/token

tools:
  gh:
    binary: /home/linuxbrew/.linuxbrew/bin/gh
    env:
      GH_TOKEN: github-token
    blocked_args:
      - pattern: "repo\\s+delete"
        message: "Repository deletion is blocked"
```

## Full Example

```yaml
# Proxy mode settings (required)
proxy:
  timeout: 300s                            # Default execution timeout
  inline_threshold: 1MB                    # Switch to temp file above this
  hmac_secret_file: /run/openclaw/auth     # Path to HMAC secret
  max_connections: 64                      # Max concurrent connections
  read_header_timeout: 3s                  # Initial request read timeout
  read_message_timeout: 15s                # Per stdin/control message timeout
  max_stdin_message_size: 1MB              # Max wrapper->daemon NDJSON message
  replay_cache_ttl: 2m                     # Replay protection cache TTL
  replay_cache_max_entries: 10000          # Replay cache size bound

security:
  allow_unverified_caller_exe: false       # Fail closed if caller executable cannot be resolved

# Credential definitions
credentials:
  bird-auth-token:
    source: pass:cli/bird/auth-token
  bird-ct0:
    source: pass:cli/bird/ct0
  github-token:
    source: pass:cli/github/token
  gog-keyring-password:
    source: pass:cli/gog/keyring-password
  openhue-bridge:
    source: pass:cli/openhue/bridge
  openhue-key:
    source: pass:cli/openhue/key

# Tool definitions
tools:
  # Simple env var injection
  bird:
    binary: /usr/local/bin/bird
    env:
      AUTH_TOKEN: bird-auth-token
      CT0: bird-ct0

  # With blocked arguments and per-tool timeout
  gog:
    binary: /usr/local/bin/gog
    timeout: 600s    # Override global timeout for slow operations
    env:
      GOG_KEYRING_PASSWORD: gog-keyring-password
    forced_env:
      GOG_ENABLE_COMMANDS: "gmail,calendar,drive,tasks,contacts,keep,time"
    blocked_args:
      - pattern: "gmail\\s+(send|delete|trash)"
        message: "Email send/delete operations are blocked"
      - pattern: "drive\\s+(delete|trash|remove)"
        message: "Drive delete operations are blocked"

  # Config file injection
  openhue:
    binary: /usr/local/bin/openhue
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

## Proxy Settings

The `proxy:` section configures proxy mode behavior:

```yaml
proxy:
  timeout: 300s                            # Default execution timeout (required)
  inline_threshold: 1MB                    # Output size before switching to temp file
  hmac_secret_file: /run/openclaw/auth     # Path where daemon writes HMAC secret
  max_connections: 64                       # Concurrent connection limit
  read_header_timeout: 3s                   # Timeout for first request read
  read_message_timeout: 15s                 # Timeout for stdin/control reads
  max_stdin_message_size: 1MB               # Max stdin/control message size
  replay_cache_ttl: 2m                      # Replay detection TTL
  replay_cache_max_entries: 10000           # Replay cache size cap
```

### `timeout`

Default timeout for tool execution. Use Go duration format: `30s`, `5m`, `1h`.

### `inline_threshold`

Output size limit before switching to temp file mode. Supports: `512KB`, `1MB`, `10MB`.

When tool output exceeds this threshold, it's written to a temp file instead of streamed inline. This prevents memory issues with large outputs.

### `hmac_secret_file`

Path where the daemon writes the HMAC secret on startup. The wrapper reads this file to sign requests. Must be readable by the sandboxed process.

### `max_connections`

Maximum number of concurrent socket connections handled by the daemon. Extra connections are rejected with `server busy`.

### `read_header_timeout`

Timeout for reading the first request payload on a new connection.

### `read_message_timeout`

Timeout applied to each stdin/control message while a proxied command is running.

### `max_stdin_message_size`

Maximum size of wrapper-to-daemon NDJSON messages (`stdin`, `signal`, `cleanup`). Oversized messages are rejected.

### `replay_cache_ttl` / `replay_cache_max_entries`

Controls replay protection for authenticated requests. Reuse of the same signed request within TTL is rejected.

## Security Settings

```yaml
security:
  allow_unverified_caller_exe: false
```

### `allow_unverified_caller_exe`

Default is `false` (recommended): if caller executable resolution fails, request is denied (fail closed).  
Set to `true` only for exceptional environments where executable lookup is unavailable.

## Credential Sources

### Password Store (`pass`)

```yaml
credentials:
  my-secret:
    source: pass:path/to/secret
```

Fetches the secret using `pass path/to/secret`.

### Environment File

```yaml
credentials:
  my-secret:
    source: env:MY_VAR_NAME
```

Reads from `/run/openclaw/env` file (used for systemd credentials).

## Tool Options

### `binary` (required)

Path to the actual tool binary.

```yaml
tools:
  mytool:
    binary: /usr/local/bin/mytool
```

### `timeout` (optional)

Per-tool timeout override. If not specified, uses the global `proxy.timeout`.

```yaml
tools:
  slow-tool:
    binary: /usr/local/bin/slow-tool
    timeout: 600s    # 10 minutes for this specific tool
```

### `env` (optional)

Map of environment variables to inject. Values are credential names.

```yaml
tools:
  mytool:
    binary: /usr/local/bin/mytool
    env:
      API_KEY: my-api-key
      API_SECRET: my-api-secret
```

### `forced_env` (optional)

Environment variables that are always set. The agent cannot override these.

```yaml
tools:
  mytool:
    binary: /usr/local/bin/mytool
    forced_env:
      SAFE_MODE: "true"
      MAX_RESULTS: "100"
```

### `blocked_args` (optional)

List of regex patterns that block certain arguments.

```yaml
tools:
  mytool:
    binary: /usr/local/bin/mytool
    blocked_args:
      - pattern: "delete\\s+--force"
        message: "Force delete is not allowed"
      - pattern: "(rm|remove)\\s+-rf"
        message: "Recursive delete blocked"
```

### `config_file` (optional)

For tools that read config from a file instead of environment variables.

```yaml
tools:
  mytool:
    binary: /usr/local/bin/mytool
    config_file:
      xdg_subdir: mytool           # Creates $XDG_CONFIG_HOME/mytool/
      filename: config.yaml        # File name within that directory
      template: |                  # Template with credential placeholders
        api_key: {{ .my-api-key }}
        api_secret: {{ .my-api-secret }}
      credentials:                 # List of credentials used in template
        - my-api-key
        - my-api-secret
```

The daemon:
1. Creates a temporary directory
2. Renders the template with credential values
3. Sets `XDG_CONFIG_HOME` to the temp directory
4. The tool reads its config from the expected location

## Template Syntax

Templates use `{{ .credential-name }}` placeholders:

```yaml
template: |
  [default]
  aws_access_key_id = {{ .aws-access-key }}
  aws_secret_access_key = {{ .aws-secret-key }}
```

Credential names with dashes can also use underscores:
- `{{ .my-api-key }}` and `{{ .my_api_key }}` both work

## Security Notes

1. **Blocked args are enforced server-side** - the agent cannot bypass them
2. **Forced env vars cannot be overridden** - stripped from inherited environment
3. **Config file paths are validated** - absolute/traversal paths are rejected
4. **Config file is in a temp directory** - cleaned up after tool exits
5. **Socket requires UID match** - only the configured user can connect
6. **Binary path is verified** - by default executable resolution is fail-closed
7. **Requests are replay-protected** - duplicate HMACs within TTL are rejected
