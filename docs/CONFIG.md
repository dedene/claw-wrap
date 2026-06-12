# Configuration Reference

claw-wrap reads its configuration from `/etc/openclaw/wrappers.yaml`.

## Platform-Specific Paths

The runtime directory varies by platform:

| Platform | Runtime Directory | Example Paths |
|----------|-------------------|---------------|
| Linux    | `/run/openclaw/`  | `/run/openclaw/auth`, `/run/openclaw/proxy-auth-token` |
| macOS    | `$TMPDIR/openclaw/` | `/var/folders/.../openclaw/auth` |

Examples in this document use Linux paths. On macOS, substitute `$TMPDIR/openclaw/` for `/run/openclaw/`.

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
  credential_cache_ttl: 0s
  write_timeout: 30s
  max_output_size: 100MB
  max_connection_lifetime: 30m

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
        match: command
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
  credential_cache_ttl: 0s                 # Credential cache TTL (0 disables)
  write_timeout: 30s                       # Write deadline per response message
  max_output_size: 100MB                   # Kill tool if output exceeds this
  max_connection_lifetime: 30m             # Hard cap on connection duration
  pass_binary: /usr/bin/pass               # Absolute path to pass binary

security:
  # deny_unverified_caller_exe: true       # Opt-in: reject when /proc/<pid>/exe is unreadable

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
        match: command
        message: "Email send/delete operations are blocked"
      - pattern: "drive\\s+(delete|trash|remove)"
        match: command
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

## Git with GitHub Authentication

Git requires special handling:
1. It needs write access to `.git/` directories (blocked by systemd's `ProtectHome=read-only`)
2. Using `credential.helper` with wrapped tools (like `gh auth git-credential`) causes recursive claw-wrap calls that get denied

Use the `GIT_ASKPASS` approach instead:

### Configuration

```yaml
credentials:
  github-token:
    source: pass:cli/github/token

tools:
  git:
    binary: /usr/bin/git
    env:
      GH_TOKEN: github-token
    forced_env:
      GIT_ASKPASS: /usr/local/bin/git-askpass-claw
      GIT_TERMINAL_PROMPT: "0"
```

### Create the askpass script

```bash
sudo install -m 755 /dev/stdin /usr/local/bin/git-askpass-claw <<'EOF'
#!/bin/bash
echo "$GH_TOKEN"
EOF
```

The script simply echoes the token that claw-wrap injects. No recursive calls.

### Add workspace write access

If running in a firejail sandbox with systemd, add write access to your workspace:

```bash
sudo systemctl edit claw-wrap.service
```

```ini
[Service]
ReadWritePaths=/home/YOUR_USERNAME/repos
```

Then reload: `sudo systemctl daemon-reload && sudo systemctl restart claw-wrap`

### Remove conflicting credential helpers

If the repo has a credential helper that calls wrapped tools:

```bash
git config --global --unset credential.helper
# Or per-repo:
git config --unset credential.helper
```

### Why GIT_ASKPASS works

- **Simple**: git calls the script, script prints the password, done
- **No recursion**: Unlike credential helpers that might invoke `gh` or other wrapped tools
- **Secure**: Token is injected by claw-wrap at runtime, never stored on disk
- **Universal**: Works for all GitHub remotes, not tied to a specific URL

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
  credential_cache_ttl: 0s                  # Credential fetch cache TTL (0 disables)
  write_timeout: 30s                        # Write deadline per response message
  max_output_size: 100MB                    # Kill tool if output exceeds this
  max_connection_lifetime: 30m              # Hard cap on connection duration
  pass_binary: /usr/bin/pass                # Absolute path to pass binary
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

Note: the TTL has a floor of 10 seconds — values below 10s are clamped.

### `credential_cache_ttl`

Optional in-memory TTL cache for credential fetch results.

- Default: `0` (disabled)
- Format: Go duration (`30s`, `2m`, `1h`)
- Scope: `op://` (1Password), `bw:` (Bitwarden), and `vault:` (HashiCorp Vault) credential sources
- `claw-wrap check` always bypasses this cache and fetches credentials live

Use this to reduce repeated upstream secret-store latency for frequently-invoked tools.

### `write_timeout`

Deadline for each response message written back to the wrapper. Default: `30s`. Prevents slow/stalled clients from holding connections open indefinitely.

### `max_output_size`

Maximum combined stdout + stderr output before the tool process is killed. Use size notation: `100MB`, `1GB`. Default: `0` (unlimited — opt-in only).

When the limit is reached, the process is killed with `SIGKILL` and the connection is closed.

### `max_connection_lifetime`

Hard upper bound on how long a single connection can remain open. Use Go duration format: `30m`, `1h`. Default: `0` (unlimited — opt-in only).

Individual read/write deadlines may shorten the effective timeout but never extend past this limit.

### `pass_binary`

Absolute path to the `pass` binary used for fetching credentials.

Must be an absolute path — relative paths are rejected with a warning and the default is used instead.

If unset, claw-wrap auto-detects `pass` only in trusted directories:
- `/usr/bin`
- `/usr/local/bin`
- `/opt/homebrew/bin`
- `/home/linuxbrew/.linuxbrew/bin`

If not found there, it falls back to platform default (`/usr/bin/pass` on Linux, `/opt/homebrew/bin/pass` on macOS).

## HTTP Proxy Settings

The optional `http_proxy:` section enables a MITM HTTP/HTTPS proxy for credential injection. This allows tools to make authenticated API calls through the proxy without explicit credential configuration.

Routes reference credentials by name from the `credentials:` section using `{{credential-name}}` syntax.

```yaml
credentials:
  github-token:
    source: op://vault/github/token
  openai-key:
    source: env:OPENAI_KEY

http_proxy:
  enabled: true
  listen: 127.0.0.1:8080
  log_level: errors                    # none, errors, info, debug
  ca:
    # path: ~/.claw-wrap/ca            # Omit to use platform default
    validity_days: 365                 # CA validity period
    organization: claw-wrap            # CA organization name
  strip_response_headers:              # Headers to remove from responses
    - Server
    - X-Powered-By
  routes:
    - host: api.github.com
      inject:
        header: Authorization
        value: "Bearer {{github-token}}"  # References credentials.github-token
      allow:
        - GET /**
        - POST /repos/*/issues
      deny:
        - DELETE /**

    - host: "*.openai.com"             # Wildcard subdomain matching
      inject:
        header: Authorization
        value: "Bearer {{openai-key}}"    # References credentials.openai-key
```

### `enabled`

Enable/disable the HTTP proxy. Default: `false`.

### `listen`

Address to listen on. Must be localhost (`127.0.0.1`, `::1`, or `localhost`). Default: `127.0.0.1:8080`.

### `require_auth`

Whether proxy authentication is required. Default: `true`.

Set to `false` for single-user localhost setups where any local process should be able to use the proxy without authentication. When disabled, no proxy auth token is generated and clients can connect without credentials.

```yaml
http_proxy:
  enabled: true
  require_auth: false  # Skip proxy auth for localhost
```

### `log_level`

Log verbosity: `none`, `errors` (default), `info`, `debug`.

### `ca`

CA certificate configuration for MITM TLS termination:

- `path`: Directory for CA cert/key storage (default: `~/.claw-wrap/ca` on macOS, `/etc/openclaw/ca` on Linux)
- `cert_file`: Certificate filename (default: `ca.crt`). Use `tls.crt` for cert-manager compatibility.
- `key_file`: Key filename (default: `ca.key`). Use `tls.key` for cert-manager compatibility.
- `external`: Enable external CA mode (default: `false`). When `true`:
  - Fails fast if CA files are missing (never auto-generates)
  - Relaxes key permission check for k8s secret mounts (allows 0644)
  - Watches files for changes and hot-reloads on rotation
- `validity_days`: Certificate validity period (default: 365, ignored in external mode)
- `organization`: CA organization name in certificate (ignored in external mode)

**Self-managed mode** (default): The CA cert is auto-generated on first start and auto-rotated 30 days before expiry.

**External mode** (`external: true`): Use with cert-manager or k8s secrets:

```yaml
http_proxy:
  ca:
    path: /etc/claw/ca
    cert_file: tls.crt
    key_file: tls.key
    external: true
```

### `strip_response_headers`

List of response headers to remove before returning to client. Useful for stripping server fingerprints.

### `routes`

List of route definitions for credential injection:

#### Route fields

- `host`: Host pattern (exact or `*.suffix` wildcard)
- `inject.header`: HTTP header name to inject
- `inject.value`: Header value with optional `{{...}}` credential references
- `allow`: Optional list of allowed method/path patterns
- `deny`: Optional list of denied method/path patterns

#### Host matching

- Exact: `api.github.com` matches only `api.github.com`
- Wildcard: `*.github.com` matches `api.github.com`, `raw.github.com` but NOT:
  - `github.com` (bare domain)
  - `deep.sub.github.com` (multi-level subdomain)
  - `evil.github.com.attacker.com` (suffix-anchored, prevents attacks)

#### Path patterns

Format: `[METHOD] /path/pattern`

- `*` matches single path segment
- `**` matches rest of path
- Method is optional, defaults to `*` (any)

Examples:
- `GET /api/**` - GET requests to any path under /api/
- `POST /users` - POST to exactly /users
- `/files/*` - Any method to /files/{segment}

#### Allow/Deny evaluation

1. Check deny rules first (any match → deny)
2. If allow rules exist, at least one must match
3. If no rules, default permit

Requests not matching any route pass through to the upstream server without credential injection.

### Tool integration with `use_proxy`

Tools can opt into using the HTTP proxy:

```yaml
tools:
  my-api-tool:
    binary: /usr/bin/my-tool
    use_proxy: true
```

When `use_proxy: true`, the daemon injects these env vars:
- `HTTP_PROXY` / `http_proxy` (with proxy auth credentials)
- `HTTPS_PROXY` / `https_proxy` (with proxy auth credentials)
- `SSL_CERT_FILE` (for CA trust)
- `NODE_EXTRA_CA_CERTS`
- `REQUESTS_CA_BUNDLE`
- `CURL_CA_BUNDLE`

The proxy requires authentication for all requests (HTTP and CONNECT). For `use_proxy: true`, credentials are injected automatically by claw-wrap.

Manual clients must authenticate to the proxy using Basic auth credentials in the proxy URL.

Run `claw-wrap check` to see the exact paths and export commands for your system:

```bash
claw-wrap check
# Shows:
#   HTTP Proxy:
#     Listen:     127.0.0.1:8080
#     CA cert:    /path/to/ca.crt
#     Auth token: /path/to/proxy-auth-token
#
#   Usage:
#     export HTTPS_PROXY="http://claw:$(cat /path/to/proxy-auth-token)@127.0.0.1:8080"
#     export SSL_CERT_FILE="/path/to/ca.crt"
```

`<daemon-generated-token>` is stored in the daemon runtime directory (see [Platform-Specific Paths](#platform-specific-paths)) as `proxy-auth-token` with strict file permissions (0600) and reused across daemon restarts (but regenerates on system reboot since runtime directory is cleared).
If you are not using `use_proxy`, you must provide your own integration to supply this token.
Deleting the token file and restarting the daemon forces token regeneration.

### Credential references

Inject values use `{{name}}` syntax to reference credentials defined in the `credentials:` section:

```yaml
credentials:
  api-token:
    source: op://vault/item/token
  api-key:
    source: env:API_KEY
  pass-token:
    source: pass:api/token

http_proxy:
  routes:
    - host: api.example.com
      inject:
        header: Authorization
        value: "Bearer {{api-token}}"   # References credentials.api-token
```

Named credentials provide:
- **Single source of truth** - credentials defined once, referenced anywhere
- **Validation** - unknown credential names caught at config load time
- **Reusability** - same credential used in multiple routes

### Security considerations

1. **Authenticated proxy** - Every request requires proxy auth (HTTP + CONNECT)
2. **Localhost only** - Proxy binds to 127.0.0.1 only, never exposed externally
3. **SSRF protection** - Requests to private/reserved IP ranges are blocked
4. **Request smuggling checks** - Transfer-Encoding + Content-Length combos are rejected
5. **Host mismatch protection** - Host header mismatch vs canonical target is rejected
6. **CA key security** - Private key stored with 0600 permissions
7. **Wildcard safety** - Host wildcards are suffix-anchored to prevent subdomain attacks
8. **Firejail integration** (Linux) - Sandboxed tools need CA access: add `whitelist /etc/openclaw/ca/ca.crt` to firejail profiles

## Security Settings

```yaml
security:
  deny_unverified_caller_exe: false
```

### `deny_unverified_caller_exe`

Default is `false`: if caller executable resolution fails (e.g. inside firejail),
the request is still allowed — HMAC auth + UID check provide sufficient security.
Set to `true` to reject connections when `/proc/<pid>/exe` is unreadable (opt-in hardening).
In firejail deployments this can fail closed unexpectedly depending on host `/proc`
policy (`hidepid`, ptrace restrictions), so test carefully before enabling.

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

Security requirements for `/run/openclaw/env`:
- Must be a regular file (symlinks are rejected)
- Must be owned by the daemon user
- Mode must be `0600` or `0640`

### 1Password (`op://`)

```yaml
credentials:
  github-token:
    source: op://Private/GitHub/token

  # With jq extraction from full item JSON
  db-password:
    source: op://Work/Database/item | .fields[] | select(.label=="password") | .value
```

Uses 1Password CLI (`op`) with [Service Account](https://developer.1password.com/docs/service-accounts/) authentication.

Optional overrides:

```yaml
proxy:
  op_binary: /usr/local/bin/op
  op_token_file: /etc/openclaw/1password.token
```

If `op_binary` is unset, claw-wrap only auto-detects `op` in trusted directories:
`/usr/bin`, `/usr/local/bin`, `/opt/homebrew/bin`, `/home/linuxbrew/.linuxbrew/bin`.

**Token sources (checked in order):**
1. `$CREDENTIALS_DIRECTORY/op-service-account-token` (systemd LoadCredential)
2. Configured `op_token_file` path (default: `/etc/openclaw/1password.token`)
3. `OP_SERVICE_ACCOUNT_TOKEN` environment variable

**Security:**
- Token file must be `0600` or `0640`, no symlinks
- If a token file exists but fails security checks, claw-wrap fails closed (no env fallback)
- Token passed via environment variable to `op`, never in command line

### age Encryption

```yaml
credentials:
  api-key:
    source: age:/etc/secrets/api-key.age

  # With jq extraction from encrypted JSON
  db-creds:
    source: age:/etc/secrets/database.json.age | .password
```

Decrypts age-encrypted files using embedded `filippo.io/age` library.
No `age_binary` setting is supported.

**Identity file sources (checked in order):**
1. `$CREDENTIALS_DIRECTORY/age-identity` (systemd LoadCredential)
2. `/etc/openclaw/age-identity` (or configured `age_identity_file`)

**Proxy config option:**
```yaml
proxy:
  age_identity_file: /etc/openclaw/age-identity
```

**Requirements:**
- Identity file must be passphrase-free (X25519 or Hybrid)
- Identity file must be `0600` or `0640`, no symlinks
- Encrypted files must also have restricted permissions

### macOS Keychain (`keychain:`)

```yaml
credentials:
  my-secret:
    source: keychain:my-service-name

  # With jq extraction from JSON stored in keychain
  api-config:
    source: keychain:my-service | .api_key
```

Reads from macOS login keychain using `security find-generic-password`.

**Setup:**
```bash
# 1. Create the keychain item with ACL for claw-wrap
claw-wrap keychain-setup my-service-name
# macOS `security` prompts for the secret directly

# 2. Authorize access (required for unattended use)
claw-wrap check
# macOS will prompt for your password - click "Always Allow"
```

After clicking "Always Allow", the daemon can access this credential without prompts. This authorization step is required once per credential after setup.

**Platform:** macOS only. Command hidden on other platforms.

### Bitwarden (`bw:`)

```yaml
credentials:
  api-key:
    source: bw:12345678-uuid-here

  # With jq extraction from item JSON
  login-password:
    source: bw:12345678-uuid-here | .login.password
```

Fetches items from Bitwarden vault using API key authentication.

Optional CLI override:

```yaml
proxy:
  bw_binary: /usr/local/bin/bw
```

If `bw_binary` is unset, claw-wrap only auto-detects `bw` in trusted directories:
`/usr/bin`, `/usr/local/bin`, `/opt/homebrew/bin`, `/home/linuxbrew/.linuxbrew/bin`.

**Credential sources (each checked in CREDENTIALS_DIRECTORY, then env var):**
- `bw-client-id` / `BW_CLIENTID`
- `bw-client-secret` / `BW_CLIENTSECRET`
- `bw-master-password` / `BW_PASSWORD` (master password for unlock)

**Features:**
- Session persists until daemon restart (no re-auth per request)
- Thread-safe with mutex protection
- Isolated data directory per session
- Automatic re-authentication on session errors

**Security:**
- Credentials loaded via `readSecureFile()` (symlink protection, permission checks)
- If a systemd credential file exists but fails security checks, claw-wrap fails closed (no env fallback)
- Session token passed via environment variable, not command line
- Session cleaned up on daemon shutdown

### HashiCorp Vault (`vault:`)

```yaml
credentials:
  api-key:
    source: vault:secret/myapp/api-key

  # With jq extraction from secret JSON
  db-password:
    source: vault:secret/myapp/database | .password
```

Fetches secrets from HashiCorp Vault using the `vault` CLI. Supports both KV-v2 (default) and KV-v1 engines.

Use natural paths (e.g., `secret/myapp/key`) — the `vault kv get` command handles the KV-v2 `/data/` path prefix internally.

Optional CLI and connection overrides:

```yaml
proxy:
  vault_binary: /usr/bin/vault
  vault_addr: https://127.0.0.1:8200
  vault_skip_verify: false
  vault_cacert: /etc/vault/ca.pem
  vault_namespace: ""
  vault_token_file: /home/bot/.vault-token
```

If `vault_binary` is unset, claw-wrap only auto-detects `vault` in trusted directories:
`/usr/bin`, `/usr/local/bin`, `/opt/homebrew/bin`, `/home/linuxbrew/.linuxbrew/bin`.

Connection settings (`vault_addr`, `vault_skip_verify`, `vault_cacert`, `vault_namespace`) override the corresponding `VAULT_ADDR`, `VAULT_SKIP_VERIFY`, `VAULT_CACERT`, and `VAULT_NAMESPACE` environment variables when set.

**Authentication model:**

claw-wrap does **not** authenticate with Vault itself. The user (or operator) must run `vault login` externally, which stores a token at `~/.vault-token`. The `vault` CLI reads this token automatically. This supports time-scoped access: configure TTL on the Vault user so tokens expire after a set window (15 minutes, 1 hour, etc.).

Use `vault_token_file` to point to a non-default token file location (requires Vault CLI 1.10+).

**Security:**

- Secrets never stored in plaintext config — fetched on-demand via CLI
- Token managed externally; claw-wrap cannot refresh or extend access
- Expired tokens produce a generic "vault read failed" error
- Supports self-signed certs via `vault_cacert` or `vault_skip_verify`

### GitHub App (`type: github-app`)

Mint GitHub App installation tokens in the daemon. Use `type: github-app` instead of `source:` — the two are mutually exclusive.

```yaml
credentials:
  github-bot:
    type: github-app
    app_id: 12345
    installation_id: 67890
    private_key: pass:github/bot-app.pem
    api_url: https://api.github.com
    permissions:
      contents: read
      issues: write
    repositories:
      - my-org/my-repo
```

#### Credential fields

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `source` | string | source-mode only | — | Mutually exclusive with `type` |
| `type` | string | optional | — | Empty = source-mode. `github-app` = installation token minting |
| `app_id` | int64 | `type: github-app` | — | GitHub App ID (must be non-zero) |
| `installation_id` | int64 | `type: github-app` | — | Installation ID (must be non-zero) |
| `private_key` | string | `type: github-app` | — | Credential source for PEM key material (e.g. `pass:github/bot.pem`); resolved at mint time only |
| `api_url` | string | optional | `https://api.github.com` | GitHub API base URL (GHES override) |
| `permissions` | map[string]string | optional | — | Scoped permissions sent in exchange body when non-empty |
| `repositories` | []string | optional | — | Repository names sent in exchange body when non-empty |

#### Validation

| Condition | Result |
| --- | --- |
| `source` non-empty AND `type` non-empty | Error: mutually exclusive |
| `source` empty AND `type` empty | Error: empty source |
| `type` empty, `source` non-empty | Valid (existing source-mode behavior) |
| `type: github-app`, `source` empty, `app_id` + `installation_id` + `private_key` set | Valid |
| `type: github-app`, missing `app_id`, `installation_id`, or `private_key` | Error |
| `type` unknown (not `github-app`) | Error |

Tokens are minted lazily, cached until `expires_at − 5m`, singleflight-deduplicated on concurrent refresh, and stale-if-valid on mint failure while the token is still within its hard expiry. The App private key is fetched with cache bypass at mint time and is not retained after mint completes.

### exec-json helper (`exec-json:`)

Run a trusted helper binary that prints a JSON credential on stdout:

```yaml
credentials:
  aws-role-token:
    source: exec-json:/usr/local/lib/openclaw/mint-aws
```

#### Source syntax

| Rule | Detail |
| --- | --- |
| Prefix | `exec-json:` |
| Path | Absolute filesystem path to the helper executable. No arguments. |
| jq | **Not supported.** A ` \| .jq_expr` suffix is rejected at parse time. |
| Config | Plain `source:` string only. No `type:` field. |

Helpers that need arguments or environment must wrap themselves in a script at a fixed absolute path.

#### Helper stdout JSON contract

The helper must print exactly one JSON object on stdout:

| Field | Required | Type | Notes |
| --- | --- | --- | --- |
| `value` | yes | string | Non-empty credential string |
| `expires_at` | no | string | RFC3339 timestamp |

Unknown fields are ignored. When `expires_at` is absent or empty, the credential uses global TTL behavior (`credential_cache_ttl`). When present, per-entry expiry and stale-if-valid apply (refresh at `expires_at − 5m`).

#### Helper binary trust rules

Validated before every execution:

| Check | Rule |
| --- | --- |
| Path | Must be absolute |
| Symlinks | Rejected (`O_NOFOLLOW`) |
| Type | Regular file |
| Executable | Owner execute bit set |
| Writable bits | Must not be group- or world-writable |
| Owner | UID must equal daemon EUID or root (UID 0) |

#### Execution and errors

| Parameter | Value |
| --- | --- |
| Timeout | 10 seconds |
| Stdin | Not connected |
| Stdout | Parsed as JSON; never included in error messages |
| Stderr | Included in errors on failure, truncated to 1 KiB |
| Environment | Inherited from daemon process |

Non-zero exit, timeout, malformed JSON, or missing/empty `value` return an error without leaking stdout content.

### jq Extraction

All backends except `env:` and `exec-json:` support jq extraction using the pipe syntax:

```yaml
credentials:
  password:
    source: bw:item-uuid | .login.password

  nested-field:
    source: op://vault/item | .fields[] | select(.name=="api_key") | .value
```

The jq expression is evaluated using embedded `github.com/itchyny/gojq` library with a 5-second timeout.
For `env:` sources, the value must be valid JSON when jq extraction is used.

## Tool Options

### Tool names

Tool names (the keys under `tools:`) must match:
`[A-Za-z0-9._-]+`

This prevents path traversal and unsafe names during symlink installation.

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

### `mode` (optional)

Controls the argument restriction mode for the tool.

- `blocklist` (default): Only `blocked_args` patterns are checked. Any match rejects the command.
- `allowlist`: Commands must match at least one `allowed_args` pattern to proceed. Optional `blocked_args` are checked first (deny-first).

### `blocked_args` (optional)

List of regex patterns that block certain arguments.
Each entry supports optional `match` mode:
- `arg` (default): pattern is matched against each argument independently
- `command`: pattern is matched against `strings.Join(args, " ")`

```yaml
tools:
  mytool:
    binary: /usr/local/bin/mytool
    blocked_args:
      - pattern: "delete"
        match: arg
        message: "Delete is not allowed"
      - pattern: "repo\\s+delete"
        match: command
        message: "Repo delete blocked"
      - pattern: "--force"
        message: "Force flag blocked"
```

### `allowed_args` (optional, requires `mode: allowlist`)

List of regex patterns that define which arguments are permitted. At least one pattern must match for the command to proceed. Structure is identical to `blocked_args`.

```yaml
tools:
  gh:
    binary: /usr/bin/gh
    mode: allowlist
    allowed_args:
      - pattern: "^(repo|issue|pr)\\s+(list|view|status)"
        match: command
        message: "Only read operations allowed"
      - pattern: "^(version|help)$"
        match: arg
        message: "Only informational commands allowed"
```

When both `blocked_args` and `allowed_args` are present (with `mode: allowlist`):
1. `blocked_args` are checked first (any match = deny)
2. `allowed_args` are checked next (at least one must match)

This layered approach lets you allowlist broad categories while still blocking specific dangerous patterns within them.

### `redact_output` (optional)

List of regex rules used to sanitize tool output before it is returned to the client.

Each rule supports:
- `pattern` (required): regex pattern to match sensitive text
- `replace` (optional): replacement string (defaults to `[REDACTED]`)

```yaml
tools:
  gh:
    binary: /usr/bin/gh
    redact_output:
      - pattern: "gh[pousr]_[A-Za-z0-9]{36}"
        replace: "[GITHUB_TOKEN]"
      - pattern: "(?i)(authorization:\\s*bearer\\s+)[^\\s]+"
        replace: "${1}[REDACTED]"
```

Behavior notes:
- Applies to both `stdout` and `stderr`
- Works for both inline and file-backed output responses
- Rules are applied in order
- Invalid regex patterns are rejected during config validation

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

Credential values are automatically YAML-escaped using single-quote wrapping before substitution. This prevents injection attacks where a credential value contains YAML metacharacters (colons, hashes, braces) or embedded newlines.

## Security Notes

1. **Arg restrictions are enforced server-side** — default `arg` mode is per-argument; use `match: command` for cross-arg patterns; `mode: allowlist` is fail-closed (no match = deny)
2. **Forced env vars cannot be overridden** — stripped from inherited environment
3. **Config file paths are validated** — absolute/traversal paths are rejected
4. **Config file is in a temp directory** — created with restrictive umask (0600), cleaned up after tool exits; stale dirs swept on daemon startup
5. **Socket requires UID match** — only the configured user can connect
6. **Binary path verification is best-effort by default** — set `deny_unverified_caller_exe: true` for strict mode (may require `/proc` tuning in firejail)
7. **Requests are replay-protected** — duplicate HMACs within TTL are rejected; nonce included in HMAC (protocol v3)
8. **Error messages are sanitized** — internal paths, versions, and tool names are not leaked to the client
9. **Environment denylist** — dangerous env vars (LD_*, DYLD_*, proxy vars, language runtime vars, git hijack vars) are stripped
10. **Credential values are YAML-escaped** — prevents config file injection via malicious secret values
11. **Working directory must be absolute** — relative paths are rejected
12. **Secret file symlink protection** — WriteSecret/LoadSecret refuse to operate on symlinks
13. **pass binary must be absolute path** — relative paths fall back to default with a warning
14. **Environment credential file hardening** — `/run/openclaw/env` must be regular file, owned by daemon user, and mode `0600`/`0640`
15. **Tool names are validated** — only `[A-Za-z0-9._-]+` to prevent unsafe symlink install paths
