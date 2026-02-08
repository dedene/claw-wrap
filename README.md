<div align="center">
  <img src="docs/assets/claw-wrap-hero.png" width="160" alt="claw-wrap lobster in a burrito" />
  <h1>claw-wrap</h1>
  <p>
    <a href="https://github.com/dedene/claw-wrap/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/dedene/claw-wrap/actions/workflows/ci.yml/badge.svg" /></a>
    <a href="https://go.dev/"><img alt="Go 1.24+" src="https://img.shields.io/badge/go-1.24+-00ADD8.svg" /></a>
    <a href="https://goreportcard.com/report/github.com/dedene/claw-wrap"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/dedene/claw-wrap" /></a>
    <a href="https://opensource.org/licenses/MIT"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-green.svg" /></a>
  </p>
  <p>A secure credential proxy for CLI tools and HTTP APIs. Executes tools with secrets on behalf of sandboxed processes, or injects credentials into HTTP requests via MITM proxy — credentials never enter the sandbox.</p>
  <p>
    <a href="docs/INSTALL.md">Install</a> ·
    <a href="docs/CONFIG.md">Config</a> ·
    <a href="docs/SANDBOX.md">Sandbox</a> ·
    <a href="docs/SPEC.md">Protocol</a>
  </p>
</div>

---

## The Problem

You're running an AI agent in a sandbox. The agent needs to call `gh` to interact with GitHub — list repos, read issues, check PRs. So you give it your `GH_TOKEN`.

Now the agent has full access to your GitHub account. It can read private repos, push code, delete repositories, create tokens. Any process in the sandbox can grab the token from the environment. One prompt injection and your credentials are exfiltrated.

**claw-wrap solves this.** The agent calls `gh repo list` like normal, but:

1. `gh` is actually a symlink to `claw-wrap`
2. claw-wrap connects to a daemon running **outside** the sandbox
3. The daemon injects credentials, executes `gh`, and streams the output back
4. The agent gets the results. The token never enters the sandbox.

You can also block dangerous commands server-side — the agent can `gh repo list` but not `gh repo delete`.

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│ SANDBOX (firejail)                                      │
│                                                         │
│  agent calls "gh repo list"                             │
│         ↓                                               │
│  /usr/local/bin/gh → claw-wrap (symlink)                │
│    1. Reads HMAC secret from /run/openclaw/auth         │
│    2. Signs request with timestamp                      │
│    3. Sends to daemon via Unix socket                   │
│    4. Streams stdout/stderr back to agent               │
│         ↓                                               │
└─────────│───────────────────────────────────────────────┘
          │ Unix socket (/run/openclaw/secrets.sock)
          ↓
┌─────────────────────────────────────────────────────────┐
│ claw-wrap daemon (outside sandbox)                      │
│  1. Verifies HMAC signature + timestamp                 │
│  2. Checks args against blocked patterns                │
│  3. Fetches GH_TOKEN from pass (password store)         │
│  4. Spawns real gh binary with token in environment     │
│  5. Streams stdout/stderr back through socket           │
│                                                         │
│  ⚠️  Credentials NEVER leave the daemon process         │
└─────────────────────────────────────────────────────────┘
```

## Two Modes

claw-wrap supports two approaches for credential injection:

| Mode | Best For | How It Works |
|------|----------|--------------|
| **CLI Wrapper** | CLI tools (gh, aws, gcloud) | Symlink intercepts command, daemon executes with credentials |
| **HTTP Proxy** | HTTP APIs, curl, SDKs | MITM proxy injects auth headers into matching requests |

**Use CLI Wrapper when:**
- Tool supports env-based credentials (GH_TOKEN, AWS_ACCESS_KEY_ID)
- You want to block specific commands (e.g., `gh repo delete`)
- Tool doesn't support HTTP proxy

**Use HTTP Proxy when:**
- Tool makes HTTP calls to APIs (curl, Python requests, Node fetch)
- You want route-based credential injection by host/path
- Multiple tools need the same API credentials

## Quick Start

This example sets up `gh` (GitHub CLI) as a proxied tool.

### Prerequisites

- Linux with systemd
- [pass](https://www.passwordstore.org/) (password store) with GPG configured
- `gh` installed somewhere (e.g. via Homebrew: `brew install gh`)

### 1. Install claw-wrap

```bash
brew install dedene/tap/claw-wrap
```

Or from source:

```bash
git clone https://github.com/dedene/claw-wrap.git
cd claw-wrap
make build
sudo make install
```

### 2. Store your GitHub token in pass

```bash
# If you haven't initialized pass yet:
gpg --gen-key
pass init <your-gpg-key-id>

# Store the token
pass insert cli/github/token
```

### 3. Create the config

Create `/etc/openclaw/wrappers.yaml`:

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
  max_output_size: 100MB
  max_connection_lifetime: 30m

credentials:
  github-token:
    source: pass:cli/github/token

tools:
  gh:
    binary: /home/linuxbrew/.linuxbrew/bin/gh   # path to real gh binary
    env:
      GH_TOKEN: github-token
```

### 4. Start the daemon

```bash
sudo cp init/claw-wrap.service /etc/systemd/system/
# Edit User=YOUR_USERNAME to your actual username
sudo editor /etc/systemd/system/claw-wrap.service
sudo systemctl daemon-reload
sudo systemctl enable --now claw-wrap
```

### 5. Create the symlink

```bash
sudo $(which claw-wrap) install
```

This creates symlinks in `/usr/local/bin` pointing to the auto-detected `claw-wrap` binary. The `$(which claw-wrap)` ensures sudo uses YOUR claw-wrap, not a stale copy. Override the symlink directory with `--install-dir`:

### 6. Verify

```bash
claw-wrap list      # Should show gh
claw-wrap check     # Should show credentials OK (run from host/admin context)
gh repo list        # Should work — using proxied credentials
```

## Safety Controls

claw-wrap doesn't just proxy credentials — it enforces what the agent can do with them.

### Blocked arguments

Reject commands that match regex patterns. The agent gets an error, the command never runs:

```yaml
tools:
  gh:
    binary: /home/linuxbrew/.linuxbrew/bin/gh
    env:
      GH_TOKEN: github-token
    blocked_args:
      - pattern: "repo\\s+delete"
        match: command
        message: "Repository deletion is blocked"
      - pattern: "repo\\s+create"
        match: command
        message: "Repository creation is blocked"
      - pattern: "auth\\s+"
        match: command
        message: "Auth commands are blocked"
      - pattern: "ssh-key"
        message: "SSH key management is blocked"
```

By default, blocked patterns run in `arg` mode (each argument is matched independently). Use `match: command` when a regex needs to span multiple args (for example `repo\\s+delete`).

### Forced environment variables

Variables that are always set and cannot be overridden by the agent:

```yaml
tools:
  gog:
    binary: /home/linuxbrew/.linuxbrew/bin/gog
    env:
      GOG_KEYRING_PASSWORD: gog-keyring-password
    forced_env:
      GOG_ENABLE_COMMANDS: "gmail,calendar,drive,tasks,contacts,keep,time"
```

The agent cannot change `GOG_ENABLE_COMMANDS` — it's stripped from inherited environment and set by the daemon.

## HTTP Proxy Mode

For tools that make HTTP API calls, claw-wrap can act as a MITM proxy that injects credentials based on request host/path:

```yaml
http_proxy:
  enabled: true
  listen: 127.0.0.1:8080
  routes:
    - host: api.github.com
      inject:
        header: Authorization
        value: "Bearer {{github-token}}"
      deny:
        - DELETE /**

tools:
  curl:
    binary: /usr/bin/curl
    use_proxy: true  # Injects HTTP_PROXY + CA trust
```

The proxy:
- Auto-generates a CA certificate for HTTPS interception
- Requires authentication (token auto-injected for `use_proxy: true` tools)
- Supports allow/deny rules per route

See [HTTP Proxy Settings](docs/CONFIG.md#http-proxy-settings) for full configuration.

### Request integrity and replay protection

- HMAC signature covers `tool`, `args`, `cwd`, and request `env` (protocol v2).
- Requests are replay-protected with a short-lived daemon cache.
- Caller executable verification is best-effort by default. Set `deny_unverified_caller_exe: true` for strict mode.

## Sandbox Setup

claw-wrap works with deny-by-default sandboxes where credentials directories (`~/.password-store`, `~/.gnupg`, `~/.ssh`) are not accessible:

- **Linux**: [firejail](https://firejail.wordpress.com/) in whitelist mode
- **macOS**: [nono](https://github.com/lukehinds/nono) using Apple's Seatbelt

See [docs/SANDBOX.md](docs/SANDBOX.md) for the full guide — firejail profile, nono setup, self-restart mechanism, and verification steps.

## Documentation

- [Installation Guide](docs/INSTALL.md) — full setup with `pass`, systemd, and troubleshooting
- [Configuration Reference](docs/CONFIG.md) — all options for credentials, tools, blocked args, config file injection
- [HTTP Proxy Setup](docs/CONFIG.md#http-proxy-settings) — MITM proxy for API credential injection
- [Sandbox Setup](docs/SANDBOX.md) — firejail (Linux) and nono (macOS) with verification steps
- [Protocol Specification](docs/SPEC.md) — HMAC authentication, message framing, proxy protocol

## Usage

```bash
# Daemon mode (usually via systemd)
claw-wrap daemon

# Admin commands
claw-wrap list      # List configured tools
claw-wrap check     # Verify credentials
claw-wrap install   # Create symlinks (auto-detects directory)
claw-wrap install --install-dir /usr/local/bin  # Override directory
claw-wrap version   # Show version
claw-wrap help      # Show help

# Tool execution (via symlinks)
gh repo list
gh issue list
gh pr view 42
```

## Building

```bash
make build    # Build to ./build/claw-wrap
make test     # Run tests
make install  # Install to /usr/local/bin
make fmt      # Format code
make lint     # Run go vet
make clean    # Remove build artifacts
```

## Requirements

- Go 1.21+ (building from source)
- Linux with systemd (or macOS with launchd)
- `pass` (password-store) + GPG
- [firejail](https://firejail.wordpress.com/) (Linux) or [nono](https://github.com/lukehinds/nono) (macOS)

## License

MIT
