<div align="center">
  <img src="docs/assets/claw-wrap-hero.png" width="220" alt="claw-wrap lobster in a burrito" />
  <h1>claw-wrap</h1>
  <p>A secure credential proxy for CLI tools. Executes tools with secrets on behalf of sandboxed processes - credentials never enter the sandbox.</p>
  <p>
    <a href="docs/INSTALL.md">Install</a> ·
    <a href="docs/CONFIG.md">Config</a> ·
    <a href="docs/SPEC.md">Protocol</a> ·
    <a href="docs/MIGRATION.md">Migration</a>
  </p>
</div>

---

## Features

- **Proxy execution** - Daemon executes tools and streams output; credentials never enter sandbox
- **Single binary** - Both wrapper and daemon in one executable
- **Symlink-based** - Tools like `bird`, `gog`, `gh` are symlinks to `claw-wrap`
- **HMAC authentication** - Requests are signed to prevent unauthorized access
- **Firejail compatible** - Designed for sandboxed environments
- **Multiple credential sources** - `pass` (password store) and env file
- **Blocked args** - Regex patterns to block dangerous operations
- **Forced env vars** - Variables that cannot be overridden
- **Config file injection** - For tools that need config files instead of env vars

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│ FIREJAIL SANDBOX                                        │
│                                                         │
│  agent calls "gog gmail list"                           │
│         ↓                                               │
│  claw-wrap wrapper:                                     │
│    1. Reads HMAC secret from /run/openclaw/auth         │
│    2. Signs request with timestamp                      │
│    3. Sends to daemon, relays stdin/stdout/stderr       │
│         ↓                                               │
└─────────│───────────────────────────────────────────────┘
          │ Unix socket (/run/openclaw/secrets.sock)
          ↓
┌─────────────────────────────────────────────────────────┐
│ claw-wrap daemon (outside sandbox)                      │
│  1. Verifies HMAC signature and timestamp               │
│  2. Validates args against blocked_args patterns        │
│  3. Fetches credentials from pass                       │
│  4. Spawns tool with credentials in environment         │
│  5. Streams stdout/stderr back to wrapper               │
│                                                         │
│  ⚠️  Credentials NEVER leave the daemon process         │
└─────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Build
make build

# Install binary and service
sudo make install
sudo cp init/claw-wrap.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now claw-wrap

# Create tool symlinks
sudo claw-wrap install

# Verify
claw-wrap list
claw-wrap check
bird whoami
```

## Usage

```bash
# Daemon mode (usually via systemd)
claw-wrap daemon

# Admin commands
claw-wrap list      # List configured tools
claw-wrap check     # Verify credentials
claw-wrap install   # Create symlinks (requires sudo)
claw-wrap version   # Show version
claw-wrap help      # Show help

# Tool execution (via symlinks)
bird whoami
gog gmail list
gh repo list
openhue get lights
```

## Documentation

- [Installation Guide](docs/INSTALL.md)
- [Configuration Reference](docs/CONFIG.md)
- [Protocol Specification](docs/SPEC.md)
- [Migration Guide](docs/MIGRATION.md)

## Quick Configuration Example

`/etc/openclaw/wrappers.yaml`:

```yaml
credentials:
  my-api-key:
    source: pass:cli/myapp/api-key

tools:
  myapp:
    binary: /usr/local/bin/myapp
    env:
      API_KEY: my-api-key
    blocked_args:
      - pattern: "delete\\s+--force"
        message: "Force delete is blocked"
```

See [docs/CONFIG.md](docs/CONFIG.md) for full reference.

## Security Model

1. **Proxy execution** - Credentials never enter the sandbox; daemon executes tools directly
2. **HMAC authentication** - Requests must be signed with a shared secret
3. **Timestamp freshness** - Requests expire after 5 seconds to prevent replay attacks
4. **UID verification** - Only requests from the allowed UID are accepted
5. **Blocked args** - Dangerous operations are rejected server-side
6. **Forced env vars** - Agent cannot override security-critical variables
7. **No config in sandbox** - `/etc/openclaw/wrappers.yaml` is not accessible inside firejail

## Project Structure

```
claw-wrap/
├── cmd/claw-wrap/main.go      # Entry point
├── internal/
│   ├── auth/                  # HMAC authentication
│   ├── config/                # YAML config loading
│   ├── credentials/           # pass/env credential fetching
│   ├── daemon/                # Socket server + tool executor
│   ├── framing/               # Length-prefixed message encoding
│   ├── protocol/              # Request/response types
│   └── wrapper/               # I/O relay client
├── init/
│   └── claw-wrap.service      # Systemd unit file
├── docs/                      # Documentation
├── go.mod
├── Makefile
└── README.md
```

## Building

```bash
make build              # Build to ./build/claw-wrap
make install            # Install to /usr/local/bin
make install-symlinks   # Install + create symlinks
make test               # Run tests
make fmt                # Format code
make lint               # Run go vet
make clean              # Remove build artifacts
```

## Requirements

- Go 1.21+
- `pass` (password-store)
- GPG (for pass decryption)

## License

MIT
