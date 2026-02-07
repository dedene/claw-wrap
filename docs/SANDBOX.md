# Sandbox Setup with OpenClaw

This guide covers running [OpenClaw](https://github.com/openclaw/openclaw) inside a deny-by-default sandbox with claw-wrap providing credential access. Credential directories (`~/.password-store`, `~/.gnupg`, `~/.ssh`) are invisible inside the sandbox — the agent accesses CLI tools through claw-wrap symlinks, which proxy credentials from outside.

Two sandbox options are available:

- [**Firejail**](#firejail-linux) — Linux, whitelist-mode sandbox with systemd integration
- [**nono**](#nono-macos--linux) — macOS (via Seatbelt) and Linux (via Landlock), with a built-in OpenClaw profile

## Firejail (Linux)

[Firejail](https://firejail.wordpress.com/) is a Linux sandbox that supports whitelist mode — everything is denied by default, only explicitly listed paths are accessible.

### Install

```bash
# Debian/Ubuntu
sudo apt install firejail

# Arch
sudo pacman -S firejail
```

### Firejail Profile

Create `/etc/firejail/openclaw-gateway.profile`:

```
# OpenClaw Gateway Firejail Profile (Whitelist Mode)
# Deny by default — only explicitly listed paths are accessible.

# === ISOLATED FILESYSTEMS ===
private-tmp
allusers

# === HOME DIRECTORY WHITELIST ===
# Everything else (including ~/.password-store, ~/.gnupg, ~/.ssh)
# simply doesn't exist in the sandbox.

# OpenClaw workspace and config
whitelist ${HOME}/.openclaw
whitelist ${HOME}/.config/openclaw
whitelist ${HOME}/.bashrc
whitelist ${HOME}/.profile

# Node.js / runtime dependencies
whitelist ${HOME}/.npm-global
whitelist ${HOME}/.local/share/pnpm
whitelist ${HOME}/.local/bin
whitelist ${HOME}/.cache
whitelist ${HOME}/.bun

# Tool-specific config dirs
whitelist ${HOME}/.config/gogcli
whitelist ${HOME}/.config/qmd
whitelist ${HOME}/.config/gh

# Linuxbrew (for gh, gog, and other tools)
noblacklist /home/linuxbrew
whitelist /home/linuxbrew/.linuxbrew

# === SYSTEM DIRECTORIES ===
include whitelist-usr-share-common.inc
include whitelist-var-common.inc

# SSL/TLS certificates (required for HTTPS)
whitelist /etc/ssl/certs
whitelist /etc/ld.so.cache
whitelist /etc/ld.so.conf.d
whitelist /etc/resolv.conf
whitelist /etc/hosts
whitelist /etc/nsswitch.conf
whitelist /etc/localtime
whitelist /etc/timezone
whitelist /etc/passwd
whitelist /etc/group
whitelist /usr/share/zoneinfo

# === CLAW-WRAP ===
# Unix socket (credential proxy) + HMAC auth file + restart sentinel
noblacklist /run/openclaw
whitelist /run/openclaw

# === SECURITY HARDENING ===
caps.drop all
nonewprivs
noroot
seccomp

# Disable unnecessary features
no3d
nodvd
noinput
noprinters
nosound
notv
nou2f
novideo

# Network: only what's needed
protocol unix,inet,inet6,netlink

# PATH must include tool locations
env PATH=/usr/local/bin:/home/YOUR_USERNAME/.local/bin:/home/YOUR_USERNAME/.bun/bin:/home/YOUR_USERNAME/.npm-global/bin:/home/YOUR_USERNAME/.local/share/pnpm:/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:/usr/bin:/bin
env BASH_ENV=/home/YOUR_USERNAME/.bashrc
```

Replace `YOUR_USERNAME` with your actual username.

### What to Whitelist

| Path | Why |
|------|-----|
| `/run/openclaw` | claw-wrap socket, HMAC auth file, restart sentinel |
| `~/.openclaw` | OpenClaw workspace, config, agents, cron jobs |
| `~/.npm-global` | Globally installed Node.js packages (including OpenClaw itself) |
| `~/.config/gogcli` | gog (Google CLI) config and encrypted keyring |
| `/home/linuxbrew/.linuxbrew` | Homebrew-installed binaries (gh, gog, etc.) |
| `/etc/ssl/certs` | HTTPS/TLS connections |

### What NOT to Whitelist

| Path | Why |
|------|-----|
| `~/.password-store` | GPG-encrypted secrets — claw-wrap handles access |
| `~/.gnupg` | GPG keys used to decrypt pass entries |
| `~/.ssh` | SSH keys |
| `/etc/openclaw/wrappers.yaml` | Credential source paths — not needed inside sandbox |

### Systemd Services

Three systemd units work together: the gateway service (firejailed), and a path unit that lets the gateway trigger its own restart from inside the sandbox.

#### openclaw-gateway.service

```ini
[Unit]
Description=OpenClaw Gateway (sandboxed)
Requires=claw-wrap.service
After=claw-wrap.service

[Service]
Type=simple
# TODO: Set to your username
User=YOUR_USERNAME

# Secrets loaded from $CREDENTIALS_DIRECTORY into env vars in-memory — never written to disk.
ExecStart=/bin/bash -c '\
  export OPENCLAW_GATEWAY_TOKEN="$(cat $CREDENTIALS_DIRECTORY/openclaw-gateway-token)"; \
  export TELEGRAM_BOT_TOKEN="$(cat $CREDENTIALS_DIRECTORY/telegram-bot-token)"; \
  exec /usr/bin/firejail --profile=/etc/firejail/openclaw-gateway.profile \
    /usr/bin/node /home/YOUR_USERNAME/.npm-global/lib/node_modules/openclaw/dist/index.js \
    gateway --port 18789'

Restart=always
RestartSec=5

# Encrypted credentials — decrypted by systemd at service start
LoadCredentialEncrypted=openclaw-gateway-token:/home/YOUR_USERNAME/.config/systemd/credentials/openclaw-gateway-token
LoadCredentialEncrypted=telegram-bot-token:/home/YOUR_USERNAME/.config/systemd/credentials/telegram-bot-token

[Install]
WantedBy=multi-user.target
```

Add your own `LoadCredentialEncrypted` lines for each secret you need, with matching `export` lines in the `ExecStart` wrapper. If you don't need encrypted credentials, use plain `Environment=` directives instead and simplify `ExecStart` to call firejail directly.

#### Self-Restart Mechanism

The gateway runs inside firejail and cannot call `systemctl`. But it can write to `/run/openclaw/` (whitelisted). A systemd path unit watches for a sentinel file — when the gateway touches it, systemd restarts the service from outside the sandbox.

This enables self-updates: the gateway installs a new version via npm, then signals for a restart.

**openclaw-gateway-restart.path:**

```ini
[Unit]
Description=Watch for OpenClaw gateway restart request
BindsTo=openclaw-gateway.service
After=openclaw-gateway.service

[Path]
PathExists=/run/openclaw/restart
Unit=openclaw-gateway-restart.service

[Install]
WantedBy=openclaw-gateway.service
```

**openclaw-gateway-restart.service:**

```ini
[Unit]
Description=Restart OpenClaw gateway

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'rm -f /run/openclaw/restart && systemctl restart openclaw-gateway.service'
User=root
```

#### Install the units

```bash
sudo cp openclaw-gateway.service /etc/systemd/system/
sudo cp openclaw-gateway-restart.path /etc/systemd/system/
sudo cp openclaw-gateway-restart.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now openclaw-gateway.service
```

The path unit starts automatically with the gateway (via `WantedBy=openclaw-gateway.service`).

#### Encrypted Credentials

The gateway needs its own secrets (auth token, bot token) that aren't CLI tool credentials handled by claw-wrap. These shouldn't sit in plaintext config files. systemd's [`LoadCredentialEncrypted`](https://systemd.io/CREDENTIALS/) keeps them encrypted at rest and only decrypted in memory at service start.

**Encrypt a secret:**

```bash
mkdir -p ~/.config/systemd/credentials
echo -n 'your-secret-value' | sudo systemd-creds encrypt \
  --name=openclaw-gateway-token - \
  ~/.config/systemd/credentials/openclaw-gateway-token
```

This creates an encrypted file bound to your machine (via TPM or host key). Only systemd on this machine can decrypt it.

**How it flows at service start:**

```
Encrypted at rest                  In memory only
┌──────────────────────┐           ┌────────────────────┐
│ ~/.config/systemd/   │  systemd  │ $CREDENTIALS_DIR   │  bash    ┌────────────┐  exec   ┌──────────┐
│   credentials/       │────────→  │ (tmpfs, per-svc)   │───────→  │ env vars   │───────→ │ firejail │
│   openclaw-gateway-* │  decrypt  │  openclaw-gateway-* │  cat +  │ OPENCLAW_* │ inherit │  → node  │
│   telegram-bot-token │           │  telegram-bot-token │  export │ TELEGRAM_* │         │          │
└──────────────────────┘           └────────────────────┘         └────────────┘         └──────────┘
```

The bash wrapper in `ExecStart` reads each credential from `$CREDENTIALS_DIRECTORY`, exports it as an environment variable, then `exec`s firejail. The `exec` replaces the bash process — the final process tree is just firejail → node. No secrets are ever written to disk as plaintext.

**OpenClaw config — use `${ENV_VAR}` references instead of hardcoded secrets:**

```json
{
  "channels": {
    "telegram": {
      "botToken": "${TELEGRAM_BOT_TOKEN}"
    }
  },
  "gateway": {
    "auth": {
      "token": "${OPENCLAW_GATEWAY_TOKEN}"
    }
  }
}
```

OpenClaw substitutes `${...}` references with the corresponding environment variables at startup.

#### How self-update works

```
1. Gateway detects new version available
2. Runs: npm install -g openclaw@latest
   (writes to ~/.npm-global — whitelisted in firejail)
3. Runs: touch /run/openclaw/restart
   (writes to /run/openclaw — whitelisted in firejail)
4. systemd path unit detects /run/openclaw/restart
5. Triggers openclaw-gateway-restart.service (as root)
6. That service removes the sentinel and restarts the gateway
7. Gateway comes back up with the new version
```

### PATH Priority

The claw-wrap symlinks in `/usr/local/bin` must come **before** the real binaries in PATH. Otherwise the agent calls the real `gh` directly, bypassing claw-wrap entirely.

The firejail profile's `env PATH=...` line already puts `/usr/local/bin` first. But your agent framework must also respect this. In OpenClaw, configure `pathPrepend` in `openclaw.json`:

```json
{
  "tools": {
    "exec": {
      "pathPrepend": [
        "/usr/local/bin"
      ]
    }
  }
}
```

This prepends `/usr/local/bin` to PATH for all tool executions, ensuring the agent always hits the claw-wrap symlink first.

### Verifying Isolation

After the gateway is running, verify from inside the sandbox:

#### Credentials are invisible

```bash
# These paths don't exist inside the sandbox
ls ~/.password-store     # No such file or directory
ls ~/.gnupg              # No such file or directory
cat /etc/openclaw/wrappers.yaml  # No such file or directory
```

#### Tools work through claw-wrap

```bash
# Works — proxied through claw-wrap daemon
gh repo list

# Token is never in the environment
echo $GH_TOKEN           # Empty
```

#### Socket attack is rejected

```bash
# Raw socket connection without HMAC — rejected
node -e "
  const net = require('net');
  const c = net.connect('/run/openclaw/secrets.sock');
  c.write('{\"credential\":\"github-token\"}');
  c.on('data', d => console.log(d.toString()));
"
# Expected: {"type":"error","message":"authentication failed"}
```

#### Self-restart works

```bash
# From inside the sandbox (or as the gateway user):
touch /run/openclaw/restart

# Watch the gateway restart:
sudo journalctl -u openclaw-gateway -f
```

---

## nono (macOS / Linux)

[nono](https://github.com/lukehinds/nono) provides kernel-enforced sandboxing on macOS (via Apple's Seatbelt) and Linux (via Landlock). It's deny-by-default — sensitive paths like `~/.ssh`, `~/.gnupg`, `~/.password-store`, and `~/.aws` are blocked automatically.

nono ships with a built-in `openclaw` profile.

> **Note:** nono is early alpha and has not undergone a security audit.

### Install

```bash
brew install lukehinds/tap/nono
```

### Socket path on macOS

macOS has no `/run/` directory. nono's built-in `openclaw` profile allows `$TMPDIR/openclaw-$UID` for runtime files. Start the claw-wrap daemon with a custom socket path:

```bash
# Create runtime directory
mkdir -p /tmp/openclaw-$(id -u)

# Start daemon with macOS socket path
claw-wrap daemon --socket /tmp/openclaw-$(id -u)/secrets.sock
```

### Using the built-in profile

```bash
nono run --profile openclaw -- openclaw gateway
```

This grants read+write to `~/.openclaw`, `~/.config/openclaw`, `~/.local`, and `$TMPDIR/openclaw-$UID` (the socket directory).

### Custom setup

For more control, specify paths explicitly:

```bash
nono run \
  --allow ~/.openclaw \
  --allow /tmp/openclaw-$(id -u) \
  --read /usr/local/bin \
  -- node ~/.npm-global/lib/node_modules/openclaw/dist/index.js gateway
```

The `--allow` flag grants recursive read+write access. Only listed paths are accessible — everything else (including credential stores) is invisible to the sandboxed process.
