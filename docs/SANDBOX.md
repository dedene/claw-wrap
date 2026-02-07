# Sandbox Setup (Firejail + OpenClaw)

This guide covers running [OpenClaw](https://github.com/openclaw/openclaw) inside a [firejail](https://firejail.wordpress.com/) whitelist sandbox with claw-wrap providing credential access.

In whitelist mode, everything is denied by default. Only explicitly listed paths are accessible — `~/.password-store`, `~/.gnupg`, and `~/.ssh` simply don't exist inside the sandbox. The agent accesses CLI tools through claw-wrap symlinks, which proxy credentials from outside.

## Install Firejail

```bash
# Debian/Ubuntu
sudo apt install firejail

# Arch
sudo pacman -S firejail
```

## Firejail Profile

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

## What to Whitelist

| Path | Why |
|------|-----|
| `/run/openclaw` | claw-wrap socket, HMAC auth file, restart sentinel |
| `~/.openclaw` | OpenClaw workspace, config, agents, cron jobs |
| `~/.npm-global` | Globally installed Node.js packages (including OpenClaw itself) |
| `~/.config/gogcli` | gog (Google CLI) config and encrypted keyring |
| `/home/linuxbrew/.linuxbrew` | Homebrew-installed binaries (gh, gog, etc.) |
| `/etc/ssl/certs` | HTTPS/TLS connections |

## What NOT to Whitelist

| Path | Why |
|------|-----|
| `~/.password-store` | GPG-encrypted secrets — claw-wrap handles access |
| `~/.gnupg` | GPG keys used to decrypt pass entries |
| `~/.ssh` | SSH keys |
| `/etc/openclaw/wrappers.yaml` | Credential source paths — not needed inside sandbox |

## Systemd Services

Three systemd units work together: the gateway service (firejailed), and a path unit that lets the gateway trigger its own restart from inside the sandbox.

### openclaw-gateway.service

```ini
[Unit]
Description=OpenClaw Gateway (sandboxed)
Requires=claw-wrap.service
After=claw-wrap.service

[Service]
Type=simple
# TODO: Set to your username
User=YOUR_USERNAME
ExecStartPre=/bin/bash -c '\
  systemd-creds decrypt gateway-token - | \
  { read val; echo "OPENCLAW_GATEWAY_TOKEN=$val"; } >> /run/openclaw/env && \
  systemd-creds decrypt telegram-token - | \
  { read val; echo "TELEGRAM_BOT_TOKEN=$val"; } >> /run/openclaw/env'
ExecStart=/usr/bin/firejail \
  --profile=/etc/firejail/openclaw-gateway.profile \
  /usr/bin/node /home/YOUR_USERNAME/.npm-global/lib/node_modules/openclaw/dist/index.js \
  gateway --port 18789
Restart=always
RestartSec=5

EnvironmentFile=-/run/openclaw/env

SetCredentialEncrypted=gateway-token: ...
SetCredentialEncrypted=telegram-token: ...

[Install]
WantedBy=multi-user.target
```

Adjust the `ExecStartPre` and `SetCredentialEncrypted` lines for your own secrets, or remove them if you don't need encrypted credentials.

### Self-Restart Mechanism

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

### Install the units

```bash
sudo cp openclaw-gateway.service /etc/systemd/system/
sudo cp openclaw-gateway-restart.path /etc/systemd/system/
sudo cp openclaw-gateway-restart.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now openclaw-gateway.service
```

The path unit starts automatically with the gateway (via `WantedBy=openclaw-gateway.service`).

### How self-update works

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

## PATH Priority

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

## Verifying Isolation

After the gateway is running, verify from inside the sandbox:

### Credentials are invisible

```bash
# These paths don't exist inside the sandbox
ls ~/.password-store     # No such file or directory
ls ~/.gnupg              # No such file or directory
cat /etc/openclaw/wrappers.yaml  # No such file or directory
```

### Tools work through claw-wrap

```bash
# Works — proxied through claw-wrap daemon
gh repo list

# Token is never in the environment
echo $GH_TOKEN           # Empty
```

### Socket attack is rejected

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

### Self-restart works

```bash
# From inside the sandbox (or as the gateway user):
touch /run/openclaw/restart

# Watch the gateway restart:
sudo journalctl -u openclaw-gateway -f
```

---

## macOS: nono

[Firejail](https://firejail.wordpress.com/) is Linux-only. For macOS, [nono](https://github.com/lukehinds/nono) provides kernel-enforced sandboxing via Apple's Seatbelt (the same technology behind App Sandbox). It's deny-by-default — sensitive paths like `~/.ssh`, `~/.gnupg`, `~/.password-store`, and `~/.aws` are blocked automatically.

> **Note:** nono is early alpha and has not undergone a security audit. It also works on Linux (via Landlock) as an alternative to firejail.

### Install nono

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

nono ships with a built-in `openclaw` profile:

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
