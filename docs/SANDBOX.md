# Sandbox Setup (Firejail)

claw-wrap is designed for sandboxed environments where an untrusted process (e.g. an AI agent) needs to call CLI tools with credentials it should never see.

[Firejail](https://firejail.wordpress.com/) in **whitelist mode** is the recommended sandbox. In whitelist mode, everything is denied by default — only explicitly listed paths are accessible. This means `~/.password-store`, `~/.gnupg`, and `~/.ssh` simply don't exist inside the sandbox.

## Install Firejail

```bash
# Debian/Ubuntu
sudo apt install firejail

# Arch
sudo pacman -S firejail
```

## Example Profile

This is a production profile for running a Node.js application (e.g. an AI agent gateway) inside firejail with claw-wrap:

```
# /etc/firejail/my-agent.profile
#
# Whitelist mode — deny by default.
# Only explicitly listed paths are accessible.

# === ISOLATED FILESYSTEMS ===
private-tmp

# === HOME DIRECTORY WHITELIST ===
# Only these paths under ~ exist in the sandbox.
# ~/.password-store, ~/.gnupg, ~/.ssh are NOT listed = invisible.

# Application workspace and config
whitelist ${HOME}/.myapp
whitelist ${HOME}/.config/myapp
whitelist ${HOME}/.bashrc
whitelist ${HOME}/.profile

# Node.js / runtime dependencies (adjust for your stack)
whitelist ${HOME}/.npm-global
whitelist ${HOME}/.local/share/pnpm
whitelist ${HOME}/.local/bin
whitelist ${HOME}/.cache
whitelist ${HOME}/.bun

# Tool-specific config dirs (if tools write config inside sandbox)
whitelist ${HOME}/.config/gh

# Linuxbrew (if tools are installed via Homebrew)
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

# === CLAW-WRAP (CRITICAL) ===
# The Unix socket and HMAC auth file must be accessible
noblacklist /run/openclaw
whitelist /run/openclaw

# === SECURITY HARDENING ===
caps.drop all       # Drop all Linux capabilities
nonewprivs          # Prevent privilege escalation
noroot              # No root inside sandbox
seccomp             # Syscall filtering

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

# Set PATH to include tool locations
env PATH=/usr/local/bin:/home/USER/.local/bin:/home/linuxbrew/.linuxbrew/bin:/usr/bin:/bin
```

Replace `USER` with your actual username.

## What to Whitelist

| Path | Why |
|------|-----|
| `/run/openclaw` | Unix socket + HMAC auth file. **Required** for claw-wrap |
| `~/.config/<tool>` | Tool-specific config dirs (if the tool reads config at runtime) |
| `/home/linuxbrew/.linuxbrew` | Homebrew-installed binaries (gh, gog, etc.) |
| `/etc/ssl/certs` | HTTPS/TLS connections |
| `~/.cache` | Runtime caches (npm, node, etc.) |

## What NOT to Whitelist

| Path | Why |
|------|-----|
| `~/.password-store` | Contains GPG-encrypted secrets — the whole point of claw-wrap |
| `~/.gnupg` | GPG keys used to decrypt pass entries |
| `~/.ssh` | SSH keys |
| `/etc/openclaw/wrappers.yaml` | Contains credential source paths — not needed inside sandbox |

## Running Your Application

```bash
firejail --profile=/etc/firejail/my-agent.profile \
  node /path/to/your/agent/server.js
```

Or as a systemd service:

```ini
[Service]
ExecStart=/usr/bin/firejail --profile=/etc/firejail/my-agent.profile \
  node /path/to/your/agent/server.js
```

## Verifying Isolation

After starting your sandboxed process, verify from **inside** the sandbox:

### Credentials are invisible

```bash
# These should fail — paths don't exist in sandbox
ls ~/.password-store     # No such file or directory
ls ~/.gnupg              # No such file or directory
cat /etc/openclaw/wrappers.yaml  # No such file or directory
```

### Tools work through claw-wrap

```bash
# This should succeed — goes through claw-wrap daemon
gh repo list

# Direct credential access should fail
echo $GH_TOKEN           # Empty — token is never in the environment
```

### Socket attack is blocked

```bash
# Attempt to extract credentials via socket — should fail with auth error
node -e "
  const net = require('net');
  const c = net.connect('/run/openclaw/secrets.sock');
  c.write('{\"credential\":\"github-token\"}');
  c.on('data', d => console.log(d.toString()));
"
# Expected: {"type":"error","message":"authentication failed"}
```

The daemon verifies HMAC signatures on every request. Only `claw-wrap` (via symlinks) can authenticate — raw socket connections are rejected.
