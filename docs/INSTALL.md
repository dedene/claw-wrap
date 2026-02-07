# Installation Guide

## Prerequisites

- Linux with systemd
- Go 1.21+ (for building from source)
- GPG key pair
- [`pass`](https://www.passwordstore.org/) (password-store)

### Setting up pass

If you don't have `pass` configured yet:

```bash
# Install pass
sudo apt install pass    # Debian/Ubuntu
brew install pass        # Linuxbrew

# Generate a GPG key (if you don't have one)
gpg --gen-key

# Initialize pass with your GPG key ID
pass init <your-gpg-key-id>

# Store a credential (e.g. GitHub token)
pass insert cli/github/token
```

## Install claw-wrap

### Homebrew (Linux)

```bash
brew install dedene/tap/claw-wrap
```

### From source

```bash
git clone https://github.com/dedene/claw-wrap.git
cd claw-wrap
make build
sudo make install
```

This installs `claw-wrap` to `/usr/local/bin/`.

## Configure

Create `/etc/openclaw/wrappers.yaml`. Here's a minimal example with just `gh`:

```bash
sudo mkdir -p /etc/openclaw
sudo editor /etc/openclaw/wrappers.yaml
```

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
```

Adjust `binary:` to the path of your real `gh` binary (`which gh` before installing claw-wrap).

See [CONFIG.md](CONFIG.md) for all configuration options.

## Start the daemon

```bash
sudo cp init/claw-wrap.service /etc/systemd/system/
```

Edit `User=` in the service file to your username:

```bash
sudo editor /etc/systemd/system/claw-wrap.service
# Change User=YOUR_USERNAME to your actual username
```

> If your GPG home is not the default `~/.gnupg`, also add `Environment=GNUPGHOME=/path/to/.gnupg` to the service file.
> The provided unit includes strict hardening defaults. If you must relax settings, keep `ReadWritePaths=/run/openclaw`.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now claw-wrap
```

## Create tool symlinks

```bash
sudo $(which claw-wrap) install
```

This creates symlinks in `/usr/local/bin` pointing to the auto-detected `claw-wrap` binary. For example, `gh → /home/linuxbrew/.linuxbrew/bin/claw-wrap`. Use `$(which claw-wrap)` so sudo resolves YOUR binary (sudo's PATH may differ). To install symlinks in a different directory:

```bash
sudo claw-wrap install --install-dir /usr/local/bin
```

## Verify

```bash
# Check daemon is running
sudo systemctl status claw-wrap

# List configured tools
claw-wrap list

# Check credentials are accessible
# Run from host/admin context (outside sandbox).
# In strict firejail, this may fail by design.
claw-wrap check

# Test gh through claw-wrap
gh repo list
```

## Troubleshooting

### Daemon won't start

```bash
sudo journalctl -u claw-wrap -n 50
```

Common causes:
- Wrong `User=` in service file
- Config file missing or invalid YAML
- `pass` not initialized for the service user
- GPG key not available (check `GNUPGHOME` in service file)

### Socket permission errors

The daemon creates `/run/openclaw/secrets.sock`. If the sandboxed process can't connect:
- Verify `/run/openclaw` is whitelisted in your firejail profile
- Check socket permissions: `ls -la /run/openclaw/`

### Protocol version mismatch

If wrapper and daemon versions are out of sync, requests fail with a protocol mismatch error.
Upgrade and restart together:

```bash
sudo make install
sudo systemctl restart claw-wrap
```

### Tools crash or fail after systemd hardening

The daemon spawns tool processes that inherit all systemd security restrictions.
Common symptoms:

| Symptom | Cause | Fix |
|---------|-------|-----|
| V8/Node.js crash (`ENOMEM` in `SetPermissions`) | `MemoryDenyWriteExecute=true` | Set to `false` |
| "token invalid" / network errors | `RestrictAddressFamilies=AF_UNIX` | Add `AF_INET AF_INET6` |
| Tool hangs or gets killed | `SystemCallFilter` too strict | Check `journalctl` for SECCOMP audit messages |

After changes: `sudo systemctl daemon-reload && sudo systemctl restart claw-wrap`

### Credential fetch fails

```bash
# Test pass directly
pass cli/github/token

# If that works but claw-wrap check fails, the daemon's
# GPG agent may not have the key cached:
sudo -u <your-user> gpg --decrypt ~/.password-store/cli/github/token.gpg
```

If you use `env:` credential sources, verify the env file hardening:

```bash
sudo chown <your-user>:<your-user> /run/openclaw/env
sudo chmod 600 /run/openclaw/env   # 640 is also accepted
```

### Symlink conflicts

If `gh` already exists in the install directory (real `gh` binary):
- Move the real binary: `sudo mv $(which gh) $(which gh)-real`
- Update `binary:` in config to point to the new path
- Re-run `sudo claw-wrap install`

## Uninstallation

```bash
sudo systemctl stop claw-wrap
sudo systemctl disable claw-wrap
sudo rm /etc/systemd/system/claw-wrap.service
sudo rm /usr/local/bin/claw-wrap
# Remove symlinks for your tools
sudo rm /usr/local/bin/gh   # etc.
```
