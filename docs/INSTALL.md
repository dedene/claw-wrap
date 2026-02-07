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

### Credential fetch fails

```bash
# Test pass directly
pass cli/github/token

# If that works but claw-wrap check fails, the daemon's
# GPG agent may not have the key cached:
sudo -u <your-user> gpg --decrypt ~/.password-store/cli/github/token.gpg
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
