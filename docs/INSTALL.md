# Installation Guide

## Prerequisites

- Go 1.21+ (for building from source)
- `pass` (password-store) for credential storage
- GPG configured for pass

## Building from Source

```bash
git clone https://github.com/dedene/claw-wrap.git
cd claw-wrap
make build
```

## Installation

### 1. Install the binary

```bash
sudo make install
```

This installs `claw-wrap` to `/usr/local/bin/`.

### 2. Install the systemd service

```bash
sudo cp init/claw-wrap.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable claw-wrap
sudo systemctl start claw-wrap
```

### 3. Create tool symlinks

```bash
sudo claw-wrap install
```

This creates symlinks for all tools defined in `/etc/openclaw/wrappers.yaml`.

### 4. Verify installation

```bash
# Check daemon is running
sudo systemctl status claw-wrap

# List configured tools
claw-wrap list

# Check credentials are accessible
claw-wrap check

# Test a tool
bird whoami  # or any other configured tool
```

## Configuration

Create `/etc/openclaw/wrappers.yaml`:

```yaml
credentials:
  my-api-key:
    source: pass:cli/myapp/api-key

tools:
  myapp:
    binary: /usr/local/bin/myapp
    env:
      API_KEY: my-api-key
```

See [CONFIG.md](CONFIG.md) for full configuration reference.

## Uninstallation

```bash
sudo systemctl stop claw-wrap
sudo systemctl disable claw-wrap
sudo rm /etc/systemd/system/claw-wrap.service
sudo rm /usr/local/bin/claw-wrap
sudo rm /usr/local/bin/{bird,gog,gh,openhue}  # remove symlinks
```
