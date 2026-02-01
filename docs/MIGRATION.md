# Migration from Python Daemon

This guide covers migrating from the Python `openclaw-secrets-daemon` to the unified Go `claw-wrap` binary.

## Why Migrate?

The Go version provides:
- **Single binary** - wrapper and daemon in one executable
- **Faster startup** - no Python interpreter overhead
- **Lower memory** - ~10MB vs ~15MB for Python
- **Easier deployment** - static binary, no dependencies
- **Same protocol** - fully backward compatible

## Migration Steps

### 1. Build and install the new binary

```bash
cd ~/.openclaw/workspace/claw-wrap
make build
sudo make install
```

### 2. Install the new systemd service

```bash
sudo cp init/claw-wrap.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### 3. Stop the old Python daemon

```bash
sudo systemctl stop openclaw-secrets
sudo systemctl disable openclaw-secrets
```

### 4. Start the new Go daemon

```bash
sudo systemctl enable claw-wrap
sudo systemctl start claw-wrap
```

### 5. Verify

```bash
# Check service status
sudo systemctl status claw-wrap

# Test admin commands
claw-wrap list
claw-wrap check

# Test tool execution
/usr/local/bin/bird whoami
/usr/local/bin/gog time now
```

### 6. Restart the gateway (if using firejail)

```bash
sudo systemctl restart openclaw-gateway
```

## Rollback

If something goes wrong, rollback to the Python daemon:

```bash
sudo systemctl stop claw-wrap
sudo systemctl disable claw-wrap
sudo systemctl enable openclaw-secrets
sudo systemctl start openclaw-secrets
```

## Configuration

No configuration changes are needed. The Go daemon reads the same `/etc/openclaw/wrappers.yaml` file.

## Protocol Compatibility

The Go daemon supports both protocols:

1. **New protocol** (tool execution):
   ```json
   {"tool": "gog", "args": ["gmail", "list"]}
   ```

2. **Legacy protocol** (credential fetch):
   ```json
   {"credential": "bird-auth-token"}
   ```

The old Go claw-wrap wrapper using the legacy protocol will continue to work during the transition.

## Files Changed

| Old | New |
|-----|-----|
| `/usr/local/bin/openclaw-secrets-daemon` (Python) | `/usr/local/bin/claw-wrap daemon` (Go) |
| `/etc/systemd/system/openclaw-secrets.service` | `/etc/systemd/system/claw-wrap.service` |

The socket path remains the same: `/run/openclaw/secrets.sock`

---

# Migration to Proxy Mode

This section covers migrating from direct-exec mode (credentials returned to sandbox) to proxy mode (credentials never enter sandbox).

## Why Migrate to Proxy Mode?

**Security vulnerability in direct-exec mode:**
- The daemon returned credentials to the wrapper inside the sandbox
- Any process in the sandbox could connect to the socket and extract credentials
- This bypassed the intended security model

**Proxy mode fixes this:**
- The daemon now executes tools directly, with credentials in its own environment
- Only stdout/stderr is streamed back to the sandbox
- Credentials never enter the sandbox

## Migration Steps

### 1. Update wrappers.yaml

Add the `proxy:` section at the top of `/etc/openclaw/wrappers.yaml`:

```yaml
# Add before 'credentials:' section
proxy:
  timeout: 300s
  inline_threshold: 1MB
  hmac_secret_file: /run/openclaw/auth
```

Optional: Add per-tool timeout overrides for slow tools:

```yaml
tools:
  gog:
    timeout: 600s  # gog can be slow for large operations
    # ... rest unchanged
```

### 2. Build and install new binary

```bash
cd ~/.openclaw/workspace/claw-wrap
make build
sudo make install
```

### 3. Restart services

```bash
sudo systemctl restart claw-wrap
sudo systemctl restart openclaw-gateway
```

### 4. Verify HMAC secret file

```bash
ls -la /run/openclaw/auth
# Should show: -rw-r----- 1 <user> <user> 44 ... /run/openclaw/auth
```

### 5. Test tool execution

```bash
# Test from inside firejail (or via gateway)
gog time now
bird whoami
```

### 6. Verify security fix

Inside the sandbox, attempt to extract credentials:

```bash
node -e "const net=require('net'); const c=net.connect('/run/openclaw/secrets.sock'); c.write('{\"credential\":\"bird-auth-token\"}'); c.on('data',d=>console.log(d.toString()))"
```

Expected result: `{"type":"error","message":"authentication failed"}`

The old credential extraction attack should now fail.

## Rollback

If proxy mode causes issues, rollback is not recommended as it re-exposes credentials. Instead, debug the proxy mode issues.

## Protocol Changes

| Aspect | Old (Direct-Exec) | New (Proxy) |
|--------|-------------------|-------------|
| Request | `{"tool":"gog","args":[...]}` | `{"tool":"gog","args":[...],"cwd":"...","timestamp":"...","hmac":"..."}` |
| Response | `{"allowed":true,"env":{"SECRET":"value"}}` | `{"type":"stdout","data":"base64..."}` |
| Execution | Wrapper execs binary with credentials | Daemon execs binary, streams output |
| Credentials | Enter sandbox | Never enter sandbox |

## Firejail Profile

No changes needed. The existing profile already whitelists `/run/openclaw` which includes the HMAC secret file.
