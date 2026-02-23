# Quickstart: OpenClaw + claw-wrap Sidecar

## 1) Prepare env

```bash
cp .env.example .env
cp wrappers.example.yaml wrappers.yaml
```

Edit `.env`:

- set provider credentials you actually use
- confirm `OPENCLAW_CONFIG_DIR` points to your real host config dir
- set `CLAW_WRAP_WRAPPERS_FILE` if your wrappers file is not `./wrappers.yaml`
- set `GITHUB_TOKEN` only if you add `gh`/GitHub routes to `wrappers.yaml`

Edit `wrappers.yaml`:

- keep the default `curl` route for a minimal start
- optionally uncomment/adjust the advanced `gh` example (allowlist + blocked args)
- if the file is missing, sidecar startup fails fast
- `install` preflight now ensures OAuth state dir exists (`.openclaw/credentials`)

## 2) Run sidecar preflight

```bash
docker compose run --rm claw-wrap-daemon install
```

This verifies:

- host config mount is writable
- sidecar bootstrap succeeds
- wrappers install resolves tool links to `claw-wrap`

## 3) Run real OpenClaw onboarding

```bash
docker compose run --rm openclaw node /app/openclaw.mjs onboard
```

The wizard writes config into your mounted `OPENCLAW_CONFIG_DIR`.

## 4) Start gateway stack

```bash
docker compose up -d --build
```

## 5) Approve device pairing (first run only)

Docker port mapping NATs browser connections through the Docker bridge network
(`172.x.x.x` instead of `127.0.0.1`), so the gateway treats them as non-local
and requires explicit device pairing approval.

Open the web UI (http://127.0.0.1:18789) first -- this triggers the pairing request.
Then list pending requests:

```bash
docker compose exec openclaw node /app/openclaw.mjs devices list
```

Approve a specific device:

```bash
docker compose exec openclaw node /app/openclaw.mjs devices approve <request-id>
```

Approve all pending devices at once:

```bash
docker compose exec openclaw node /app/openclaw.mjs devices approve --all
```

This is only needed once per device. Subsequent starts reuse the stored device token.

If you see `device_token_mismatch` errors in the TUI, the stored device token is stale.
Run `devices approve --all` again to re-authorize pending devices.

**Tip:** If you don't need LAN access, set `OPENCLAW_GATEWAY_BIND=localhost` in `.env`
to skip device pairing entirely.

## 6) Verify health

```bash
docker compose exec claw-wrap-daemon doctor
docker compose exec openclaw node /app/openclaw.mjs doctor
docker compose exec openclaw sh -lc 'ls -l /opt/claw-wrap/bin/curl && readlink -f /opt/claw-wrap/bin/curl'
```

Web UI:
- http://127.0.0.1:${OPENCLAW_GATEWAY_PORT:-18789}

Terminal UI (inside container):

```bash
docker compose exec -it openclaw node /app/openclaw.mjs tui
```

Expected wrapped-tool proof:

- `/opt/claw-wrap/bin/curl` exists in the OpenClaw container
- symlink target resolves to `/opt/claw-wrap/bin/claw-wrap`

Note:

- OpenClaw's container entrypoint may reset `PATH`. To use wrapped tools for agent execs,
  set OpenClaw config `pathPrepend` to include `/opt/claw-wrap/bin`.

## Optional: install extra tools in sidecar

Set package lists in `.env`:

```bash
APT_PACKAGES="gh yq"
BREW_PACKAGES=""
NPM_GLOBAL_PACKAGES="@anthropic-ai/claude-code"
```

Recreate sidecar:

```bash
docker compose up -d --build claw-wrap-daemon
```

Notes:

- `pnpm` and modern `yarn` are baked into the sidecar image by default.
- Homebrew is baked into the image and seeded into canonical prefix `/home/linuxbrew/.linuxbrew` on first use.
- npm globals persist in `claw_state` at `/opt/claw-wrap/npm-global`.
- brew install output is buffered to `/opt/claw-wrap/logs`; on failure, sidecar prints a tail and full log path.
