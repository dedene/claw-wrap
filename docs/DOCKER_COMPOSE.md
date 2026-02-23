# Docker Compose: Vanilla OpenClaw + claw-wrap Sidecar

## What this gives you

- stock `ghcr.io/openclaw/openclaw` image
- separate `claw-wrap` sidecar daemon
- exactly two named volumes:
  - `openclaw_runtime` for `/run/openclaw` socket/auth IPC
  - `claw_state` for persistent sidecar tool state (mounted at `/opt/claw-wrap` and `/home/linuxbrew/.linuxbrew`)
- wrapped tools exposed to OpenClaw PATH from `/opt/claw-wrap/bin`
- localhost-only HTTP proxy inside shared namespace
- host-loopback gateway port publish (`127.0.0.1:${OPENCLAW_GATEWAY_PORT}`)

## Why shared namespace

`openclaw` uses `network_mode: service:claw-wrap-daemon`.

This keeps proxy traffic on loopback while preserving the daemon's localhost-only bind guard. No proxy listener is exposed outside the compose network namespace by default.

## Files

- `docker-compose.yml`
- `docker/claw-wrap/Dockerfile`
- `docker/claw-wrap/entrypoint.sh`
- `docker/claw-wrap/onboard.sh` (install/preflight step)
- `docker/claw-wrap/doctor.sh`
- `wrappers.example.yaml` (copy to `wrappers.yaml`)
- `docs/quickstart.md`

## Bootstrap flow

Follow `docs/quickstart.md`.

Wrapper config source is controlled by `CLAW_WRAP_WRAPPERS_FILE` (defaults to `./wrappers.yaml`).
Gateway bind/port are controlled by `OPENCLAW_GATEWAY_BIND` and `OPENCLAW_GATEWAY_PORT`.

Short version:

```bash
cp .env.example .env
cp wrappers.example.yaml wrappers.yaml
docker compose run --rm claw-wrap-daemon install
docker compose run --rm openclaw node /app/openclaw.mjs onboard
docker compose up -d --build
docker compose exec openclaw node /app/openclaw.mjs devices approve --all  # first-run only
```

## Security defaults

- proxy bind remains localhost-only (`127.0.0.1`)
- sidecar daemon runs non-root (root init -> `gosu` drop)
- package installs are user-controlled via `APT_PACKAGES`, `BREW_PACKAGES`, `NPM_GLOBAL_PACKAGES`
- Homebrew is baked in and seeded into canonical prefix `/home/linuxbrew/.linuxbrew` on first use
- npm globals persist in `claw_state` at `/opt/claw-wrap/npm-global`
- brew install logs are buffered under `/opt/claw-wrap/logs` with concise failure tail output
- `pnpm` and modern `yarn` are baked in (pinned major tracks)
- daemon caller executable verification remains enabled
- diagnostics are sanitized (no env dumps/tokens)

## Sidecar image release

Multi-arch publish is defined in `.github/workflows/publish-sidecar.yml`:

- platforms: `linux/amd64`, `linux/arm64`
- trigger: git tags `v*`
- registry: GHCR (`ghcr.io/<owner>/claw-wrap-sidecar`)
- supply-chain outputs: SBOM, provenance attestation, image signatures
- vuln scan: report-only

## Rollback

Use pinned image tags in `.env`.

- set `OPENCLAW_IMAGE` to previous known-good tag
- set `CLAW_WRAP_SIDECAR_IMAGE` to previous known-good sidecar tag
- keep same known-good env/config values

Then redeploy:

```bash
docker compose pull
docker compose up -d
```

## Release governance

- tag-triggered publish only (`v*`)
- stable channel only (workflow skips prerelease tags containing `-`)
- protect release tags in GitHub settings; maintainer-only tag creation
