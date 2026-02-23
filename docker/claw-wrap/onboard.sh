#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[claw-wrap-install] %s\n' "$*"
}

fail() {
  printf '[claw-wrap-install] error: %s\n' "$*" >&2
  exit 1
}

assert_readable_file() {
  local path="$1"
  [[ -f "$path" ]] || fail "missing file: $path"
  [[ -r "$path" ]] || fail "file not readable: $path"
}

assert_writable_dir() {
  local dir="$1"
  [[ -d "$dir" ]] || fail "missing directory mount: $dir"
  [[ -w "$dir" ]] || fail "directory not writable: $dir"
}

CLAW_WRAP_CONFIG="${CLAW_WRAP_CONFIG:-/etc/openclaw/wrappers.yaml}"
CLAW_CONFIG_DIR="${CLAW_CONFIG_DIR:-/workspace/config}"

assert_readable_file "$CLAW_WRAP_CONFIG"
assert_writable_dir "$CLAW_CONFIG_DIR"
mkdir -p "$CLAW_CONFIG_DIR/credentials"

if [[ ! -e "$CLAW_CONFIG_DIR/openclaw.json" ]]; then
  log "openclaw.json not found in $CLAW_CONFIG_DIR (expected before first gateway start)"
fi

log "preflight passed"
log "next:"
log "  1) docker compose run --rm openclaw node /app/openclaw.mjs onboard"
log "  2) docker compose up -d --build"
log "  3) open http://127.0.0.1:18789 then approve the device pairing request:"
log "     docker compose exec openclaw node /app/openclaw.mjs devices approve --all"
log "  4) docker compose exec openclaw node /app/openclaw.mjs doctor"
