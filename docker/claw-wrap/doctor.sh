#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[claw-wrap-doctor] %s\n' "$*"
}

fail() {
  printf '[claw-wrap-doctor] error: %s\n' "$*" >&2
  exit 1
}

SOCKET_PATH="${SOCKET_PATH:-/run/openclaw/secrets.sock}"
AUTH_PATH="${AUTH_PATH:-/run/openclaw/auth}"
TOOLS_DIR="${TOOLS_DIR:-/opt/claw-wrap/bin}"

[[ -S "$SOCKET_PATH" ]] || fail "missing socket: $SOCKET_PATH"
[[ -f "$AUTH_PATH" ]] || fail "missing auth file: $AUTH_PATH"
[[ -x "$TOOLS_DIR/claw-wrap" ]] || fail "missing claw-wrap binary: $TOOLS_DIR/claw-wrap"
[[ -x "$TOOLS_DIR/curl" ]] || fail "missing wrapped curl binary: $TOOLS_DIR/curl"

resolved_curl="$(readlink -f "$TOOLS_DIR/curl" 2>/dev/null || true)"
[[ -n "$resolved_curl" ]] || fail "cannot resolve wrapped curl symlink: $TOOLS_DIR/curl"
[[ "$(basename "$resolved_curl")" == "claw-wrap" ]] || fail "wrapped curl does not resolve to claw-wrap: $resolved_curl"

pgrep -f 'claw-wrap daemon' >/dev/null 2>&1 || fail "daemon process not running"

log "daemon reachable"
log "socket/auth present"
log "wrapped curl symlink: OK ($resolved_curl)"
log "wrapped curl path check: docker compose exec openclaw sh -lc 'ls -l /opt/claw-wrap/bin/curl && readlink -f /opt/claw-wrap/bin/curl'"
