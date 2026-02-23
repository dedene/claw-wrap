#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[claw-wrap-sidecar] %s\n' "$*"
}

die() {
  printf '[claw-wrap-sidecar] error: %s\n' "$*" >&2
  exit 1
}

split_entries() {
  local input="$1"
  local -n out_ref="$2"
  local normalized

  out_ref=()
  normalized="${input//,/ }"
  if [[ -z "${normalized// }" ]]; then
    return
  fi
  read -r -a out_ref <<<"$normalized"
}

dir_has_entries() {
  local dir="$1"
  find "$dir" -mindepth 1 -maxdepth 1 -print -quit | grep -q .
}

validate_package_token() {
  local ecosystem="$1"
  local pkg="$2"
  if [[ -z "$pkg" ]]; then
    die "${ecosystem} package name is empty"
  fi
  if [[ ! "$pkg" =~ ^[A-Za-z0-9@._+:/=-]+$ ]]; then
    die "${ecosystem} package contains invalid characters: ${pkg}"
  fi
}

validate_package_list() {
  local ecosystem="$1"
  shift
  local pkgs=("$@")
  local pkg
  for pkg in "${pkgs[@]}"; do
    validate_package_token "$ecosystem" "$pkg"
  done
}

install_apt_packages() {
  local pkgs=("$@")
  if [[ "${#pkgs[@]}" -eq 0 ]]; then
    return
  fi

  local missing=()
  local pkg
  for pkg in "${pkgs[@]}"; do
    if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then
      continue
    fi
    missing+=("$pkg")
  done

  if [[ "${#missing[@]}" -eq 0 ]]; then
    log "extra apt packages already installed"
    return
  fi

  log "installing extra apt packages: ${missing[*]}"
  apt-get update
  apt-get install -y --no-install-recommends "${missing[@]}"
}

ensure_linuxbrew_user() {
  if ! getent group linuxbrew >/dev/null; then
    groupadd --system linuxbrew
  fi
  if ! id -u linuxbrew >/dev/null 2>&1; then
    useradd --system --create-home --home-dir /home/linuxbrew --gid linuxbrew --shell /bin/bash linuxbrew
  fi
  mkdir -p /home/linuxbrew/.linuxbrew "${BREW_PREFIX}"
  chown -R linuxbrew:linuxbrew /home/linuxbrew "${BREW_PREFIX}"
}

run_as_linuxbrew() {
  local cmd="$1"
  su -s /bin/bash - linuxbrew -c "$cmd"
}

sanitize_filename() {
  local input="$1"
  local output

  output="${input//[^A-Za-z0-9._-]/_}"
  if [[ -z "$output" ]]; then
    output="pkg"
  fi
  printf '%s' "$output"
}

brew_log_tail_lines() {
  if [[ "${CLAW_WRAP_BREW_LOG_TAIL_LINES}" =~ ^[1-9][0-9]*$ ]]; then
    printf '%s' "${CLAW_WRAP_BREW_LOG_TAIL_LINES}"
    return
  fi
  printf '%s' "80"
}

prepare_brew_log_dir() {
  mkdir -p "${CLAW_WRAP_BREW_LOG_DIR}"
  chown -R linuxbrew:linuxbrew "${CLAW_WRAP_BREW_LOG_DIR}"
}

install_brew_package_buffered() {
  local pkg="$1"
  local pkg_escaped="$2"
  local safe_pkg ts log_file log_file_escaped tail_lines

  prepare_brew_log_dir

  safe_pkg="$(sanitize_filename "$pkg")"
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  log_file="${CLAW_WRAP_BREW_LOG_DIR}/brew-install-${safe_pkg}-${ts}.log"
  printf -v log_file_escaped '%q' "$log_file"

  if run_as_linuxbrew "eval \"\$(${BREW_PREFIX}/bin/brew shellenv)\"; HOMEBREW_NO_AUTO_UPDATE=1 brew install -- ${pkg_escaped} > ${log_file_escaped} 2>&1"; then
    log "brew package installed: ${pkg} (log: ${log_file})"
    return
  fi

  tail_lines="$(brew_log_tail_lines)"
  log "brew install failed for ${pkg}; showing last ${tail_lines} lines from ${log_file}"
  tail -n "${tail_lines}" "${log_file}" >&2 || true
  die "brew install failed for ${pkg} (full log: ${log_file})"
}

install_brew_packages() {
  local pkgs=("$@")
  if [[ "${#pkgs[@]}" -eq 0 ]]; then
    return
  fi

  ensure_linuxbrew_user

  seed_brew_prefix_if_needed

  local pkg pkg_escaped
  for pkg in "${pkgs[@]}"; do
    pkg_escaped="$(printf '%q' "$pkg")"
    if run_as_linuxbrew "eval \"\$(${BREW_PREFIX}/bin/brew shellenv)\"; HOMEBREW_NO_AUTO_UPDATE=1 brew list --versions -- ${pkg_escaped} >/dev/null 2>&1"; then
      continue
    fi
    log "installing extra brew package: ${pkg}"
    install_brew_package_buffered "$pkg" "$pkg_escaped"
  done
}

install_npm_packages() {
  local pkgs=("$@")
  if [[ "${#pkgs[@]}" -eq 0 ]]; then
    return
  fi

  command -v npm >/dev/null 2>&1 || die "npm missing in image"

  mkdir -p "${NPM_PREFIX}"
  npm config set prefix "${NPM_PREFIX}" --global >/dev/null

  local pkg
  for pkg in "${pkgs[@]}"; do
    if npm list -g --depth=0 "$pkg" >/dev/null 2>&1; then
      continue
    fi
    log "installing extra npm package: ${pkg}"
    npm install -g "$pkg"
  done
}

seed_brew_prefix_if_needed() {
  mkdir -p "${BREW_PREFIX}"
  if [[ -x "${BREW_PREFIX}/bin/brew" ]]; then
    return
  fi

  if dir_has_entries "${BREW_PREFIX}"; then
    log "brew prefix is non-empty; seeding missing Homebrew files into ${BREW_PREFIX}"
  fi

  [[ -f "${BREW_SEED_TAR}" ]] || die "missing baked Homebrew seed archive: ${BREW_SEED_TAR}"

  log "seeding Linuxbrew into ${BREW_PREFIX}"
  tar -xf "${BREW_SEED_TAR}" -C "${BREW_PREFIX}"
  chown -R linuxbrew:linuxbrew "${BREW_PREFIX}" /home/linuxbrew
  touch "${BREW_PREFIX}/.seeded-by-claw-wrap"
}

bootstrap_tools() {
  mkdir -p "$TOOLS_DIR"
  rm -f "$TOOLS_DIR/claw-wrap"
  cp /usr/local/bin/claw-wrap "$TOOLS_DIR/claw-wrap"
  chmod 0755 "$TOOLS_DIR/claw-wrap"

  "$TOOLS_DIR/claw-wrap" install \
    --config "$CLAW_WRAP_CONFIG" \
    --install-dir "$TOOLS_DIR" \
    --force

  # Optional npm global binaries in PATH for wrapper binary targets.
  if [[ -d "${NPM_PREFIX}/bin" ]]; then
    ln -sf "${NPM_PREFIX}/bin"/* "$TOOLS_DIR"/ 2>/dev/null || true
  fi
}

prepare_runtime_permissions() {
  mkdir -p /run/openclaw
  chown "${DAEMON_UID}:${OPENCLAW_SHARED_GID}" /run/openclaw || true
  chmod 0750 /run/openclaw || true
  chmod 0755 "$TOOLS_DIR"
}

install_optional_extras() {
  declare -a apt_list brew_list npm_list
  split_entries "$APT_PACKAGES" apt_list
  split_entries "$BREW_PACKAGES" brew_list
  split_entries "$NPM_GLOBAL_PACKAGES" npm_list

  validate_package_list "apt" "${apt_list[@]}"
  validate_package_list "brew" "${brew_list[@]}"
  validate_package_list "npm" "${npm_list[@]}"

  install_apt_packages "${apt_list[@]}"
  install_brew_packages "${brew_list[@]}"
  install_npm_packages "${npm_list[@]}"
}

bootstrap_sidecar() {
  install_optional_extras

  bootstrap_tools
  prepare_runtime_permissions
}

assert_no_legacy_allowlist_env() {
  if [[ -n "${INSTALL_ALLOWLIST_MODE+x}" ]]; then
    die "INSTALL_ALLOWLIST_MODE was removed; delete it from .env/compose"
  fi
  if [[ -n "${CLAW_WRAP_TOOL_ALLOWLIST_FILE+x}" ]]; then
    die "CLAW_WRAP_TOOL_ALLOWLIST_FILE was removed; delete it from .env/compose"
  fi
}

start_daemon() {
  local daemon_cmd=(
    "$TOOLS_DIR/claw-wrap" daemon
    --config "$CLAW_WRAP_CONFIG"
    --uid "$OPENCLAW_UID"
    --runtime-gid "$OPENCLAW_SHARED_GID"
    --auth-mode "$AUTH_MODE"
    --socket-mode "$SOCKET_MODE"
  )

  if [[ "$#" -gt 0 ]]; then
    daemon_cmd+=("$@")
  fi

  log "starting daemon uid=${DAEMON_UID} allowed_uid=${OPENCLAW_UID} runtime_gid=${OPENCLAW_SHARED_GID}"
  exec gosu "${DAEMON_UID}:${OPENCLAW_SHARED_GID}" "${daemon_cmd[@]}"
}

DAEMON_UID="${DAEMON_UID:-1000}"
OPENCLAW_UID="${OPENCLAW_UID:-1000}"
OPENCLAW_SHARED_GID="${OPENCLAW_SHARED_GID:-2000}"
CLAW_WRAP_CONFIG="${CLAW_WRAP_CONFIG:-/etc/openclaw/wrappers.yaml}"
TOOLS_DIR="${TOOLS_DIR:-/opt/claw-wrap/bin}"
BREW_PREFIX="${BREW_PREFIX:-/home/linuxbrew/.linuxbrew}"
BREW_SEED_TAR="${BREW_SEED_TAR:-/opt/claw-wrap-seed/homebrew.tar}"
NPM_PREFIX="${NPM_PREFIX:-/opt/claw-wrap/npm-global}"
CLAW_WRAP_BREW_LOG_DIR="${CLAW_WRAP_BREW_LOG_DIR:-/opt/claw-wrap/logs}"
CLAW_WRAP_BREW_LOG_TAIL_LINES="${CLAW_WRAP_BREW_LOG_TAIL_LINES:-80}"
AUTH_MODE="${AUTH_MODE:-0640}"
SOCKET_MODE="${SOCKET_MODE:-0660}"
APT_PACKAGES="${APT_PACKAGES:-}"
BREW_PACKAGES="${BREW_PACKAGES:-}"
NPM_GLOBAL_PACKAGES="${NPM_GLOBAL_PACKAGES:-}"
CLAW_CONFIG_DIR="${CLAW_CONFIG_DIR:-/workspace/config}"

assert_no_legacy_allowlist_env

command="${1:-daemon}"
case "$command" in
  install|preflight|onboard)
    if [[ "$#" -gt 0 ]]; then
      shift
    fi
    bootstrap_sidecar
    exec /usr/local/bin/onboard.sh "$@"
    ;;
  doctor)
    if [[ "$#" -gt 0 ]]; then
      shift
    fi
    exec /usr/local/bin/doctor.sh "$@"
    ;;
  daemon)
    if [[ "$#" -gt 0 ]]; then
      shift
    fi
    bootstrap_sidecar
    start_daemon "$@"
    ;;
  *)
    bootstrap_sidecar
    start_daemon "$@"
    ;;
esac
