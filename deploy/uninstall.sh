#!/usr/bin/env bash

set -Eeuo pipefail

SERVICE_NAME=ngstoned.service
SERVICE_PATH=/etc/systemd/system/ngstoned.service
BINARY_PATH=/usr/local/bin/ngstoned
ENV_DIR=/etc/ngstoned
ENV_PATH=/etc/ngstoned/env
STATE_PRIVATE=/var/lib/private/ngstoned
STATE_PUBLIC=/var/lib/ngstoned
ASSUME_YES=0
REMOVE_STATE=0
REMOVE_FIREWALL=0

info() {
  printf 'ngstone-edge-uninstall: %s\n' "$1"
}

warn() {
  printf 'ngstone-edge-uninstall: warning: %s\n' "$1" >&2
}

fail() {
  printf 'ngstone-edge-uninstall: error: %s\n' "$1" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: uninstall.sh [options]

Options:
  -y, --yes                   skip the confirmation prompt
  --remove-state              delete the persisted certificate and ACME state
  --remove-firewall-rules     remove matching UFW allow rules for 80/tcp, 443/tcp, 4443/tcp and any TCP tunnel range
  -h, --help                  show this help

The default removes the ngstoned systemd unit, binary, and root-only secrets.
Certificate state is preserved so a later reinstall can renew existing
certificates. The source checkout and SSH firewall access are never removed.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
  -y|--yes)
    ASSUME_YES=1
    shift
    ;;
  --remove-state)
    REMOVE_STATE=1
    shift
    ;;
  --remove-firewall-rules)
    REMOVE_FIREWALL=1
    shift
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    fail "unknown option: $1"
    ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  fail "run as root, for example: sudo $0"
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  fail "the edge uninstaller supports Linux VPS hosts only"
fi

command -v systemctl >/dev/null 2>&1 || fail "systemctl is required"

found=0
for target in "$SERVICE_PATH" "$BINARY_PATH" "$ENV_PATH" "$STATE_PRIVATE" "$STATE_PUBLIC"; do
  if [[ -e "$target" || -L "$target" ]]; then
    found=1
    break
  fi
done
if systemctl cat "$SERVICE_NAME" >/dev/null 2>&1; then
  found=1
fi

if [[ "$found" -eq 0 ]]; then
  info "ngstoned is not installed"
  exit 0
fi

# Read the TCP tunnel range before the unit is removed, so its firewall rule
# can be removed too.
TCP_PORTS=""
if [[ -f "$SERVICE_PATH" ]]; then
  TCP_PORTS="$(awk '$1 == "-tcp-ports" { print $2; exit }' "$SERVICE_PATH")"
fi
[[ "$TCP_PORTS" =~ ^[0-9]+-[0-9]+$ ]] || TCP_PORTS=""
FIREWALL_PORTS="80/tcp, 443/tcp, and 4443/tcp${TCP_PORTS:+, plus the ${TCP_PORTS} TCP tunnel range}"

printf 'This removes:\n'
printf '  - the %s systemd unit and its enablement\n' "$SERVICE_NAME"
printf '  - %s\n' "$BINARY_PATH"
printf '  - %s, including the DNS provider credentials and auth-token hash\n' "$ENV_PATH"
if [[ "$REMOVE_STATE" -eq 1 ]]; then
  printf '  - persisted certificate and ACME state under %s\n' "$STATE_PRIVATE"
else
  printf 'The certificate and ACME state under %s will be preserved.\n' "$STATE_PRIVATE"
fi
if [[ "$REMOVE_FIREWALL" -eq 1 ]]; then
  printf 'Matching UFW allow rules for %s will be removed; SSH rules stay.\n' "$FIREWALL_PORTS"
else
  printf 'UFW rules will be left unchanged.\n'
fi
printf 'The source checkout will be left in place.\n'

if [[ "$ASSUME_YES" -eq 0 ]]; then
  if ! { exec 3</dev/tty; } 2>/dev/null; then
    fail "interactive confirmation is required; rerun with --yes"
  fi
  reply=
  read -r -p "Continue? [y/N] " reply <&3 || fail "input was interrupted"
  case "$reply" in
  y|Y|yes|YES|Yes)
    ;;
  *)
    info "cancelled"
    exit 0
    ;;
  esac
fi

info "stopping and disabling $SERVICE_NAME"
if systemctl is-active --quiet "$SERVICE_NAME"; then
  systemctl stop "$SERVICE_NAME" || fail "could not stop $SERVICE_NAME; no files were removed"
fi
systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
rm -f -- "$SERVICE_PATH"
systemctl daemon-reload

info "removing the edge binary and secrets"
rm -f -- "$BINARY_PATH"
rm -f -- "$ENV_PATH"
rmdir -- "$ENV_DIR" 2>/dev/null || true

if [[ "$REMOVE_STATE" -eq 1 ]]; then
  info "removing persisted certificate and ACME state"
  public_target=
  if [[ -L "$STATE_PUBLIC" ]]; then
    public_target="$(readlink "$STATE_PUBLIC" || true)"
  fi
  rm -rf -- "$STATE_PRIVATE"
  if [[ -L "$STATE_PUBLIC" ]]; then
    case "$public_target" in
    "$STATE_PRIVATE"|private/ngstoned)
      rm -f -- "$STATE_PUBLIC"
      ;;
    *)
      warn "left unexpected state symlink $STATE_PUBLIC -> $public_target"
      ;;
    esac
  elif [[ -d "$STATE_PUBLIC" ]]; then
    if ! rmdir -- "$STATE_PUBLIC" 2>/dev/null; then
      warn "left non-empty directory $STATE_PUBLIC"
    fi
  fi
else
  info "preserved certificate and ACME state"
fi

if [[ "$REMOVE_FIREWALL" -eq 1 ]]; then
  if ! command -v ufw >/dev/null 2>&1; then
    warn "ufw is not installed; no firewall rules were changed"
  elif ufw status | grep -q '^Status: active'; then
    info "removing ngstoned UFW rules"
    ufw delete allow 80/tcp >/dev/null || true
    ufw delete allow 443/tcp >/dev/null || true
    ufw delete allow 4443/tcp >/dev/null || true
    if [[ -n "$TCP_PORTS" ]]; then
      ufw delete allow "${TCP_PORTS/-/:}/tcp" >/dev/null || true
    fi
  else
    info "UFW is not active; no firewall rules were changed"
  fi
fi

printf '\nngstoned has been uninstalled.\n'
if [[ "$REMOVE_STATE" -eq 0 ]]; then
  printf 'Certificate state remains at %s for a future reinstall.\n' "$STATE_PRIVATE"
fi
if [[ "$REMOVE_FIREWALL" -eq 0 ]]; then
  printf 'Review UFW rules for %s if they are no longer needed.\n' "$FIREWALL_PORTS"
fi
