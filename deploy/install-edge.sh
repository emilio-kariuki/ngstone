#!/usr/bin/env bash

set -Eeuo pipefail

REPOSITORY="emilio-kariuki/ngstone"
INSTALL_PATH="/usr/local/bin/ngstoned"
SERVICE_PATH="/etc/systemd/system/ngstoned.service"
ENV_DIR="/etc/ngstoned"
ENV_PATH="${ENV_DIR}/env"
VERSION="${NGSTONE_VERSION:-}"
DOMAIN="${NGSTONE_DOMAIN:-}"
EMAIL="${NGSTONE_CERT_EMAIL:-}"
CF_API_TOKEN="${NGSTONE_CF_API_TOKEN:-}"
AUTH_TOKEN="${NGSTONE_AUTH_TOKEN:-}"
ACME_CA="${NGSTONE_ACME_CA:-}"
BINARY_PATH="${NGSTONE_EDGE_BINARY:-}"
SSH_PORT="${NGSTONE_SSH_PORT:-22}"
SKIP_FIREWALL=0
SKIP_DNS_CHECK=0
TEMP_DIR=""

if [[ -r /dev/tty ]]; then
  if { exec 3</dev/tty; } 2>/dev/null; then
    :
  else
    exec 3<&0
  fi
else
  exec 3<&0
fi

info() {
  printf 'ngstone-edge-install: %s\n' "$1"
}

warn() {
  printf 'ngstone-edge-install: warning: %s\n' "$1" >&2
}

fail() {
  printf 'ngstone-edge-install: error: %s\n' "$1" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: install-edge.sh [options]

Options:
  --domain DOMAIN           public base domain
  --email ADDRESS           Let's Encrypt account email
  --version VERSION         release version, for example v0.3.2
  --acme-ca staging|production
  --ssh-port PORT           SSH port to preserve in UFW (default: 22)
  --binary PATH             use a local ngstoned binary instead of downloading
  --skip-firewall           do not configure UFW
  --skip-dns-check          do not verify apex and wildcard DNS first
  -h, --help                show this help

The Cloudflare token is read from NGSTONE_CF_API_TOKEN or prompted for
without echoing it. The auth token is generated automatically unless
NGSTONE_AUTH_TOKEN is provided or an existing installation is detected.
EOF
}

cleanup() {
  if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
    rm -rf -- "$TEMP_DIR"
  fi
}

trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
  --domain)
    [[ $# -ge 2 ]] || fail "--domain requires a value"
    DOMAIN="$2"
    shift 2
    ;;
  --email|--cert-email)
    [[ $# -ge 2 ]] || fail "$1 requires a value"
    EMAIL="$2"
    shift 2
    ;;
  --version)
    [[ $# -ge 2 ]] || fail "--version requires a value"
    VERSION="$2"
    shift 2
    ;;
  --acme-ca)
    [[ $# -ge 2 ]] || fail "--acme-ca requires staging or production"
    ACME_CA="$2"
    shift 2
    ;;
  --production)
    ACME_CA=production
    shift
    ;;
  --staging)
    ACME_CA=staging
    shift
    ;;
  --ssh-port)
    [[ $# -ge 2 ]] || fail "--ssh-port requires a value"
    SSH_PORT="$2"
    shift 2
    ;;
  --binary)
    [[ $# -ge 2 ]] || fail "--binary requires a path"
    BINARY_PATH="$2"
    shift 2
    ;;
  --skip-firewall)
    SKIP_FIREWALL=1
    shift
    ;;
  --skip-dns-check)
    SKIP_DNS_CHECK=1
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

if [[ ${EUID} -ne 0 ]]; then
  fail "run as root, for example: sudo $0 --domain example.com --email you@example.com"
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  fail "the edge installer supports Linux VPS hosts only"
fi

if [[ ! -r /etc/os-release ]]; then
  fail "cannot identify the Linux distribution"
fi

. /etc/os-release
case "${ID:-}" in
ubuntu|debian)
  ;;
*)
  fail "the edge installer currently supports Ubuntu and Debian; detected ${ID:-unknown}"
  ;;
esac

if command -v apt-get >/dev/null 2>&1; then
  info "installing host dependencies"
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl dnsutils openssl ufw
fi

for command_name in awk curl dig install openssl sha256sum systemctl tar; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: $command_name"
done

if [[ "$SKIP_FIREWALL" -eq 0 ]]; then
  command -v ufw >/dev/null 2>&1 || fail "ufw is required unless --skip-firewall is used"
fi

if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || ((SSH_PORT < 1 || SSH_PORT > 65535)); then
  fail "invalid SSH port: $SSH_PORT"
fi

get_env_value() {
  local key="$1"
  if [[ -f "$ENV_PATH" ]]; then
    awk -v key="$key" 'index($0, key "=") == 1 { print substr($0, length(key) + 2); exit }' "$ENV_PATH"
  fi
}

get_service_value() {
  local key="$1"
  if [[ -f "$SERVICE_PATH" ]]; then
    awk -v key="$key" '$1 == key { print $2; exit }' "$SERVICE_PATH"
  fi
}

prompt_value() {
  local label="$1"
  local current="$2"
  local variable_name="$3"
  local reply
  if [[ -n "$current" ]]; then
    read -r -p "${label} [${current}]: " reply <&3 || fail "input was interrupted"
    reply="${reply:-$current}"
  else
    read -r -p "${label}: " reply <&3 || fail "input was interrupted"
  fi
  printf -v "$variable_name" '%s' "$reply"
}

prompt_secret() {
  local label="$1"
  local variable_name="$2"
  local reply
  read -r -s -p "$label" reply <&3 || fail "input was interrupted"
  printf '\n' >&2
  printf -v "$variable_name" '%s' "$reply"
}

EXISTING_HASH="$(get_env_value NGSTONE_TOKEN_SHA256)"
EXISTING_CF_API_TOKEN="$(get_env_value NGSTONE_CF_API_TOKEN)"
EXISTING_EMAIL="$(get_env_value NGSTONE_CERT_EMAIL)"
EXISTING_DOMAIN="$(get_service_value -domain)"
EXISTING_ACME_CA="$(get_service_value -acme-ca)"

if [[ -z "$DOMAIN" ]]; then
  prompt_value "Public domain" "$EXISTING_DOMAIN" DOMAIN
fi
if [[ -z "$EMAIL" ]]; then
  prompt_value "Let's Encrypt email" "$EXISTING_EMAIL" EMAIL
fi
if [[ -z "$CF_API_TOKEN" ]]; then
  CF_API_TOKEN="$EXISTING_CF_API_TOKEN"
fi
if [[ -z "$CF_API_TOKEN" ]]; then
  prompt_secret "Cloudflare API token: " CF_API_TOKEN
fi

if [[ -z "$ACME_CA" ]]; then
  ACME_CA="$EXISTING_ACME_CA"
fi
if [[ -z "$ACME_CA" ]]; then
  ACME_CA=staging
  if [[ -t 3 ]]; then
    prompt_value "ACME CA (staging or production)" "$ACME_CA" ACME_CA
  fi
fi
ACME_CA="${ACME_CA,,}"

if [[ ! "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || [[ "$DOMAIN" != *.* ]] || [[ "$DOMAIN" == *..* ]]; then
  fail "invalid domain: $DOMAIN"
fi
if [[ ! "$EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; then
  fail "invalid email address: $EMAIL"
fi
if [[ "$ACME_CA" != staging && "$ACME_CA" != production ]]; then
  fail "ACME CA must be staging or production"
fi
if [[ -z "$CF_API_TOKEN" ]]; then
  fail "Cloudflare API token is required"
fi

if [[ -n "$AUTH_TOKEN" ]]; then
  TOKEN_HASH="$(printf '%s' "$AUTH_TOKEN" | sha256sum | awk '{print $1}')"
elif [[ -n "$EXISTING_HASH" ]]; then
  TOKEN_HASH="$EXISTING_HASH"
  if [[ ! "$TOKEN_HASH" =~ ^[0-9a-fA-F]{64}$ ]]; then
    fail "existing NGSTONE_TOKEN_SHA256 is not a 64-character hex digest"
  fi
else
  AUTH_TOKEN="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
  TOKEN_HASH="$(printf '%s' "$AUTH_TOKEN" | sha256sum | awk '{print $1}')"
fi

resolve_version() {
  local latest
  latest="$(curl -fsSL "https://api.github.com/repos/${REPOSITORY}/releases/latest" | awk -F'"' '/"tag_name"/ { print $4; exit }')"
  [[ -n "$latest" ]] || fail "could not resolve the latest ngstone release"
  printf '%s' "$latest"
}

install_binary() {
  local architecture archive checksum_line download_base
  if [[ -n "$BINARY_PATH" ]]; then
    [[ -f "$BINARY_PATH" ]] || fail "edge binary not found: $BINARY_PATH"
    install -o root -g root -m 0755 "$BINARY_PATH" "$INSTALL_PATH"
    return
  fi
  if [[ -z "$VERSION" ]]; then
    VERSION="$(resolve_version)"
  fi
  [[ "$VERSION" == v* ]] || VERSION="v${VERSION}"
  [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "invalid release version: $VERSION"
  case "$(uname -m)" in
  x86_64|amd64)
    architecture=amd64
    ;;
  aarch64|arm64)
    architecture=arm64
    ;;
  *)
    fail "unsupported VPS architecture: $(uname -m)"
    ;;
  esac
  TEMP_DIR="$(mktemp -d)"
  archive="ngstone_linux_${architecture}.tar.gz"
  download_base="https://github.com/${REPOSITORY}/releases/download/${VERSION}"
  info "downloading ngstone ${VERSION} for linux/${architecture}"
  curl -fsSL -o "${TEMP_DIR}/${archive}" "${download_base}/${archive}"
  curl -fsSL -o "${TEMP_DIR}/checksums.txt" "${download_base}/checksums.txt"
  checksum_line="$(grep " ${archive}$" "${TEMP_DIR}/checksums.txt" || true)"
  [[ -n "$checksum_line" ]] || fail "release checksums do not contain ${archive}"
  ( cd "$TEMP_DIR" && printf '%s\n' "$checksum_line" | sha256sum -c - )
  tar -xzf "${TEMP_DIR}/${archive}" -C "$TEMP_DIR"
  [[ -f "${TEMP_DIR}/ngstoned" ]] || fail "release archive did not contain ngstoned"
  install -o root -g root -m 0755 "${TEMP_DIR}/ngstoned" "$INSTALL_PATH"
}

check_dns() {
  local probe apex_records wildcard_records
  if [[ "$SKIP_DNS_CHECK" -eq 1 ]]; then
    warn "skipping DNS validation"
    return
  fi
  probe="ngstone-dns-check-$(date +%s).${DOMAIN}"
  apex_records="$(dig +short A "$DOMAIN"; dig +short AAAA "$DOMAIN")"
  wildcard_records="$(dig +short A "$probe"; dig +short AAAA "$probe")"
  [[ -n "${apex_records//[[:space:]]/}" ]] || fail "${DOMAIN} does not resolve yet; create an apex A/AAAA record or use --skip-dns-check"
  [[ -n "${wildcard_records//[[:space:]]/}" ]] || fail "*.${DOMAIN} does not resolve yet; create a wildcard A/AAAA record or use --skip-dns-check"
  info "DNS resolves for ${DOMAIN} and *.${DOMAIN}"
}

configure_firewall() {
  if [[ "$SKIP_FIREWALL" -eq 1 ]]; then
    warn "skipping UFW configuration; open SSH, 80/tcp, 443/tcp, and 4443/tcp manually"
    return
  fi
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow "${SSH_PORT}/tcp"
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow 4443/tcp
  ufw --force enable
  info "UFW allows SSH port ${SSH_PORT}, 80/tcp, 443/tcp, and 4443/tcp"
}

write_env() {
  local temporary
  install -d -o root -g root -m 0700 "$ENV_DIR"
  temporary="$(mktemp "${ENV_DIR}/.env.XXXXXX")"
  printf 'NGSTONE_TOKEN_SHA256=%s\n' "$TOKEN_HASH" > "$temporary"
  printf 'NGSTONE_CERT_EMAIL=%s\n' "$EMAIL" >> "$temporary"
  printf 'NGSTONE_CF_API_TOKEN=%s\n' "$CF_API_TOKEN" >> "$temporary"
  chown root:root "$temporary"
  chmod 600 "$temporary"
  mv -f "$temporary" "$ENV_PATH"
}

write_service() {
  local temporary
  temporary="$(mktemp "${SERVICE_PATH}.XXXXXX")"
  cat > "$temporary" <<'EOF'
[Unit]
Description=ngstoned edge server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/ngstoned/env
ExecStart=/usr/local/bin/ngstoned \
    -domain __NGSTONE_DOMAIN__ \
    -cert-email ${NGSTONE_CERT_EMAIL} \
    -acme-ca __NGSTONE_ACME_CA__ \
    -cert-storage ${STATE_DIRECTORY}/certs
Restart=always
RestartSec=2s

StateDirectory=ngstoned
StateDirectoryMode=0700

AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes

DynamicUser=yes

LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
  sed -i "s/__NGSTONE_DOMAIN__/${DOMAIN}/g; s/__NGSTONE_ACME_CA__/${ACME_CA}/g" "$temporary"
  chown root:root "$temporary"
  chmod 644 "$temporary"
  mv -f "$temporary" "$SERVICE_PATH"
}

start_service() {
  systemctl daemon-reload
  systemctl enable --now ngstoned
  if ! systemctl is-active --quiet ngstoned; then
    journalctl -u ngstoned -n 80 --no-pager >&2 || true
    fail "ngstoned did not start"
  fi
}

wait_for_health() {
  local attempt health
  for attempt in $(seq 1 60); do
    if health="$(curl -fsS http://127.0.0.1:4041/healthz 2>/dev/null)"; then
      printf '%s\n' "$health"
      return
    fi
    sleep 1
  done
  journalctl -u ngstoned -n 80 --no-pager >&2 || true
  fail "ngstoned started but its loopback health endpoint did not become ready"
}

info "checking DNS"
check_dns
info "installing edge binary"
install_binary
info "writing root-only secrets file"
write_env
info "installing hardened systemd unit"
write_service
info "configuring firewall"
configure_firewall
info "starting ngstoned"
start_service
wait_for_health

CONTROL_HOST="edge.${DOMAIN}"
printf '\nngstoned is running for %s using %s certificates.\n' "$DOMAIN" "$ACME_CA"
printf 'Health endpoint: http://127.0.0.1:4041/healthz\n'
if [[ -n "$AUTH_TOKEN" ]]; then
  printf '\nSave this auth token now; it is not written to the VPS:\n%s\n' "$AUTH_TOKEN"
  printf '\nLaptop setup:\n'
  printf "ngstone auth '%s' --server %s:4443 --server-name %s\n" "$AUTH_TOKEN" "$CONTROL_HOST" "$CONTROL_HOST"
  printf 'ngstone port 3000 --server %s:4443 --server-name %s --subdomain demo\n' "$CONTROL_HOST" "$CONTROL_HOST"
else
  printf '\nThe existing auth token hash was preserved. Use the original token on the laptop.\n'
fi
if [[ "$ACME_CA" == staging ]]; then
  printf '\nAfter staging health checks pass, rerun with --acme-ca production.\n'
fi
