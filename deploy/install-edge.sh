#!/usr/bin/env bash

set -Eeuo pipefail

REPOSITORY="emilio-kariuki/ngstone"
INSTALL_PATH="/usr/local/bin/ngstoned"
AGENT_INSTALL_PATH="/usr/local/bin/ngstone"
SERVICE_PATH="/etc/systemd/system/ngstoned.service"
ENV_DIR="/etc/ngstoned"
ENV_PATH="${ENV_DIR}/env"
VERSION="${NGSTONE_VERSION:-}"
DOMAIN="${NGSTONE_DOMAIN:-}"
EMAIL="${NGSTONE_CERT_EMAIL:-}"
CF_API_TOKEN="${NGSTONE_CF_API_TOKEN:-}"
ADMIN_TOKEN_HASH="${NGSTONE_ADMIN_TOKEN_SHA256:-}"
ADMIN_TOKEN="${NGSTONE_ADMIN_TOKEN:-}"
ALERT_WEBHOOK_URL="${NGSTONE_ALERT_WEBHOOK_URL:-}"
ALERT_WEBHOOK_TOKEN="${NGSTONE_ALERT_WEBHOOK_TOKEN:-}"
AUTH_TOKEN="${NGSTONE_AUTH_TOKEN:-}"
ACME_CA="${NGSTONE_ACME_CA:-}"
BINARY_PATH="${NGSTONE_EDGE_BINARY:-}"
AGENT_BINARY_PATH="${NGSTONE_AGENT_BINARY:-}"
SUBDOMAIN="${NGSTONE_SUBDOMAIN:-demo}"
CREDENTIAL_TTL="${NGSTONE_CREDENTIAL_TTL:-24h}"
CREDENTIALS_PATH="${NGSTONE_CREDENTIALS_FILE:-/var/lib/private/ngstoned/credentials.json}"
DATABASE_URL="${NGSTONE_DATABASE_URL:-sqlite:///var/lib/ngstoned/control.db}"
LEGACY_MODE=0
PRESERVE_SCOPED=0
INITIAL_TOKEN=""
INITIAL_CREDENTIAL_ID=""
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
  --agent-binary PATH       use a local ngstone binary with --binary
  --subdomain NAME          initial scoped credential subdomain (default: demo)
  --credential-ttl DURATION initial scoped credential lifetime (default: 24h)
  --skip-firewall           do not configure UFW
  --skip-dns-check          do not verify apex and wildcard DNS first
  -h, --help                show this help

The Cloudflare token is read from NGSTONE_CF_API_TOKEN or prompted for
without echoing it. Fresh installs issue a scoped credential automatically.
NGSTONE_AUTH_TOKEN and existing NGSTONE_TOKEN_SHA256 installations remain
available as a legacy shared-token migration path.
The management API stays loopback-only unless NGSTONE_ADMIN_TOKEN_SHA256 is set.
Fresh installs use SQLite at /var/lib/ngstoned/control.db. Set
NGSTONE_DATABASE_URL to a PostgreSQL URL to use PostgreSQL instead. Set
NGSTONE_ADMIN_TOKEN when also setting NGSTONE_ADMIN_TOKEN_SHA256 if the
installer should issue the first credential through the authenticated API.
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
  --agent-binary)
    [[ $# -ge 2 ]] || fail "--agent-binary requires a path"
    AGENT_BINARY_PATH="$2"
    shift 2
    ;;
  --subdomain)
    [[ $# -ge 2 ]] || fail "--subdomain requires a value"
    SUBDOMAIN="$2"
    shift 2
    ;;
  --credential-ttl)
    [[ $# -ge 2 ]] || fail "--credential-ttl requires a duration"
    CREDENTIAL_TTL="$2"
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

for command_name in awk curl dig dirname install openssl runuser sha256sum stat systemctl tar; do
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
EXISTING_CREDENTIALS_FILE="$(get_env_value NGSTONE_CREDENTIALS_FILE)"
EXISTING_ADMIN_TOKEN_HASH="$(get_env_value NGSTONE_ADMIN_TOKEN_SHA256)"
EXISTING_ALERT_WEBHOOK_URL="$(get_env_value NGSTONE_ALERT_WEBHOOK_URL)"
EXISTING_ALERT_WEBHOOK_TOKEN="$(get_env_value NGSTONE_ALERT_WEBHOOK_TOKEN)"
EXISTING_DATABASE_URL="$(get_env_value NGSTONE_DATABASE_URL)"
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
if [[ -z "$ALERT_WEBHOOK_URL" ]]; then
  ALERT_WEBHOOK_URL="$EXISTING_ALERT_WEBHOOK_URL"
fi
if [[ -z "$ALERT_WEBHOOK_TOKEN" ]]; then
  ALERT_WEBHOOK_TOKEN="$EXISTING_ALERT_WEBHOOK_TOKEN"
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

if [[ -n "$EXISTING_CREDENTIALS_FILE" && -z "${NGSTONE_CREDENTIALS_FILE:-}" ]]; then
  CREDENTIALS_PATH="$EXISTING_CREDENTIALS_FILE"
fi
if [[ -z "$ADMIN_TOKEN_HASH" ]]; then
  ADMIN_TOKEN_HASH="$EXISTING_ADMIN_TOKEN_HASH"
fi
if [[ -z "${NGSTONE_DATABASE_URL:-}" && -n "$EXISTING_DATABASE_URL" ]]; then
  DATABASE_URL="$EXISTING_DATABASE_URL"
fi
if [[ -n "$EXISTING_CREDENTIALS_FILE" && -f "$CREDENTIALS_PATH" ]]; then
  PRESERVE_SCOPED=1
fi

case "$CREDENTIALS_PATH" in
/*)
  ;;
*)
  fail "NGSTONE_CREDENTIALS_FILE must be an absolute path"
  ;;
esac

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
if [[ -n "$ADMIN_TOKEN_HASH" && ! "$ADMIN_TOKEN_HASH" =~ ^[0-9a-fA-F]{64}$ ]]; then
  fail "NGSTONE_ADMIN_TOKEN_SHA256 must be a 64-character hex digest"
fi
if [[ -n "$ADMIN_TOKEN" ]]; then
  computed_admin_hash="$(printf '%s' "$ADMIN_TOKEN" | sha256sum | awk '{print $1}')"
  if [[ -n "$ADMIN_TOKEN_HASH" && "${ADMIN_TOKEN_HASH,,}" != "$computed_admin_hash" ]]; then
    fail "NGSTONE_ADMIN_TOKEN does not match NGSTONE_ADMIN_TOKEN_SHA256"
  fi
  ADMIN_TOKEN_HASH="$computed_admin_hash"
fi
if [[ "$DATABASE_URL" == *$'\n'* || "$DATABASE_URL" == *$'\r'* ]]; then
  fail "NGSTONE_DATABASE_URL must not contain newlines"
fi

if [[ -n "$AUTH_TOKEN" ]]; then
  LEGACY_MODE=1
  TOKEN_HASH="$(printf '%s' "$AUTH_TOKEN" | sha256sum | awk '{print $1}')"
elif [[ -n "$EXISTING_CREDENTIALS_FILE" || -n "${NGSTONE_CREDENTIALS_FILE:-}" ]]; then
  LEGACY_MODE=0
elif [[ -n "$EXISTING_HASH" ]]; then
  LEGACY_MODE=1
  TOKEN_HASH="$EXISTING_HASH"
  if [[ ! "$TOKEN_HASH" =~ ^[0-9a-fA-F]{64}$ ]]; then
    fail "existing NGSTONE_TOKEN_SHA256 is not a 64-character hex digest"
  fi
else
  LEGACY_MODE=0
fi

resolve_version() {
  local latest
  latest="$(curl -fsSL "https://api.github.com/repos/${REPOSITORY}/releases/latest" | awk -F'"' '/"tag_name"/ { print $4; exit }')"
  [[ -n "$latest" ]] || fail "could not resolve the latest ngstone release"
  printf '%s' "$latest"
}

install_binary() {
  local architecture archive checksum_line download_base local_agent
  if [[ -n "$BINARY_PATH" ]]; then
    [[ -f "$BINARY_PATH" ]] || fail "edge binary not found: $BINARY_PATH"
    install -o root -g root -m 0755 "$BINARY_PATH" "$INSTALL_PATH"
    if [[ -n "$AGENT_BINARY_PATH" ]]; then
      [[ -f "$AGENT_BINARY_PATH" ]] || fail "agent binary not found: $AGENT_BINARY_PATH"
      install -o root -g root -m 0755 "$AGENT_BINARY_PATH" "$AGENT_INSTALL_PATH"
    else
      local_agent="$(dirname "$BINARY_PATH")/ngstone"
      if [[ -f "$local_agent" ]]; then
        install -o root -g root -m 0755 "$local_agent" "$AGENT_INSTALL_PATH"
      elif [[ "$LEGACY_MODE" -eq 0 ]]; then
        fail "fresh scoped installs need --agent-binary or a ngstone binary next to the ngstoned binary"
      fi
    fi
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
  [[ -f "${TEMP_DIR}/ngstone" ]] || fail "release archive did not contain ngstone"
  install -o root -g root -m 0755 "${TEMP_DIR}/ngstoned" "$INSTALL_PATH"
  install -o root -g root -m 0755 "${TEMP_DIR}/ngstone" "$AGENT_INSTALL_PATH"
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
  if [[ "$LEGACY_MODE" -eq 1 ]]; then
    printf 'NGSTONE_TOKEN_SHA256=%s\n' "$TOKEN_HASH" > "$temporary"
  elif [[ "$PRESERVE_SCOPED" -eq 1 ]]; then
    printf 'NGSTONE_CREDENTIALS_FILE=%s\n' "$CREDENTIALS_PATH" > "$temporary"
  else
    printf 'NGSTONE_DATABASE_URL=%s\n' "$DATABASE_URL" > "$temporary"
  fi
  if [[ -n "$ADMIN_TOKEN_HASH" ]]; then
    printf 'NGSTONE_ADMIN_TOKEN_SHA256=%s\n' "$ADMIN_TOKEN_HASH" >> "$temporary"
  fi
  if [[ -n "$ALERT_WEBHOOK_URL" ]]; then
    printf 'NGSTONE_ALERT_WEBHOOK_URL=%s\n' "$ALERT_WEBHOOK_URL" >> "$temporary"
  fi
  if [[ -n "$ALERT_WEBHOOK_TOKEN" ]]; then
    printf 'NGSTONE_ALERT_WEBHOOK_TOKEN=%s\n' "$ALERT_WEBHOOK_TOKEN" >> "$temporary"
  fi
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

issue_scoped_credential() {
  local issue_output
  if [[ "$LEGACY_MODE" -eq 1 || "$PRESERVE_SCOPED" -eq 1 ]]; then
    return
  fi
  [[ -x "$AGENT_INSTALL_PATH" ]] || fail "the ngstone agent binary is required to issue the initial scoped credential"
  if [[ -n "$ADMIN_TOKEN_HASH" && -z "$ADMIN_TOKEN" ]]; then
    warn "NGSTONE_ADMIN_TOKEN_SHA256 is configured without NGSTONE_ADMIN_TOKEN; the initial credential was not issued. Run ngstone admin credentials issue with the bearer token after installation."
    return
  fi
  if [[ -n "$ADMIN_TOKEN" ]]; then
    issue_output="$($AGENT_INSTALL_PATH admin credentials issue --server http://127.0.0.1:4041 --token "$ADMIN_TOKEN" --subdomain "$SUBDOMAIN" --ttl "$CREDENTIAL_TTL" --json)" || fail "could not issue the initial scoped credential"
  else
    issue_output="$($AGENT_INSTALL_PATH admin credentials issue --server http://127.0.0.1:4041 --subdomain "$SUBDOMAIN" --ttl "$CREDENTIAL_TTL" --json)" || fail "could not issue the initial scoped credential"
  fi
  INITIAL_TOKEN="$(printf '%s\n' "$issue_output" | awk -F'"' '$2 == "token" { print $4; exit }')"
  INITIAL_CREDENTIAL_ID="$(printf '%s\n' "$issue_output" | awk -F'"' '$2 == "id" { print $4; exit }')"
  [[ -n "$INITIAL_TOKEN" && -n "$INITIAL_CREDENTIAL_ID" ]] || fail "the credential command returned no usable token"
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
info "issuing scoped tunnel credential"
issue_scoped_credential

CONTROL_HOST="edge.${DOMAIN}"
printf '\nngstoned is running for %s using %s certificates.\n' "$DOMAIN" "$ACME_CA"
printf 'Health endpoint: http://127.0.0.1:4041/healthz\n'
if [[ -n "$INITIAL_TOKEN" ]]; then
  printf '\nSave this scoped auth token now; it is not written to the VPS:\n%s\n' "$INITIAL_TOKEN"
  printf '\nCredential ID: %s\n' "$INITIAL_CREDENTIAL_ID"
  printf '\nLaptop setup:\n'
  printf "ngstone auth '%s' --server %s:4443 --server-name %s\n" "$INITIAL_TOKEN" "$CONTROL_HOST" "$CONTROL_HOST"
  printf 'ngstone port 3000 --server %s:4443 --server-name %s --subdomain %s\n' "$CONTROL_HOST" "$CONTROL_HOST" "$SUBDOMAIN"
elif [[ -n "$AUTH_TOKEN" ]]; then
  printf '\nSave this auth token now; it is not written to the VPS:\n%s\n' "$AUTH_TOKEN"
  printf '\nLaptop setup:\n'
  printf "ngstone auth '%s' --server %s:4443 --server-name %s\n" "$AUTH_TOKEN" "$CONTROL_HOST" "$CONTROL_HOST"
  printf 'ngstone port 3000 --server %s:4443 --server-name %s --subdomain demo\n' "$CONTROL_HOST" "$CONTROL_HOST"
else
  if [[ "$LEGACY_MODE" -eq 1 ]]; then
    printf '\nThe existing auth token hash was preserved. Use the original token on the laptop.\n'
  elif [[ "$PRESERVE_SCOPED" -eq 0 ]]; then
    printf '\nDurable control-plane storage is ready. Use the management API to issue a scoped credential:\n'
    printf 'ngstone admin credentials issue --server http://127.0.0.1:4041 --subdomain %s --ttl %s\n' "$SUBDOMAIN" "$CREDENTIAL_TTL"
  else
    printf '\nThe existing scoped credential file was preserved. Use its existing token on the laptop.\n'
  fi
fi
if [[ "$ACME_CA" == staging ]]; then
  printf '\nAfter staging health checks pass, rerun with --acme-ca production.\n'
fi
