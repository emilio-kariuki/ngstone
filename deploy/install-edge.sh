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
DNS_PROVIDER="${NGSTONE_DNS_PROVIDER:-}"
TCP_PORTS="${NGSTONE_TCP_PORTS:-}"
AUTH_TOKEN="${NGSTONE_AUTH_TOKEN:-}"
ACME_CA="${NGSTONE_ACME_CA:-}"
BINARY_PATH="${NGSTONE_EDGE_BINARY:-}"
SSH_PORT="${NGSTONE_SSH_PORT:-22}"
SKIP_FIREWALL=0
SKIP_DNS_CHECK=0
FROM_SOURCE=0
TEMP_DIR=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"

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

# dns-providers:begin
# One line per provider: name, then each credential as VAR:secret or
# VAR:plain. Keep in sync with internal/edge/dnsprovider.go (a Go test
# checks this table against it).
DNS_PROVIDER_TABLE='
cloudflare NGSTONE_CF_API_TOKEN:secret
route53 NGSTONE_AWS_REGION:plain NGSTONE_AWS_ACCESS_KEY_ID:plain NGSTONE_AWS_SECRET_ACCESS_KEY:secret
digitalocean NGSTONE_DO_API_TOKEN:secret
hetzner NGSTONE_HETZNER_API_TOKEN:secret
vultr NGSTONE_VULTR_API_KEY:secret
ovh NGSTONE_OVH_ENDPOINT:plain NGSTONE_OVH_APPLICATION_KEY:plain NGSTONE_OVH_APPLICATION_SECRET:secret NGSTONE_OVH_CONSUMER_KEY:secret
desec NGSTONE_DESEC_TOKEN:secret
bunny NGSTONE_BUNNY_API_KEY:secret
'
# dns-providers:end

provider_credentials() {
  local name="$1" line
  while read -r line; do
    [[ -n "$line" ]] || continue
    if [[ "${line%% *}" == "$name" ]]; then
      printf '%s\n' "${line#* }"
      return 0
    fi
  done <<<"$DNS_PROVIDER_TABLE"
  return 1
}

provider_names() {
  awk 'NF { print $1 }' <<<"$DNS_PROVIDER_TABLE" | paste -sd ' ' -
}

usage() {
  local help_lines line
  help_lines="$(while read -r line; do
    [[ -n "$line" ]] || continue
    printf '  %-14s' "${line%% *}"
    for credential in ${line#* }; do printf ' %s' "${credential%%:*}"; done
    printf '\n'
  done <<<"$DNS_PROVIDER_TABLE")"
  cat <<'EOF' | awk -v help="$help_lines" '{ if ($0 == "__NGSTONE_PROVIDER_HELP__") print help; else print }'
Usage: install-edge.sh [options]

Options:
  --domain DOMAIN           public base domain
  --email ADDRESS           Let's Encrypt account email
  --dns-provider NAME       DNS host for certificate challenges (default: cloudflare)
  --tcp-ports MIN-MAX       enable raw TCP tunnels on this port range; "off" disables
  --version VERSION         release version, for example v0.3.2
  --from-source             build ngstoned from this checkout (needs Go) instead of downloading
  --acme-ca staging|production
  --ssh-port PORT           SSH port to preserve in UFW (default: 22)
  --binary PATH             use a local ngstoned binary instead of downloading
  --skip-firewall           do not configure UFW
  --skip-dns-check          do not verify apex and wildcard DNS first
  -h, --help                show this help

DNS providers and the credentials each needs:
__NGSTONE_PROVIDER_HELP__
Credentials are read from the environment variables above or prompted for
without echoing them, and are stored only in the root-only /etc/ngstoned/env.
The auth token is generated automatically unless NGSTONE_AUTH_TOKEN is
provided or an existing installation is detected.
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
  --dns-provider)
    [[ $# -ge 2 ]] || fail "--dns-provider requires a value; one of: $(provider_names)"
    DNS_PROVIDER="$2"
    shift 2
    ;;
  --tcp-ports)
    [[ $# -ge 2 ]] || fail "--tcp-ports requires MIN-MAX or off"
    TCP_PORTS="$2"
    shift 2
    ;;
  --from-source)
    FROM_SOURCE=1
    shift
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

# Read ID in a subshell: /etc/os-release also defines VERSION, which would
# clobber the --version / NGSTONE_VERSION value this script relies on.
DISTRO_ID="$(. /etc/os-release && printf '%s' "${ID:-}")"
case "$DISTRO_ID" in
ubuntu|debian)
  ;;
*)
  fail "the edge installer currently supports Ubuntu and Debian; detected ${DISTRO_ID:-unknown}"
  ;;
esac

if command -v apt-get >/dev/null 2>&1; then
  info "installing host dependencies"
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl dnsutils openssl ufw
fi

for command_name in awk curl dig install openssl paste sha256sum systemctl tar; do
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
EXISTING_EMAIL="$(get_env_value NGSTONE_CERT_EMAIL)"
EXISTING_DOMAIN="$(get_service_value -domain)"
EXISTING_ACME_CA="$(get_service_value -acme-ca)"
EXISTING_DNS_PROVIDER="$(get_service_value -dns-provider)"
EXISTING_TCP_PORTS="$(get_service_value -tcp-ports)"
if [[ -z "$EXISTING_DNS_PROVIDER" && -f "$SERVICE_PATH" ]]; then
  EXISTING_DNS_PROVIDER=cloudflare
fi

# On a rerun, keep the existing domain and email unless new ones are given.
DOMAIN="${DOMAIN:-$EXISTING_DOMAIN}"
EMAIL="${EMAIL:-$EXISTING_EMAIL}"
if [[ -z "$DOMAIN" ]]; then
  prompt_value "Public domain" "" DOMAIN
fi
if [[ -z "$EMAIL" ]]; then
  prompt_value "Let's Encrypt email" "" EMAIL
fi
if [[ -z "$DNS_PROVIDER" ]]; then
  DNS_PROVIDER="${EXISTING_DNS_PROVIDER:-cloudflare}"
fi
DNS_PROVIDER="${DNS_PROVIDER,,}"
PROVIDER_CREDENTIALS="$(provider_credentials "$DNS_PROVIDER")" \
  || fail "unsupported DNS provider: ${DNS_PROVIDER}; supported: $(provider_names)"

# Each credential comes from the environment, then the existing env file
# (only when the provider is unchanged), then an interactive prompt.
declare -A CREDENTIAL_VALUES=()
for credential in $PROVIDER_CREDENTIALS; do
  credential_name="${credential%%:*}"
  credential_kind="${credential#*:}"
  value="${!credential_name:-}"
  if [[ -z "$value" && "$DNS_PROVIDER" == "$EXISTING_DNS_PROVIDER" ]]; then
    value="$(get_env_value "$credential_name")"
  fi
  if [[ -z "$value" ]]; then
    [[ -t 3 ]] || fail "${credential_name} is required for --dns-provider ${DNS_PROVIDER}; set it in the environment when running non-interactively"
    if [[ "$credential_kind" == secret ]]; then
      prompt_secret "${DNS_PROVIDER} credential ${credential_name}: " value
    else
      prompt_value "${DNS_PROVIDER} credential ${credential_name}" "" value
    fi
  fi
  [[ -n "$value" ]] || fail "${credential_name} is required for --dns-provider ${DNS_PROVIDER}"
  [[ "$value" != *$'\n'* ]] || fail "${credential_name} must be a single line"
  CREDENTIAL_VALUES["$credential_name"]="$value"
done

if [[ -z "$TCP_PORTS" ]]; then
  TCP_PORTS="$EXISTING_TCP_PORTS"
fi
if [[ "${TCP_PORTS,,}" == off ]]; then
  TCP_PORTS=""
fi
if [[ -n "$TCP_PORTS" ]]; then
  [[ "$TCP_PORTS" =~ ^([0-9]+)-([0-9]+)$ ]] || fail "--tcp-ports must look like 10000-10100"
  TCP_LO="${BASH_REMATCH[1]}"
  TCP_HI="${BASH_REMATCH[2]}"
  if ((TCP_LO < 1024 || TCP_HI > 65535 || TCP_LO > TCP_HI)); then
    fail "--tcp-ports must be an ascending range within 1024-65535"
  fi
  if ((TCP_LO <= 4443 && 4443 <= TCP_HI)); then
    fail "--tcp-ports must not include the control port 4443"
  fi
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

build_from_source() {
  local repo_root build_version
  repo_root="$(cd "${SCRIPT_DIR}/.." 2>/dev/null && pwd || true)"
  [[ -n "$repo_root" && -f "${repo_root}/go.mod" && -d "${repo_root}/cmd/ngstoned" ]] \
    || fail "--from-source must be run from a clone of the repository (deploy/install-edge.sh)"
  command -v go >/dev/null 2>&1 || fail "--from-source needs Go; install it from https://go.dev/dl/ first"
  TEMP_DIR="$(mktemp -d)"
  build_version="$(git -C "$repo_root" describe --tags --always --dirty 2>/dev/null || echo dev)"
  info "building ngstoned ${build_version} from ${repo_root}"
  ( cd "$repo_root" && CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X ngstone/internal/version.Version=${build_version}" \
      -o "${TEMP_DIR}/ngstoned" ./cmd/ngstoned )
  BINARY_PATH="${TEMP_DIR}/ngstoned"
}

# Checked before the binary replaces the installed one, so a rerun with an
# unsupported provider leaves a working installation untouched.
check_binary_supports_provider() {
  local candidate="$1"
  if [[ "$DNS_PROVIDER" == cloudflare ]]; then
    return
  fi
  if ! "$candidate" -dns-provider help 2>/dev/null | awk '{ print $1 }' | grep -qx "$DNS_PROVIDER"; then
    fail "this ngstoned build does not support --dns-provider ${DNS_PROVIDER}; use --from-source or a newer --version"
  fi
}

install_binary() {
  local architecture archive checksum_line download_base
  if [[ "$FROM_SOURCE" -eq 1 && -z "$BINARY_PATH" ]]; then
    build_from_source
  fi
  if [[ -n "$BINARY_PATH" ]]; then
    [[ -f "$BINARY_PATH" ]] || fail "edge binary not found: $BINARY_PATH"
    check_binary_supports_provider "$BINARY_PATH"
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
  check_binary_supports_provider "${TEMP_DIR}/ngstoned"
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
    warn "skipping UFW configuration; open SSH, 80/tcp, 443/tcp, and 4443/tcp${TCP_PORTS:+, and ${TCP_PORTS}/tcp} manually"
    return
  fi
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow "${SSH_PORT}/tcp"
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow 4443/tcp
  if [[ -n "$TCP_PORTS" ]]; then
    ufw allow "${TCP_LO}:${TCP_HI}/tcp"
  fi
  ufw --force enable
  info "UFW allows SSH port ${SSH_PORT}, 80/tcp, 443/tcp, and 4443/tcp${TCP_PORTS:+, and ${TCP_LO}-${TCP_HI}/tcp for TCP tunnels}"
}

write_env() {
  local temporary
  install -d -o root -g root -m 0700 "$ENV_DIR"
  temporary="$(mktemp "${ENV_DIR}/.env.XXXXXX")"
  printf 'NGSTONE_TOKEN_SHA256=%s\n' "$TOKEN_HASH" > "$temporary"
  printf 'NGSTONE_CERT_EMAIL=%s\n' "$EMAIL" >> "$temporary"
  for credential_name in "${!CREDENTIAL_VALUES[@]}"; do
    printf '%s=%s\n' "$credential_name" "${CREDENTIAL_VALUES[$credential_name]}" >> "$temporary"
  done
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
    __NGSTONE_DNS_PROVIDER_LINE__ \
    __NGSTONE_TCP_PORTS_LINE__ \
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
  # Omit -dns-provider for cloudflare so the unit also works with releases
  # that predate the flag.
  if [[ "$DNS_PROVIDER" == cloudflare ]]; then
    sed -i '/__NGSTONE_DNS_PROVIDER_LINE__/d' "$temporary"
  else
    sed -i "s/__NGSTONE_DNS_PROVIDER_LINE__/-dns-provider ${DNS_PROVIDER}/" "$temporary"
  fi
  if [[ -n "$TCP_PORTS" ]]; then
    sed -i "s/__NGSTONE_TCP_PORTS_LINE__/-tcp-ports ${TCP_PORTS}/" "$temporary"
  else
    sed -i '/__NGSTONE_TCP_PORTS_LINE__/d' "$temporary"
  fi
  chown root:root "$temporary"
  chmod 644 "$temporary"
  mv -f "$temporary" "$SERVICE_PATH"
}

start_service() {
  systemctl daemon-reload
  systemctl enable ngstoned
  # restart, not start: on a re-run the service is already active and
  # "enable --now" would leave the old binary, unit and env in place.
  systemctl restart ngstoned
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

# The control port serves the apex certificate, so agents connect to the
# bare domain.
CONTROL_HOST="${DOMAIN}"
printf '\nngstoned is running for %s using %s certificates (DNS: %s).\n' "$DOMAIN" "$ACME_CA" "$DNS_PROVIDER"
printf 'Health endpoint: http://127.0.0.1:4041/healthz\n'
if [[ -n "$AUTH_TOKEN" ]]; then
  printf '\nSave this auth token now; it is not written to the VPS:\n%s\n' "$AUTH_TOKEN"
  printf '\nLaptop setup:\n'
  printf "ngstone auth '%s' --server %s:4443 --server-name %s\n" "$AUTH_TOKEN" "$CONTROL_HOST" "$CONTROL_HOST"
  printf 'ngstone port 3000 --server %s:4443 --server-name %s --subdomain demo\n' "$CONTROL_HOST" "$CONTROL_HOST"
else
  printf '\nThe existing auth token hash was preserved. Use the original token on the laptop.\n'
fi
if [[ -n "$TCP_PORTS" ]]; then
  printf 'TCP tunnels: ngstone tcp 5432 --server %s:4443 --server-name %s\n' "$CONTROL_HOST" "$CONTROL_HOST"
fi
if [[ "$ACME_CA" == staging ]]; then
  printf '\nStaging certificates are not trusted by browsers or the ngstone agent.\n'
  printf 'After the health check above shows both certificates, rerun with --acme-ca production.\n'
fi
