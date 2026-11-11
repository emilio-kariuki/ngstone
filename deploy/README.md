# Deploying ngstoned

## Fast path (Ubuntu/Debian VPS)

Create the apex and wildcard DNS records first, then run the installer from a
fresh clone:

```
git clone https://github.com/emilio-kariuki/ngstone.git /opt/ngstone
cd /opt/ngstone
sudo ./deploy/install-edge.sh \
  --domain example.com \
  --email you@example.com \
  --dns-provider cloudflare \
  --acme-ca staging
```

The script prompts for the DNS provider credentials without echoing them
(see [DNS provider credentials](#dns-provider-credentials)). It downloads and
verifies both binaries, creates the root-only environment
file, installs the hardened systemd unit, configures UFW, checks DNS, starts
`ngstoned`, and prints the laptop command. Existing installs using the shared
token hash remain supported; fresh deployments use durable SQLite storage and
issue scoped credentials through the loopback management API. Set
`NGSTONE_DATABASE_URL` before running the installer to use PostgreSQL instead.
Use `--acme-ca staging` first if you are still validating DNS or the VPS.

Once the health output shows both certificates, rerun the installer with
`--acme-ca production`; the domain, provider, credentials and token are kept.

Other options: `--tcp-ports MIN-MAX` enables raw TCP tunnels and opens that
range in UFW (`--tcp-ports off` removes it), and `--from-source` builds
`ngstoned` and `ngstone` from the checkout with Go instead of downloading a release. A
release that predates a provider cannot use it; the installer checks this
before replacing the installed binary.

For a disposable VPS, the same installer can be fetched directly after
reviewing the script:

```
curl -fsSL https://raw.githubusercontent.com/emilio-kariuki/ngstone/main/deploy/install-edge.sh \
  | sudo bash -s -- --domain example.com --email you@example.com --acme-ca production
```

The installer supports Ubuntu and Debian. It does not create DNS records or
store the plaintext tunnel token on the VPS, so save the token it prints.
`sudo` drops variables exported in your shell, so pass credentials on the
command line (`sudo NGSTONE_CF_API_TOKEN=... ./deploy/install-edge.sh ...`)
when running non-interactively.

## Run with Docker

The `ghcr.io/emilio-kariuki/ngstoned` image (linux/amd64 and linux/arm64,
published for each release) runs the same edge on any host with Docker and
the Compose plugin. The [DNS records](#dns-records) and
[provider credentials](#dns-provider-credentials) are the same as for the
systemd install, and the host's firewall must allow `80`, `443` and `4443`
(plus any TCP tunnel range). The installer's UFW and DNS checks do not run,
so do those yourself.

Copy [`docker/compose.yaml`](docker/compose.yaml) and
[`docker/.env.example`](docker/.env.example) into a directory on the host,
rename the latter to `.env`, `chmod 600 .env`, and fill it in: domain, email,
`NGSTONE_DNS_PROVIDER` and that provider's variables, and
`NGSTONE_TOKEN_SHA256`. Then:

```
docker compose up -d
docker compose ps                  # STATUS turns "healthy" once both certificates load
docker compose logs -f ngstoned
docker compose exec ngstoned /ngstoned healthcheck   # exit 0 when /healthz is OK
```

Start with `NGSTONE_ACME_CA=staging`. Once the container is healthy, which
means both certificates loaded, set `NGSTONE_ACME_CA=production` in `.env`
and run `docker compose up -d` to recreate the container with the new flag.
The [staging -> production](#staging---production-promotion) notes apply
unchanged; certificates and the ACME account live in the `ngstoned-data`
volume at `/data/certs`. Upgrade with `docker compose pull && docker compose up -d`.

How the container differs from the systemd unit:

- **Ports.** The edge listens on unprivileged ports inside the container
  (`-http :8080`, `-public :8443`, `-control :4443`), so it needs no added
  capabilities, and Compose publishes them as the host's `80`, `443` and
  `4443`. The ops endpoint stays on the container's loopback,
  `127.0.0.1:4041`, where the image's `HEALTHCHECK` (`ngstoned healthcheck`)
  probes `/healthz`; it is not published. `/healthz` returns 503 until both
  certificates load, so the health check has a 3 minute start period.
- **Secrets.** `NGSTONE_TOKEN_SHA256` and the DNS credentials reach the edge
  only through `env_file: .env`, never through `command` flags, for the same
  reason as `EnvironmentFile=` below: the container's command line is visible
  to every user of the host through `ps`, but its environment is not.
- **Client addresses.** Docker's published ports forward with NAT and keep
  the client's source IP, so per-IP rate limits, `X-Forwarded-For` and
  `--allow-cidr` work without `-proxy-protocol`. The exception is IPv6 when
  the Compose network has no IPv6: Docker's userland proxy then accepts the
  connection and it appears to come from the bridge gateway. Enable IPv6 on
  the network, or serve only IPv4 (A records), if that matters.
- **Storage.** The image runs as the distroless `nonroot` user, uid and gid
  65532, and creates `/data` owned by it, so the named volume is writable. A
  bind mount in its place must be writable by that uid first, for example
  `sudo install -d -o 65532 -g 65532 -m 0700 /srv/ngstoned`.
- **Shutdown.** On SIGTERM the edge finishes in-flight requests and drains
  agent sessions for up to about 30 seconds, so the Compose file sets
  `stop_grace_period: 60s` instead of Docker's 10 seconds.
- **TCP tunnels.** Uncomment the `-tcp-ports` line and the matching `ports`
  range in `compose.yaml`; the published range must equal `-tcp-ports`
  exactly. Docker sets up forwarding per published port, so keep the range
  small.
- **Inter-edge forwarding.** Under Docker's bridge network the host's address
  cannot be bound inside the container. Set `NGSTONE_DATABASE_URL`,
  `NGSTONE_EDGE_ID` and `NGSTONE_PEER_ADDR` (the host's `ip:port` as the other
  edges reach it) in `.env`, and leave `NGSTONE_TOKEN_SHA256` empty: the
  legacy token cannot be combined with a database, so agents use scoped
  credentials (see the next bullet). Then uncomment the `-peer-listen=:4043`
  line and the `"4043:4043"` port in `compose.yaml`. The Compose file sets the
  `-peer-listen` flag, so the edge listens on `:4043` and still advertises
  `NGSTONE_PEER_ADDR`. Firewall the peer port to the other edges.
- **Management API.** The image has no `ngstone` CLI, so issue credentials from
  a machine that has it. The API is served on the ops endpoint, which stays on
  the container's loopback and is not reachable through a published port, and
  without `NGSTONE_ADMIN_TOKEN_SHA256` the API accepts loopback clients only.
  To reach it, set `NGSTONE_ADMIN_TOKEN_SHA256` in `.env` (generate the pair as
  in [Management API and CLI](#management-api-and-cli)), change `-ops` in
  `compose.yaml` to `-ops=:4041` (the health check still reaches it on the
  container's loopback), and publish `"127.0.0.1:4041:4041"`. Then, on the
  Docker host or through `ssh -L 4041:127.0.0.1:4041`:

  ```
  NGSTONE_ADMIN_TOKEN=<admin token> ngstone admin credentials issue \
    --server http://127.0.0.1:4041 --subdomain demo --ttl 24h
  ```

  The ops endpoint also serves pprof, expvar and metrics without
  authentication, so publish it on the host's loopback only, never on a public
  interface.

To build the image from a checkout instead of pulling it, replace `image:`
with the commented `build: ../..` in `compose.yaml`, or run
`docker build -t ngstoned .` at the repository root.

## Upgrading existing control-plane databases

Back up the database and stop every edge process before upgrading to schema
v4. Start all edges on the new binary; do not leave an older edge writing to
the migrated database. Migration runs automatically and moves tunnel, lease,
and policy ownership from credential IDs to their recorded owner principals.
Identical policies are merged, differing same-name policies are preserved
under unique names, and custom-domain associations retain their tunnel IDs.
Credentials without an owner retain their existing identity.

## Uninstalling

From the checkout on the VPS, remove the service, binary, and root-only
secrets with a confirmation prompt:

```
sudo ./deploy/uninstall.sh
```

The default uninstall removes both installed binaries and preserves the
certificate, ACME account, and default SQLite control-plane state under
`/var/lib/private/ngstoned` so a later reinstall can continue using it. To
remove that state as well, and remove matching public listener allow rules from
UFW, use the explicit destructive options:

```
sudo ./deploy/uninstall.sh --remove-state --remove-firewall-rules
```

`--remove-firewall-rules` removes matching allow rules for only `80/tcp`,
`443/tcp`, `4443/tcp` and the TCP tunnel range, if one was configured; it
leaves SSH rules alone. If another service
uses the same allow rule, review it before selecting this option. The source
checkout is never removed. Use `--yes` only when running the uninstall
non-interactively.

## DNS records

Two records in your zone, here `example.com`. On Cloudflare, DNS-only
records (grey cloud) are the simplest setup:

| Type        | Name            | Value               |
| ----------- | --------------- | ------------------- |
| A (or AAAA) | `example.com`   | the VPS's public IP |
| A (or AAAA) | `*.example.com` | the VPS's public IP |

The agent's default `--transport auto` first uses the raw control listener on
`:4443`, then falls back to the authenticated WebSocket control endpoint on
HTTPS `:443`. A proxied Cloudflare record can therefore support the fallback
when WebSockets are enabled, but DNS-only records remain the least surprising
setup and are required when forcing `--transport raw`.

## DNS provider credentials

Certificates are issued with the ACME DNS-01 challenge, so the edge needs an
API credential that can create TXT records in the zone. Choose the provider
with `-dns-provider` (default `cloudflare`). Credentials are read only from
the environment; `ngstoned -dns-provider help` lists every provider and the
variables it reads.

| `-dns-provider` | Variables |
| --- | --- |
| `cloudflare` | `NGSTONE_CF_API_TOKEN` |
| `route53` | `NGSTONE_AWS_REGION`, `NGSTONE_AWS_ACCESS_KEY_ID`, `NGSTONE_AWS_SECRET_ACCESS_KEY` |
| `digitalocean` | `NGSTONE_DO_API_TOKEN` |
| `hetzner` | `NGSTONE_HETZNER_API_TOKEN` |
| `vultr` | `NGSTONE_VULTR_API_KEY` |
| `ovh` | `NGSTONE_OVH_ENDPOINT`, `NGSTONE_OVH_APPLICATION_KEY`, `NGSTONE_OVH_APPLICATION_SECRET`, `NGSTONE_OVH_CONSUMER_KEY` |
| `desec` | `NGSTONE_DESEC_TOKEN` |
| `bunny` | `NGSTONE_BUNNY_API_KEY` |

Scope each credential as tightly as the provider allows:

- **Route 53:** an IAM user whose policy allows only
  `route53:ListHostedZonesByName`, `route53:ListResourceRecordSets`,
  `route53:ChangeResourceRecordSets` and `route53:GetChange`.
- **Hetzner:** a read and write API token of the Hetzner Console project that
  holds the zone. Zones still on the deprecated `dns.hetzner.com` must be
  migrated first.
- **Vultr:** allow only the VPS's IP in the API key's access control.
- **OVH:** a consumer key limited to `GET`, `POST` and `DELETE` on
  `/domain/zone/*`; the endpoint is `ovh-eu`, `ovh-ca` or `ovh-us`.
- **deSEC:** enforces a 3600 s minimum TTL and rate limits, so issuance can
  take a few minutes.

GoDaddy, Namecheap, Porkbun, IONOS, Azure, DNSimple and netcup are not
supported. Their libdns modules replace or delete every TXT value at a name,
and the apex and wildcard certificates publish two values at
`_acme-challenge.<domain>` at the same time, so one issuance would break the
other. Keep the registrar and move only DNS hosting to a supported provider
by changing the nameservers.

### Cloudflare token

Create a scoped token, not the Global API Key:

1. Cloudflare dashboard -> My Profile -> API Tokens -> Create Token -> Custom Token.
2. Permissions: `Zone` / `DNS` / `Edit`.
3. Zone Resources: `Include` / `Specific zone` / your zone only.
4. No other permissions, no other zones.

This token can create and delete `_acme-challenge` TXT records in the one zone and nothing else — it cannot read other zones, change nameservers, or touch account-level settings.

## Environment

Create `/etc/ngstoned/env` (mode 0600, owned by root, referenced by the unit's `EnvironmentFile=`). It holds the storage settings, ACME email and your DNS provider's variables. Durable SQLite storage is the default; this example uses Cloudflare:

```
NGSTONE_DATABASE_URL=sqlite:///var/lib/ngstoned/control.db
NGSTONE_EDGE_ID=edge-a
NGSTONE_CERT_EMAIL=<your email, required by Let's Encrypt>
NGSTONE_CF_API_TOKEN=<the scoped Cloudflare token above>
# Optional: SHA-256 hash of the management API bearer token
NGSTONE_ADMIN_TOKEN_SHA256=<64-character hex digest>
# Optional: browser management login and team RBAC
NGSTONE_OIDC_ISSUER=https://login.example.com/realms/ngstone
NGSTONE_OIDC_CLIENT_ID=ngstone-ops
NGSTONE_OIDC_CLIENT_SECRET=<provider client secret>
NGSTONE_OIDC_COOKIE_SECRET=<base64 secret from openssl rand -base64 32>
NGSTONE_OIDC_REDIRECT_URL=https://edge.example.com:4041/api/v1/auth/oidc/callback
NGSTONE_OIDC_GROUPS_CLAIM=groups
NGSTONE_OIDC_ADMIN_GROUPS=ngstone-admins
NGSTONE_OIDC_OPERATOR_GROUPS=ngstone-operators
NGSTONE_OIDC_VIEWER_GROUPS=ngstone-viewers
# Optional: restrict login and set an explicit fallback role
NGSTONE_OIDC_ALLOWED_EMAIL_DOMAINS=example.com
NGSTONE_OIDC_DEFAULT_ROLE=
# Optional: management API over mTLS with client certificates
# NGSTONE_ADMIN_MTLS_ADDR=:4044
# NGSTONE_ADMIN_MTLS_CLIENT_CA=/etc/ngstoned/admin-ca.pem
# Optional: lifecycle alert webhook
NGSTONE_ALERT_WEBHOOK_URL=https://alerts.example.com/ngstone
NGSTONE_ALERT_WEBHOOK_TOKEN=<webhook secret>
```

For multiple edge servers, use the same PostgreSQL URL on every server and a
different stable `NGSTONE_EDGE_ID` on each one:

```
NGSTONE_DATABASE_URL=postgres://ngstone:<password>@db.internal/ngstone?sslmode=require
NGSTONE_EDGE_ID=edge-b
```

To let any edge serve any tunnel, enable inter-edge forwarding. Add the edge's
private address and a peer port to the same root-only environment file on every
edge:

```
NGSTONE_PEER_ADDR=10.0.0.11:4043
```

Then open that port to the other edges only, for example:

```
sudo ufw allow from 10.0.0.0/24 to any port 4043 proto tcp
```

Forwarding requires PostgreSQL (not SQLite, not `-insecure`), a concrete
private address, a certificate for the same domain on every edge (share the
certificate storage to stay under the ACME duplicate-certificate limit), and
identical `NGSTONE_VISITOR_OIDC_*` values, including the cookie secret, on
every edge. Raw TCP tunnels are forwarded when every edge uses the same
`-tcp-ports` range: each edge opens the tunnel's port within about two seconds
and forwards to the owner, which enforces allow-CIDR with the real client
address (open the range in every edge's firewall). Share links are forwarded
for sharers using a `share` credential; custom domains are not forwarded. With Docker's bridge network, set `NGSTONE_PEER_LISTEN` (or
`-peer-listen`) to the address inside the container and publish that port; see
[Run with Docker](#run-with-docker). `NGSTONE_PEER_ADDR` stays the address the
other edges dial.

The peer port must be reachable only from other edges: it accepts at most 64
concurrent handshakes with a 5 second deadline and has no per-source limit.
Each edge needs a distinct `NGSTONE_EDGE_ID`; two edges with the same id
overwrite each other's registration. A forwarded connection holds one of the
client address's in-flight slots on the ingress edge for its lifetime and
closes after the TCP idle timeout (30 minutes by default) of silence in both
directions, so long-lived WebSocket and SSE connections need traffic or
keep-alives within that window. During a database outage, connections for
tunnel hostnames not bound on the receiving edge are closed, where a single
edge would answer 404.

Keep the PostgreSQL URL in the root-only environment file or a secret manager;
do not put it in `ExecStart`, because a password in a process argument is
visible through `ps`.

After `ngstoned` is running, issue a tunnel credential through the loopback
management API:

```
sudo /usr/local/bin/ngstone admin credentials issue \
  --server http://127.0.0.1:4041 --subdomain demo --ttl 24h
```

Copy the printed token to the laptop and run `ngstone auth '<token>'`. Use
`ngstone admin credentials list` and `ngstone admin credentials revoke` to
inspect or revoke credentials. The database stores only SHA-256 token hashes,
and a credential is limited to one exact HTTP subdomain, one exact TCP
remote port, or one edge-assigned preview hostname. For `ngstone preview`,
issue with `--kind preview --ttl 2h` and omit `--subdomain` / `--remote-port`.
The preview credential retains its assigned hostname across reconnects;
issue another credential for a new URL. For `ngstone share`, issue with
`--kind share --ttl 24h`; it takes no `--subdomain` / `--remote-port` and
manages only the shares of its owner.
The edge rechecks active credentials during the heartbeat, so
revocation and expiry close live sessions shortly afterward.

The file-backed credential mode remains available for existing installations:

```
NGSTONE_CREDENTIALS_FILE=/var/lib/private/ngstoned/credentials.json
```

Use it only as a compatibility path while migrating to the database-backed
store.

For a legacy deployment, `NGSTONE_TOKEN_SHA256=<sha256 of the shared agent auth token, hex>` remains accepted when `NGSTONE_CREDENTIALS_FILE` is absent. Generate that pair on the laptop with `token=$(openssl rand -base64 32)` and `printf %s "$token" | shasum -a 256 | cut -d' ' -f1`. The shared token is not independently revocable, so migrate it to scoped credentials when practical.

## Management API and CLI

The ops listener exposes a versioned management API at `/api/v1`. It is
loopback-only unless `NGSTONE_ADMIN_TOKEN_SHA256` is configured. Reach the
default listener from a workstation through SSH:

```
ssh -L 4041:127.0.0.1:4041 root@example.com
ngstone admin status
ngstone admin tunnels --json
ngstone admin observability --json
ngstone admin credentials issue --subdomain demo --ttl 24h
ngstone admin policies list
ngstone admin domains list
ngstone admin tunnel drain demo
```

The credential issue command prints the scoped token once. Revoke it later
with `ngstone admin credentials revoke <credential-id>`. The available API
resources are `GET /api/v1/status`, `GET /api/v1/tunnels`, `GET|POST
/api/v1/credentials`, `DELETE /api/v1/credentials/{id}`, `GET|POST
/api/v1/policies`, `DELETE /api/v1/policies/{id}`, `GET|POST
/api/v1/domains`, `DELETE /api/v1/domains/{id}`, and `POST
/api/v1/tunnels/{hostname}/drain`. Traffic policies are validated and stored
by digest; custom domains start in `pending` status until DNS and certificate
automation is attached. The API also exposes `GET
/api/v1/observability/tunnels` for per-tunnel request counts, approximate
p50/p95/p99 latency, status-code counts, connector health, reconnects, bytes,
and credential lifecycle counters. Configure `NGSTONE_ALERT_WEBHOOK_URL` to
receive lifecycle events for reconnects, lease loss, and expired or revoked
credentials; the optional webhook token is sent as a bearer header.

For private non-loopback access, generate a high-entropy bearer token, store
only its SHA-256 hash in `/etc/ngstoned/env`, and keep the plaintext in the
operator's environment:

```
ADMIN_TOKEN="$(openssl rand -base64 32)"
ADMIN_HASH="$(printf '%s' "$ADMIN_TOKEN" | shasum -a 256 | cut -d' ' -f1)"
printf '%s\n' "$ADMIN_TOKEN"   # save in the operator's secret store
printf '%s\n' "$ADMIN_HASH"    # put this value in NGSTONE_ADMIN_TOKEN_SHA256
export NGSTONE_ADMIN_TOKEN="$ADMIN_TOKEN"
```

The bearer token protects `/api/v1` only. Do not expose `-ops` directly to the
internet: the dashboard, `/api/state`, metrics, health, and pprof endpoints
remain separate. Use a private network or a TLS-authenticated proxy and
firewall when remote access is required.

### OIDC browser login and team roles

Register the exact `NGSTONE_OIDC_REDIRECT_URL` with the provider. Start the
edge with the OIDC variables in `/etc/ngstoned/env`, then print the login URL
from an operator workstation:

```
ngstone login --server https://edge.example.com:4041
# or
ngstone admin login --server https://edge.example.com:4041
```

The provider must return the configured group claim in userinfo. `admin` has
full management access, `operator` can change credentials, policies, domains,
and tunnel draining, and `viewer` is read-only. Group matches are evaluated in
admin/operator/viewer order. With an empty default role, users without a
configured group are rejected. Set `NGSTONE_OIDC_DEFAULT_ROLE=viewer` only when
that broad fallback is intentional.

OIDC sessions use encrypted, eight-hour cookies and PKCE. The edge validates
the signed ID token against the provider JWKS, including issuer, audience,
nonce, expiry, and subject consistency with userinfo. Browser mutations require
the session CSRF token. Keep the client secret and cookie secret in the
root-only environment file; do not put either in `ExecStart` or a shell
command-line argument. The management bearer token remains useful for CI and
other non-browser automation.

### mTLS team access

Set `NGSTONE_ADMIN_MTLS_ADDR` and `NGSTONE_ADMIN_MTLS_CLIENT_CA` together to
open a separate TLS listener for the management API. On that listener a client
certificate is the only authentication: bearer tokens, OIDC cookies, and the
loopback bypass do not apply, and nothing changes while both settings are
unset. The listener serves only the management API and dashboard state, not
metrics, health, or pprof. Every edge needs the same CA file.

An unauthenticated peer can still complete TCP connections and occupy the 32
connection slots. Open the port only to the networks your team uses, for
example with a firewall rule; the loopback ops port remains available as a
fallback.

Create a CA used only for ngstone management, then issue short-lived client
certificates from it:

```sh
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1825 -subj "/CN=ngstone management CA" -keyout admin-ca.key -out admin-ca.pem -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=alice/OU=operator" -keyout alice.key -out alice.csr
printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' > client.ext
openssl x509 -req -in alice.csr -CA admin-ca.pem -CAkey admin-ca.key -CAcreateserial -days 7 -extfile client.ext -out alice.pem
chmod 600 alice.key
ngstone admin status --server https://<apex-domain>:4044 --client-cert alice.pem --client-key alice.key
```

Copy `admin-ca.pem` (never the key) to `/etc/ngstoned/admin-ca.pem` on every
edge. Guidance:

- Keep `admin-ca.key` offline and use that CA only for ngstone.
- The role comes from `OU=admin`, `OU=operator`, or `OU=viewer`; a certificate
  without one of them is rejected, and the highest role wins if several are set.
- The `CN` becomes the audit and ownership principal `mtls:<cn>`. It must be
  lowercase `[a-z0-9._@-]`.
- Certificates must carry the clientAuth extended key usage and live at most
  30 days. Prefer 1-7 days, and never request exactly 720 h.
- There is no revocation list. To cut off every certificate at once, replace
  the CA file and restart every edge.
- The server certificate is the edge's apex certificate. To reach one edge by
  IP, pass `--server-name <apex-domain>`; use `--ca` to verify the server
  against a private bundle instead of the system roots.
- The client key must be readable only by its owner (`chmod 600`); the CLI
  refuses a group- or world-readable key.

Secrets must only ever reach `ngstoned` through `EnvironmentFile=`, never through `ExecStart` flags: `/proc/<pid>/cmdline` is world-readable, so any local user can read a flag value with `ps auxww`, but not the process's environment. `ngstoned` reads `$NGSTONE_CREDENTIALS_FILE`, the legacy `$NGSTONE_TOKEN_SHA256`, and `$NGSTONE_CF_API_TOKEN` in preference to their equivalent flags for exactly this reason, and other providers' credentials have no flags at all — do not add those flags to the unit's `ExecStart`. The agent has the same exposure: prefer `$NGSTONE_TOKEN` over `-token` whenever the agent runs somewhere another local user could run `ps`.

## Staging -> production promotion

`-acme-ca` defaults to `staging` and must stay that way until the whole pipeline (DNS, token, systemd unit) is verified working. Let's Encrypt staging certs are not trusted by browsers but exercise the exact same code path, so a mistake there costs nothing. Once `systemctl status ngstoned` shows both certificates loaded and `/healthz` (via `ssh -L 4041:127.0.0.1:4041`) reports sane `not_after` dates, flip the unit's `ExecStart` (or environment) to `-acme-ca production` and restart. Do **not** delete the staging-issued certs first: certmagic namespaces on-disk storage per issuer (`certificates/<issuer-key>/<domain>/`), so the staging and production certs live in separate subtrees and cannot collide or shadow one another — the new `-acme-ca production` config simply starts issuing (and serving) certs from its own subtree. Deleting the staging tree also deletes the ACME account key stored alongside it, which only forces an unnecessary re-registration; it buys nothing. Production Let's Encrypt has real rate limits (5 duplicate certs/week per exact name set) — do not bounce between staging and production repeatedly against the same names.

Do not add or upgrade a libdns DNS provider module without re-verifying its append and delete semantics first. Every supported provider appends TXT values without replacing others and deletes by record content, so the apex and wildcard certs' concurrent ACME challenges under `_acme-challenge.<domain>` don't clobber each other mid-renewal. A provider that deletes by name+type instead of by content would race the two challenges and could break renewal of both certs simultaneously.

## Installing the unit

```
sudo cp deploy/ngstoned.service /etc/systemd/system/ngstoned.service
sudo $EDITOR /etc/systemd/system/ngstoned.service   # set -domain, and -dns-provider if not Cloudflare
sudo mkdir -p /etc/ngstoned
sudo chmod 700 /etc/ngstoned
sudo $EDITOR /etc/ngstoned/env   # see above
sudo systemctl daemon-reload
sudo systemctl enable --now ngstoned
```

`StateDirectory=ngstoned` makes systemd create `/var/lib/private/ngstoned` (with a `/var/lib/ngstoned` symlink) and `chown` it to whichever dynamic UID/GID the service gets on that start, every start — the numeric UID itself is not guaranteed to stay the same across restarts, but the directory ownership is fixed up automatically each time so the service can always read and write it. This only works because `StateDirectory=` is used instead of a manual `ReadWritePaths=`; the latter gets no such ownership handling from systemd and would leave the cert cache unreadable by a freshly assigned dynamic user, silently losing it — and therefore burning a Let's Encrypt issuance — on every single restart. `AmbientCapabilities=CAP_NET_BIND_SERVICE` lets the otherwise-unprivileged dynamic user bind `:80`/`:443`.

## Behind a TCP proxy (PROXY protocol)

Skip this section if `ngstoned` owns `:443` directly. It applies only when something else terminates the inbound TCP connection first — typically Traefik doing TLS passthrough (`HostSNIRegexp` + `tls.passthrough`) so `ngstoned` can still terminate TLS itself.

Passthrough is not transparent at the TCP layer: Traefik accepts the browser's connection and opens a **new** one to `ngstoned`. Without extra configuration `conn.RemoteAddr()` on the public listener is Traefik's own address (on Docker, a private address such as `10.0.1.69`), which means every `X-Forwarded-For` the edge stamps is wrong, the local app cannot trust the forwarding headers, and the per-IP rate limiter buckets the entire internet into a single key — one abusive client either escapes limiting or locks everybody out.

The fix is the PROXY protocol: the proxy prefixes each connection with the original endpoints, and `ngstoned` uses them as the client address.

**Both sides must be changed together.** The edge rejects any connection to the public listener that does not begin with a valid PROXY header, and a proxy that sends one to a listener that is not expecting it produces a TLS handshake failure. Enabling one side alone breaks every public request.

On the edge, add `-proxy-protocol` to the unit's `ExecStart`:

```
ExecStart=/usr/local/bin/ngstoned -proxy-protocol ...
```

On Traefik, set `proxyProtocol.version = 2` on the **TCP service** that points at `ngstoned` (dynamic configuration, not the static file):

```yaml
tcp:
  routers:
    ngstoned:
      entryPoints:
        - websecure
      rule: "HostSNIRegexp(`^.+\\.ngstone\\.site$`)"
      tls:
        passthrough: true
      service: ngstoned
  services:
    ngstoned:
      loadBalancer:
        proxyProtocol:
          version: 2
        servers:
          - address: "ngstoned:443"
```

The equivalent Docker label is `traefik.tcp.services.ngstoned.loadbalancer.proxyprotocol.version=2`. Version 2 is Traefik's default when `proxyProtocol` is present at all; `ngstoned` also accepts the text-based version 1 for other proxies, and accepts the `LOCAL` command (used by health checks) by falling back to the real socket address.

**The public port must be reachable only from the proxy.** With `-proxy-protocol` on, whoever can open a TCP connection to that port chooses the client IP that the edge logs, stamps into `X-Forwarded-For`, and rate-limits on. Bind `ngstoned` to the proxy-facing interface only (`-public 127.0.0.1:443`, or a Docker network address) and make sure no firewall rule exposes it to the internet. Leaving the flag off — the default — preserves the previous behaviour exactly.

The flag applies to the public listener only. Do **not** put the control listener (`:4443`, where agents connect) behind a PROXY-protocol proxy; it does not parse the header and every agent connection would fail.

## Deploying a new build

```
make deploy DEPLOY_HOST=example.com DEPLOY_USER=root
```

Cross-compiles `linux/amd64`, copies the new `ngstoned` binary over, and restarts the unit. The agent binary (`ngstone`) ships to the laptop separately (`make cross` and copy `bin/linux_amd64/ngstone`, or `make build` for a macOS binary of the same source).

## Verifying

```
ssh -L 4041:127.0.0.1:4041 root@example.com
curl http://127.0.0.1:4041/healthz
```

The same SSH tunnel opens the local operations dashboard at
`http://127.0.0.1:4041/`. It shows routed tunnels, connector capacity,
certificate state, request counters, and recent in-memory edge events. Scrape
`http://127.0.0.1:4041/metrics` through that tunnel for Prometheus-compatible
global and per-tunnel metrics. The ops listener is read-only and must remain on loopback; do not
change it to a public address without putting a separately authenticated proxy
in front of it.

`/healthz` reports both certificates' `not_after` separately. A restart
(`systemctl restart ngstoned`, three times in a row) should show no new ACME
traffic in the logs — the certs load from the `StateDirectory` cache.
