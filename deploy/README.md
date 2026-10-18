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
# Optional: lifecycle alert webhook
NGSTONE_ALERT_WEBHOOK_URL=https://alerts.example.com/ngstone
NGSTONE_ALERT_WEBHOOK_TOKEN=<webhook secret>
# Optional: screen-sharing TURN fallback. The shared secret must match
# coturn's static-auth-secret and is read only from this root-owned file.
NGSTONE_SCREEN_TURN_URLS=turn:turn.example.com:3478?transport=udp,turns:turn.example.com:5349
NGSTONE_SCREEN_TURN_SHARED_SECRET=<coturn-rest-auth-secret>
NGSTONE_SCREEN_MAX_VIEWERS=8
```

For multiple edge servers, use the same PostgreSQL URL on every server and a
different stable `NGSTONE_EDGE_ID` on each one:

```
NGSTONE_DATABASE_URL=postgres://ngstone:<password>@db.internal/ngstone?sslmode=require
NGSTONE_EDGE_ID=edge-b
```

The shared database coordinates names and leases, but public request routing
is still local to the edge that receives the request. Use a load balancer or
DNS strategy that targets the edge holding the connector; inter-edge request
forwarding is a later layer.

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
issue another credential for a new URL.
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
ngstone admin screens create --name demo-screen --ttl 30m --max-viewers 4
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

Screen sessions are direct sender-to-viewer WebRTC by default. `--max-viewers
N` with `N > 1` enables the edge SFU, which forwards the encoded RTP track to
each viewer. TURN is supplied by coturn or another external TURN service; the
edge derives short-lived REST credentials and delivers them only over the
authenticated screen signaling WebSocket. Open coturn's UDP/TCP and TLS ports
in the VPS firewall as well as the normal ngstone ports. See
`docs/PRODUCTION-SCREENCAST.md` for a full coturn setup guide, the exact
ports and env vars, and a verification procedure that proves the TURN relay
path actually works before you ship it.

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
