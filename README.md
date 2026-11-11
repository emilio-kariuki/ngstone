# ngstone

A personal, self-hosted alternative to ngrok. You run the edge (`ngstoned`) on
your own VPS, and the agent (`ngstone`) on your laptop or wherever your app
lives. The agent dials out to your edge and exposes a local port at
`https://<subdomain>.yourdomain.com`.

There's no multi-tenant SaaS behind this — it's a two-binary system built for
one operator running their own domain and their own VPS.

## Status

ngstone handles both **HTTP/HTTPS tunnels** and **raw TCP tunnels** end to
end, with real TLS (via certmagic + DNS-01), per-IP rate limiting, in-flight
caps, and graceful reconnect/takeover semantics. WebSocket upgrades and SSE
streams are proxied end to end with immediate flushing — covered by the same
e2e suite as plain HTTP/HTTPS traffic — and show up live in the terminal
inspector at connect time. A long-lived connection is bounded by its own
upgrade budget separate from the regular request-concurrency caps: once it's
exhausted, a new upgrade is rejected outright with `503` instead of silently
starving ordinary requests behind it. `ngstone port` opens a terminal request
inspector — a full-screen dashboard with a live request list, headers/body
detail pane, and replay — with no web UI and no `localhost:4040` involved.
Project mode (`ngstone up`) starts several tunnels from one checked-in JSON
file, while TTLs, edge-enforced traffic policies, JSON Lines status output, and
HAR export make it practical to use in scripts and CI.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design doc,
including the milestone-by-milestone build order and what "done" means for
each one.

## Quick start (agent)

Install the agent binary:

```
brew install emilio-kariuki/tap/ngstone
# or
curl -fsSL https://raw.githubusercontent.com/emilio-kariuki/ngstone/main/install.sh | sh
```

(The short `brew install ngstone` works too, but only after
`brew tap emilio-kariuki/tap && brew trust emilio-kariuki/tap` — Homebrew 6
requires explicitly trusting third-party taps first.)

Authenticate against your edge, then expose a local port:

```
ngstone auth <token>
ngstone port 3000
ngstone port 3000 --subdomain demo   # request a specific name instead of a random one
ngstone port 3000 --host-header demo.localhost:3000
ngstone port 3000 --subdomain demo --multi-connector  # join a load-balanced connector pool
ngstone preview 3000 --ttl 30m    # disposable, server-assigned preview URL
```

To share a folder of files without running a web server first:

```
ngstone serve ./dist --subdomain demo
ngstone serve ./dist --spa          # serve index.html for client-side routes
```

By default, the local app receives the public tunnel hostname in `Host`. Use
`--host-header` when it expects a tenant-specific local hostname; the public
hostname remains available in `X-Forwarded-Host`.

### Several tunnels at once

Describe your tunnels in `ngstone.yml` and start them all with one command.
They share one terminal inspector, which shows each request's tunnel and
replays it to the right app.

```yaml
server: example.com:4443
tunnels:
  web:
    port: 3000
    subdomain: demo
  api:
    url: http://127.0.0.1:8080
    basic_auth: ["user:pass"]
  db:
    kind: tcp
    port: 5432
```

```
ngstone start            # every tunnel in ./ngstone.yml
ngstone start web api    # just these
```

`ngstone start` looks for `./ngstone.yml`, then `ngstone.json` or
`.ngstone.json`, then `tunnels.yml` in the config directory
(`~/.config/ngstone/`), or takes `--config FILE`. Both YAML and JSON use the
same runner and terminal inspector. Each YAML tunnel
accepts the same options as `ngstone port` and `ngstone tcp`: `port` or
`url`, `subdomain`, `host_header`, `basic_auth` or `basic_auth_file`, and
`allow_cidr` for HTTP; `port` or `address`, `remote_port` and `allow_cidr`
for `kind: tcp`; `port` or `address`, `subdomain` and `allow_cidr` for
`kind: tls` (see [TLS passthrough](#tls-passthrough)). Unknown keys are errors, so a typo cannot silently drop a
setting. YAML also supports per-tunnel `credential_env` or `credential_file`,
`connector_token_env` or `connector_token_file`, `http2`, `multi_connector`,
`ttl`, `policy_file`, `transport`, `insecure`, and `pin`.
If one tunnel fails, for example because its subdomain is taken,
the others keep running.

### Run tunnels in the background

```
ngstone service install          # systemd user unit on Linux, launchd agent on macOS
ngstone service status
ngstone service uninstall
ngstone ps                       # tunnels of every running ngstone process, with their URLs
```

The service runs `ngstone start --no-tui` with the tunnels file you point it
at (`--config`, or the same lookup as `start`), restarts it if it fails, and
uses per-tunnel `credential_file` values or the token saved by `ngstone auth`.
JSON projects work too: `ngstone service install --config ngstone.json`.
Background services require `credential_file` instead of `credential_env`,
and pools require `connector_token_file`, so secrets survive logout and
restart. Token files contain only the token, must be regular files with mode
`0600`, and resolve relative to the project file. Keep them out of version
control. Tokens are never embedded in the generated service definition.
`--print` shows the unit or plist
without installing it. Logs go to `journalctl --user -u ngstone` on Linux and
`~/Library/Logs/ngstone.log` on macOS. On Linux, run
`sudo loginctl enable-linger $USER` once to keep it running after you log out
and start it at boot.

### Durable control-plane storage and scoped credentials

`ngstoned` uses SQLite by default at `/var/lib/ngstoned/control.db`. The
database is opened and migrated automatically and stores tunnel names and
ownership, hashed credentials, connector leases, audit events, traffic
policies, and custom-domain registrations. Connector leases are renewed by
heartbeats, so several edge processes can share one database and only the
process holding a live lease serves a tunnel.

This coordinates ownership; it does not yet proxy public requests between
edge processes. Put a load balancer or DNS strategy in front that sends a
tunnel's traffic to the edge holding its live connector, or keep the public
listener on one edge until inter-edge forwarding is added.

For multiple edge servers, point every process at PostgreSQL and give each
process a stable edge ID:

```
export NGSTONE_DATABASE_URL='postgres://ngstone:password@db.internal/ngstone?sslmode=require'
export NGSTONE_EDGE_ID=edge-a
ngstoned -domain example.com -cert-email you@example.com
```

Keep the DSN in the environment rather than a process argument when it
contains a password. Set `NGSTONE_EDGE_ID=edge-b` on the next edge. SQLite is
the simpler single-VPS default; PostgreSQL is the recommended backend for
active/active edge servers.

Ownership follows the credential's owner principal, so its tunnels, policies,
and custom domains use the same identity. Schema migration v4 maps older
credential-ID ownership to those principals, merges identical policies, and
preserves differing policies with unique names. Back up the database and stop
all edge processes before upgrading; restart every edge on the new version.
Do not mix old writers with the migrated database.

For a self-hosted edge, prefer a short-lived credential for each tunnel. The
management API issues credentials from durable storage:

```
ngstone admin credentials issue --subdomain demo --ttl 24h
```

The file-backed credential store remains available for existing deployments:

```
ngstoned -credentials-file /var/lib/ngstoned/credentials.json ...
```

Issue a credential on the edge host, then save the one-time token on the agent
machine:

```
ngstone credentials issue --file /var/lib/ngstoned/credentials.json --subdomain demo --ttl 24h
ngstone auth '<token printed by the previous command>'
ngstone port 3000 --subdomain demo
```

The credential is restricted to the exact `demo` subdomain, is hashed in the
edge file, expires automatically, and can be revoked without affecting other
tunnels:

```
ngstone credentials list --file /var/lib/ngstoned/credentials.json
ngstone credentials revoke <credential-id> --file /var/lib/ngstoned/credentials.json
```

TCP credentials are restricted to one allocated port and require an explicit
remote port: `ngstone credentials issue --kind tcp --remote-port 15432 ...`.
The edge checks the credential at bind time and during the heartbeat, so an
active tunnel is disconnected shortly after its credential expires or is
revoked. Keep the file mode `0600` and run the credential command as the same
service account that owns it. `-token-sha256` remains available as a legacy
migration path; it is not scoped or independently revocable.

TLS credentials are restricted to one subdomain and may bind only `ngstone tls`
tunnels: `ngstone credentials issue --kind tls --subdomain secure`.

Database-share commands require a legacy shared-token operator session. Scoped
tunnel credentials cannot create, inspect, or manage database shares. Configure
each edge for either scoped credentials or the legacy shared-token mode.

The same management API persists traffic policies and custom domains:

```
ngstone admin policies apply --name web --file traffic-policy.json
ngstone admin policies list
ngstone admin domains add --domain demo.example.org --tunnel-id <tunnel-id>
ngstone admin domains list
```

For a multi-tunnel project, create `ngstone.json` in the project directory:

```json
{
  "tunnels": {
    "web": {
      "target": "3000",
      "subdomain": "demo",
      "host_header": "demo.localhost:3000",
      "credential_env": "NGSTONE_WEB_TOKEN",
      "multi_connector": true,
      "connector_token_env": "NGSTONE_CONNECTOR_TOKEN",
      "policy_file": "traffic-policy.json",
      "ttl": "2h"
    },
    "api": {
      "target": "3001",
      "subdomain": "api"
    }
  }
}
```

Start every tunnel with `ngstone up`. Use `ngstone up --file path/to/project.json`
to select another file. The project file never contains an auth token; use
`ngstone auth` for one saved token, or set `credential_env` to give each
tunnel its own scoped token environment variable. Alternatively, set
`credential_file` to a private token file. A missing explicit credential
source fails startup instead of falling back to a different token.
`ngstone ps` lists both `start` and `up`, including expired tunnels while
their siblings remain running. A tunnel can also be
bounded directly with `ngstone port 3000 --ttl 2h`.

For automation, add `--json` to `up`, `port`, or `tcp` for one JSON status
event per line. Add `--har requests.har` to an HTTP tunnel or `up` to export
the in-memory request history when the process exits. Authorization, cookie,
and API-key headers are redacted by default; `--har-include-sensitive` opts
in to including them. HAR request and response bodies can still contain
secrets, so inspect the file before sharing it.

`ngstone preview` creates a temporary share link. For a scoped deployment,
issue a dedicated preview credential first:

```
ngstone admin credentials issue --kind preview --ttl 2h
ngstone preview 3000 --token '<issued token>' --ttl 30m
```

A preview credential receives one opaque edge-assigned hostname, stable
across reconnects. Issue a new credential for a new URL. It cannot request a
named tunnel, TCP port, takeover, or connector pool. Existing named HTTP
credentials remain restricted to their exact subdomain. Legacy shared-token
deployments continue using random preview names.

Preview requires a positive local TTL; the default is two hours. Credential
expiration or revocation can end it sooner. Pass `--json` for a
machine-readable link with `expires_at`, or
`--no-tui` when you want plain logs instead of the inspector.
The URL is public while it is live; add `--basic-auth`, `--allow-cidr`, or
`--oidc` for private previews.

### Inspector workflows

The terminal inspector keeps the latest 200 HTTP exchanges in memory. Select a
request and use these shortcuts:

```
c       copy a redacted cURL command
C       copy a cURL command with sensitive headers
d       compare the response with its replay
s       save the request as ngstone-replay-<id>.json
/       search by method, status class, or path substring
```

Saved replay files are private JSON files containing the complete request body
and headers. Run them against a local app later, or print a cURL command:

```
ngstone replay ngstone-replay-000000000001.json --target 3000
ngstone replay ngstone-replay-000000000001.json --target 3000 --json
ngstone replay ngstone-replay-000000000001.json --curl
```

`--curl` redacts authorization, cookie, proxy-authorization, API-key, and
`Set-Cookie` headers unless `--include-sensitive` is passed. Replay files can
contain secrets; keep them out of commits and CI artifacts.

### GitHub Actions

Use the reusable action to expose a service during a CI job. With the
management API inputs it creates a unique, short-lived credential for the run,
verifies the downloaded release checksum, waits for the public URL, and
revokes the credential in the action's post-job cleanup:

```yaml
- uses: emilio-kariuki/ngstone@v0.3.2
  id: tunnel
  with:
    target: 3000
    admin-server: https://edge.example.com:4041
    admin-token: ${{ secrets.NGSTONE_ADMIN_TOKEN }}
    ttl: 20m

- run: curl --fail "$NGSTONE_URL/health"
```

The action derives a run-specific subdomain when `subdomain` is empty. The
admin bearer token must be able to reach the edge management API over a
private HTTPS path. The action's post hook stops the agent and revokes the
credential even when a later workflow step fails. To run a command through the
tunnel, pass it as `command`:

```yaml
- uses: emilio-kariuki/ngstone@v0.3.2
  with:
    target: 3000
    admin-server: https://edge.example.com:4041
    admin-token: ${{ secrets.NGSTONE_ADMIN_TOKEN }}
    command: npm run e2e -- --base-url "$NGSTONE_URL"
```

The old `token` input remains as a compatibility fallback, but it uses a
long-lived shared credential and cannot be revoked automatically. Pin the
action to a release tag or commit, store management credentials as GitHub
Actions secrets, and never put them in `command`, logs, or artifacts. The TTL
is still the last-resort lifetime bound if a runner disappears.

### Native HTTP/2 and gRPC

HTTP tunnels use HTTP/1.1 inside the yamux stream by default. For a local
gRPC or HTTP/2 service, opt into the native stream mode:

```
ngstone port http://127.0.0.1:50051 --http2
```

The target must speak HTTP/2 over TLS when its URL uses `https://`, or cleartext
h2c when its URL uses `http://`. This preserves gRPC trailers, streaming, and
full-duplex request/response behavior. The mode is explicit because ordinary
HTTP applications commonly listen on an `http://` URL but only speak HTTP/1.1.
It can also be set per tunnel with `"http2": true` in `ngstone.json`; it is
HTTP-only and cannot be combined with a TCP tunnel.

The native path is covered by transport tests for response trailers,
bidirectional streaming, cleartext h2c, cancellation propagation, 2 MiB
messages, and backend HTTP/2 connection reuse.

### TLS passthrough

HTTP tunnels end TLS at the edge with its wildcard certificate. When the local
service must present its own certificate (mTLS, a pinned or EV certificate, a
non-HTTP protocol over TLS, or traffic the edge must never see in plaintext),
use a `tls` tunnel:

```
ngstone tls 8443 --subdomain secure
# tls://secure.example.com -> 127.0.0.1:8443
ngstone tls app.local:9443 --subdomain secure --allow-cidr 203.0.113.0/24
```

The edge reads only the SNI from the ClientHello on its public `:443`
listener, without consuming it, and when the name matches a `tls` tunnel it
hands the raw connection to the agent, replaying the bytes it peeked. The agent
dials the local address and splices bytes both ways, so the TLS handshake,
certificate, and ALPN negotiation happen between the client and your service.
Connections whose SNI is not a `tls` tunnel, that carry no SNI, or that are not
TLS at all continue to the normal TLS-terminating path unchanged, so HTTP
tunnels and the `/_ngstone/control` WebSocket fallback on the apex keep
working on the same port. The peek is bounded to 16 KiB and the edge's
`-read-header-timeout`; a larger ClientHello is closed.

The edge never decrypts traffic for a passthrough connection; an HTTPS request
that reaches the edge's own TLS for that hostname (for example on a reused or
domain-fronted connection) gets 421 and is never forwarded. Because of that,
`--basic-auth`, `--host-header`, `--policy-file`, `--http2`, and
`--multi-connector` are rejected for `tls` tunnels; `--allow-cidr`, per-IP rate and in-flight limits, PROXY protocol
client addresses, and `--ttl` all apply. The local service needs a certificate
for the public hostname (`secure.example.com`) that clients trust; the edge's
own certificate is never involved. A hostname is either an HTTP or a `tls`
tunnel at a time: binding one kind over a live tunnel of the other kind fails
with `kind_conflict`.

In `ngstone.json` (`ngstone up`) or `ngstone.yml` (`ngstone start`):

```json
{"tunnels": {"secure": {"kind": "tls", "target": "8443", "subdomain": "secure", "allow_cidr": "203.0.113.0/24"}}}
```

`ngstone ps`, `ngstone up --json`, and the terminal inspector's tunnel list
report the kind as `tls`.

### Multiple connectors

Run several agent processes for the same named tunnel with
`--multi-connector` on every process:

```
export NGSTONE_CONNECTOR_TOKEN="$(openssl rand -hex 32)"
ngstone port 3000 --subdomain demo --multi-connector
ngstone port 3000 --subdomain demo --multi-connector
```

The edge round-robins new requests across live connectors and skips connectors
that have reached their per-session capacity. Reconnecting replaces only that
connector; stopping one connector drains its in-flight requests while the
remaining connectors continue serving traffic. Connector settings must match
for HTTP/2, access control, and traffic policies. The option requires an
explicit `--subdomain` and is HTTP-only. The connector token is separate from
the edge auth token; keep it in `NGSTONE_CONNECTOR_TOKEN` or pass it with
`--connector-token`. For `ngstone up`, set `connector_token_env` in the project
tunnel if it should read a different environment variable. It can also be set
as `"multi_connector": true` in a project tunnel.

### Traffic policies

Use an edge-enforced policy file to allow, deny or redirect HTTP requests by
method, path prefix, and request-header presence or exact value, to rewrite
request and response headers, and to answer CORS at the edge:

```json
{
  "default_action": "deny",
  "rules": [
    {"action": "redirect", "path_prefix": "/old", "redirect_url": "/new$path", "redirect_status": 308},
    {"action": "allow", "path_prefix": "/public"},
    {"action": "allow", "method": "GET", "header": "X-Preview", "header_value": "yes", "path_prefix": "/preview"},
    {"action": "transform", "path_prefix": "/public",
     "request_headers": {"set": {"X-Env": "preview"}, "remove": ["X-Debug"]},
     "response_headers": {"set": {"Cache-Control": "no-store"}, "add": {"X-Robots-Tag": "noindex"}, "remove": ["Server"]}}
  ],
  "cors": {
    "allowed_origins": ["https://app.example.com"],
    "allowed_methods": ["GET", "POST"],
    "allowed_headers": ["Content-Type"],
    "exposed_headers": ["X-Total-Count"],
    "allow_credentials": true,
    "max_age": 600
  }
}
```

Start a direct tunnel with `ngstone port 3000 --policy-file traffic-policy.json`,
or set `"policy_file": "traffic-policy.json"` on an HTTP tunnel in
`ngstone.json`. Relative project paths are resolved from the project file.
Policies saved with `ngstone admin policies apply` keep every field.

How rules combine:

- `allow`, `deny` and `redirect` are evaluated in order and the **first
  match wins**; an unmatched request uses `default_action` (`allow` or
  `deny`, default `allow`). A denied request receives `403` and never
  reaches the local app.
- `transform` rules never decide anything. **Every** matching transform
  rule applies, in file order, wherever it sits relative to the deciding
  rule, but only to requests that are proxied (not denied or redirected).
  All rules match against the request as the client sent it, so one
  transform cannot make another rule match.
- Within one header block, `remove` runs first, then `set` (replace), then
  `add` (append). Request header actions are applied before the request is
  sent to the agent, so the local app and the terminal inspector see the
  rewritten headers. Response header actions are applied to the response
  from the agent before it reaches the client; the inspector shows the
  response as the local app sent it. Edge-generated responses (403, 502,
  redirects, CORS preflights) are not transformed.
- `redirect` answers at the edge with `redirect_status` (`301`, `302`,
  `307` or `308`, default `302`) and `Location: redirect_url`.
  `redirect_url` is an absolute path or an `http(s)` URL; `$path` (or
  `${path}`) expands to the request path with the rule's `path_prefix`
  removed, so `/old/a/b` becomes `/new/a/b` above. The request's query
  string is appended only when `redirect_url` has no query of its own, and
  `$path` after a `?` is query-escaped.
  Redirect rules are not checked for loops: a rule whose target matches the
  rule itself redirects repeatedly until the browser stops.
- `cors` answers preflight requests (`OPTIONS` with `Origin` and
  `Access-Control-Request-Method`) at the edge with `204`, after the
  CIDR allow list and the per-IP rate limit but before basic auth, visitor
  login and rules, because browsers never send credentials on a preflight.
  On proxied responses the edge removes any `Access-Control-*` headers the
  app set and adds its own for allowed origins.
  `allowed_origins` lists exact `scheme://host[:port]` origins, or is
  `["*"]` (not allowed with `allow_credentials`). `allowed_methods`
  defaults to `GET, HEAD, POST`; `allowed_headers` may be `["*"]` to echo
  the requested headers; `max_age` is in seconds (max 86400). `*` is
  accepted in `allowed_origins` and `allowed_headers` only as the whole
  entry and is rejected in `allowed_methods`.

Header actions cannot touch hop-by-hop headers (`Connection`, `Keep-Alive`,
`TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, `Proxy-*`), or headers
the edge owns: `Host`, `Content-Length`, `Authorization`, `Forwarded`,
`X-Real-IP`, `X-Forwarded-*` and `X-Ngstone-*`. With `cors` set,
`Access-Control-*` response headers are reserved for it. Such a policy is
rejected when the tunnel starts.

Policies are HTTP-only and are not access control by themselves: combine
them with `--basic-auth`, `--allow-cidr`, or `--oidc` when the tunnel must be
private.

### Visitor login (OIDC)

Put an edge-enforced login wall in front of an HTTP tunnel. Visitors sign in
with your OIDC provider (Google, Keycloak, Okta, Auth0, Dex in front of GitHub,
and so on) before any request reaches the local app:

```
ngstone port 3000 --oidc --oidc-allow-domain example.com --oidc-allow-email contractor@gmail.com
```

`--oidc-allow-email` and `--oidc-allow-domain` are comma-separated or
repeatable. A visitor is let in when their **verified** email matches one of
the emails exactly or belongs to one of the domains (subdomains do not match).
With `--oidc` and no allow list, any account the provider authenticates is let
in, so only do that with a provider limited to your own organization. The same
settings work in project files:

```json
{"tunnels": {"web": {"target": "3000", "oidc": true, "oidc_allow_domain": ["example.com"]}}}
```

```yaml
tunnels:
  web:
    port: 3000
    oidc: true
    oidc_allow_email: [alice@example.com]
```

Visitor login is HTTP-only; `kind: tcp` tunnels reject it. The agent refuses to
start if the edge does not acknowledge the login wall, so an old edge can never
silently serve the tunnel without it.

On the edge, visitor login uses its own OIDC client, separate from the
[ops-dashboard OIDC login](#oidc-login-and-team-rbac):

```
export NGSTONE_VISITOR_OIDC_ISSUER=https://accounts.google.com
export NGSTONE_VISITOR_OIDC_CLIENT_ID=ngstone-visitors
export NGSTONE_VISITOR_OIDC_CLIENT_SECRET='provider-client-secret'
export NGSTONE_VISITOR_OIDC_COOKIE_SECRET="$(openssl rand -base64 32)"
ngstoned -domain example.com -cert-email you@example.com
```

Register `https://example.com/.ngstone/auth/callback` (the apex of `-domain`)
as the client's redirect URI. Set `NGSTONE_VISITOR_OIDC_REDIRECT_URL` or
`-visitor-oidc-redirect-url` to use another host under `-domain`.
`NGSTONE_VISITOR_OIDC_ALLOWED_EMAIL_DOMAINS` sets an edge-wide floor that every
visitor must meet in addition to the tunnel's own list. The issuer and client
ID can also be passed as `-visitor-oidc-issuer` and `-visitor-oidc-client-id`;
the secrets are read only from the environment. The settings are kept separate
from `NGSTONE_OIDC_*` on purpose. The ops client maps groups to admin roles and
calls back to the loopback ops listener, while visitor login serves tunnel
audiences on the public apex host and often uses a different provider. You can
point both at the same provider client by registering both redirect URIs.

How it works:

- An unauthenticated `GET`/`HEAD` that accepts `text/html` is redirected to
  `/.ngstone/auth/start` on the apex host. Other requests (APIs, `fetch`,
  websockets without a session) get `401`.
- The apex start step sets a short-lived state cookie and sends the browser to
  the provider with PKCE. The callback on the apex host validates the ID token,
  checks the tunnel's allow list, and redirects back to the tunnel host with a
  sealed one-minute, single-use ticket. The original path travels inside sealed
  state, never as a plain query parameter, so it cannot be used as an open
  redirect.
- The tunnel host trades the ticket for an encrypted, host-only, `HttpOnly`,
  `SameSite=Lax` `ngstone_visitor_session` cookie (8 hours). A cookie for one
  tunnel is rejected on every other tunnel.
- The ticket is tied to the browser that started the login by a short-lived
  `HttpOnly` binding cookie, so a ticket opened in another browser is refused.
  On the secure scheme the session, state, and binding cookies use the
  `__Host-` prefix so a sibling tunnel cannot plant them; under `-insecure`
  (development only) these protections do not apply. The tunnel's login rule is
  stored in the durable lease record.
- On each request the edge strips every edge visitor cookie, deletes every
  client-supplied `X-Ngstone-*`, `X-Forwarded-*`, `Forwarded`, and `X-Real-IP`
  header in any spelling, such as `X_Ngstone_User_Email` (on all tunnels, with
  or without `--oidc`), and sets `X-Ngstone-User-Email`, `X-Ngstone-User-Subject`, and
  `X-Ngstone-User-Name` for the local app. Trust these headers only when the
  app is reachable solely through the tunnel.
- Limits to know about: every tunnel shares one registrable domain, so
  `SameSite=Lax` does not separate sibling tunnels and apps still need their own
  CSRF and `Origin` checks. One identity-provider client is shared by all tunnel
  owners, so an owner can learn the email, subject, and name of anyone who
  follows a link to their walled tunnel. Sessions are stateless and cannot be
  revoked before they expire.
- `/.ngstone/auth/finish` and `/.ngstone/auth/logout` are reserved on tunnels
  that use `--oidc`. Visit `/.ngstone/auth/logout` to sign out.

Visitor login composes with the other controls. `--allow-cidr` and the per-IP
rate limit are checked first, then `--basic-auth`, then the login wall, then the
traffic policy. The policy sees the verified identity headers, so a rule such
as `{"action": "allow", "path_prefix": "/admin", "header": "X-Ngstone-User-Email", "header_value": "alice@example.com"}`
followed by a `deny` for `/admin` limits a path to one person.

### Webhook signature verification

The edge can check webhook signatures before forwarding, so unsigned or tampered
deliveries, and `stripe` or `slack` deliveries whose timestamp is outside the
tolerance, get `401` and never reach the local app:

```bash
export NGSTONE_WEBHOOK_SECRET=whsec_...
ngstone port 3000 --verify-webhook stripe --verify-webhook-path /webhooks/stripe
ngstone port 3000 --verify-webhook github --verify-webhook-secret-file github.secret
ngstone port 3000 --verify-webhook slack --verify-webhook-tolerance 2m
ngstone port 3000 --verify-webhook hmac --verify-webhook-header X-Shopify-Hmac-Sha256 --verify-webhook-encoding base64
```

| Provider | Header | Signed content |
| --- | --- | --- |
| `stripe` | `Stripe-Signature` (`t=…,v1=…`) | `timestamp.body`, timestamp within tolerance (default 5m) |
| `github` | `X-Hub-Signature-256` (`sha256=…`) | body |
| `slack` | `X-Slack-Signature` + `X-Slack-Request-Timestamp` | `v0:timestamp:body`, timestamp within tolerance (default 5m) |
| `hmac` | `--verify-webhook-header` | body, `hex` (default) or `base64`, optional `--verify-webhook-prefix` such as `sha256=` |

The secret comes from `--verify-webhook-secret-file` or `NGSTONE_WEBHOOK_SECRET`;
there is deliberately no flag that takes the secret itself. `--verify-webhook-path`
verifies every request whose decoded, cleaned path contains the configured path at
a segment boundary (starting at any `/`), case-insensitively, so `/webhooks/stripe.json`, `/webhooks/stripe;x=1` and
`/index.php/webhooks/stripe` are all checked; a path the edge cannot classify
(an encoded slash or backslash, a bad escape, a control byte, a backslash, `;`)
is verified too. Without it every request is verified. The path must not
contain `%`, `?` or `#`.

Replay protection is limited. `stripe` and `slack` reject a delivery only when
its signed timestamp is outside the tolerance, a whole number of seconds from
1s to 24h. The edge keeps no nonce cache, so a captured delivery can be replayed
within that window; `github` and `hmac` sign no timestamp and have no replay
protection at all. Deduplicate on the provider's event ID in the app.

Verification works on HTTP tunnels only, and cannot be combined with `--http2`
or `--oidc` (`http2: true` or `oidc: true` in project files). `ngstone serve`
rejects the `--verify-webhook` flags, and `ngstone service` requires
`webhook.secret_file` so the secret survives logout and restart.

In `ngstone.json` or `ngstone.yml`, add a `webhook` block to an HTTP tunnel:

```yaml
tunnels:
  payments:
    port: 3000
    webhook:
      provider: stripe
      secret_file: stripe.secret   # relative to the project file, must be chmod 600
      path_prefix: /webhooks/stripe
      tolerance: 5m
  bot:
    port: 3001
    webhook:
      provider: slack
      secret_env: SLACK_SIGNING_SECRET   # defaults to NGSTONE_WEBHOOK_SECRET
```

A missing or malformed signature header gets `401` before any body is read.
Otherwise the edge buffers a matching request body up to the smaller of
`-webhook-max-body-bytes` (default 1 MiB) and `-max-body-bytes` (`413` beyond
that), compares signatures in constant time, then forwards the original body
unchanged. All in-flight verifications share a `-webhook-buffer-bytes` budget
(default 64 MiB); the edge reserves the declared length, or the full cap for a
chunked body, before reading, and answers `503` with `Retry-After` when the
budget is spent (`ngstoned_rejected_webhook_buffer_total`). Signature failures
return a short reason (`missing signature`, `malformed signature`, `invalid
signature`, `timestamp outside tolerance`) and increment
`ngstoned_rejected_webhook_signature_total`.

HMAC verification needs the signing secret itself, so the agent sends it to the
edge in the bind message over the TLS control channel. With `--insecure` the
control channel is plaintext, so the agent refuses to send a webhook secret
unless the edge address is loopback (`localhost`, `127.0.0.0/8` or `::1`).
The edge keeps it in memory
only: it is not stored durably and never appears in the dashboard, admin API,
events, `ngstone ps`, `--json` output or HAR exports, which show only the
provider name. An edge that does not acknowledge webhook verification makes the
agent refuse to bind rather than open an unverified tunnel.

This assumes you (or someone) already has `ngstoned` running on a VPS with a
domain pointed at it — see [Self-hosting](#self-hosting) below. `ngstoned` is
not installed by this script; it's server infrastructure, not something to
curl-pipe onto a box. There is no `ngstone token` command; use the scoped
`ngstone credentials issue` flow on the edge, or the legacy shell one-liner
shown in the next section.

## Share a database temporarily

`ngstone share` exposes a local Postgres, MySQL or Redis (or any TCP
service) to teammates through a link, without opening a public port. Both
sides dial out to the edge; the edge joins the two sessions and copies
bytes. Shares expire, carry a policy, and show every connection in the
sharer's terminal:

```
ngstone share postgres --expires 2h --label "staging replica"
# prints a link: ngstone://example.com:4443/s/...
```

A teammate runs the link, and gets the database on their own loopback:

```
ngstone connect ngstone://example.com:4443/s/...
# listening  127.0.0.1:5432  ->  psql "postgres://127.0.0.1:5432/"
```

Ctrl-C on the sharer revokes the link and connectors are told within a
second. `--allow-cidr`, `--max-conns`, `--max-connectors`, `--max-uses`,
`--single-use`, `--idle`, `--approve` and `--passphrase` set the policy;
`--audit-log` writes every event as JSON Lines. Several services go in one
link (`ngstone share postgres redis:6380`), and connectors can name
themselves (`--as alice`). From any terminal with the token, `ngstone
shares` lists live shares (`--watch` tails their events), `ngstone extend`
moves an expiry, `ngstone kick` drops a connector and `ngstone unshare`
revokes. The full design is in [docs/SHARE-DESIGN.md](docs/SHARE-DESIGN.md).

## Run it locally, no TLS

You don't need a VPS or a domain to try ngstone. This runs both binaries on
your machine with TLS turned off entirely, useful for development or just
kicking the tires:

```
TOKEN=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
HASH=$(printf '%s' "$TOKEN" | shasum -a 256 | cut -d' ' -f1)
go run ./cmd/ngstoned -insecure -domain localhost -public 127.0.0.1:8443 -control 127.0.0.1:7443 -ops "" -public-scheme http -token-sha256 "$HASH"
NGSTONE_TOKEN="$TOKEN" go run ./cmd/ngstone -insecure -control 127.0.0.1:7443 -target http://127.0.0.1:3001 -subdomain demo
curl -H 'Host: demo.localhost' http://127.0.0.1:8443/
```

The first two lines generate a random legacy auth token and its SHA-256 hash;
there is no `ngstone token` command, this is the compatibility procedure. The third command
starts the edge listening in plaintext, configured with only the hash (the
edge never sees the plaintext token). The fourth starts the agent using the
legacy flag form, connects it to the edge, and binds it to the `demo`
subdomain, forwarding to whatever is listening on `127.0.0.1:3001`. The last
line simulates a browser request by setting the `Host` header directly (in
production this would be the real hostname, resolved via DNS).

For local testing with scoped credentials, replace the hash flag with
`-credentials-file /tmp/ngstone-credentials.json`, issue a credential for
`demo`, and pass the printed token through `NGSTONE_TOKEN`. The shared hash
example above remains useful for compatibility testing.

### Local admin dashboard

`ngstoned` serves a read-only operations dashboard and a versioned management
API on `127.0.0.1:4041` by default. The dashboard shows active HTTP/TCP
tunnels, connector health and capacity, request counters, certificate expiry,
per-tunnel latency/status/byte metrics, and the last 200 in-memory edge events.
Open it through an SSH port-forward
on a VPS:

```
ssh -L 4041:127.0.0.1:4041 root@example.com
```

Then open <http://127.0.0.1:4041/> locally, or use the admin CLI:

```
ngstone admin status
ngstone admin tunnels --json
ngstone admin observability --json
ngstone admin credentials issue --subdomain demo --ttl 24h
ngstone admin credentials revoke <credential-id>
ngstone admin policies list
ngstone admin domains list
ngstone admin tunnel drain demo
```

For the common read-only operations, shorter aliases are available:

```
ngstone status
ngstone tunnels
ngstone observability
ngstone drain demo
```

They use the same `NGSTONE_ADMIN_SERVER`, `NGSTONE_ADMIN_TOKEN`, `--server`,
`--token`, and `--json` options as their `ngstone admin` counterparts.

The CLI defaults to `http://127.0.0.1:4041`; use `--server` or
`NGSTONE_ADMIN_SERVER` to select another management endpoint. The API uses
`GET /api/v1/status`, `GET /api/v1/tunnels`, `GET|POST /api/v1/credentials`,
`DELETE /api/v1/credentials/{id}`, and
`POST /api/v1/tunnels/{hostname}/drain`, `GET|POST /api/v1/policies`,
`DELETE /api/v1/policies/{id}`, `GET|POST /api/v1/domains`, and
`DELETE /api/v1/domains/{id}`, and `GET /api/v1/observability/tunnels`.
Successful responses are wrapped in
`{"data": ...}` and errors in `{"error": {"code": ..., "message": ...}}`.

The observability endpoint returns durable counters plus current connector
health. Latency percentiles are approximate histogram percentiles, so they are
stable across restarts without storing every request:

```json
{
  "data": [
    {
      "tunnel_id": "5c1d...",
      "hostname": "demo.example.com",
      "kind": "http",
      "request_count": 42,
      "latency_p50_ms": 25,
      "latency_p95_ms": 100,
      "latency_p99_ms": 250,
      "status_codes": {"200": 40, "404": 2},
      "active_connectors": 2,
      "reconnects": 1,
      "bytes_in": 8192,
      "bytes_out": 65536,
      "bytes_transferred": 73728,
      "credential_expired": 0,
      "credential_revoked": 1
    }
  ]
}
```

For example, issuing a credential directly over the SSH-forwarded API returns
the plaintext token once:

```
curl -X POST http://127.0.0.1:4041/api/v1/credentials \
  -H 'Content-Type: application/json' \
  -d '{"subdomain":"demo","ttl":"24h"}'
```

```json
{
  "data": {
    "credential": {
      "id": "0123456789abcdef0123456789abcdef",
      "kind": "http",
      "subdomain": "demo",
      "created_at": "2026-08-18T12:00:00Z",
      "expires_at": "2026-08-19T12:00:00Z"
    },
    "token": "nst_<printed-once>"
  }
}
```

By default, `/api/v1` accepts only loopback requests, which makes the SSH
forward the normal access path. To authorize a private, non-loopback
management connection, configure the edge with the SHA-256 hash of a bearer
token in `NGSTONE_ADMIN_TOKEN_SHA256`, then give the plaintext token to the
CLI through `NGSTONE_ADMIN_TOKEN` or `--token`. The bearer token protects only
`/api/v1`; keep the ops listener private or put TLS and an authenticated proxy
in front of it because the dashboard, metrics, health, and pprof endpoints
remain separate. Set `-ops ""` to disable the entire listener.

When OIDC is enabled, browser access to the dashboard and management API uses
the OIDC session and team roles instead of the loopback bypass. Keep the ops
listener private or put it behind HTTPS; the OIDC callback must be reachable by
the browser and must exactly match the registered provider callback.

For lifecycle alerts, set `NGSTONE_ALERT_WEBHOOK_URL` and optionally
`NGSTONE_ALERT_WEBHOOK_TOKEN` in the edge environment. ngstoned sends
non-blocking JSON events for connector reconnects, lease loss, and expired or
revoked credentials; event payloads contain tunnel identity and metadata, not
tokens.

### Doctor

Run the diagnostic command on the agent or VPS to check the local config, token,
control-plane DNS and reachability, token authentication, management API health,
and OIDC environment configuration:

```
ngstone doctor
ngstone doctor --admin-server https://edge.example.com:4041 --admin-token "$NGSTONE_ADMIN_TOKEN"
ngstone doctor --json
```

The human output is intended for operators; `--json` returns a stable report
with `pass`, `warn`, `fail`, and `skip` checks for scripts. A missing config file
is a warning, but a missing tunnel token, unreachable control plane, invalid
OIDC configuration, or failed authenticated check is a failure. Plaintext
management URLs are accepted only for loopback or with `--insecure`.

### OIDC login and team RBAC

Enable browser login on the edge with an OIDC provider. Register the exact
callback URL with the provider before starting `ngstoned`:

```
export NGSTONE_OIDC_ISSUER=https://login.example.com/realms/ngstone
export NGSTONE_OIDC_CLIENT_ID=ngstone-ops
export NGSTONE_OIDC_CLIENT_SECRET='provider-client-secret'
export NGSTONE_OIDC_COOKIE_SECRET="$(openssl rand -base64 32)"
export NGSTONE_OIDC_REDIRECT_URL=https://edge.example.com:4041/api/v1/auth/oidc/callback
export NGSTONE_OIDC_GROUPS_CLAIM=groups
export NGSTONE_OIDC_ADMIN_GROUPS=ngstone-admins
export NGSTONE_OIDC_OPERATOR_GROUPS=ngstone-operators
export NGSTONE_OIDC_VIEWER_GROUPS=ngstone-viewers
export NGSTONE_OIDC_ALLOWED_EMAIL_DOMAINS=example.com
ngstoned -domain example.com -cert-email you@example.com
```

Use `ngstone login --server https://edge.example.com:4041` (or
`ngstone admin login`) to print the browser login URL. The roles are cumulative:
`admin` can manage everything, `operator` can mutate tunnel resources, and
`viewer` is read-only. Group matches win in admin/operator/viewer order. The
default role is empty, so users without a configured group are rejected; set
`NGSTONE_OIDC_DEFAULT_ROLE=viewer` only when every authenticated IdP user should
have read-only access.

OIDC sessions are encrypted, short-lived cookies. The edge validates the
provider's signed ID token, issuer, audience, nonce, expiry, and PKCE exchange;
mutating browser requests also require the session's CSRF token. Resource
ownership is derived from the authenticated OIDC subject, not from an
`owner_id` request field. Keep the client secret and cookie secret in the
root-only systemd environment file. The bearer-token API remains available for
non-browser automation.

This login protects the ops dashboard and management API only. To require a
login in front of tunnels, see [Visitor login (OIDC)](#visitor-login-oidc).

## Self-hosting

You need a Linux VPS with a public IP, a domain, and that domain's DNS hosted
on one of the supported providers below. The installer supports Ubuntu and
Debian; [deploy/README.md](deploy/README.md) covers the manual systemd path.

**1. Point DNS at the VPS.** Create two records with the VPS's public IP:

| Type | Name | Value |
| --- | --- | --- |
| A (or AAAA) | `example.com` | VPS IP |
| A (or AAAA) | `*.example.com` | VPS IP |

On Cloudflare, **both records must be "DNS only" (grey cloud), not
proxied.** Cloudflare's proxy does not forward `:4443`, the port agents dial,
so an orange-cloud record breaks every agent connection even though `:443`
looks fine.

**2. Create an API credential for your DNS provider.** The edge uses it to
publish the DNS-01 challenge records that prove you own the domain, which is
how it gets the wildcard certificate.

| `--dns-provider` | Credential to create | Variables |
| --- | --- | --- |
| `cloudflare` (default) | API token with Zone / DNS / Edit on this zone only | `NGSTONE_CF_API_TOKEN` |
| `route53` | IAM user allowed to change the hosted zone | `NGSTONE_AWS_REGION`, `NGSTONE_AWS_ACCESS_KEY_ID`, `NGSTONE_AWS_SECRET_ACCESS_KEY` |
| `digitalocean` | Personal access token with domain read and write | `NGSTONE_DO_API_TOKEN` |
| `hetzner` | Hetzner Console project API token, read and write | `NGSTONE_HETZNER_API_TOKEN` |
| `vultr` | API key, with the VPS's IP allowed | `NGSTONE_VULTR_API_KEY` |
| `ovh` | Application key, application secret and consumer key | `NGSTONE_OVH_ENDPOINT`, `NGSTONE_OVH_APPLICATION_KEY`, `NGSTONE_OVH_APPLICATION_SECRET`, `NGSTONE_OVH_CONSUMER_KEY` |
| `desec` | Token from desec.io | `NGSTONE_DESEC_TOKEN` |
| `bunny` | Account API key | `NGSTONE_BUNNY_API_KEY` |

If your domain's DNS is at GoDaddy, Namecheap, Porkbun or another registrar
not listed, move just the DNS hosting to a supported provider by changing the
nameservers; Cloudflare and deSEC are free. Those registrars' APIs replace or
delete every challenge record at once, which breaks issuing the two
certificates side by side. `ngstoned -dns-provider help` lists the providers
and variables of the binary you have.

**3. Open the ports** in your VPS provider's firewall: SSH, `80`, `443` and
`4443`, plus any TCP tunnel range you plan to use. The installer configures
UFW on the machine itself.

**4. Run the installer on the VPS.** It prompts for the credential without
echoing it, installs a hardened systemd unit, obtains the certificates and
prints the commands for your laptop. Start with Let's Encrypt staging:

```
git clone https://github.com/emilio-kariuki/ngstone.git /opt/ngstone
cd /opt/ngstone
sudo ./deploy/install-edge.sh --domain example.com --email you@example.com \
  --dns-provider digitalocean --acme-ca staging
```

It installs `ngstoned` and the VPS-side `ngstone` management CLI, configures
systemd and UFW, obtains the certificates, initializes durable SQLite storage,
issues a first scoped credential through the loopback API, and prints the
agent authentication command. Set `NGSTONE_DATABASE_URL` before running the
installer to use PostgreSQL instead. The full manual systemd path is in
[deploy/README.md](deploy/README.md).

Save the auth token it prints; only its hash is stored on the VPS. When the
health output shows both certificates, switch to trusted certificates. The
token and credentials are kept:

```
sudo ./deploy/install-edge.sh --acme-ca production
```

Useful options:

- `--tcp-ports 10000-10100` enables raw TCP tunnels on that range and opens
  it in UFW.
- `--from-source` builds `ngstoned` and `ngstone` from the checkout instead of downloading
  a release. It needs Go, and is required for providers other than
  Cloudflare until a release that includes them is published.
- To pass credentials without a prompt, put them on the sudo command line,
  for example `sudo NGSTONE_DO_API_TOKEN=... ./deploy/install-edge.sh ...`.
  Plain `sudo` drops variables exported in your shell.

**5. Connect from your laptop.**

```
ngstone auth '<token>' --server example.com:4443
ngstone port 3000 --subdomain demo
```

Your app is now at `https://demo.example.com`. Agents released before this
version also need `--server-name example.com` on each command.

If you're using Cloudflare, the raw control listener on `:4443` requires the
apex record to be **DNS only** (grey cloud), not proxied. With the default
`--transport auto`, the agent can fall back to the authenticated WebSocket
endpoint on HTTPS `:443`, which can traverse a proxy when WebSockets are
enabled. Keeping both records DNS-only remains the simplest deployment and
also supports explicit `--transport raw`.

To remove the edge later, run `sudo ./deploy/uninstall.sh` from the checkout.
It removes the service, binaries, and secrets while preserving certificates
and default SQLite control-plane state. See
[deploy/README.md](deploy/README.md#uninstalling) for the optional state and
firewall cleanup flags.

### Run with Docker

Instead of the installer, you can run the edge from the
`ghcr.io/emilio-kariuki/ngstoned` image on any host with Docker and the
Compose plugin. Steps 1 to 3 are the same: the two DNS records, a DNS
provider credential, and ports `80`, `443` and `4443` open. Then:

```
mkdir ngstone && cd ngstone
curl -fsSLO https://raw.githubusercontent.com/emilio-kariuki/ngstone/main/deploy/docker/compose.yaml
curl -fsSL -o .env https://raw.githubusercontent.com/emilio-kariuki/ngstone/main/deploy/docker/.env.example
chmod 600 .env
$EDITOR .env    # domain, email, DNS provider and its credentials, token hash
docker compose up -d
docker compose ps    # STATUS turns "healthy" once both certificates load
docker compose logs -f ngstoned
```

`.env` explains each variable, including how to generate the auth token and
its hash on your laptop. When `docker compose ps` reports healthy, set
`NGSTONE_ACME_CA=production` in `.env` and run `docker compose up -d` again;
certificates live in the `ngstoned-data` volume and survive restarts and
upgrades. Then connect from your laptop as in step 5.

Docker's published ports keep the client's real IP address, so per-IP rate
limits and `--allow-cidr` work without PROXY protocol. To keep certificates
in a host directory instead of the named volume, make it writable by uid
65532 first (`sudo chown 65532:65532 /srv/ngstoned`), since the edge runs as
that non-root user. [deploy/README.md](deploy/README.md#run-with-docker) has
the details, including raw TCP tunnels and an IPv6 caveat.

## Architecture, in brief

The agent always dials out to the edge and never listens for inbound
connections, so there's nothing to open on your home firewall or NAT. By
default it tries one TLS yamux connection to `:4443`, then falls back to the
same yamux session inside an authenticated WebSocket upgrade at
`/_ngstone/control` on `:443`. Use `--transport raw` or
`--transport websocket` to force one path. Every proxied HTTP request gets its
own yamux stream inside the selected session, opened by the edge and read by
the agent. A `tls` tunnel's connections are routed by ClientHello SNI before
the edge terminates TLS and ride their stream as raw bytes. Certificates for both the apex and the wildcard are issued and
renewed automatically via
[certmagic](https://github.com/caddyserver/certmagic) using the DNS-01
challenge, so no ports need to be exposed for ACME HTTP-01 validation.

### Network reliability

The default `--transport auto` tries raw TCP/TLS on the configured control
address first, then retries the same agent session over WebSocket/TLS on port
443. In insecure development mode the fallback uses plain WebSocket on port
443. `--transport raw` and `--transport websocket` are available when an
operator needs a deterministic path; QUIC is intentionally reserved for a
later transport mode.

Reconnects use decorrelated exponential jitter from 500 ms to a 30 s cap.
The edge and agent exchange control pings, skip connectors that have exceeded
the heartbeat health window, and drain active HTTP/TCP streams before closing
on shutdown, credential revocation, lease loss, or management drain.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full write-up,
including the wire protocol, failure modes, and the security model.

## Building from source

```
go build ./cmd/ngstone
go build ./cmd/ngstoned
```

Or `make build` to build both into `bin/`. See the [Makefile](Makefile) for
cross-compiling and deploy targets.

Set `NGSTONE_TEST_POSTGRES_URL` to a throwaway PostgreSQL DSN to run the PostgreSQL storage tests (`go test ./internal/storage -run Postgres`); they use their own schema and skip when it is unset.

## License

MIT — see [LICENSE](LICENSE).
