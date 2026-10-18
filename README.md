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
for `kind: tcp`. Unknown keys are errors, so a typo cannot silently drop a
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
The URL is public while it is live; add `--basic-auth` or `--allow-cidr` for
private previews.

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

Use an edge-enforced policy file to allow or deny HTTP requests by method, path
prefix, and request-header presence or exact value:

```json
{
  "default_action": "deny",
  "rules": [
    {"action": "allow", "path_prefix": "/public"},
    {"action": "allow", "method": "GET", "header": "X-Preview", "header_value": "yes", "path_prefix": "/preview"}
  ]
}
```

Start a direct tunnel with `ngstone port 3000 --policy-file traffic-policy.json`,
or set `"policy_file": "traffic-policy.json"` on an HTTP tunnel in
`ngstone.json`. Relative project paths are resolved from the project file.
Rules are evaluated in order and the first match wins; an unmatched request
uses `default_action`, which defaults to `allow`. A denied request receives
`403` and never reaches the local app. Policies are HTTP-only and are not
access control by themselves: combine them with `--basic-auth` or
`--allow-cidr` when the tunnel must be private.

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
ngstone admin screens create --name demo --ttl 30m --max-viewers 4
ngstone admin screens list
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

### Screen sharing

The default screen-sharing path is direct WebRTC between one native sender and
one browser viewer. Sessions created with `--max-viewers > 1` use the edge's
Pion SFU to forward one encoded RTP track to multiple viewers. The edge
creates short-lived sessions, authenticates participants, and delivers
short-lived STUN/TURN credentials over the authenticated signaling socket.
Reusable native senders for Android and iOS are in `android/` and `ios/`. See
[Screen sharing](docs/SCREENCAST.md) for the protocol and Android/KMM/iOS
integration.

Create a session from the edge management API or CLI:

```
ngstone admin screens create --name demo --ttl 30m --max-viewers 4
```

The command prints a sender token for the Android client and a viewer URL.
Treat both as secrets. The viewer token is in the URL fragment, so it is not
sent as an HTTP query parameter or included in edge request paths. Configure
`NGSTONE_SCREEN_TURN_URLS` and
`NGSTONE_SCREEN_TURN_SHARED_SECRET` for TURN fallback. The Android and iOS
senders adapt bitrate, frame rate, and resolution from WebRTC
loss/RTT/bandwidth samples on weak links. Remote control remains a later stage.

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

## Architecture, in brief

The agent always dials out to the edge and never listens for inbound
connections, so there's nothing to open on your home firewall or NAT. By
default it tries one TLS yamux connection to `:4443`, then falls back to the
same yamux session inside an authenticated WebSocket upgrade at
`/_ngstone/control` on `:443`. Use `--transport raw` or
`--transport websocket` to force one path. Every proxied HTTP request gets its
own yamux stream inside the selected session, opened by the edge and read by
the agent. Certificates for both the apex and the wildcard are issued and
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

## License

MIT — see [LICENSE](LICENSE).
