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
```

By default, the local app receives the public tunnel hostname in `Host`. Use
`--host-header` when it expects a tenant-specific local hostname; the public
hostname remains available in `X-Forwarded-Host`.

This assumes you (or someone) already has `ngstoned` running on a VPS with a
domain pointed at it — see [Self-hosting](#self-hosting) below. `ngstoned` is
not installed by this script; it's server infrastructure, not something to
curl-pipe onto a box. There's no `ngstone token` command — the token is a
plain shell one-liner, shown in the next section.

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

The first two lines generate a random auth token and its SHA-256 hash — there
is no `ngstone token` command, this is the whole procedure. The third command
starts the edge listening in plaintext, configured with only the hash (the
edge never sees the plaintext token). The fourth starts the agent using the
legacy flag form, connects it to the edge, and binds it to the `demo`
subdomain, forwarding to whatever is listening on `127.0.0.1:3001`. The last
line simulates a browser request by setting the `Host` header directly (in
production this would be the real hostname, resolved via DNS).

## Self-hosting

For the easiest Ubuntu/Debian setup, create the apex and wildcard DNS records,
then run the installer on the VPS:

```
git clone https://github.com/emilio-kariuki/ngstone.git /opt/ngstone
cd /opt/ngstone
sudo ./deploy/install-edge.sh --domain example.com --email you@example.com --acme-ca production
```

It installs `ngstoned`, configures systemd and UFW, obtains the certificates,
and prints the agent authentication command. The full manual systemd path is
in [deploy/README.md](deploy/README.md).

To remove the edge later, run this from the VPS checkout:

~~~
sudo ./deploy/uninstall.sh
~~~

This removes the service, binary, and secrets while preserving certificate
state by default. See [deploy/README.md](deploy/README.md#uninstalling) for
the optional state and firewall cleanup flags.

Running your own edge (`ngstoned`) requires:

- A VPS with a public IP (any cheap Linux box works — see
  [deploy/README.md](deploy/README.md) for a systemd unit).
- A domain you control.
- Two DNS records pointed at the VPS's IP: the apex (`example.com`) and the
  wildcard (`*.example.com`).

If you're using Cloudflare, **both records must be "DNS only" (grey cloud),
not proxied.** Cloudflare's proxy only forwards a fixed set of ports and does
not forward `:4443` (the control-plane port the agent dials), so an
orange-cloud record will break the agent's connection to the edge even though
`:443` traffic looks fine. This is the single most common way to get this
setup wrong.

Full setup instructions — DNS, the Cloudflare API token scoped for DNS-01,
the systemd unit, staging-vs-production ACME, and deploying new builds — are
in [deploy/README.md](deploy/README.md).

## Architecture, in brief

The agent always dials out to the edge and never listens for inbound
connections, so there's nothing to open on your home firewall or NAT. That
one TCP connection is upgraded to TLS and then carries a single
[yamux](https://github.com/hashicorp/yamux) session for the whole tunnel's
lifetime; every proxied HTTP request gets its own yamux stream inside that
session, opened by the edge and read by the agent. Certificates for both the
apex and the wildcard are issued and renewed automatically via
[certmagic](https://github.com/caddyserver/certmagic) using the DNS-01
challenge, so no ports need to be exposed for ACME HTTP-01 validation.

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
