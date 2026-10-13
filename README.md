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

Save the auth token it prints; only its hash is stored on the VPS. When the
health output shows both certificates, switch to trusted certificates. The
token and credentials are kept:

```
sudo ./deploy/install-edge.sh --acme-ca production
```

Useful options:

- `--tcp-ports 10000-10100` enables raw TCP tunnels on that range and opens
  it in UFW.
- `--from-source` builds `ngstoned` from the checkout instead of downloading
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

To remove the edge later, run `sudo ./deploy/uninstall.sh` from the checkout.
It keeps certificate state by default; see
[deploy/README.md](deploy/README.md#uninstalling) for the cleanup options.

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
