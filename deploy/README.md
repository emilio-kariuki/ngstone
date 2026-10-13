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

The script prompts for the DNS provider's credentials without echoing them
(see [DNS provider credentials](#dns-provider-credentials)). It downloads and
verifies the edge binary, generates the tunnel auth token, creates the
root-only environment file, installs the hardened systemd unit, configures
UFW, checks DNS, starts `ngstoned`, and prints the laptop commands. Once the
health output shows both certificates, rerun it with only
`--acme-ca production`; the domain, provider, credentials and token are kept.

Other options: `--tcp-ports MIN-MAX` enables raw TCP tunnels and opens that
range in UFW (`--tcp-ports off` removes it), and `--from-source` builds
`ngstoned` from the checkout with Go instead of downloading a release. A
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

## Uninstalling

From the checkout on the VPS, remove the service, binary, and root-only
secrets with a confirmation prompt:

```
sudo ./deploy/uninstall.sh
```

The default uninstall preserves the certificate and ACME account state under
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

Two records in your zone, here `example.com`. On Cloudflare both must be proxy status "DNS only" (grey cloud), since Cloudflare's proxy would break the TLS termination and the agent's persistent yamux connection:

| Type        | Name            | Value               |
| ----------- | --------------- | ------------------- |
| A (or AAAA) | `example.com`   | the VPS's public IP |
| A (or AAAA) | `*.example.com` | the VPS's public IP |

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

Create `/etc/ngstoned/env` (mode 0600, owned by root, referenced by the unit's `EnvironmentFile=`). It holds the token hash, the ACME email and your DNS provider's variables, for example for Cloudflare:

```
NGSTONE_TOKEN_SHA256=<sha256 of the agent auth token, hex>
NGSTONE_CERT_EMAIL=<your email, required by Let's Encrypt>
NGSTONE_CF_API_TOKEN=<the scoped Cloudflare token above>
```

Generate the token pair on the laptop: `token=$(openssl rand -base64 32)` produces the plaintext the agent authenticates with (`ngstone auth "$token"`), and `printf %s "$token" | shasum -a 256 | cut -d' ' -f1` produces the hex digest that goes in `NGSTONE_TOKEN_SHA256`. The plaintext token is never written to disk on the VPS, only its SHA-256 is.

Secrets must only ever reach `ngstoned` through `EnvironmentFile=`, never through `ExecStart` flags: `/proc/<pid>/cmdline` is world-readable, so any local user can read a flag value with `ps auxww`, but not the process's environment. `ngstoned` reads `$NGSTONE_TOKEN_SHA256` and `$NGSTONE_CF_API_TOKEN` in preference to the equivalent `-token-sha256`/`-cf-api-token` flags for exactly this reason, and other providers' credentials have no flags at all — do not add those flags to the unit's `ExecStart`. The agent has the same exposure: prefer `$NGSTONE_TOKEN` over `-token` whenever the agent runs somewhere another local user could run `ps`.

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

reports both certificates' `not_after` separately. A restart (`systemctl restart ngstoned`, three times in a row) should show no new ACME traffic in the logs — the certs load from the `StateDirectory` cache.
