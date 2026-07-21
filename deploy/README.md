# Deploying ngstoned

## DNS records

Two records in the `ngstone.site` zone, both proxy status "DNS only" (grey cloud) since Cloudflare's proxy would break the TLS termination and the agent's persistent yamux connection:

| Type | Name | Value |
|---|---|---|
| A (or AAAA) | `ngstone.site` | the VPS's public IP |
| A (or AAAA) | `*.ngstone.site` | the VPS's public IP |

## Cloudflare API token

Create a scoped token, not the Global API Key:

1. Cloudflare dashboard -> My Profile -> API Tokens -> Create Token -> Custom Token.
2. Permissions: `Zone` / `DNS` / `Edit`.
3. Zone Resources: `Include` / `Specific zone` / `ngstone.site` only.
4. No other permissions, no other zones.

This token can create and delete `_acme-challenge` TXT records in the one zone and nothing else — it cannot read other zones, change nameservers, or touch account-level settings.

## Environment

`ngstoned` reads its Cloudflare token from `-cf-api-token` or `$NGSTONE_CF_API_TOKEN`. Create `/etc/ngstoned/env` (mode 0600, owned by root, referenced by the unit's `EnvironmentFile=`):

```
NGSTONE_TOKEN_SHA256=<sha256 of the agent auth token, hex, from `ngstone token new`>
NGSTONE_CERT_EMAIL=<your email, required by Let's Encrypt>
NGSTONE_CF_API_TOKEN=<the scoped Cloudflare token above>
```

The agent side needs the plaintext token in `$NGSTONE_TOKEN` on the laptop; it is never written to disk on the VPS, only its SHA-256 is.

Secrets must only ever reach `ngstoned` through `EnvironmentFile=`, never through `ExecStart` flags: `/proc/<pid>/cmdline` is world-readable, so any local user can read a flag value with `ps auxww`, but not the process's environment. `ngstoned` reads `$NGSTONE_TOKEN_SHA256` and `$NGSTONE_CF_API_TOKEN` in preference to the equivalent `-token-sha256`/`-cf-api-token` flags for exactly this reason — do not add those flags to the unit's `ExecStart`. The agent has the same exposure: prefer `$NGSTONE_TOKEN` over `-token` whenever the agent runs somewhere another local user could run `ps`.

## Staging -> production promotion

`-acme-ca` defaults to `staging` and must stay that way until the whole pipeline (DNS, token, systemd unit) is verified working. Let's Encrypt staging certs are not trusted by browsers but exercise the exact same code path, so a mistake there costs nothing. Once `systemctl status ngstoned` shows both certificates loaded and `/healthz` (via `ssh -L 4041:127.0.0.1:4041`) reports sane `not_after` dates, flip the unit's `ExecStart` (or environment) to `-acme-ca production` and restart. Do **not** delete the staging-issued certs first: certmagic namespaces on-disk storage per issuer (`certificates/<issuer-key>/<domain>/`), so the staging and production certs live in separate subtrees and cannot collide or shadow one another — the new `-acme-ca production` config simply starts issuing (and serving) certs from its own subtree. Deleting the staging tree also deletes the ACME account key stored alongside it, which only forces an unnecessary re-registration; it buys nothing. Production Let's Encrypt has real rate limits (5 duplicate certs/week per exact name set) — do not bounce between staging and production repeatedly against the same names.

Also do not swap the libdns DNS provider (`github.com/libdns/cloudflare`) without re-verifying delete semantics first. The pinned `libdns/cloudflare@v0.2.2` deletes `_acme-challenge` TXT records filtered by record content, so the apex and wildcard certs' concurrent ACME challenges under `_acme-challenge.ngstone.site` don't clobber each other mid-renewal. A provider that deletes by name+type instead of by content would race the two challenges and could break renewal of both certs simultaneously.

## Installing the unit

```
sudo cp deploy/ngstoned.service /etc/systemd/system/ngstoned.service
sudo mkdir -p /etc/ngstoned
sudo chmod 700 /etc/ngstoned
sudo $EDITOR /etc/ngstoned/env   # see above
sudo systemctl daemon-reload
sudo systemctl enable --now ngstoned
```

`StateDirectory=ngstoned` makes systemd create `/var/lib/private/ngstoned` (with a `/var/lib/ngstoned` symlink) and `chown` it to whichever dynamic UID/GID the service gets on that start, every start — the numeric UID itself is not guaranteed to stay the same across restarts, but the directory ownership is fixed up automatically each time so the service can always read and write it. This only works because `StateDirectory=` is used instead of a manual `ReadWritePaths=`; the latter gets no such ownership handling from systemd and would leave the cert cache unreadable by a freshly assigned dynamic user, silently losing it — and therefore burning a Let's Encrypt issuance — on every single restart. `AmbientCapabilities=CAP_NET_BIND_SERVICE` lets the otherwise-unprivileged dynamic user bind `:80`/`:443`.

## Deploying a new build

```
make deploy DEPLOY_HOST=ngstone.site DEPLOY_USER=root
```

Cross-compiles `linux/amd64`, copies the new `ngstoned` binary over, and restarts the unit. The agent binary (`ngstone`) ships to the laptop separately (`make cross` and copy `bin/linux_amd64/ngstone`, or `make build` for a macOS binary of the same source).

## Verifying

```
ssh -L 4041:127.0.0.1:4041 root@ngstone.site
curl http://127.0.0.1:4041/healthz
```

reports both certificates' `not_after` separately. A restart (`systemctl restart ngstoned`, three times in a row) should show no new ACME traffic in the logs — the certs load from the `StateDirectory` cache.
