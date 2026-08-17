import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { Card, CardGrid } from "@/components/docs/card"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"
import { Step, Steps } from "@/components/docs/steps"

export const metadata: Metadata = {
  title: "Running the edge on a VPS",
  description: "Stand up ngstoned on a Linux server with TLS.",
}

const TOC: TocItem[] = [
  { id: "fast-path", title: "Fast path installer" },
  { id: "uninstalling", title: "Uninstalling" },
  { id: "prerequisites", title: "Prerequisites" },
  { id: "dns-records", title: "DNS records" },
  { id: "cloudflare-token", title: "The Cloudflare API token" },
  { id: "two-certificates", title: "Two certificates, not one" },
  { id: "auth-token", title: "Generating an auth token" },
  { id: "install-the-binary", title: "Installing the binary" },
  { id: "systemd-unit", title: "Running it under systemd" },
  { id: "firewall", title: "Firewall" },
  { id: "tcp-tunnels", title: "TCP tunnels" },
  { id: "behind-a-proxy", title: "Behind an existing reverse proxy" },
  { id: "connect-an-agent", title: "Connecting an agent" },
  { id: "troubleshooting", title: "Troubleshooting" },
]

export default function EdgeVpsPage() {
  return (
    <DocsArticle href="/docs/guides/edge-vps" toc={TOC}>
      <h1>Running the edge on a VPS</h1>
      <p>
        <code>ngstoned</code> is the half of ngstone that lives on the public
        internet. This is a runbook: work top to bottom on a fresh Linux
        server and you end with a managed service holding valid
        certificates, an open control plane, and an agent tunnelling through
        it. <code>example.com</code> stands in for your domain throughout.
      </p>

      <Anchor id="fast-path">Fast path installer</Anchor>
      <p>
        On a fresh Ubuntu or Debian VPS, create the apex and wildcard DNS
        records first, then install the edge from a checkout. The installer
        downloads the release binary, verifies its checksum, creates the
        root-only secrets file, installs the hardened systemd unit, configures
        UFW, and starts <code>ngstoned</code>:
      </p>
      <CodeBlock
        language="bash"
        code={`$ git clone https://github.com/emilio-kariuki/ngstone.git /opt/ngstone
$ cd /opt/ngstone
$ sudo ./deploy/install-edge.sh \\
    --domain example.com \\
    --email you@example.com \\
    --acme-ca production`}
      />
      <p>
        It prompts for a narrowly scoped Cloudflare DNS token without
        echoing it, and prints the generated agent token once. Use{" "}
        <code>--acme-ca staging</code> while validating DNS and promote to{" "}
        <code>production</code> after the health check passes. The installer
        does not create DNS records, so the apex and wildcard must already
        resolve to the VPS.
      </p>

      <Anchor id="uninstalling">Uninstalling</Anchor>
      <p>
        From the checkout, remove the service, binary, and root-only secrets:
      </p>
      <CodeBlock
        language="bash"
        code={`$ sudo ./deploy/uninstall.sh`}
      />
      <p>
        Certificate and ACME state is preserved by default under{" "}
        <code>/var/lib/private/ngstoned</code>, so a later reinstall can reuse
        it. To delete that state and remove matching public UFW allow rules,
        opt in explicitly:
      </p>
      <CodeBlock
        language="bash"
        code={`$ sudo ./deploy/uninstall.sh --remove-state --remove-firewall-rules`}
      />
      <Callout variant="warning" title="SSH access is kept">
        The firewall option removes matching allow rules for only{" "}
        <code>80/tcp</code>, <code>443/tcp</code>, and <code>4443/tcp</code>.
        SSH rules and the source checkout are left in place. If another
        service uses the same allow rule, review it before selecting this
        option. Use <code>--yes</code> only for a deliberate non-interactive
        uninstall.
      </Callout>

      <Anchor id="prerequisites">Prerequisites</Anchor>
      <Steps>
        <Step title="A Linux VPS with a public IP">
          Anything that runs a static Go binary. It needs a stable public
          address — every DNS record below points at it — and root or{" "}
          <code>sudo</code> for installing a systemd unit and binding
          privileged ports.
        </Step>
        <Step title="A domain you control">
          A registered domain, here <code>example.com</code>. Tunnels get
          hostnames one label below it, such as{" "}
          <code>amber-fox-42.example.com</code>.
        </Step>
        <Step title="The zone hosted on Cloudflare">
          Certificates are issued through the ACME DNS-01 challenge, and{" "}
          <code>github.com/libdns/cloudflare</code> is the only DNS provider
          compiled into <code>ngstoned</code>. The domain&apos;s nameservers
          must therefore point at Cloudflare and the zone must be active
          there before anything below will work.
        </Step>
        <Step title="A machine to run the agent">
          Your laptop, with the <code>ngstone</code> binary installed — see{" "}
          <a href="/docs/installation">Installation</a>.
        </Step>
      </Steps>

      <Anchor id="dns-records">DNS records</Anchor>
      <p>
        Create two records in the <code>example.com</code> zone, both
        pointing at the VPS&apos;s public IP.
      </p>
      <ParamTable>
        <Property name="example.com" type="A record" required>
          The apex. Backs the control plane on port <code>4443</code>, which
          is what the agent dials, and the apex certificate that secures it.
        </Property>
        <Property name="*.example.com" type="A record" required>
          The wildcard. This is what makes per-tunnel hostnames resolve:
          the edge invents names like <code>amber-fox-42.example.com</code>{" "}
          at bind time and never touches DNS, so every possible tunnel name
          has to already resolve to the VPS through this one record.
        </Property>
      </ParamTable>
      <p>
        Use <code>AAAA</code> instead if the VPS is IPv6-only, or add both.
      </p>
      <Callout variant="warning" title="Set both records to DNS only (grey cloud)">
        Cloudflare&apos;s orange-cloud proxy terminates TLS itself and will
        not carry the agent&apos;s long-lived control connection on{" "}
        <code>:4443</code>. <code>ngstoned</code> terminates its own TLS;
        proxying in front of it breaks both certificate validation and the
        tunnel.
      </Callout>

      <Anchor id="cloudflare-token">The Cloudflare API token</Anchor>
      <p>
        The edge needs to create and delete <code>_acme-challenge</code> TXT
        records in the one zone. Create a scoped API token for exactly that
        — never the Global API Key, which authenticates everything on the
        account.
      </p>
      <Steps>
        <Step title="Open the token editor">
          Cloudflare dashboard → My Profile → API Tokens → Create Token →
          Custom Token.
        </Step>
        <Step title="Grant one permission">
          <code>Zone</code> / <code>DNS</code> / <code>Edit</code>. Nothing
          else.
        </Step>
        <Step title="Scope it to one zone">
          Zone Resources: <code>Include</code> / <code>Specific zone</code> /{" "}
          <code>example.com</code>. Not &ldquo;All zones&rdquo;.
        </Step>
        <Step title="Keep the value">
          Cloudflare shows the token once. It goes into the edge&apos;s
          environment file as <code>NGSTONE_CF_API_TOKEN</code> below.
        </Step>
      </Steps>
      <p>
        A token scoped this way can write challenge records in one zone and
        nothing more — it cannot read other zones, change nameservers, or
        touch account settings. If it leaks, the blast radius is one
        zone&apos;s DNS.
      </p>

      <Anchor id="two-certificates">Two certificates, not one</Anchor>
      <p>
        <code>ngstoned</code> calls{" "}
        <code>
          ManageSync(ctx, [&quot;*.example.com&quot;,
          &quot;example.com&quot;])
        </code>{" "}
        once, which reads like a single multi-domain certificate. It is not.
        certmagic does not obtain multi-SAN certificates: that call places
        two independent ACME orders and produces two certificates with two
        independent renewal schedules.
      </p>
      <p>
        This is forced anyway, because a wildcard covers exactly one
        left-most label (RFC 6125) — <code>*.example.com</code> does{" "}
        <em>not</em> match SNI <code>example.com</code>. The wildcard serves
        public tunnel traffic on <code>:443</code>; the apex certificate
        serves the control plane on <code>:4443</code>, where agents connect.
        Both names validate through the same{" "}
        <code>_acme-challenge.example.com</code> TXT record.
      </p>
      <Callout variant="warning" title="A healthy wildcard can hide a dead apex">
        If the apex order fails while the wildcard renews fine, public
        traffic looks perfect and <em>no agent can connect</em>.{" "}
        <code>ngstoned</code> checks at startup that an apex certificate is
        loadable with at least 24 hours of life left before accepting on{" "}
        <code>:4443</code>, and exits loudly rather than listening with a
        certificate it cannot serve. <code>/healthz</code> reports each
        certificate&apos;s expiry separately — check both, not just one.
      </Callout>

      <Anchor id="auth-token">Generating an auth token</Anchor>
      <Callout variant="note" title="There is no ngstone token command">
        Token generation is a shell one-liner, not a CLI verb. The edge only
        ever stores the SHA-256 hash; the plaintext lives on machines
        running the agent and never touches the VPS disk.
      </Callout>
      <CodeBlock
        language="bash"
        code={`$ TOKEN=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
$ HASH=$(printf '%s' "$TOKEN" | shasum -a 256 | cut -d' ' -f1)   # sha256sum on Linux
$ echo "$TOKEN"   # keep this for 'ngstone auth' on the agent machine
$ echo "$HASH"    # this goes to the edge`}
      />
      <p>
        The hash must be 64 hex characters; <code>ngstoned</code> refuses to
        start otherwise. There is exactly one token per edge — rotating it
        means changing the hash and restarting, which invalidates every
        agent at once.
      </p>
      <p>
        The edge reads three values from its environment. Put them in{" "}
        <code>/etc/ngstoned/env</code>, mode <code>0600</code>, owned by
        root:
      </p>
      <CodeBlock
        filename="/etc/ngstoned/env"
        language="ini"
        code={`NGSTONE_TOKEN_SHA256=3b1f0c2d…64 hex characters…9a7e
NGSTONE_CERT_EMAIL=you@example.com
NGSTONE_CF_API_TOKEN=cf_fake_token_value_goes_here`}
      />
      <ParamTable>
        <Property name="NGSTONE_TOKEN_SHA256" type="env" required>
          Hex SHA-256 of the auth token. Equivalent flag{" "}
          <code>-token-sha256</code>; the environment wins when both are
          set.
        </Property>
        <Property name="NGSTONE_CF_API_TOKEN" type="env" required>
          The scoped Cloudflare token. Equivalent flag{" "}
          <code>-cf-api-token</code>; the environment wins when both are
          set.
        </Property>
        <Property name="NGSTONE_CERT_EMAIL" type="env" required>
          Not read by <code>ngstoned</code> directly — the unit interpolates
          it into <code>-cert-email</code>, which is required unless{" "}
          <code>-insecure</code>. It is the ACME account contact, not a
          secret.
        </Property>
      </ParamTable>
      <Callout variant="danger" title="Never pass secrets as ExecStart flags">
        <code>/proc/&lt;pid&gt;/cmdline</code> is world-readable, so any
        local user can read a flag value with <code>ps auxww</code> — but
        not the process environment. That is precisely why{" "}
        <code>ngstoned</code> prefers <code>$NGSTONE_TOKEN_SHA256</code> and{" "}
        <code>$NGSTONE_CF_API_TOKEN</code> over their flags. Keep both out
        of <code>ExecStart</code>.
      </Callout>

      <Anchor id="install-the-binary">Installing the binary</Anchor>
      <p>
        Release archives contain both binaries — <code>ngstone</code> and{" "}
        <code>ngstoned</code>. On the VPS, download the archive matching its
        architecture, verify the checksum, and install the edge binary:
      </p>
      <CodeBlock
        language="bash"
        code={`$ VERSION=v0.2.0
$ ARCHIVE=ngstone_linux_amd64.tar.gz   # ngstone_linux_arm64.tar.gz on arm64
$ BASE=https://github.com/emilio-kariuki/ngstone/releases/download/$VERSION
$ curl -fsSLO "$BASE/$ARCHIVE"
$ curl -fsSLO "$BASE/checksums.txt"
$ sha256sum --ignore-missing -c checksums.txt
$ tar -xzf "$ARCHIVE" ngstoned
$ sudo install -m 0755 ngstoned /usr/local/bin/ngstoned
$ ngstoned -version`}
      />

      <Anchor id="systemd-unit">Running it under systemd</Anchor>
      <p>
        Install the unit, create the environment file from the section
        above, and start the service:
      </p>
      <CodeBlock
        filename="/etc/systemd/system/ngstoned.service"
        language="ini"
        code={`[Unit]
Description=ngstoned edge server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ngstoned \\
    -domain example.com \\
    -cert-email \${NGSTONE_CERT_EMAIL} \\
    -acme-ca staging \\
    -cert-storage \${STATE_DIRECTORY}/certs
EnvironmentFile=/etc/ngstoned/env
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
WantedBy=multi-user.target`}
      />
      <CodeBlock
        language="bash"
        code={`$ sudo mkdir -p /etc/ngstoned && sudo chmod 700 /etc/ngstoned
$ sudo $EDITOR /etc/ngstoned/env
$ sudo chmod 600 /etc/ngstoned/env
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now ngstoned
$ systemctl status ngstoned`}
      />
      <p>
        <code>DynamicUser=yes</code> gives the service a transient,
        unprivileged UID allocated fresh on every start, and{" "}
        <code>AmbientCapabilities=CAP_NET_BIND_SERVICE</code> lets that
        unprivileged user still bind <code>:80</code> and <code>:443</code>.
        The certificate cache has to survive across those changing UIDs,
        which is what <code>StateDirectory=ngstoned</code> is for: systemd
        creates <code>/var/lib/private/ngstoned</code> (with a{" "}
        <code>/var/lib/ngstoned</code> symlink) and re-<code>chown</code>s it
        to the current UID on every start. Point{" "}
        <code>-cert-storage</code> at <code>{"${STATE_DIRECTORY}"}/certs</code>{" "}
        so the two always agree.
      </p>
      <Callout variant="danger" title="Do not substitute ReadWritePaths= for StateDirectory=">
        <code>ReadWritePaths=</code> gets no ownership handling from
        systemd, so a freshly assigned dynamic user cannot read the existing
        cache. The certificates are silently lost and re-issued on{" "}
        <em>every restart</em>, burning Let&apos;s Encrypt rate limits until
        issuance starts failing.
      </Callout>
      <p>
        <code>-acme-ca</code> defaults to <code>staging</code> and the unit
        above keeps it there deliberately. Staging certificates are not
        trusted by browsers but exercise the identical code path, so a
        misconfiguration costs nothing. Once{" "}
        <code>systemctl status ngstoned</code> is clean and{" "}
        <code>/healthz</code> reports sane expiry dates for both
        certificates, switch the unit to <code>-acme-ca production</code> and
        restart. Do not delete the staging certificates first — certmagic
        namespaces storage per issuer, so the two live in separate subtrees
        and cannot collide.
      </p>

      <Anchor id="firewall">Firewall</Anchor>
      <p>
        Four listeners, three of them public. The addresses below are the
        defaults; each has a flag if you need to move it.
      </p>
      <ParamTable>
        <Property name="-public" type="string" defaultValue=":443">
          Public HTTPS. Must be reachable from the internet — this is where
          tunnel traffic lands.
        </Property>
        <Property name="-control" type="string" defaultValue=":4443">
          Control plane. Must be reachable from wherever agents run. Serves
          the apex certificate.
        </Property>
        <Property name="-http" type="string" defaultValue=":80">
          Plain HTTP, which only issues <code>301</code> redirects to HTTPS.
          DNS-01 means no ACME traffic ever arrives here, so you can close
          it if you do not want the redirect.
        </Property>
        <Property name="-ops" type="string" defaultValue="127.0.0.1:4041">
          <code>expvar</code>, <code>/healthz</code>, and pprof. Loopback
          only — never open this port. Reach it over an SSH tunnel instead.
          An empty value disables it.
        </Property>
      </ParamTable>
      <CodeBlock
        language="bash"
        code={`$ sudo ufw allow 443/tcp
$ sudo ufw allow 4443/tcp
$ sudo ufw allow 80/tcp
$ sudo ufw enable`}
      />

      <Anchor id="tcp-tunnels">TCP tunnels</Anchor>
      <p>
        Off by default. An operator opts in with <code>-tcp-ports</code>,
        which lets agents run <code>ngstone tcp</code> — see{" "}
        <a href="/docs/guides/tcp-tunnels">TCP tunnels</a> for the
        client-side guide.
      </p>
      <ParamTable>
        <Property name="-tcp-ports" type="string">
          Port range for raw TCP tunnels, e.g. <code>10000-10999</code>.
          Empty disables TCP tunnels.
        </Property>
        <Property name="-tcp-bind" type="string" defaultValue="0.0.0.0">
          Interface address the TCP tunnel port range binds on.
        </Property>
      </ParamTable>
      <Callout variant="danger" title="This range bypasses Traefik entirely">
        Ports in <code>-tcp-ports</code> are bound directly by{" "}
        <code>ngstoned</code> — real listeners, not routed through the{" "}
        <code>:443</code> reverse proxy or any front proxy sitting in front
        of it. The range needs its own firewall opening, the same way{" "}
        <code>443/tcp</code> does above:
      </Callout>
      <CodeBlock
        language="bash"
        code={`$ sudo ufw allow 10000:10999/tcp`}
      />

      <Anchor id="behind-a-proxy">Behind an existing reverse proxy</Anchor>
      <p>
        Skip this section if <code>ngstoned</code> owns <code>:443</code>{" "}
        directly. If something else already holds that port, the edge still
        has to terminate its own TLS — it serves certificates it manages
        itself — so the proxy must pass the connection through at the TCP
        layer rather than terminating it. With Traefik that is an SNI-routed
        TCP router with <code>tls.passthrough</code>:
      </p>
      <CodeBlock
        filename="traefik dynamic configuration"
        language="yaml"
        code={`tcp:
  routers:
    ngstoned:
      entryPoints:
        - websecure
      rule: "HostSNIRegexp(\`^.+\\\\.example\\\\.com$\`)"
      tls:
        passthrough: true
      service: ngstoned
  services:
    ngstoned:
      loadBalancer:
        proxyProtocol:
          version: 2
        servers:
          - address: "ngstoned:443"`}
      />
      <p>
        Passthrough is not transparent at the TCP layer. Traefik accepts the
        browser&apos;s connection and opens a <em>new</em> one to{" "}
        <code>ngstoned</code>, so without further configuration the edge
        sees the proxy&apos;s address as the client address — often a
        private one such as <code>10.0.1.69</code>. Every{" "}
        <code>X-Forwarded-For</code> the edge stamps is then wrong, the local
        app cannot trust the forwarding headers, and the per-IP rate limiter
        collapses the entire internet into one shared bucket, so a single
        abusive client either escapes limiting or locks everyone out.
      </p>
      <p>
        The fix is the PROXY protocol: the proxy prefixes each connection
        with the original endpoints and the edge uses them as the client
        address. That is the <code>proxyProtocol.version: 2</code> block
        above, plus <code>-proxy-protocol</code> on the edge:
      </p>
      <CodeBlock
        language="ini"
        code={`ExecStart=/usr/local/bin/ngstoned -proxy-protocol -public 127.0.0.1:443 ...`}
      />
      <Callout variant="danger" title="Both sides must change together">
        With <code>-proxy-protocol</code> on, the edge rejects any
        connection to the public listener that does not begin with a valid
        PROXY header; with it off, a proxy that sends one produces a TLS
        handshake failure. Enabling either side alone breaks every public
        request. Change the unit and the Traefik service in the same
        deployment.
      </Callout>
      <Callout variant="warning" title="The public port must then be reachable only from the proxy">
        Whoever can open a TCP connection to that port chooses the client IP
        the edge logs, stamps into <code>X-Forwarded-For</code>, and
        rate-limits on. Bind the public listener to the proxy-facing
        interface only (<code>-public 127.0.0.1:443</code>, or a Docker
        network address) and make sure no firewall rule exposes it. Leaving
        the flag off — the default — preserves the normal behaviour exactly.
      </Callout>
      <p>
        If binding to a loopback/Docker-only address isn&apos;t possible,{" "}
        <code>-proxy-protocol-trusted</code> restricts which peers the edge
        accepts a PROXY header from — it closes the connection immediately
        if the socket&apos;s real peer address isn&apos;t in the list,
        before even trying to parse a header:
      </p>
      <CodeBlock
        language="ini"
        code={`ExecStart=/usr/local/bin/ngstoned -proxy-protocol -proxy-protocol-trusted 10.0.1.69/32 ...`}
      />
      <p>
        This also matters for per-tunnel <code>--allow-cidr</code> (see{" "}
        <a href="/docs/guides/access-control">Access control</a>): that
        check trusts whatever the edge believes is the source IP, and behind
        a proxy that&apos;s whatever the PROXY header says. Left empty, the
        edge accepts a PROXY header from any peer, so a direct client could
        forge one and spoof its way past an allowlist unless the public port
        is firewalled to the proxy alone.
      </p>
      <p>
        The flag applies to the public listener only. Do <strong>not</strong>{" "}
        put the control listener on <code>:4443</code> behind a
        PROXY-protocol proxy: it does not parse the header and every agent
        connection would fail. Version 2 is Traefik&apos;s default when{" "}
        <code>proxyProtocol</code> is present at all; the edge also accepts
        the text-based version 1, and the <code>LOCAL</code> command used by
        health checks, falling back to the real socket address.
      </p>

      <Anchor id="connect-an-agent">Connecting an agent</Anchor>
      <p>
        On the agent machine, point <code>ngstone</code> at your edge and
        hand it the <em>plaintext</em> token. Both flags matter for a custom
        domain: <code>-server</code> is the address to dial, and{" "}
        <code>-server-name</code> is the SNI and certificate name to verify —
        it defaults to <code>ngstone.site</code>, so verification fails
        against any other domain without it.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone auth "$TOKEN" -server example.com:4443 -server-name example.com
verified against example.com:4443 and saved`}
      />
      <p>
        <code>auth</code> persists the token and server address to the
        config file, but not <code>-server-name</code> — pass it again on
        every <code>ngstone port</code> invocation:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone port 3000 -server-name example.com
$ ngstone port 3000 -server-name example.com --subdomain demo`}
      />
      <p>
        The agent prints the assigned URL. Verify it end to end from a third
        machine:
      </p>
      <CodeBlock
        language="bash"
        code={`$ curl -i https://demo.example.com/
HTTP/2 200`}
      />
      <Callout variant="note" title="Staging certificates fail curl">
        While <code>-acme-ca staging</code> is in effect the chain is not in
        any trust store, so <code>curl</code> reports an unknown issuer. Use{" "}
        <code>curl -k</code> to confirm routing works, then promote to{" "}
        <code>production</code> for a certificate real clients accept.
      </Callout>

      <Anchor id="troubleshooting">Troubleshooting</Anchor>
      <p>Everything the edge does is logged to the journal:</p>
      <CodeBlock
        language="bash"
        code={`$ journalctl -u ngstoned -f
$ journalctl -u ngstoned -n 200 --no-pager`}
      />
      <p>
        The ops endpoint is loopback-only by design; reach it over SSH.{" "}
        <code>/healthz</code> reports the apex and wildcard expiry
        separately, which is the fastest way to tell a half-working
        certificate state from a healthy one:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ssh -L 4041:127.0.0.1:4041 root@example.com
$ curl http://127.0.0.1:4041/healthz`}
      />
      <ParamTable>
        <Property name="Certificate issuance fails" type="startup">
          Check that both DNS records exist and have propagated, that the
          zone is actually served by Cloudflare, and that the API token has{" "}
          <code>Zone:DNS:Edit</code> on <em>this</em> zone. A token scoped to
          the wrong zone fails at the TXT-record write, which the log names
          explicitly.
        </Property>
        <Property name="The service exits at startup" type="startup">
          The apex certificate check runs before <code>:4443</code> accepts
          connections and fails loudly if no apex certificate is loadable
          with 24 hours of life remaining. Fix issuance first; the wildcard
          being healthy proves nothing about the apex.
        </Property>
        <Property name="ngstoned refuses to start with no ACME traffic" type="config">
          <code>-token-sha256</code> (or{" "}
          <code>$NGSTONE_TOKEN_SHA256</code>) is required always, and{" "}
          <code>-cert-email</code> plus <code>-cf-api-token</code> are
          required unless <code>-insecure</code>. Each missing value is
          named in a single error line before exit.
        </Property>
        <Property name="rejected this token" type="agent">
          The agent hashed a different string than the edge was given.
          Re-derive the hash from the exact plaintext — a trailing newline
          from <code>echo</code> instead of <code>printf</code> is the usual
          cause — and confirm the edge picked up the new value with a
          restart.
        </Property>
        <Property name="could not reach ..." type="agent">
          Port <code>4443</code> is closed, or the agent is dialling the
          wrong host. Confirm the firewall rule and the saved address with{" "}
          <code>ngstone config get server</code>.
        </Property>
        <Property name="TLS handshake failures from the agent" type="agent">
          Usually a missing <code>-server-name example.com</code>: the
          default SNI is <code>ngstone.site</code>, which the apex
          certificate does not cover. It is also what a staging-issued apex
          certificate looks like from a client with a normal trust store.
        </Property>
      </ParamTable>
      <p>
        Restarting three times in a row should produce no new ACME traffic
        in the logs. If it does, the certificate cache is not persisting and
        the <code>StateDirectory</code> configuration is wrong.
      </p>

      <CardGrid columns={2}>
        <Card title="Deployment & systemd" href="/docs/operations/deployment-systemd">
          More on DynamicUser, ambient capabilities, and restart behaviour.
        </Card>
        <Card title="TLS & certificates" href="/docs/reference/tls-certificates">
          How DNS-01, certmagic, and the two-certificate split fit together.
        </Card>
      </CardGrid>
    </DocsArticle>
  )
}
