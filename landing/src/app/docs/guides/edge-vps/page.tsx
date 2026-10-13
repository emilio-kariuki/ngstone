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
  { id: "dns-provider", title: "Choosing a DNS provider" },
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
        records first and create an API credential for your{" "}
        <a href="#dns-provider">DNS provider</a>, then install the edge from
        a checkout. The installer downloads the release binary, verifies its
        checksum, creates the root-only secrets file, installs the hardened
        systemd unit, configures UFW, and starts <code>ngstoned</code>:
      </p>
      <CodeBlock
        language="bash"
        code={`$ git clone https://github.com/emilio-kariuki/ngstone.git /opt/ngstone
$ cd /opt/ngstone
$ sudo ./deploy/install-edge.sh \\
    --domain example.com \\
    --email you@example.com \\
    --dns-provider cloudflare \\
    --acme-ca staging`}
      />
      <p>
        It prompts for the chosen provider&apos;s credentials without
        echoing them, and prints the generated agent token once — save it,
        since only its hash is stored on the VPS. The installer does not
        create DNS records, so the apex and wildcard must already resolve to
        the VPS. Once the health output shows both certificates, switch to
        trusted certificates:
      </p>
      <CodeBlock
        language="bash"
        code={`$ sudo ./deploy/install-edge.sh --acme-ca production`}
      />
      <p>
        A rerun with only <code>--acme-ca production</code> keeps the
        domain, email, DNS provider, credentials, TCP port range, and auth
        token from the existing installation. The installer then prints the
        laptop commands, which connect to the bare domain,{" "}
        <code>example.com:4443</code>.
      </p>
      <ParamTable>
        <Property name="--domain" type="string" required>
          Public base domain. Tunnels get hostnames one label below it.
        </Property>
        <Property name="--email" type="string" required>
          Let&apos;s Encrypt account email.
        </Property>
        <Property name="--dns-provider" type="string" defaultValue="cloudflare">
          DNS host for the certificate challenges; see{" "}
          <a href="#dns-provider">Choosing a DNS provider</a>. The installer
          prompts for that provider&apos;s credentials.
        </Property>
        <Property name="--acme-ca" type="string" defaultValue="staging">
          <code>staging</code> or <code>production</code>. Start with{" "}
          <code>staging</code>, then promote; neither browsers nor the agent
          trust staging certificates. A rerun keeps the current value.
        </Property>
        <Property name="--tcp-ports" type="MIN-MAX">
          Enable raw <a href="#tcp-tunnels">TCP tunnels</a> on this range,
          e.g. <code>10000-10100</code>. Adds <code>-tcp-ports</code> to the
          unit and opens the range in UFW; the range is kept across reruns
          and <code>--tcp-ports off</code> removes it. It must lie within{" "}
          <code>1024-65535</code> and must not include <code>4443</code>.
        </Property>
        <Property name="--from-source" type="bool">
          Build <code>ngstoned</code> from the checkout with Go instead of
          downloading a release. Needed for providers other than Cloudflare
          until a release that includes them is published; the installer
          refuses to install a binary that does not support the chosen
          provider.
        </Property>
        <Property name="--version" type="string">
          Release to download, for example <code>v0.3.2</code>.
        </Property>
        <Property name="--ssh-port" type="int" defaultValue="22">
          SSH port to keep open in UFW.
        </Property>
        <Property name="--skip-firewall" type="bool">
          Do not configure UFW.
        </Property>
        <Property name="--skip-dns-check" type="bool">
          Do not verify that the apex and wildcard records resolve first.
        </Property>
      </ParamTable>
      <Callout variant="note" title="Passing credentials without a prompt">
        <code>sudo</code> drops variables exported in your shell, so put
        them on the <code>sudo</code> command line instead:{" "}
        <code>sudo NGSTONE_CF_API_TOKEN=... ./deploy/install-edge.sh ...</code>.
        Either way they are stored only in the root-only{" "}
        <code>/etc/ngstoned/env</code>.
      </Callout>

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
        <code>80/tcp</code>, <code>443/tcp</code>, <code>4443/tcp</code>,
        and the TCP tunnel range if one is configured.
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
        <Step title="The zone hosted on a supported DNS provider">
          Certificates are issued through the ACME DNS-01 challenge, so{" "}
          <code>ngstoned</code> needs API access to the zone. The
          domain&apos;s nameservers must point at one of the{" "}
          <a href="#dns-provider">supported providers</a> and the zone must
          be active there before anything below will work.
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
      <Callout variant="warning" title="On Cloudflare, set both records to DNS only (grey cloud)">
        Cloudflare&apos;s orange-cloud proxy terminates TLS itself and will
        not carry the agent&apos;s long-lived control connection on{" "}
        <code>:4443</code>. <code>ngstoned</code> terminates its own TLS;
        proxying in front of it breaks both certificate validation and the
        tunnel.
      </Callout>

      <Anchor id="dns-provider">Choosing a DNS provider</Anchor>
      <p>
        The edge needs to create and delete <code>_acme-challenge</code> TXT
        records in the one zone. Pick the provider that hosts the zone with{" "}
        <code>-dns-provider</code> (default <code>cloudflare</code>) and
        create a credential scoped as tightly as that provider allows.
        Credentials are read from the environment only;{" "}
        <code>ngstoned -dns-provider help</code> lists the providers and the
        variables of the binary you have.
      </p>
      <ParamTable>
        <Property name="cloudflare" type="NGSTONE_CF_API_TOKEN">
          The default. API token with <code>Zone</code> / <code>DNS</code> /{" "}
          <code>Edit</code> on this zone only. See{" "}
          <a href="#cloudflare-token">below</a>.
        </Property>
        <Property
          name="route53"
          type="NGSTONE_AWS_REGION, NGSTONE_AWS_ACCESS_KEY_ID, NGSTONE_AWS_SECRET_ACCESS_KEY"
        >
          An IAM user whose policy allows only{" "}
          <code>route53:ListHostedZonesByName</code>,{" "}
          <code>route53:ListResourceRecordSets</code>,{" "}
          <code>route53:ChangeResourceRecordSets</code>, and{" "}
          <code>route53:GetChange</code>.
        </Property>
        <Property name="digitalocean" type="NGSTONE_DO_API_TOKEN">
          Personal access token with domain read and write scopes.
        </Property>
        <Property name="hetzner" type="NGSTONE_HETZNER_API_TOKEN">
          Read and write API token of the Hetzner Console project that holds
          the zone. Zones still on the deprecated{" "}
          <code>dns.hetzner.com</code> must be migrated first.
        </Property>
        <Property name="vultr" type="NGSTONE_VULTR_API_KEY">
          API key; allow only the VPS&apos;s IP in the key&apos;s access
          control.
        </Property>
        <Property
          name="ovh"
          type="NGSTONE_OVH_ENDPOINT, NGSTONE_OVH_APPLICATION_KEY, NGSTONE_OVH_APPLICATION_SECRET, NGSTONE_OVH_CONSUMER_KEY"
        >
          The endpoint is <code>ovh-eu</code>, <code>ovh-ca</code>, or{" "}
          <code>ovh-us</code>. Limit the consumer key to <code>GET</code>,{" "}
          <code>POST</code>, and <code>DELETE</code> on{" "}
          <code>/domain/zone/*</code>.
        </Property>
        <Property name="desec" type="NGSTONE_DESEC_TOKEN">
          Token from desec.io. deSEC enforces a 3600 s minimum TTL and rate
          limits, so issuance can take a few minutes.
        </Property>
        <Property name="bunny" type="NGSTONE_BUNNY_API_KEY">
          Bunny DNS account API key.
        </Property>
      </ParamTable>
      <Callout variant="warning" title="GoDaddy, Namecheap, Porkbun and others are not supported">
        GoDaddy, Namecheap, Porkbun, IONOS, Azure, DNSimple, and netcup are
        left out deliberately: their <code>libdns</code> modules replace or
        delete every TXT value at a name, and the apex and wildcard
        certificates publish two values at{" "}
        <code>_acme-challenge.example.com</code> at the same time, so one
        issuance would break the other. Keep the registrar and move only the
        DNS hosting to a supported provider by changing the nameservers —
        Cloudflare and deSEC are free.
      </Callout>

      <Anchor id="cloudflare-token">The Cloudflare API token</Anchor>
      <p>
        The default provider, and the example used below. Create a scoped
        API token for exactly the challenge records — never the Global API
        Key, which authenticates everything on the account.
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
        <code>_acme-challenge.example.com</code> TXT record, which is why
        only providers that add and remove challenge values individually
        are supported.
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
        The edge reads the token hash, the ACME email, and your DNS
        provider&apos;s credentials from its environment. Put them in{" "}
        <code>/etc/ngstoned/env</code>, mode <code>0600</code>, owned by
        root — for Cloudflare:
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
          The scoped Cloudflare token. Equivalent legacy flag{" "}
          <code>-cf-api-token</code>; the environment wins when both are
          set. Other providers read the variables listed under{" "}
          <a href="#dns-provider">Choosing a DNS provider</a> instead, and
          have no flags at all.
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
        <code>$NGSTONE_CF_API_TOKEN</code> over their flags, and why other
        providers&apos; credentials can only come from the environment. Keep
        all of them out of <code>ExecStart</code>.
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
      <p>
        <code>-domain</code> is required and has no default. For a DNS host
        other than Cloudflare, add <code>-dns-provider NAME</code> to{" "}
        <code>ExecStart</code> and put that provider&apos;s variables in the
        environment file.
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
          Empty disables TCP tunnels. The installer sets it with{" "}
          <code>--tcp-ports MIN-MAX</code> and opens the range in UFW for
          you.
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
      <p>
        <a href="/docs/guides/database-sharing">Database sharing</a> needs
        none of this: shares ride the control port and open no listener.
        The one edge knob for it is <code>-max-share-ttl</code> (default{" "}
        <code>24h</code>), the longest lifetime <code>ngstone share
        --expires</code> may ask for.
      </p>

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
        hand it the <em>plaintext</em> token. Dial the bare domain: the
        control port serves the apex certificate, and the agent verifies it
        against the host in <code>--server</code>.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone auth "$TOKEN" --server example.com:4443
verified against example.com:4443 and saved`}
      />
      <p>
        <code>auth</code> persists the token and server address to the
        config file, so later commands need no extra flags:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone port 3000
$ ngstone port 3000 --subdomain demo`}
      />
      <Callout variant="note" title="Older agents">
        Agent releases from before <code>--server-name</code> defaulted to
        the <code>--server</code> host verify against{" "}
        <code>ngstone.site</code> instead, and need{" "}
        <code>--server-name example.com</code> on every command.
      </Callout>
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
          zone is actually served by the provider named in{" "}
          <code>-dns-provider</code>, and that the credential can edit{" "}
          <em>this</em> zone — for Cloudflare, <code>Zone:DNS:Edit</code>{" "}
          on it. A credential scoped to the wrong zone fails at the
          TXT-record write, which the log names explicitly.
        </Property>
        <Property name="The service exits at startup" type="startup">
          The apex certificate check runs before <code>:4443</code> accepts
          connections and fails loudly if no apex certificate is loadable
          with 24 hours of life remaining. Fix issuance first; the wildcard
          being healthy proves nothing about the apex.
        </Property>
        <Property name="ngstoned refuses to start with no ACME traffic" type="config">
          <code>-token-sha256</code> (or{" "}
          <code>$NGSTONE_TOKEN_SHA256</code>) and <code>-domain</code> are
          required always, and <code>-cert-email</code> plus the DNS
          provider&apos;s credentials are required unless{" "}
          <code>-insecure</code>. Each missing value is named in a single
          error line before exit; <code>ngstoned -dns-provider help</code>{" "}
          lists the variables each provider reads.
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
          Usually the agent is dialling a name the apex certificate does
          not cover, such as <code>edge.example.com</code> (which older
          installer versions printed) — use <code>example.com:4443</code>,
          and see <a href="#connect-an-agent">Older agents</a> above. It is
          also what a staging-issued apex certificate looks like from a
          client with a normal trust store.
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
