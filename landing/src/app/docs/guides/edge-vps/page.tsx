import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { Card, CardGrid } from "@/components/docs/card"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "Running the edge on a VPS",
  description: "Stand up ngstoned on a Linux server with TLS.",
}

const TOC: TocItem[] = [
  { id: "dns-setup", title: "DNS setup" },
  { id: "acme-dns01", title: "ACME and DNS-01" },
  { id: "starting-ngstoned", title: "Starting ngstoned" },
  { id: "apex-vs-wildcard", title: "Apex vs wildcard certs" },
  { id: "health-checks", title: "Health checks" },
]

export default function EdgeVpsPage() {
  return (
    <DocsArticle href="/docs/guides/edge-vps" toc={TOC}>
      <h1>Running the edge on a VPS</h1>
      <p>
        <code>ngstoned</code> is the half of ngstone that lives on the
        public internet. This guide walks through DNS, certificates, and
        starting the process on a fresh Linux VPS.
      </p>

      <Anchor id="dns-setup">DNS setup</Anchor>
      <p>
        Point two records at your VPS&apos;s IP address: a wildcard covering
        every tunnel, and an apex record for the control plane.
      </p>
      <ParamTable>
        <Property name="*.ngstone.site" type="A record">
          Catches every tunnel hostname — <code>amber-fox-42.ngstone.site</code>,{" "}
          <code>api.ngstone.site</code>, and so on.
        </Property>
        <Property name="ngstone.site" type="A record">
          The apex. Backs the control plane on port <code>4443</code>, which
          the agent connects to.
        </Property>
      </ParamTable>

      <Anchor id="acme-dns01">ACME and DNS-01</Anchor>
      <p>
        Certificates are issued via the DNS-01 challenge, using a{" "}
        <code>libdns</code> provider — Cloudflare in the reference setup.
        DNS-01 is the only ACME challenge type that can issue a wildcard
        certificate; HTTP-01 and TLS-ALPN-01 can&apos;t. It also means
        individual tunnel names never appear in a Certificate Transparency
        log, since one wildcard cert covers all of them.
      </p>
      <p>
        The DNS provider needs a scoped API token — <code>Zone:DNS:Edit</code>{" "}
        on the one zone you&apos;re using, nothing broader.
      </p>

      <Anchor id="starting-ngstoned">Starting ngstoned</Anchor>
      <p>
        There&apos;s no <code>ngstone token</code> command — generate a
        token yourself first, and hash it:
      </p>
      <CodeBlock
        language="bash"
        code={`$ TOKEN=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
$ HASH=$(printf '%s' "$TOKEN" | shasum -a 256 | cut -d' ' -f1)   # sha256sum on Linux`}
      />
      <p>
        With DNS in place, start the edge with your domain, a certificate
        contact email, a scoped Cloudflare API token, and the hash above:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstoned --domain ngstone.site --cert-email you@ngstone.site \\
    --cf-api-token "$CF_API_TOKEN" --token-sha256 "$HASH"`}
      />
      <p>
        On first boot, <code>ngstoned</code> requests both certificates and
        starts listening — it does not generate or print a token itself;
        the edge only ever stores the hash you gave it. Keep{" "}
        <code>$TOKEN</code> for <code>ngstone auth</code> on whichever
        machines will run the agent. From here it&apos;s typically run as a
        systemd service — see{" "}
        <a href="/docs/operations/deployment-systemd">
          Deployment &amp; systemd
        </a>
        .
      </p>

      <Anchor id="apex-vs-wildcard">Apex vs wildcard certs</Anchor>
      <p>
        This is two independent certificates, not one multi-domain cert. A
        wildcard for <code>*.ngstone.site</code> does not match SNI{" "}
        <code>ngstone.site</code> — a wildcard covers exactly one left-most
        label — so the control plane on port <code>4443</code> needs its own
        apex certificate, issued and renewed on its own schedule.
      </p>
      <Callout variant="warning" title="A healthy wildcard can hide a dead apex">
        If the apex order fails to renew, public tunnel traffic on the
        wildcard cert keeps working perfectly while no agent can connect —
        the control plane is silently down. <code>ngstoned</code> performs a
        startup check that a valid apex cert is loadable before it accepts
        connections on <code>:4443</code>, and exits loudly rather than
        listening with a certificate it can&apos;t serve.
      </Callout>

      <Anchor id="health-checks">Health checks</Anchor>
      <p>
        <code>/healthz</code>, served on the loopback-only ops endpoint at{" "}
        <code>127.0.0.1:4041</code>, reports each certificate&apos;s{" "}
        <code>NotAfter</code> separately — check both, not just one. The
        same ops endpoint also exposes <code>expvar</code> counters and
        pprof, reachable over an SSH tunnel:
      </p>
      <CodeBlock language="bash" code={`$ ssh -L 4041:127.0.0.1:4041 you@ngstone.site
$ curl http://127.0.0.1:4041/healthz`} />
      <CardGrid columns={1}>
        <Card title="Deployment & systemd" href="/docs/operations/deployment-systemd">
          Run ngstoned as a managed service with DynamicUser and a
          persistent certificate cache.
        </Card>
      </CardGrid>
    </DocsArticle>
  )
}
