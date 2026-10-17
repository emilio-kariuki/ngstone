import type { Metadata } from "next"
import { Layers, Server, Terminal } from "lucide-react"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Card, CardGrid } from "@/components/docs/card"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"
import { Step, Steps } from "@/components/docs/steps"

export const metadata: Metadata = {
  title: "Quickstart",
  description: "From a fresh VPS to a public URL on your laptop.",
}

const TOC: TocItem[] = [
  { id: "prerequisites", title: "Prerequisites" },
  { id: "generate-a-token", title: "Generate a scoped credential" },
  { id: "start-the-edge", title: "Start the edge" },
  { id: "install-the-agent", title: "Install the agent" },
  { id: "authenticate", title: "Authenticate" },
  { id: "start-tunneling", title: "Start tunneling" },
  { id: "next-steps", title: "Next steps" },
]

export default function QuickstartPage() {
  return (
    <DocsArticle href="/docs/quickstart" toc={TOC}>
      <h1>Quickstart</h1>
      <p>
        This walks through the whole path: standing up the edge on a VPS
        you control, then pointing the agent at a local port from your
        laptop. No dashboard, no account creation — just two binaries and
        one short-lived, per-tunnel credential.
      </p>

      <Anchor id="prerequisites">Prerequisites</Anchor>
      <Steps>
        <Step title="A Linux VPS">
          Anything that can run a static Go binary and accept inbound
          connections on ports 80, 443, and 4443.
        </Step>
        <Step title="A domain with wildcard DNS">
          A domain such as <code>example.com</code> with a wildcard record
          (<code>*.example.com</code>) and an apex record (
          <code>example.com</code>) both pointing at your VPS&apos;s IP
          address.
        </Step>
        <Step title="DNS hosted on a supported provider">
          The edge obtains its certificates through DNS-01, so it needs an
          API credential for the zone: Cloudflare (the default), Route 53,
          DigitalOcean, Hetzner, Vultr, OVH, deSEC, or Bunny. See{" "}
          <a href="/docs/guides/edge-vps#dns-provider">
            Choosing a DNS provider
          </a>
          .
        </Step>
        <Step title="The ngstoned binary">
          Release archives include <code>ngstoned</code> and <code>ngstone</code>. Providers other
          than Cloudflare need a build from source (Go 1.25) until a release
          that includes them is published. The agent has prebuilt installs
          (below), so you don&apos;t need Go on your laptop.
        </Step>
      </Steps>

      <Anchor id="generate-a-token">Initialize durable storage and generate a scoped credential</Anchor>
      <p>
        The edge uses SQLite by default for tunnel names, credentials, leases,
        policies, domains, and audit history. Issue a short-lived credential
        through the loopback management API; only a hash is stored and the
        plaintext is printed once.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone admin credentials issue --server http://127.0.0.1:4041 \\
    --subdomain demo --ttl 24h
credential <id> issued
token: <save this value on the laptop>`}
      />

      <Anchor id="start-the-edge">Start the edge</Anchor>
      <p>
        On the VPS, run <code>ngstoned</code> with your domain, a
        certificate contact email, and the chosen DNS provider&apos;s credentials in the environment
        (Cloudflare by default, or select <code>--dns-provider</code>). SQLite is used automatically; set{" "}
        <code>NGSTONE_DATABASE_URL</code> to a PostgreSQL URL for multiple
        edge servers:
      </p>
      <CodeBlock
        language="bash"
        code={`$ NGSTONE_CF_API_TOKEN="$CF_API_TOKEN" \\
  ngstoned --domain example.com --cert-email you@example.com`}
      />
      <p>
        For another provider, add <code>--dns-provider NAME</code> and set
        its variables instead; <code>ngstoned -dns-provider help</code>{" "}
        lists them. On Ubuntu or Debian,{" "}
        <a href="/docs/guides/edge-vps#fast-path">
          <code>deploy/install-edge.sh</code>
        </a>{" "}
        does all of this, generates the token, and installs a systemd unit.
      </p>
      <p>
        The edge requests two independent TLS certificates via DNS-01 — a
        wildcard for tunnel traffic and an apex certificate for the
        control plane on port <code>4443</code> — then starts listening.
        For anything beyond a quick trial, run it under systemd; see{" "}
        <a href="/docs/operations/deployment-systemd">
          Deployment &amp; systemd
        </a>
        .
      </p>

      <Anchor id="install-the-agent">Install the agent</Anchor>
      <p>On your laptop, install the agent binary:</p>
      <CodeBlock
        language="bash"
        code={`$ brew install emilio-kariuki/tap/ngstone
# or
$ curl -fsSL https://raw.githubusercontent.com/emilio-kariuki/ngstone/main/install.sh | sh`}
      />

      <Anchor id="authenticate">Authenticate</Anchor>
      <p>
        Verify the scoped token from earlier against your edge, and
        save it locally:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone auth "$TOKEN" --server example.com:4443
verified against example.com:4443 and saved`}
      />
      <p>
        The server address is saved with the token, and the certificate is
        verified against its host, so later commands need no further flags.
      </p>

      <Anchor id="start-tunneling">Start tunneling</Anchor>
      <p>
        Point the agent at any local port. Without{" "}
        <code>--subdomain</code>, the edge assigns a random name:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone port 3000
$ ngstone port 3000 --subdomain demo`}
      />

      <Anchor id="next-steps">Next steps</Anchor>
      <CardGrid columns={3}>
        <Card title="Installation" icon={Server} href="/docs/installation">
          Homebrew, curl, and building both binaries from source.
        </Card>
        <Card title="Core Concepts" icon={Layers} href="/docs/core-concepts">
          The vocabulary behind sessions, streams, and bindings.
        </Card>
        <Card
          title="CLI reference"
          icon={Terminal}
          href="/docs/reference/cli"
        >
          Every verb, every flag, and the config file&apos;s resolution
          order.
        </Card>
      </CardGrid>
    </DocsArticle>
  )
}
