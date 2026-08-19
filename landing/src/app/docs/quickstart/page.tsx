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
          A domain such as <code>ngstone.site</code> with a wildcard record
          (<code>*.ngstone.site</code>) and an apex record (
          <code>ngstone.site</code>) both pointing at your VPS&apos;s IP
          address.
        </Step>
        <Step title="Go 1.25, to build the edge">
          Build <code>ngstoned</code> and the VPS-side credential CLI from
          source for the VPS&apos;s architecture, or use the release archive.
          The laptop agent has prebuilt installs (next section), so you
          don&apos;t need Go on your laptop.
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
        certificate contact email, and a Cloudflare API token scoped to{" "}
        <code>Zone:DNS:Edit</code>. SQLite is used automatically; set{" "}
        <code>NGSTONE_DATABASE_URL</code> to a PostgreSQL URL for multiple
        edge servers:
      </p>
      <CodeBlock
        language="bash"
        code={`$ NGSTONE_CF_API_TOKEN="$CF_API_TOKEN" \\
  ngstoned --domain ngstone.site --cert-email you@ngstone.site`}
      />
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
        code={`$ ngstone auth "$TOKEN"
verified against ngstone.site:4443 and saved`}
      />

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
