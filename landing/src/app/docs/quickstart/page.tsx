import type { Metadata } from "next"
import { Eye, Layers, Server } from "lucide-react"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Card, CardGrid } from "@/components/docs/card"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"
import { Step, Steps } from "@/components/docs/steps"

export const metadata: Metadata = {
  title: "Quickstart",
  description: "From clone to a public URL in three commands.",
}

const TOC: TocItem[] = [
  { id: "prerequisites", title: "Prerequisites" },
  { id: "start-the-edge", title: "Start the edge" },
  { id: "set-your-token", title: "Set your token" },
  { id: "start-tunneling", title: "Start tunneling" },
  { id: "next-steps", title: "Next steps" },
]

export default function QuickstartPage() {
  return (
    <DocsArticle href="/docs/quickstart" toc={TOC}>
      <h1>Quickstart</h1>
      <p>
        Three commands take you from a fresh VPS to a public HTTPS URL
        forwarding to a port on your laptop. No dashboard, no account
        creation — just two binaries.
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
          <code>ngstone.site</code>) both pointing at your VPS&apos;s IP address.
        </Step>
        <Step title="Go 1.25, to build">
          Both binaries build from the same module. You only need the Go
          toolchain on whichever machine you build on — the compiled binaries
          have no runtime dependency on it.
        </Step>
      </Steps>

      <Anchor id="start-the-edge">Start the edge</Anchor>
      <p>
        On the VPS, run <code>ngstoned</code> with your domain and an email
        address for ACME certificate issuance:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstoned --domain ngstone.site --email you@ngstone.site`}
      />
      <p>
        The edge requests two independent TLS certificates via DNS-01 — a
        wildcard for tunnel traffic and an apex certificate for the control
        plane on port <code>4443</code> — then starts listening.
      </p>

      <Anchor id="set-your-token">Set your token</Anchor>
      <p>
        On first boot, the edge generates and prints an auth token. Copy it
        to wherever you&apos;ll run the agent and export it as an environment
        variable:
      </p>
      <CodeBlock
        language="bash"
        code={`$ export NGSTONE_TOKEN=nst_••••••••••••••••••••`}
      />

      <Anchor id="start-tunneling">Start tunneling</Anchor>
      <p>
        Point the agent at any local port. Without a name, the edge assigns a
        random one:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone http 3000
→ https://amber-fox-42.ngstone.site`}
      />
      <p>
        Pass <code>--subdomain</code> to request a specific name instead:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone http 3000 --subdomain api
→ https://api.ngstone.site`}
      />

      <Anchor id="next-steps">Next steps</Anchor>
      <CardGrid columns={3}>
        <Card title="Installation" icon={Server} href="/docs/installation">
          Build both binaries from source and put them where they run.
        </Card>
        <Card title="Core Concepts" icon={Layers} href="/docs/core-concepts">
          The vocabulary behind sessions, streams, and bindings.
        </Card>
        <Card
          title="Request Inspector"
          icon={Eye}
          href="/docs/guides/request-inspector"
        >
          See every request and response at localhost:4040.
        </Card>
      </CardGrid>
    </DocsArticle>
  )
}
