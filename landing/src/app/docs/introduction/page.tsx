import type { Metadata } from "next"
import { Laptop, Server } from "lucide-react"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { Card, CardGrid } from "@/components/docs/card"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"

export const metadata: Metadata = {
  title: "Introduction",
  description: "What ngstone is, and why it exists.",
}

const TOC: TocItem[] = [
  { id: "what-is-ngstone", title: "What is ngstone?" },
  { id: "the-two-binaries", title: "The two binaries" },
  { id: "how-a-request-flows", title: "How a request flows" },
  { id: "what-v1-covers", title: "What v1 covers" },
  { id: "out-of-scope", title: "Out of scope" },
]

export default function IntroductionPage() {
  return (
    <DocsArticle href="/docs/introduction" toc={TOC}>
      <h1>Introduction</h1>
      <p>
        ngstone is a personal, self-hosted alternative to ngrok. You run the
        edge on your own Linux VPS, point a wildcard domain at it, and run the
        agent next to whatever you&apos;re building. No dashboard, no account, no
        third party sitting between your laptop and the internet.
      </p>

      <Anchor id="what-is-ngstone">What is ngstone?</Anchor>
      <p>
        It&apos;s two binaries and one shared Go module. There is no managed
        service, no signup flow, and no traffic that touches infrastructure
        you don&apos;t control — everything you tunnel stays between your VPS and
        your machine.
      </p>

      <Anchor id="the-two-binaries">The two binaries</Anchor>
      <p>
        ngstone splits cleanly into an edge process that lives on the public
        internet and an agent that lives on your dev machine.
      </p>
      <CardGrid columns={2}>
        <Card title="ngstoned" icon={Server}>
          The edge. Runs on a Linux VPS, terminates public TLS, issues
          certificates, and routes incoming requests to the right agent
          session.
        </Card>
        <Card title="ngstone" icon={Laptop}>
          The agent, CLI, and local inspector. Runs on macOS, dials out to the
          edge, and forwards traffic to a port on your machine.
        </Card>
      </CardGrid>

      <Anchor id="how-a-request-flows">How a request flows</Anchor>
      <p>
        The agent always dials out — the VPS never connects into your laptop.
        That means no inbound firewall holes at home and no NAT traversal to
        worry about. One long-lived TLS TCP connection carries a{" "}
        <code>yamux</code> session between the two; the first stream on that
        session is a dedicated control stream, and every proxied HTTP request
        gets its own stream.
      </p>
      <CodeBlock
        language="text"
        code={`browser ──► ngstoned :443 ──► yamux session ──► ngstone agent ──► localhost:3000`}
      />
      <p>
        HTTP and HTTPS tunnels are all v1 supports. The wire protocol is
        deliberately shaped — a <code>Kind</code> field on the bind and stream
        messages — so raw TCP tunnels can be added later without a protocol
        version bump.
      </p>

      <Anchor id="what-v1-covers">What v1 covers</Anchor>
      <p>
        A handful of guiding principles shape every decision in this project,
        in priority order:
      </p>
      <ul>
        <li>stdlib-first — reach for the Go standard library before a dependency</li>
        <li>boring over clever — predictable behavior beats a clever abstraction</li>
        <li>one path per feature — no alternate code paths to keep in sync</li>
        <li>everything flow-controlled — a slow reader backpressures the whole pipe</li>
        <li>nothing unbounded in memory — every buffer has a stated cap</li>
      </ul>

      <Anchor id="out-of-scope">Out of scope</Anchor>
      <Callout variant="info" title="Not in v1">
        ngstone is built for a single operator exposing HTTP services. It
        deliberately does not try to be a general-purpose ingress platform.
      </Callout>
      <p>The following are explicitly out of scope for v1:</p>
      <ul>
        <li>Native gRPC and h2c backends</li>
        <li>Defending against volumetric DDoS beyond your VPS&apos;s own capacity</li>
        <li>VPS compromise — the edge is treated as trusted infrastructure</li>
        <li>OAuth-grade authentication in front of tunnels</li>
      </ul>
    </DocsArticle>
  )
}
