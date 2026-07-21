import type { Metadata } from "next"
import { Eye, Laptop, Server } from "lucide-react"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Card, CardGrid } from "@/components/docs/card"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"

export const metadata: Metadata = {
  title: "Core Concepts",
  description: "The vocabulary — edge, agent, sessions, streams, bindings.",
}

const TOC: TocItem[] = [
  { id: "the-edge", title: "The edge (ngstoned)" },
  { id: "the-agent", title: "The agent (ngstone)" },
  { id: "sessions-and-streams", title: "Sessions and streams" },
  { id: "bindings-and-registry", title: "Bindings and the registry" },
  { id: "instance-identity", title: "Instance identity" },
  { id: "the-inspector", title: "The inspector" },
]

export default function CoreConceptsPage() {
  return (
    <DocsArticle href="/docs/core-concepts" toc={TOC}>
      <h1>Core Concepts</h1>
      <p>
        A handful of ideas recur throughout ngstone&apos;s design. Once these
        click, the rest of the docs — the wire protocol, the failure modes,
        the operations guides — read as consequences of a small set of
        decisions rather than a pile of unrelated facts.
      </p>

      <Anchor id="the-edge">The edge (ngstoned)</Anchor>
      <p>
        Runs on a public Linux VPS. Terminates public TLS, issues
        certificates, and routes each incoming request to the agent session
        that owns its hostname.
      </p>

      <Anchor id="the-agent">The agent (ngstone)</Anchor>
      <p>
        Runs on your macOS dev machine. Dials out to the edge, forwards
        traffic to a local port, and serves the request inspector.
      </p>
      <CardGrid columns={2}>
        <Card title="ngstoned" icon={Server}>
          The edge. Public TLS, certificate issuance, request routing.
        </Card>
        <Card title="ngstone" icon={Laptop}>
          The agent, CLI, and local inspector, all in one binary.
        </Card>
      </CardGrid>
      <p>
        The agent always initiates the connection to the edge — the VPS
        never dials into your laptop. That single design choice is why
        ngstone needs no inbound firewall holes at home and no NAT
        traversal.
      </p>

      <Anchor id="sessions-and-streams">Sessions and streams</Anchor>
      <p>
        The agent dials <code>ngstone.site:4443</code> and establishes one
        long-lived TLS connection. On top of that connection runs a single{" "}
        <code>yamux</code> session, which multiplexes many independent byte
        streams over the one TCP connection.
      </p>
      <p>
        The first stream opened on a session is a dedicated control stream —
        it carries authentication, bind/unbind requests, and heartbeats.
        Every proxied HTTP request the edge forwards to the agent gets its
        own stream, opened fresh and closed when the request completes.
      </p>
      <CodeBlock
        language="text"
        code={`one TLS connection
└── yamux session
    ├── control stream   (auth, bind, ping/pong, goodbye)
    ├── request stream    (one HTTP exchange)
    ├── request stream    (one HTTP exchange)
    └── ...`}
      />

      <Anchor id="bindings-and-registry">Bindings and the registry</Anchor>
      <p>
        A <code>Binding</code> maps a hostname (like{" "}
        <code>api.ngstone.site</code>) to the agent session that owns it.
        The edge keeps all bindings in a <code>Registry</code>: a plain map
        guarded by an <code>RWMutex</code>, plus a secondary index from
        session to the set of hostnames it owns. That secondary index is
        what lets a dying session&apos;s cleanup release exactly its own
        bindings without racing a newer session that just took the same
        name.
      </p>
      <p>
        Routing a request is a read lock and a map lookup. A miss returns an
        immediate <code>404</code> without ever touching the agent; a hit
        hands the request to that binding&apos;s session.
      </p>

      <Anchor id="instance-identity">Instance identity</Anchor>
      <p>
        Every agent process mints a stable <code>InstanceID</code> once, at
        startup, and keeps it for the process&apos;s lifetime — it survives
        reconnects but dies with the process. This identity is what
        authorizes taking over a binding: if a reconnecting agent presents
        the same <code>InstanceID</code> as the current holder of a
        subdomain, the takeover is immediate, regardless of whether the old
        session still looks alive.
      </p>

      <Anchor id="the-inspector">The inspector</Anchor>
      <p>
        Each agent process runs one tunnel and one local inspector, bound to{" "}
        <code>127.0.0.1:4040</code> by default. If you need more than one
        tunnel at a time, run more than one agent process — pass{" "}
        <code>--inspect-port</code> to avoid a collision on 4040.
      </p>
      <CardGrid columns={1}>
        <Card title="Request inspector" icon={Eye} href="/docs/guides/request-inspector">
          See every request and response your tunnel handles, live, at
          localhost:4040.
        </Card>
      </CardGrid>
    </DocsArticle>
  )
}
