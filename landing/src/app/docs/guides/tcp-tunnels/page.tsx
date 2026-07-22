import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "TCP tunnels",
  description: "Expose SSH, Postgres, or any raw TCP service through the edge.",
}

const TOC: TocItem[] = [
  { id: "basic-usage", title: "Basic usage" },
  { id: "requesting-a-specific-port", title: "Requesting a specific port" },
  { id: "encryption", title: "Encryption" },
  { id: "public-exposure", title: "Public exposure" },
  { id: "a-known-limitation", title: "A known limitation" },
  { id: "opt-in-per-edge", title: "Opt-in per edge" },
]

export default function TcpTunnelsPage() {
  return (
    <DocsArticle href="/docs/guides/tcp-tunnels" toc={TOC}>
      <h1>TCP tunnels</h1>
      <p>
        <code>ngstone port</code> forwards HTTP. Plenty of things you might
        want to reach aren&apos;t HTTP — SSH, Postgres, Redis, anything
        speaking its own wire protocol over a raw socket.{" "}
        <code>ngstone tcp</code> is for those: it opens a tunnel to a local
        TCP target and hands back an allocated public host and port instead
        of a URL.
      </p>

      <Anchor id="basic-usage">Basic usage</Anchor>
      <p>Point it at a local port:</p>
      <CodeBlock
        language="bash"
        code={`$ ngstone tcp 22
tcp://amber-fox-42.example.com:14201 -> 127.0.0.1:22`}
      />
      <p>
        Now <code>ssh</code> through the tunnel instead of directly:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ssh -p 14201 amber-fox-42.example.com`}
      />
      <p>Same pattern for a database:</p>
      <CodeBlock
        language="bash"
        code={`$ ngstone tcp 5432
tcp://amber-fox-42.example.com:14202 -> 127.0.0.1:5432`}
      />
      <CodeBlock
        language="bash"
        code={`$ psql -h amber-fox-42.example.com -p 14202`}
      />
      <p>
        The positional argument accepts either a bare port number, forwarded
        to <code>127.0.0.1:&lt;port&gt;</code>, or a <code>host:port</code>{" "}
        target used as-is — useful when the service you&apos;re tunneling to
        isn&apos;t on the same machine as the agent.
      </p>

      <Anchor id="requesting-a-specific-port">Requesting a specific port</Anchor>
      <p>
        Left alone, the edge assigns whatever port is free in its configured
        range. Ask for a specific one instead:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone tcp db.local:5432 --remote-port 15432`}
      />
      <ParamTable>
        <Property name="--remote-port, -r" type="int" defaultValue="0">
          Requested remote port. <code>0</code> means server-assigned. If
          the port is outside the edge&apos;s configured range or already
          taken, the request is rejected.
        </Property>
      </ParamTable>

      <Anchor id="encryption">Encryption</Anchor>
      <Callout variant="warning" title="The client-to-edge hop is raw pass-through">
        Every tunnel rides an encrypted agent-to-edge session — that part
        never changes. But the edge can terminate TLS for HTTP tunnels
        because it understands HTTP; it can&apos;t do the same for{" "}
        <code>ngstone tcp</code>, because it doesn&apos;t know what protocol
        is inside the bytes. The client-to-edge leg is therefore only as
        encrypted as the tunneled protocol makes itself. SSH self-encrypts,
        so <code>ngstone tcp 22</code> is end-to-end encrypted. Plain
        Postgres does not encrypt by default — a Postgres tunnel is only
        encrypted if you turn on Postgres&apos;s own TLS (
        <code>sslmode=require</code> or stronger).
      </Callout>

      <Anchor id="public-exposure">Public exposure</Anchor>
      <p>
        The allocated port is reachable by anyone on the internet who can
        reach the edge on that port — the same residual exposure as any
        tunnel. The edge&apos;s per-IP rate limiting and per-tunnel
        concurrent-connection cap apply, but they limit abuse; they
        don&apos;t hide the service. Don&apos;t tunnel something you
        wouldn&apos;t otherwise expose.
      </p>

      <Anchor id="a-known-limitation">A known limitation</Anchor>
      <p>
        If one direction of a tunnel&apos;s stream half-closes — one side
        signals it&apos;s done sending — and the other direction then sits
        idle for around five minutes with nothing else happening, the
        underlying stream multiplexer forcibly closes the whole stream.
      </p>
      <Callout variant="note">
        This does not affect normal interactive or bidirectional use — an
        open SSH session, a live database connection — because those stay
        active in both directions. It only bites an unusual pattern: one
        side closes its write direction and the connection then sits
        one-way-idle for minutes.
      </Callout>

      <Anchor id="opt-in-per-edge">Opt-in per edge</Anchor>
      <p>
        TCP tunnels aren&apos;t available unless the edge operator turns
        them on. See{" "}
        <a href="/docs/guides/edge-vps#tcp-tunnels">TCP tunnels</a> in the
        edge runbook for how that&apos;s configured.
      </p>
    </DocsArticle>
  )
}
