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
  { id: "reconnects", title: "Reconnects keep the port" },
  { id: "encryption", title: "Encryption" },
  { id: "public-exposure", title: "Public exposure" },
  { id: "stream-lifetime", title: "Stream lifetime" },
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
          the port is outside the edge&apos;s configured range or held by
          another agent, the request is rejected with{" "}
          <code>port_unavailable</code> and the agent keeps retrying with
          backoff — it never silently moves you to a different port.
        </Property>
      </ParamTable>

      <Anchor id="reconnects">Reconnects keep the port</Anchor>
      <p>
        TCP tunnels reconnect the same way HTTP tunnels do. After a laptop
        sleep or a network blip the agent reclaims its port straight away,
        using the same{" "}
        <a href="/docs/operations/reconnection-takeover#takeover-rules">
          identity-based takeover rules
        </a>{" "}
        as subdomains: the same agent process gets its port back
        immediately, even while the edge still thinks the old, half-open
        session is alive. It doesn&apos;t wait out the 45 s dead-peer window.
        Another agent can only take a port whose holder is already dead.
      </p>
      <p>
        Without <code>--remote-port</code>, the agent remembers the port the
        edge assigned and asks for it again on every reconnect, so the{" "}
        <code>tcp://host:port</code> you handed out stays valid:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone tcp 22
tcp://amber-fox-42.example.com:14201 -> 127.0.0.1:22
# laptop sleeps, wakes up, agent reconnects
tcp://amber-fox-42.example.com:14201 -> 127.0.0.1:22`}
      />
      <Callout variant="note">
        If the agent was gone long enough for the edge to free its port and
        another tunnel has taken it since, the agent gives up on the old port
        and comes back on a new one in the same reconnect attempt. Check the
        status line for the new address. A restarted agent is a new process
        with a new identity, so it gets whichever port is free. Pass{" "}
        <code>--remote-port</code> if you need the same port across
        restarts too.
      </Callout>

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

      <Anchor id="stream-lifetime">Stream lifetime</Anchor>
      <p>
        A tunnel&apos;s stream normally lives as long as the tunnel session
        does. There is one internal cutoff: if a stream is half-closed in
        one direction (one side has finished sending) and the other
        direction then stays idle or keeps streaming continuously for more
        than 30 minutes without the remote side finishing its own half, the
        stream is reset. Interactive and request/response protocols — SSH
        sessions, database connections — keep both directions open and
        exchanging data, so they&apos;re unaffected.
      </p>
      <Callout variant="note">
        This also isn&apos;t a promise of an infinitely idle connection: the
        agent&apos;s local target, the client, or the OS-level TCP stack on
        either end can still time out or drop an idle connection on their
        own, independent of the 30-minute half-closed cutoff above.
      </Callout>

      <Anchor id="opt-in-per-edge">Opt-in per edge</Anchor>
      <p>
        TCP tunnels aren&apos;t available unless the edge operator turns
        them on with <code>-tcp-ports</code> — with the installer, rerun{" "}
        <code>sudo ./deploy/install-edge.sh --tcp-ports 10000-10100</code>,
        which also opens the range in UFW. See{" "}
        <a href="/docs/guides/edge-vps#tcp-tunnels">TCP tunnels</a> in the
        edge runbook for how that&apos;s configured.
      </p>
    </DocsArticle>
  )
}
