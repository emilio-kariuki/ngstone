import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "Sharing a database",
  description:
    "Share a local Postgres, MySQL or Redis with teammates through a link that expires, without opening a public port.",
}

const TOC: TocItem[] = [
  { id: "sharer", title: "Sharing" },
  { id: "connector", title: "Connecting" },
  { id: "how-it-works", title: "How it works" },
  { id: "policies", title: "Policies" },
  { id: "auditing", title: "Auditing" },
  { id: "lifecycle", title: "Expiry, revocation and reconnects" },
  { id: "what-it-is-not", title: "What it is not" },
]

export default function DatabaseSharingPage() {
  return (
    <DocsArticle href="/docs/guides/database-sharing" toc={TOC}>
      <h1>Sharing a database</h1>
      <p>
        <code>ngstone tcp</code> gives a service a public port on the edge.
        Sometimes that is more exposure than you want: a staging database
        a teammate needs for an afternoon should not be reachable by anyone
        who can guess a port. <code>ngstone share</code> is for that case.
        It hands out a link; whoever has the link runs{" "}
        <code>ngstone connect</code> and gets the database on their own
        loopback interface. Nothing on the edge listens for it.
      </p>

      <Anchor id="sharer">Sharing</Anchor>
      <CodeBlock
        language="bash"
        code={`$ ngstone share postgres --expires 2h --label "staging replica"
share     staging replica  postgres  127.0.0.1:5432
expires   in 2h (14:03 UTC)   policy: allow all, 16 conns, 8 connectors
link      ngstone://example.com:4443/s/N7kq...Vb0Q

send the link to a teammate; they run:  ngstone connect <link>

14:01:02  share live         id sh_7f3a...
14:01:03  connector joined   203.0.113.9            id c1
14:01:04  conn #1   open     203.0.113.9            via c1
14:05:11  conn #1   closed   4m07s     12.3 MiB up   482.0 KiB down`}
      />
      <p>
        <code>postgres</code>, <code>mysql</code> and <code>redis</code> are
        presets for ports 5432, 3306 and 6379 on <code>127.0.0.1</code>. A
        second argument overrides the target:{" "}
        <code>ngstone share postgres 5433</code> or{" "}
        <code>ngstone share postgres db.local:5432</code>. Anything else
        goes through <code>ngstone share tcp &lt;port|host:port&gt;</code>.
      </p>
      <p>
        Ctrl-C revokes the share. Every connector is told within a second
        and told why.
      </p>

      <Anchor id="connector">Connecting</Anchor>
      <CodeBlock
        language="bash"
        code={`$ ngstone connect ngstone://example.com:4443/s/N7kq...Vb0Q
connecting to example.com:4443
connected  "staging replica" (postgres)  expires in 1h58m (14:03 UTC)
listening  127.0.0.1:5432  ->  psql "postgres://127.0.0.1:5432/"`}
      />
      <p>
        The connector listens on the loopback interface only, on the
        preset&apos;s port. If that port is busy it picks a free one and
        says so; <code>--port</code> chooses explicitly. Each local
        connection becomes one tunnel stream to the edge.
      </p>
      <p>
        The link carries the edge address, so the connector needs no{" "}
        <code>ngstone auth</code> and no config file. To keep the secret
        out of shell history, pass the link on standard input with{" "}
        <code>ngstone connect -</code> or set{" "}
        <code>NGSTONE_SHARE_LINK</code>.
      </p>
      <ParamTable>
        <Property name="--port, -p" type="int" defaultValue="0">
          Local port to listen on. <code>0</code> means the share&apos;s
          preset port, or a free port when that one is taken.
        </Property>
        <Property name="--insecure" type="bool" defaultValue="false">
          Dial the edge in plaintext. Only for links from an edge running
          with <code>-insecure</code>; the link never encodes it.
        </Property>
        <Property name="--server-name" type="string">
          TLS <code>ServerName</code>/SNI to verify against. Defaults to the
          host in the link.
        </Property>
        <Property name="--pin" type="string">
          Optional SPKI pin, checked in addition to normal chain
          validation.
        </Property>
      </ParamTable>

      <Anchor id="how-it-works">How it works</Anchor>
      <p>
        Both sides dial out to the edge over TLS, exactly like a normal
        agent. The sharer registers the share: a label, an expiry, a policy
        and the SHA-256 of a 32-byte secret it minted. The link is that
        secret. A connector authenticates with the secret instead of the
        operator token and gets a session that may do one thing: open
        streams to its share. The edge opens a matching stream to the
        sharer, whose agent dials the local database, and copies bytes
        both ways with the same flow control and idle timeout as a TCP
        tunnel.
      </p>
      <p>
        The edge keeps shares in memory only and stores nothing but the
        hash. An edge restart forgets every share; the sharer re-registers
        on reconnect, connectors retry, and the same link keeps working.
      </p>

      <Anchor id="policies">Policies</Anchor>
      <ParamTable>
        <Property name="--expires" type="duration" defaultValue="1h">
          Share lifetime. The edge enforces it and caps it with{" "}
          <code>-max-share-ttl</code> (24h by default).
        </Property>
        <Property name="--allow-cidr" type="string">
          Comma-separated CIDRs connectors must come from. A connector
          outside the list is refused at join time with{" "}
          <code>forbidden_cidr</code>, and the sharer sees the rejection.
        </Property>
        <Property name="--max-conns" type="int" defaultValue="16">
          Concurrent relayed connections across all connectors. The edge
          allows at most 64.
        </Property>
        <Property name="--max-connectors" type="int" defaultValue="8">
          Concurrent connector agents. The edge allows at most 32.
        </Property>
        <Property name="--single-use" type="bool" defaultValue="false">
          Lock the link to the first connector agent that uses it. A second
          machine with the same link is refused with{" "}
          <code>share_locked</code>; the first one may reconnect.
        </Property>
      </ParamTable>
      <Callout variant="warning" title="--allow-cidr checks the connector's address as the edge sees it">
        Behind a front proxy with <code>-proxy-protocol</code>, source
        addresses are only trustworthy with{" "}
        <code>-proxy-protocol-trusted</code>, as for every other
        allowlist. See{" "}
        <a href="/docs/guides/access-control">Access control</a>.
      </Callout>

      <Anchor id="auditing">Auditing</Anchor>
      <p>
        The sharer&apos;s terminal shows every connector joining and
        leaving and every connection opening and closing, with the
        connector&apos;s address, duration and bytes in each direction.{" "}
        <code>--audit-log PATH</code> appends the same events as JSON
        Lines. The edge logs them too, by share id; the secret and its hash
        never appear in logs.
      </p>
      <CodeBlock
        language="json"
        code={`{"share_id":"sh_7f3a...","event":"conn_close","at_unix_ms":1791902431793,"connector_id":"c1","conn_id":1,"client_addr":"203.0.113.9:49418","duration_ms":247113,"bytes_up":12897280,"bytes_down":493568}`}
      />

      <Anchor id="lifecycle">Expiry, revocation and reconnects</Anchor>
      <ul>
        <li>
          <strong>Expiry.</strong> The edge closes the share at the
          deadline. Open connections are cut within a second, the sharer
          prints <code>share expired</code> and exits 0, and each
          connector prints why and exits with status 3.
        </li>
        <li>
          <strong>Revocation.</strong> Ctrl-C on the sharer sends goodbye;
          the edge tells every connector <code>revoked</code>. Same exit
          codes as expiry.
        </li>
        <li>
          <strong>Sharer offline.</strong> If the sharer&apos;s session dies
          without a goodbye (a laptop lid), connectors are told{" "}
          <code>sharer_gone</code> and retry quietly until the expiry they
          were given. The sharer re-registers the same secret when it
          returns.
        </li>
        <li>
          <strong>Connector offline.</strong> Its local listener stays up.
          While disconnected, new local connections are refused at once
          rather than queued, like a database that is down.
        </li>
      </ul>

      <Anchor id="what-it-is-not">What it is not</Anchor>
      <p>
        There are no named users: identity is possession of the link plus
        network policy. There is no query-level auditing or read-only
        enforcement; use database roles for that. And the edge terminates
        TLS on both sides and sees plaintext, as with every tunnel, so
        enable the database&apos;s own TLS when the VPS is not fully
        trusted. The full design, including the protocol additions, is in{" "}
        <code>docs/SHARE-DESIGN.md</code> in the repository.
      </p>
    </DocsArticle>
  )
}
