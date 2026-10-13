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
  { id: "managing", title: "Managing shares from anywhere" },
  { id: "how-it-works", title: "How it works" },
  { id: "policies", title: "Policies" },
  { id: "approval-passphrase", title: "Approval and passphrases" },
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
share     staging replica  postgres 127.0.0.1:5432
expires   in 2h (14:03 UTC)   policy: allow all, 16 conns, 8 connectors
link      ngstone://example.com:4443/s/N7kq...Vb0Q

send the link to a teammate; they run:  ngstone connect <link>
commands here:  y <id> / n <id> (approve)   kick <id>   extend 1h   q

14:01:02  share live         id sh_7f3a...
14:01:03  connector joined   203.0.113.9            alice
14:01:04  conn #1   open     203.0.113.9            via alice
14:05:11  conn #1   closed   4m07s     12.3 MiB up   482.0 KiB down`}
      />
      <p>
        Each positional argument is a target. <code>postgres</code>,{" "}
        <code>mysql</code>, <code>redis</code> and <code>http</code> are
        presets for ports 5432, 3306, 6379 and 8080 on{" "}
        <code>127.0.0.1</code>; add <code>:port</code> or{" "}
        <code>:host:port</code> to point elsewhere, and use{" "}
        <code>tcp:port</code> for anything else. Several targets go in one
        link:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone share postgres redis:6380 tcp:db.local:27017`}
      />
      <p>
        Lines typed into the sharing terminal are commands:{" "}
        <code>kick alice</code> drops a connector, <code>extend 1h</code>{" "}
        moves the expiry, <code>y alice</code> and <code>n alice</code>{" "}
        answer approval requests, <code>q</code> quits. Ctrl-C revokes the
        share; every connector is told within a second and told why.
      </p>

      <Anchor id="connector">Connecting</Anchor>
      <CodeBlock
        language="bash"
        code={`$ ngstone connect ngstone://example.com:4443/s/N7kq...Vb0Q --as alice
connecting to example.com:4443
connected  "staging replica" as alice  expires in 1h58m (14:03 UTC)
listening  127.0.0.1:5432          postgres  ->  psql "postgres://127.0.0.1:5432/"
listening  127.0.0.1:6380          redis     ->  redis-cli -p 6380`}
      />
      <p>
        The connector listens on the loopback interface only, on each
        target&apos;s preset port. If a port is busy it picks a free one and
        says so; <code>--port 5433</code> chooses for the first target and{" "}
        <code>--port redis=6380</code> for a named one. Each local
        connection becomes one tunnel stream to the edge. A status line
        appears when activity changes, and the connector warns five minutes
        and one minute before the share expires.
      </p>
      <p>
        <code>--as</code> gives the connector a name the sharer sees in
        every audit line instead of <code>c1</code>. It is a label, not an
        identity: approval mode (below) is where a human checks it.
      </p>
      <p>
        The link carries the edge address, so the connector needs no{" "}
        <code>ngstone auth</code> and no config file. To keep the secret
        out of shell history, pass the link on standard input with{" "}
        <code>ngstone connect -</code> or set{" "}
        <code>NGSTONE_SHARE_LINK</code>.
      </p>
      <ParamTable>
        <Property name="--as" type="string">
          Connector name shown to the sharer. Letters, digits,{" "}
          <code>.</code> <code>_</code> <code>-</code>; a taken name gets{" "}
          <code>-2</code> appended.
        </Property>
        <Property name="--port, -p" type="string">
          <code>N</code> for the first target, or <code>preset=N</code> /{" "}
          <code>t2=N</code> per target. Repeatable.
        </Property>
        <Property name="--passphrase" type="string">
          Passphrase the share requires. Prompted for when stdin is a
          terminal; <code>NGSTONE_SHARE_PASSPHRASE</code> also works.
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

      <Anchor id="managing">Managing shares from anywhere</Anchor>
      <p>
        Any terminal with the token can see and manage every share, not
        only the one that started it. These open a fresh session, do one
        thing and exit, so they work from scripts too.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone shares
sh_7f3a...  staging replica          postgres,redis       expires in 1h52m (14:03 UTC)
                      policy: 16 conns, 8 connectors;  1 open connections
                      connector alice        203.0.113.9            joined 4m ago

$ ngstone extend sh_7f3a... 2h      # expire two hours from now; connectors are told
$ ngstone kick sh_7f3a... alice     # drop one connector; it exits with status 3
$ ngstone unshare sh_7f3a...        # revoke; the sharing terminal says so and exits
$ ngstone shares --watch            # every share's audit lines, live
$ ngstone shares --json`}
      />

      <Anchor id="how-it-works">How it works</Anchor>
      <p>
        Both sides dial out to the edge over TLS, exactly like a normal
        agent. The sharer registers the share: a label, its targets, an
        expiry, a policy and the SHA-256 of a 32-byte secret it minted. The
        link is that secret. A connector authenticates with the secret
        instead of the operator token and gets a session that may do one
        thing: open streams to its share, each tagged with a target. The
        edge opens a matching stream to the sharer, whose agent dials the
        right local address, and copies bytes both ways with the same flow
        control and idle timeout as a TCP tunnel.
      </p>
      <p>
        The edge keeps shares in memory only and stores nothing but the
        hash. An edge restart forgets every share; the sharer re-registers
        on reconnect, connectors retry, and the same link keeps working.
        With <code>--secret-file</code> the link also survives restarting
        the sharer itself.
      </p>

      <Anchor id="policies">Policies</Anchor>
      <ParamTable>
        <Property name="--expires" type="duration" defaultValue="1h">
          Share lifetime. The edge enforces it and caps it with{" "}
          <code>-max-share-ttl</code> (24h by default). <code>extend</code>{" "}
          moves it later while the share is live.
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
        <Property name="--max-uses" type="int" defaultValue="0">
          How many connector agents may ever join. <code>1</code> is the
          same as <code>--single-use</code>: the link locks to the first
          agent, which may reconnect; anyone else gets{" "}
          <code>share_locked</code>.
        </Property>
        <Property name="--idle" type="duration" defaultValue="0">
          Close the share after this long with no open connection, for
          sharers who forget Ctrl-C. Minimum 30s.
        </Property>
        <Property name="--user" type="string">
          A database user for the hint connectors see, such as{" "}
          <code>readonly</code>. The edge cannot enforce read-only access;
          a scoped database role can, and this points people at it.
        </Property>
      </ParamTable>
      <Callout variant="warning" title="--allow-cidr checks the connector's address as the edge sees it">
        Behind a front proxy with <code>-proxy-protocol</code>, source
        addresses are only trustworthy with{" "}
        <code>-proxy-protocol-trusted</code>, as for every other
        allowlist. See{" "}
        <a href="/docs/guides/access-control">Access control</a>.
      </Callout>

      <Anchor id="approval-passphrase">Approval and passphrases</Anchor>
      <p>
        A link in a chat log is enough to connect. Two options raise the
        bar without accounts:
      </p>
      <ul>
        <li>
          <strong><code>--passphrase</code></strong> makes connectors type a
          second secret the link does not carry. The sharer sends the edge
          a digest bound to the share; the connector presents the
          passphrase at join; a wrong one counts against the edge&apos;s
          per-IP auth limiter like a bad token.
        </li>
        <li>
          <strong><code>--approve</code></strong> parks every join until the
          sharer types <code>y</code> or <code>n</code> in the sharing
          terminal, with the connector&apos;s name and address on screen.
          Sixty seconds without an answer refuses the connector. This is
          the lightest form of identity available: a human looks.
        </li>
      </ul>
      <CodeBlock
        language="bash"
        code={`$ ngstone share postgres --approve --passphrase hunter2
...
14:01:03  approve?           203.0.113.9            alice wants to connect: type  y alice  or  n alice
y alice
14:01:05  approved alice
14:01:05  connector joined   203.0.113.9            alice`}
      />

      <Anchor id="auditing">Auditing</Anchor>
      <p>
        The sharer&apos;s terminal shows every connector joining and
        leaving and every connection opening and closing, with the
        connector&apos;s name and address, the target, duration and bytes
        in each direction. <code>--audit-log PATH</code> appends the same
        events as JSON Lines. <code>ngstone shares --watch</code> shows the
        same lines for every share from any terminal, and the edge can keep
        its own file with <code>-share-audit-log</code>. The secret, its
        hash and the passphrase never appear anywhere.
      </p>
      <CodeBlock
        language="json"
        code={`{"share_id":"sh_7f3a...","event":"conn_close","at_unix_ms":1791902431793,"connector_id":"alice","conn_id":1,"target":"t1","client_addr":"203.0.113.9:49418","duration_ms":247113,"bytes_up":12897280,"bytes_down":493568,"label":"staging replica"}`}
      />

      <Anchor id="lifecycle">Expiry, revocation and reconnects</Anchor>
      <ul>
        <li>
          <strong>Expiry.</strong> The edge closes the share at the
          deadline. Open connections are cut within a second, the sharer
          prints <code>share expired</code> and exits 0, and each
          connector prints why and exits with status 3. Connectors warn at
          five minutes and one minute; <code>extend</code> from either
          terminal postpones it.
        </li>
        <li>
          <strong>Revocation.</strong> Ctrl-C on the sharer, or{" "}
          <code>ngstone unshare</code> from anywhere, tells every connector{" "}
          <code>revoked</code>. <code>kick</code> does the same for one
          connector. Same exit codes as expiry.
        </li>
        <li>
          <strong>Idle.</strong> With <code>--idle</code>, a share with no
          open connection for that long closes on its own.
        </li>
        <li>
          <strong>Sharer offline.</strong> If the sharer&apos;s session dies
          without a goodbye (a laptop lid), connectors are told{" "}
          <code>sharer_gone</code> and retry quietly until the expiry they
          were given. The sharer re-registers the same secret when it
          returns.
        </li>
        <li>
          <strong>Connector offline.</strong> Its local listeners stay up.
          While disconnected, new local connections are refused at once
          rather than queued, like a database that is down.
        </li>
      </ul>

      <Anchor id="what-it-is-not">What it is not</Anchor>
      <p>
        There are no named users: a connector&apos;s name is a claim for the
        audit trail, and identity is possession of the link plus the
        passphrase, network policy and approval if you set them. There is
        no query-level auditing or read-only enforcement; use database
        roles for that. And the edge terminates TLS on both sides and sees
        plaintext, as with every tunnel, so enable the database&apos;s own
        TLS when the VPS is not fully trusted. The full design, including
        the protocol additions, is in <code>docs/SHARE-DESIGN.md</code> in
        the repository.
      </p>
    </DocsArticle>
  )
}
