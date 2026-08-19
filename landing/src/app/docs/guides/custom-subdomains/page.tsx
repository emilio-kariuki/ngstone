import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Card, CardGrid } from "@/components/docs/card"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "Custom subdomains",
  description: "Pick your own name instead of a random one.",
}

const TOC: TocItem[] = [
  { id: "random-vs-chosen", title: "Random vs chosen names" },
  { id: "naming-rules", title: "Naming rules" },
  { id: "reserved-names", title: "Reserved names" },
  { id: "collisions-and-takeover", title: "Collisions and takeover" },
]

export default function CustomSubdomainsPage() {
  return (
    <DocsArticle href="/docs/guides/custom-subdomains" toc={TOC}>
      <h1>Custom subdomains</h1>
      <p>
        By default the edge hands you a random, memorable name. If you want
        something stable — for OAuth callback URLs, for a demo link you
        share more than once — you can ask for it explicitly.
      </p>

      <Anchor id="random-vs-chosen">Random vs chosen names</Anchor>
      <p>
        Without a <code>--subdomain</code> flag, the server assigns a random
        name like <code>amber-fox-42</code>:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone port 3000
→ https://amber-fox-42.ngstone.site`}
      />
      <p>
        Pass <code>--subdomain</code> (or its shorthand <code>-s</code>) to
        request a specific one instead:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone port 3000 --subdomain demo
→ https://demo.ngstone.site`}
      />

      <Anchor id="naming-rules">Naming rules</Anchor>
      <p>Chosen names are validated against a single pattern:</p>
      <CodeBlock language="text" code={`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`} />
      <p>
        Lowercase letters, digits, and hyphens; must start and end with a
        letter or digit; up to 63 characters total.
      </p>

      <Anchor id="reserved-names">Reserved names</Anchor>
      <p>
        A handful of names are denylisted and can never be bound as a
        tunnel, chosen or random:
      </p>
      <ParamTable>
        <Property name="www" type="reserved" />
        <Property name="mail" type="reserved" />
        <Property name="ns1" type="reserved" />
        <Property name="ns2" type="reserved" />
        <Property name="admin" type="reserved" />
        <Property name="api-edge" type="reserved" />
      </ParamTable>

      <Anchor id="collisions-and-takeover">Collisions and takeover</Anchor>
      <p>
        Requesting a name someone else already holds resolves differently
        depending on who&apos;s asking. The rules below apply to normal binds;
        use <code>--multi-connector</code> when the agents are intentional
        members of one load-balanced tunnel:
      </p>
      <ParamTable>
        <Property name="Different instance, holder is live" type="BindErr">
          The bind is rejected with <code>subdomain_taken</code>. The agent
          exits non-zero if you asked for that name explicitly, or retries
          with a fresh random name if it was auto-assigned.
        </Property>
        <Property name="Different instance, holder is dead" type="Takeover">
          The new agent takes over the name. The old (zombie) session
          receives <code>Evicted</code> and is force-closed.
        </Property>
        <Property name="Same instance reconnecting" type="Takeover">
          Immediate takeover, regardless of whether the old session still
          looks alive — this is what makes reconnecting after your laptop
          sleeps feel instant.
        </Property>
        <Property name="Multi-connector mode" type="Pool">
          Run every agent with <code>--multi-connector</code> and the same
          explicit <code>--subdomain</code>. Live connectors share requests;
          a reconnect replaces only its own connector, and stopping one
          drains its in-flight requests without taking the other connectors
          offline. HTTP/2, access-control, and traffic-policy settings must
          match.
        </Property>
      </ParamTable>
      <CardGrid columns={1}>
        <Card
          title="Reconnection & takeover"
          href="/docs/operations/reconnection-takeover"
        >
          How instance identity decides who gets to keep a name.
        </Card>
      </CardGrid>
    </DocsArticle>
  )
}
