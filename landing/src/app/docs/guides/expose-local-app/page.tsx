import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "Exposing a local app",
  description: "Forward a public URL to a port on your machine.",
}

const TOC: TocItem[] = [
  { id: "basic-usage", title: "Basic usage" },
  { id: "how-forwarding-works", title: "How forwarding works" },
  { id: "forwarded-headers", title: "Forwarded headers" },
  { id: "the-host-header", title: "The Host header" },
  { id: "app-not-running", title: "When the local app isn't running" },
]

export default function ExposeLocalAppPage() {
  return (
    <DocsArticle href="/docs/guides/expose-local-app" toc={TOC}>
      <h1>Exposing a local app</h1>
      <p>
        The whole point of ngstone: turn a port on your laptop into a public
        HTTPS URL.
      </p>

      <Anchor id="basic-usage">Basic usage</Anchor>
      <p>
        Point the agent at whatever port your app is listening on:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone port 3000
→ https://amber-fox-42.ngstone.site`}
      />
      <p>
        That forwards <code>https://amber-fox-42.ngstone.site</code> to{" "}
        <code>localhost:3000</code>. Anything the public URL receives, your
        local app receives.
      </p>

      <Anchor id="how-forwarding-works">How forwarding works</Anchor>
      <p>
        Each incoming request opens a fresh <code>yamux</code> stream from
        the edge to the agent, carrying a small JSON preamble ahead of the
        raw request bytes. The agent reads the preamble, then forwards the
        request to your local app over a pooled, keep-alive transport.
        Bodies stream through end to end — nothing is buffered in full on
        either side, so a large upload or download costs constant memory
        regardless of size.
      </p>

      <Anchor id="forwarded-headers">Forwarded headers</Anchor>
      <p>
        The edge stamps <code>X-Forwarded-For</code>,{" "}
        <code>X-Forwarded-Proto</code>, and <code>X-Forwarded-Host</code> on
        every request before it reaches the agent, and the agent preserves
        them unmodified on the way to your local app.
      </p>
      <Callout variant="note">
        Your local app can trust these headers. Inbound spoofed values are
        stripped and replaced at the edge before the request ever reaches
        the tunnel, so <code>X-Forwarded-For</code> always reflects the real
        public client, not something an attacker sent.
      </Callout>

      <Anchor id="the-host-header">The Host header</Anchor>
      <p>
        The original public <code>Host</code> header is preserved end to
        end — what most OAuth callback URLs and vhost routers expect.
        There is currently no flag to rewrite it to something like{" "}
        <code>localhost:3000</code> instead; if your app is picky about the{" "}
        <code>Host</code> it receives, it needs to accept the public
        hostname (e.g. <code>amber-fox-42.ngstone.site</code>) for now.
      </p>

      <Anchor id="app-not-running">When the local app isn&apos;t running</Anchor>
      <p>
        If the agent can&apos;t dial your local port, it doesn&apos;t just
        fail silently — it synthesizes a <code>502</code> with a body that
        says what went wrong, so a request against a stopped dev server
        reads as an obvious, actionable error rather than a mystery.
      </p>
      <ParamTable>
        <Property name="502" type="response">
          Local dial failed. Body includes a message like &quot;nothing
          listening on localhost:3000&quot;.
        </Property>
      </ParamTable>
    </DocsArticle>
  )
}
