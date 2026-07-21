import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { Card, CardGrid } from "@/components/docs/card"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "Using the request inspector",
  description: "See every request and response at localhost:4040.",
}

const TOC: TocItem[] = [
  { id: "opening", title: "Opening the inspector" },
  { id: "request-list", title: "The request list" },
  { id: "inspecting", title: "Inspecting a request" },
  { id: "bodies-truncation", title: "Bodies and truncation" },
  { id: "live-view", title: "Live streaming view" },
]

export default function RequestInspectorPage() {
  return (
    <DocsArticle href="/docs/guides/request-inspector" toc={TOC}>
      <h1>Using the request inspector</h1>
      <p>
        Every request that passes through your tunnel is captured and shown
        in a local web UI, with no dashboard account and no traffic leaving
        your machine to render it.
      </p>

      <Anchor id="opening">Opening the inspector</Anchor>
      <p>
        The agent binds the inspector to <code>127.0.0.1:4040</code> by
        default — loopback only, so nothing on your network (let alone the
        public internet) can reach it. It&apos;s a single embedded HTML
        file, plain JavaScript and an <code>EventSource</code> connection,
        no build step. Open it in a browser:
      </p>
      <CodeBlock language="text" code={`http://localhost:4040`} />
      <p>
        Running more than one tunnel at once? Each agent process owns one
        tunnel and one inspector, so give the second one its own port with{" "}
        <code>--inspect-port</code>.
      </p>

      <Anchor id="request-list">The request list</Anchor>
      <p>
        As requests flow through your tunnel, they appear in a live list —
        method, path, status, timing. Nothing needs to be refreshed; new
        entries stream in as they complete.
      </p>

      <Anchor id="inspecting">Inspecting a request</Anchor>
      <p>
        Click any entry to see the full exchange: request headers and body,
        response headers and body, and status and duration. Each entry
        carries a <code>ReqID</code> — a ULID minted by the edge — that also
        appears in the edge&apos;s own logs, so you can correlate an
        inspector entry with what the VPS saw.
      </p>

      <Anchor id="bodies-truncation">Bodies and truncation</Anchor>
      <p>
        Up to 256 KiB of each request and response body is captured into a
        ring buffer without blocking the stream — capture observes, it
        never gates. Bodies larger than that are shown truncated.
      </p>
      <ParamTable>
        <Property name="Capture cap" type="256 KiB per body">
          Beyond this, the body is marked truncated but the stream itself is
          unaffected.
        </Property>
        <Property name="Ring buffer" type="200 entries, overwrite-oldest">
          About 100 MiB worst case for the inspector&apos;s own store.
        </Property>
      </ParamTable>
      <p>
        Gzipped bodies are decoded for display — you see readable JSON, not
        a hex dump — while the raw bytes are kept underneath for accurate
        replay. Binary bodies that don&apos;t decode as text render as a hex
        preview.
      </p>

      <Anchor id="live-view">Live streaming view</Anchor>
      <p>
        The inspector updates over server-sent events, so new exchanges
        appear the moment they complete — no polling, no manual refresh.
      </p>
      <Callout variant="note" title="WebSockets appear immediately">
        A WebSocket connection is finalized in the inspector at the moment
        the <code>101</code> upgrade completes, not when the socket
        eventually closes — so a long-lived connection shows up right away
        instead of sitting invisible for its entire lifetime.
      </Callout>
      <CardGrid columns={2}>
        <Card title="Replaying requests" href="/docs/guides/replaying-requests">
          Re-send a captured request straight to your local app.
        </Card>
        <Card title="The inspector API" href="/docs/reference/inspector-api">
          The HTTP API behind localhost:4040.
        </Card>
      </CardGrid>
    </DocsArticle>
  )
}
