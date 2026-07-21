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
  description: "Planned design for a local request inspector — not yet implemented (M5).",
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
      <Callout variant="warning" title="Not implemented yet (M5)">
        The request inspector does not exist in ngstone today — there is no{" "}
        <code>localhost:4040</code> UI, no <code>--inspect-port</code> flag,
        and no capture of any kind. Everything below describes the{" "}
        <strong>planned</strong> design for milestone M5, not shipped
        behavior. Don&apos;t build a workflow around it yet.
      </Callout>
      <p>
        Once built, every request that passes through your tunnel would be
        captured and shown in a local web UI, with no dashboard account and
        no traffic leaving your machine to render it.
      </p>

      <Anchor id="opening">Opening the inspector</Anchor>
      <p>
        The plan is for the agent to bind the inspector to{" "}
        <code>127.0.0.1:4040</code> by default — loopback only, so nothing
        on your network (let alone the public internet) could reach it. A
        single embedded HTML file, plain JavaScript and an{" "}
        <code>EventSource</code> connection, no build step:
      </p>
      <CodeBlock language="text" code={`http://localhost:4040`} />
      <p>
        For more than one tunnel at once, each agent process would own one
        tunnel and one inspector, so the second one would need its own
        port via a (planned) <code>--inspect-port</code> flag.
      </p>

      <Anchor id="request-list">The request list</Anchor>
      <p>
        As requests flow through your tunnel, they would appear in a live
        list — method, path, status, timing — streaming in as they
        complete, with nothing to refresh.
      </p>

      <Anchor id="inspecting">Inspecting a request</Anchor>
      <p>
        Clicking an entry would show the full exchange: request headers
        and body, response headers and body, and status and duration. Each
        entry would carry a <code>ReqID</code> — a ULID minted by the edge
        — that also appears in the edge&apos;s own logs, so an inspector
        entry could be correlated with what the VPS saw.
      </p>

      <Anchor id="bodies-truncation">Bodies and truncation</Anchor>
      <p>
        The design calls for up to 256 KiB of each request and response
        body to be captured into a ring buffer without blocking the
        stream — capture would observe, never gate. Bodies larger than
        that would be shown truncated.
      </p>
      <ParamTable>
        <Property name="Capture cap" type="256 KiB per body (planned)">
          Beyond this, the body would be marked truncated but the stream
          itself unaffected.
        </Property>
        <Property name="Ring buffer" type="200 entries, overwrite-oldest (planned)">
          About 100 MiB worst case for the inspector&apos;s own store.
        </Property>
      </ParamTable>
      <p>
        Gzipped bodies would be decoded for display — readable JSON, not a
        hex dump — while the raw bytes are kept underneath for accurate
        replay. Binary bodies that don&apos;t decode as text would render
        as a hex preview.
      </p>

      <Anchor id="live-view">Live streaming view</Anchor>
      <p>
        The inspector would update over server-sent events, so new
        exchanges appear the moment they complete — no polling, no manual
        refresh.
      </p>
      <Callout variant="note" title="Planned: WebSockets appear immediately">
        The design finalizes a WebSocket connection in the inspector at the
        moment the <code>101</code> upgrade completes, not when the socket
        eventually closes — so a long-lived connection would show up right
        away instead of sitting invisible for its entire lifetime.
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
