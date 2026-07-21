import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { DocsArticle } from "@/components/docs/docs-article"

export const metadata: Metadata = {
  title: "WebSockets & SSE",
  description: "Long-lived and streaming connections through the tunnel.",
}

const TOC: TocItem[] = [
  { id: "websocket-passthrough", title: "WebSocket passthrough" },
  { id: "ws-over-h2", title: "WebSocket over HTTP/2" },
  { id: "server-sent-events", title: "Server-Sent Events" },
  { id: "in-the-inspector", title: "How they appear in the inspector" },
]

export default function WebsocketsSsePage() {
  return (
    <DocsArticle href="/docs/guides/websockets-sse" toc={TOC}>
      <h1>WebSockets &amp; SSE</h1>
      <p>
        Long-lived connections aren&apos;t a special case in ngstone — they
        ride the same per-request yamux stream as any other HTTP exchange,
        for as long as they stay open.
      </p>

      <Anchor id="websocket-passthrough">WebSocket passthrough</Anchor>
      <p>
        The edge&apos;s <code>ReverseProxy</code> handles{" "}
        <code>Connection: Upgrade</code> natively. It hijacks the connection,
        completes the <code>101</code> handshake, and then bidirectionally
        copies bytes for the rest of the socket&apos;s life — over the exact
        same yamux stream that was opened for the original upgrade request.
        No separate channel, no re-dialing.
      </p>

      <Anchor id="ws-over-h2">WebSocket over HTTP/2</Anchor>
      <Callout variant="note" title="Not enabled">
        WS-over-h2 (RFC 8441 extended CONNECT) is not enabled on the edge.
        Browsers already fall back to HTTP/1.1 for WebSocket upgrades
        automatically, so this is a non-issue in practice — just don&apos;t
        expect an h2 WebSocket frame in the wild.
      </Callout>

      <Anchor id="server-sent-events">Server-Sent Events</Anchor>
      <p>
        SSE works because both proxies set <code>FlushInterval: -1</code>,
        which flushes bytes to the client as soon as they arrive instead of
        batching them. <code>text/event-stream</code> responses are detected
        automatically, so there&apos;s nothing to configure — point ngstone
        at an SSE endpoint and it streams.
      </p>

      <Anchor id="in-the-inspector">How they appear in the inspector</Anchor>
      <p>
        WebSockets are finalized in the inspector at{" "}
        <strong>101 time</strong>, not at close. The capture middleware
        records the request and response headers the moment the upgrade
        completes, so the entry shows up in the request list instantly —
        rather than staying invisible until the socket eventually closes,
        possibly hours later.
      </p>
    </DocsArticle>
  )
}
