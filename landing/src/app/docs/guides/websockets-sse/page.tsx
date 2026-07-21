import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { DocsArticle } from "@/components/docs/docs-article"

export const metadata: Metadata = {
  title: "WebSockets & SSE",
  description: "Long-lived and streaming connections through the tunnel — hardening not yet complete (M4).",
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
      <Callout variant="warning" title="Not hardened yet (M4)">
        Plain HTTP request/response is what ngstone has actually been
        built and tested for. WebSocket and SSE traffic is not yet
        specifically tested or hardened — it may work today as a side
        effect of the stdlib reverse proxy&apos;s default behavior, but
        don&apos;t rely on it in production until M4 lands.
      </Callout>
      <p>
        Long-lived connections aren&apos;t meant to be a special case in
        ngstone&apos;s design — they&apos;d ride the same per-request yamux
        stream as any other HTTP exchange, for as long as they stay open.
      </p>

      <Anchor id="websocket-passthrough">WebSocket passthrough</Anchor>
      <p>
        Both the edge and the agent use Go&apos;s stdlib{" "}
        <code>httputil.ReverseProxy</code>, which handles{" "}
        <code>Connection: Upgrade</code> on its own — hijacking the
        connection, completing the <code>101</code> handshake, and copying
        bytes bidirectionally for the rest of the socket&apos;s life, over
        the same yamux stream that was opened for the original upgrade
        request. That&apos;s the mechanism in place today; it just
        hasn&apos;t been specifically exercised or hardened yet (see the
        callout above), so treat it as untested rather than guaranteed.
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
        SSE is plain HTTP streaming, not an upgrade, and both proxies set{" "}
        <code>FlushInterval: -1</code>, which flushes bytes to the client as
        soon as they arrive instead of batching them. That part rides the
        same code path as ordinary HTTP responses, so it&apos;s on firmer
        ground than WebSockets — but it hasn&apos;t been separately
        load-tested for long-lived streams either, which is why it&apos;s
        grouped under the same M4 milestone.
      </p>

      <Anchor id="in-the-inspector">How they appear in the inspector</Anchor>
      <p>
        The <a href="/docs/guides/request-inspector">request inspector</a>{" "}
        already understands WebSockets: an upgrade is finalized in the
        inspector at <strong>101 time</strong>, not at close, so a
        long-lived connection shows up in the request list the instant it
        connects instead of staying invisible until the socket eventually
        closes. Rows for an open socket show <code>WS</code> in the method
        column and live byte counts in both directions in place of a
        duration. This inspector behavior is solid; it&apos;s the broader
        WebSocket/SSE hardening above (M4) that&apos;s still outstanding.
      </p>
    </DocsArticle>
  )
}
