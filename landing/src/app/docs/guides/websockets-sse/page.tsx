import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "WebSockets & SSE",
  description:
    "Long-lived and streamed connections through the tunnel — proxied end to end with immediate flushing and a dedicated upgrade budget.",
}

const TOC: TocItem[] = [
  { id: "websocket-passthrough", title: "WebSocket passthrough" },
  { id: "ws-over-h2", title: "WebSocket over HTTP/2" },
  { id: "server-sent-events", title: "Server-Sent Events" },
  { id: "the-upgrade-budget", title: "The upgrade budget" },
  { id: "upgrade-budget-exhausted", title: "When the upgrade budget is full" },
  { id: "timeout-behavior", title: "Timeout behavior" },
  { id: "access-control", title: "Access control applies too" },
  { id: "in-the-inspector", title: "How they appear in the inspector" },
]

export default function WebsocketsSsePage() {
  return (
    <DocsArticle href="/docs/guides/websockets-sse" toc={TOC}>
      <h1>WebSockets &amp; SSE</h1>
      <p>
        WebSocket upgrades and SSE streams are proxied end to end, over the
        same yamux stream that was opened for the original request, for as
        long as the connection stays open. Both the edge and the agent
        configure their <code>httputil.ReverseProxy</code> with{" "}
        <code>FlushInterval: -1</code>, so bytes reach the client as soon as
        they arrive instead of being batched.
      </p>

      <Anchor id="websocket-passthrough">WebSocket passthrough</Anchor>
      <p>
        Go&apos;s stdlib <code>httputil.ReverseProxy</code> handles{" "}
        <code>Connection: Upgrade</code> on its own — hijacking the
        connection, completing the <code>101</code> handshake, and copying
        bytes bidirectionally for the rest of the socket&apos;s life. That
        passthrough is now covered end to end by the e2e suite: a real{" "}
        <code>101</code> handshake with a multi-frame echo and a clean close.
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
        SSE is plain HTTP streaming, not an upgrade — the response keeps
        status <code>200</code> and a <code>Content-Type</code> of{" "}
        <code>text/event-stream</code>, with bytes flushed to the client as
        they&apos;re written on the local app side. This is also covered by
        the e2e suite: a real SSE response with incremental delivery.
      </p>

      <Anchor id="the-upgrade-budget">The upgrade budget</Anchor>
      <p>
        A long-lived connection would otherwise hold a normal request slot —
        one of the global and per-session in-flight semaphores described in{" "}
        <a href="/docs/reference/limits-timeouts">Limits &amp; timeouts</a> —
        for its entire life, which would starve ordinary HTTP requests behind
        it. The edge avoids that by watching for a long-lived response —{" "}
        <code>101 Switching Protocols</code>, or a <code>200</code> whose{" "}
        <code>Content-Type</code> is <code>text/event-stream</code> — and
        moving it onto a separate upgrade budget the moment it&apos;s
        detected, releasing the request-scoped slot back to the pool.
      </p>
      <ParamTable>
        <Property name="-upgrade-inflight" type="int" defaultValue="256">
          Global concurrent upgraded (WebSocket/SSE) connection cap, across
          every tunnel on the edge.
        </Property>
        <Property name="-per-session-upgrade" type="int" defaultValue="32">
          Per-session concurrent upgraded connection cap, beneath the global
          one, so one tunnel can&apos;t monopolize the upgrade budget.
        </Property>
      </ParamTable>

      <Anchor id="upgrade-budget-exhausted">
        When the upgrade budget is full
      </Anchor>
      <p>
        A connection that can&apos;t be reclassified because the upgrade
        budget is exhausted is <strong>rejected</strong>, not silently
        downgraded or left on the request slot: the edge returns{" "}
        <code>503 Service Unavailable</code> and increments{" "}
        <code>ngstoned_rejected_upgrade_cap_total</code>.{" "}
        <code>ngstoned_active_upgrades</code> is a live gauge of currently
        open upgraded connections, visible on the <code>expvar</code> ops
        endpoint.
      </p>

      <Anchor id="timeout-behavior">Timeout behavior</Anchor>
      <Callout variant="warning" title="Long-lived, not unlimited">
        Streams don&apos;t live forever — several independent timeouts still
        apply. None of them are tuned to cut a healthy, active stream short,
        but it&apos;s worth knowing exactly what each one does and doesn&apos;t
        cover.
      </Callout>
      <ParamTable>
        <Property name="WriteTimeout" type="duration" defaultValue="unset">
          The public server sets no <code>WriteTimeout</code>, so a live
          stream is never cut off mid-flight by the HTTP server itself.
        </Property>
        <Property name="IdleTimeout" type="duration" defaultValue="120s">
          Applies to keep-alive idle time <em>between</em> requests on a
          reused connection — not to an active stream. An open WebSocket or
          SSE response is not idle.
        </Property>
        <Property name="ResponseHeaderTimeout" type="duration" defaultValue="30s">
          Only bounds the time to the <em>first</em> response header. A{" "}
          <code>101</code> or an SSE response&apos;s headers arrive
          immediately in practice, so this timeout is not in the way once the
          stream is established.
        </Property>
        <Property name="yamux StreamCloseTimeout" type="duration" defaultValue="30m">
          Only affects a stream that has been half-closed in one direction —
          it forces the other side closed if it doesn&apos;t follow suit
          within the timeout. A live, bidirectional WebSocket never triggers
          it, since neither side has half-closed.
        </Property>
      </ParamTable>

      <Anchor id="access-control">Access control applies too</Anchor>
      <p>
        Source-IP allowlisting and HTTP basic auth are enforced{" "}
        <strong>before</strong> the upgrade happens, on the same request path
        as any other HTTP request. A gated tunnel&apos;s WebSocket and SSE
        traffic requires the same credentials or source IP as its plain HTTP
        traffic — there&apos;s no separate, unprotected path for upgrades. See{" "}
        <a href="/docs/guides/access-control">Access control</a>.
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
        duration.
      </p>
    </DocsArticle>
  )
}
