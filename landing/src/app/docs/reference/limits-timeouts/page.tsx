import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "Limits & timeouts",
  description: "Every cap the edge enforces.",
}

const TOC: TocItem[] = [
  { id: "http-timeouts", title: "HTTP server timeouts" },
  { id: "body-limits", title: "Body limits" },
  { id: "rate-limiting", title: "Rate limiting" },
  { id: "concurrency-window", title: "Concurrency & the window budget" },
  { id: "upgrade-budget", title: "The upgrade budget" },
  { id: "control-plane-caps", title: "Control-plane caps" },
]

export default function LimitsTimeoutsPage() {
  return (
    <DocsArticle href="/docs/reference/limits-timeouts" toc={TOC}>
      <h1>Limits & timeouts</h1>
      <p>
        Every cap in this page is flag-overridable, but the defaults are
        chosen deliberately — each one guards against a specific failure
        mode, not a round number picked for its own sake.
      </p>

      <Anchor id="http-timeouts">HTTP server timeouts</Anchor>
      <ParamTable>
        <Property name="ReadHeaderTimeout" type="duration" defaultValue="10s">
          Guards against slowloris-style clients that trickle headers in one
          byte at a time.
        </Property>
        <Property name="IdleTimeout" type="duration" defaultValue="120s">
          Public keep-alive idle timeout. Guards against file-descriptor
          exhaustion from idle connections.
        </Property>
        <Property name="MaxHeaderBytes" type="bytes" defaultValue="64 KiB">
          Guards against header bombs.
        </Property>
        <Property name="ResponseHeaderTimeout" type="duration" defaultValue="30s">
          How long the edge waits for the local app to start responding
          before returning <code>504</code>. Guards against a hung local
          app. Post-header response duration is unlimited by design —
          streaming downloads and SSE need that, and a client disconnect
          cancels the request context anyway.
        </Property>
        <Property name="Dial-to-agent" type="duration" defaultValue="5s">
          Budget for opening the yamux stream and writing its preamble.
          Times out to <code>502</code> if the session is wedged.
        </Property>
        <Property name="-client-idle-timeout" type="duration" defaultValue="60s">
          How long one read of a request body, or one write of a response,
          may wait on the public client. A client that stops sending its
          upload gets <code>408</code>; one that stops reading its response
          is disconnected. Either way its request slots are freed. The
          deadline applies only while a read or write is blocked, so long
          uploads, SSE streams and WebSockets that keep moving are
          unaffected.
        </Property>
        <Property name="-tcp-idle-timeout" type="duration" defaultValue="30m">
          Closes a TCP tunnel connection that has carried no bytes in either
          direction for this long. A connection busy in only one direction,
          such as a download, stays open. Raise it, or enable keepalives such
          as SSH&apos;s <code>ServerAliveInterval</code>, for sessions that
          sit idle longer.
        </Property>
      </ParamTable>

      <Anchor id="body-limits">Body limits</Anchor>
      <ParamTable>
        <Property name="Declared body cap" type="bytes" defaultValue="256 MiB">
          Checked against <code>Content-Length</code> before the request is
          proxied at all — this is the real <code>413</code>, and it covers
          every well-behaved client.
        </Property>
        <Property name="Streaming body cap" type="bytes" defaultValue="256 MiB">
          Enforced via <code>MaxBytesReader</code> for chunked or
          unknown-length bodies, surfaced as <code>413</code> from a custom{" "}
          <code>ErrorHandler</code> that type-checks{" "}
          <code>*http.MaxBytesError</code>.
        </Property>
        <Property name="-webhook-max-body-bytes" type="bytes" defaultValue="1 MiB">
          Largest body the edge buffers to verify a webhook signature
          (capped by <code>-max-body-bytes</code>). Larger bodies get{" "}
          <code>413</code>.
        </Property>
        <Property name="-webhook-buffer-bytes" type="bytes" defaultValue="64 MiB">
          Total memory all in-flight webhook verifications may hold. The
          edge reserves a request&apos;s declared length (or the full
          per-request cap for chunked bodies) before reading it; when the
          budget is spent it answers <code>503</code> with{" "}
          <code>Retry-After</code> and counts{" "}
          <code>ngstoned_rejected_webhook_buffer_total</code>. Must be at
          least <code>-webhook-max-body-bytes</code>.
        </Property>
      </ParamTable>
      <Callout variant="warning" title="A chunked 413 may ship a partial body">
        The naive design — relying on <code>MaxBytesReader</code> alone —
        returns <code>502</code>, not <code>413</code>, because the trip
        surfaces as a request-body read error inside <code>RoundTrip</code>{" "}
        after headers and up to 256 MiB have already reached the agent.
        With both checks in place the chunked path still means the agent may
        have already forwarded a partial body to the local app before the
        edge cuts it off.
      </Callout>

      <Anchor id="rate-limiting">Rate limiting</Anchor>
      <ParamTable>
        <Property name="Per-IP rate limit" type="token bucket" defaultValue="20 req/s, burst 50">
          Backed by an LRU of 10k IPs. Exceeding it returns{" "}
          <code>429</code>.
        </Property>
        <Property name="Auth attempts" type="rate" defaultValue="5 / IP / minute">
          Applies to the control-plane authentication handshake on{" "}
          <code>:4443</code>.
        </Property>
      </ParamTable>

      <Anchor id="concurrency-window">Concurrency & the window budget</Anchor>
      <ParamTable>
        <Property name="Global in-flight semaphore" type="int" defaultValue="64">
          The total memory ceiling for the system — see the callout below.
        </Property>
        <Property name="Per-session concurrent streams" type="int" defaultValue="48">
          Its own semaphore, beneath the global one, so one tunnel can&apos;t
          monopolize the edge. Exceeding it returns <code>429</code>.
        </Property>
        <Property name="-per-ip-inflight" type="int" defaultValue="32">
          In-flight HTTP requests plus TCP tunnel connections one client
          address may hold at once, across every tunnel on the edge (IPv6 is
          grouped by /48, like the rate limiter). Without it, one client
          could take every per-session or global slot with slow or idle
          connections. Exceeding it returns <code>429</code>, or closes the
          TCP connection.
        </Property>
        <Property name="yamux AcceptBacklog" type="int" defaultValue="512">
          Deliberately set above both caps — see the callout below.
        </Property>
        <Property name="Peak tunnel buffering" type="bytes" defaultValue="64 MiB per side">
          64 concurrent streams × a 1 MiB yamux receive window each — the
          largest buffer in the system.
        </Property>
      </ParamTable>
      <Callout variant="info" title="AcceptBacklog is not the concurrency cap">
        It&apos;s an easy and expensive misreading. <code>AcceptBacklog</code>{" "}
        is the depth of yamux&apos;s accept queue; when it&apos;s full, a new
        stream gets RST&apos;d — a <code>502</code> the client can&apos;t
        interpret, instead of the <code>429</code> the system intends.
        Concurrency is enforced by the per-session (48) and global (64)
        semaphores instead, with <code>AcceptBacklog</code> set comfortably
        above both (512) so it never becomes the binding constraint. The
        yamux receive window is itself a buffer — each open stream may hold
        up to its window of received-but-unread bytes on both machines, so
        concurrency × window is the number that matters, not either alone.
      </Callout>

      <Anchor id="upgrade-budget">The upgrade budget</Anchor>
      <p>
        A WebSocket upgrade or an SSE stream would otherwise hold one of the
        semaphores above for its entire life, starving ordinary HTTP requests
        behind it. The edge detects a long-lived response —{" "}
        <code>101 Switching Protocols</code>, or a <code>200</code> whose{" "}
        <code>Content-Type</code> is <code>text/event-stream</code> — and
        moves it onto this separate budget, releasing its global and
        per-session in-flight slot back to the pool. See{" "}
        <a href="/docs/guides/websockets-sse#the-upgrade-budget">
          WebSockets &amp; SSE
        </a>{" "}
        for the full picture.
      </p>
      <ParamTable>
        <Property name="-upgrade-inflight" type="int" defaultValue="256">
          Global concurrent upgraded (WebSocket/SSE) connection cap, across
          every tunnel on the edge.
        </Property>
        <Property name="-per-session-upgrade" type="int" defaultValue="32">
          Per-session concurrent upgraded connection cap, beneath the global
          one.
        </Property>
      </ParamTable>
      <p>
        A connection that can&apos;t be reclassified because either cap is
        exhausted is rejected outright with <code>503 Service Unavailable</code>{" "}
        — it is not silently downgraded or left occupying a request slot —
        and <code>ngstoned_rejected_upgrade_cap_total</code> increments.{" "}
        <code>ngstoned_active_upgrades</code> is a live gauge of currently
        open upgraded connections.
      </p>

      <Anchor id="control-plane-caps">Control-plane caps</Anchor>
      <ParamTable>
        <Property name=":4443 concurrent TLS handshakes" type="int" defaultValue="16">
          Guards against an unauthenticated handshake flood.
        </Property>
        <Property name=":4443 unauthenticated sessions" type="int" defaultValue="32">
          Guards against slow-auth session hoarding. QUIC connections share
          both caps with TCP. An unauthenticated QUIC connection is closed no
          later than 5 s after admission and holds its slot until it is
          closed.
        </Property>
        <Property name=":4443 unauthenticated sessions per client address" type="int" defaultValue="4">
          Set with <code>-unauth-per-addr</code>; the default is a quarter of{" "}
          <code>-handshake-concurrency</code>, and never below 1. Counted per
          IPv4 address or per IPv6 /48 and shared by TCP, QUIC, WebSocket and
          forwarded control, where the address is the original client&apos;s.
          Stops one address from filling the handshake cap, though four
          addresses (or /48s) can still fill it. A refused client gets
          no reply: a TCP connection is closed at once, a QUIC handshake is
          refused, and a WebSocket upgrade gets{" "}
          <code>503 too many connections</code>. Refusals are counted in{" "}
          <code>ngstoned_rejected_unauth_per_addr_total</code>. Many agents
          behind one NAT or one IPv6 /48 that start together can hit it.
        </Property>
        <Property name="QUIC handshake idle timeout" type="duration" defaultValue="10s">
          Applies only with <code>-quic</code>. A QUIC handshake that stalls
          is dropped. The edge sends a QUIC Retry before it admits a
          connection, so the agent&apos;s first handshake reply arrives two
          round trips after it starts. The agent waits up to 10 s for it, and
          the whole handshake and authentication must fit in the 5 s
          pre-authentication budget after admission. A link with a round trip
          above about 4.5 s cannot connect over QUIC and should use TCP.
          Agents older than this release wait 5 s and are limited to about
          2.5 s.
        </Property>
        <Property name="QUIC dial timeout" type="duration" defaultValue="20s">
          Applies only with <code>-quic</code>. The agent&apos;s whole QUIC
          dial budget. With UDP blocked, a literal address fails after 10 s. A
          name with both an IPv4 and an IPv6 address tries IPv4 first and then
          IPv6, so it fails after up to 20 s.
        </Property>
        <Property name="QUIC max idle timeout" type="duration" defaultValue="15s">
          Applies only with <code>-quic</code>. A peer that vanishes without
          a clean close is noticed within about this long.
        </Property>
        <Property name="QUIC keep-alive" type="duration" defaultValue="5s">
          Applies only with <code>-quic</code>. Keeps an idle connection open
          and lets a vanished peer be detected.
        </Property>
      </ParamTable>
    </DocsArticle>
  )
}
