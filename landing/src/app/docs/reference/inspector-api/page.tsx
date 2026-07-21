import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"
import { Pill } from "@/components/docs/pill"

export const metadata: Metadata = {
  title: "The inspector API",
  description: "Planned design for the inspector's HTTP API — not yet implemented (M5).",
}

const TOC: TocItem[] = [
  { id: "endpoints", title: "Endpoints" },
  { id: "exchange-schema", title: "Exchange schema" },
  { id: "sse-events", title: "SSE events" },
  { id: "security", title: "Security" },
]

export default function InspectorApiPage() {
  return (
    <DocsArticle href="/docs/reference/inspector-api" toc={TOC}>
      <h1>The inspector API</h1>
      <Callout variant="warning" title="Not implemented yet (M5)">
        None of this API exists today. There is no inspector, no{" "}
        <code>127.0.0.1:4040</code> listener, and no <code>/api/*</code>{" "}
        endpoints anywhere in ngstone. This page describes the{" "}
        <strong>planned</strong> shape of the API for milestone M5, not a
        contract you can script against yet.
      </Callout>
      <p>
        The intent is for the inspector&apos;s embedded UI to be just a
        client of a small HTTP API served on <code>127.0.0.1:4040</code> —
        everything the UI could do (list exchanges, inspect one, replay it,
        stream new ones) would also be available directly for scripting.
      </p>

      <Anchor id="endpoints">Endpoints (planned)</Anchor>
      <ul>
        <li>
          <Pill variant="outline">GET</Pill> <code>/api/exchanges</code> —
          list captured exchanges.
        </li>
        <li>
          <Pill variant="outline">GET</Pill>{" "}
          <code>/api/exchanges/{"{id}"}</code> — fetch one exchange in full.
        </li>
        <li>
          <Pill>POST</Pill> <code>/api/exchanges/{"{id}"}/replay</code> —
          resend a captured request to the local app.
        </li>
        <li>
          <Pill variant="outline">GET</Pill> <code>/api/events</code> — an{" "}
          <code>EventSource</code> stream of newly finalized exchanges.
        </li>
        <li>
          <Pill variant="outline">GET</Pill> <code>/api/status</code> —
          current tunnel status.
        </li>
      </ul>

      <Anchor id="exchange-schema">Exchange schema (planned)</Anchor>
      <p>
        Every captured request/response pair would be stored as an
        immutable <code>Exchange</code>:
      </p>
      <ParamTable>
        <Property name="ID" type="string">
          A ULID minted when the exchange is finalized.
        </Property>
        <Property name="ReqID" type="string">
          The edge-minted ULID from the stream preamble — joins this entry to
          the edge&apos;s own logs.
        </Property>
        <Property name="Kind" type="&quot;http&quot; | &quot;upgrade&quot;">
          <code>upgrade</code> marks a WebSocket, finalized the instant the
          101 response is sent, not when the socket closes.
        </Property>
        <Property name="Start" type="time.Time" />
        <Property name="Duration" type="duration" />
        <Property name="Req" type="CapturedReq">
          Method, URL, proto, headers, body, body size, and whether the body
          was truncated.
        </Property>
        <Property name="Resp" type="CapturedResp">
          Status, headers, body, body size, and truncation flag.
        </Property>
        <Property name="Replayed" type="bool">
          True if this exchange was created by replaying another one.
        </Property>
        <Property name="Err" type="string">
          Non-empty if the exchange failed.
        </Property>
      </ParamTable>
      <p>
        The plan is to cap bodies at 256 KiB per side via a capped tee that
        passes bytes through untouched — capture observing, never gating,
        the stream. Gzipped bodies would be decoded for display while the
        raw bytes are kept for replay; binary bodies would render as a hex
        preview.
      </p>

      <Anchor id="sse-events">SSE events (planned)</Anchor>
      <p>
        <code>GET /api/events</code> is designed to fan a new{" "}
        <code>Exchange</code> out to every connected subscriber as soon as
        it&apos;s finalized, dropping slow subscribers rather than letting
        them block the fan-out. A WebSocket entry would appear at
        101-connect time, so long-lived sockets show up immediately instead
        of only after they close.
      </p>

      <Anchor id="security">Security (planned)</Anchor>
      <Callout variant="note" title="Design intent: loopback-only, CSRF-hardened">
        The design is for the inspector to bind <code>127.0.0.1</code>{" "}
        only — never reachable from the public URL — with mutating
        endpoints (replay) additionally requiring the custom header{" "}
        <code>X-Ngstone: 1</code>, which can&apos;t be sent cross-origin
        without CORS approval, plus an <code>Origin</code>/<code>Host</code>{" "}
        validation check. Together these are meant to close off both
        cross-site replay and DNS-rebinding attacks against the inspector —
        once it exists.
      </Callout>
    </DocsArticle>
  )
}
