import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"
import { Pill } from "@/components/docs/pill"

export const metadata: Metadata = {
  title: "The inspector API",
  description: "The HTTP API behind localhost:4040.",
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
      <p>
        The inspector&apos;s embedded UI is just a client of a small HTTP API
        served on <code>127.0.0.1:4040</code>. Everything the UI can do — list
        exchanges, inspect one, replay it, stream new ones — is available
        directly if you want to script against it.
      </p>

      <Anchor id="endpoints">Endpoints</Anchor>
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

      <Anchor id="exchange-schema">Exchange schema</Anchor>
      <p>
        Every captured request/response pair is stored as an immutable{" "}
        <code>Exchange</code>:
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
        Bodies are captured up to 256 KiB per side via a capped tee that
        passes bytes through untouched — capture observes, it never gates
        the stream. Gzipped bodies are decoded for display while the raw
        bytes are kept for replay; binary bodies render as a hex preview.
      </p>

      <Anchor id="sse-events">SSE events</Anchor>
      <p>
        <code>GET /api/events</code> fans a new <code>Exchange</code> out to
        every connected subscriber as soon as it&apos;s finalized. Slow
        subscribers are dropped rather than allowed to block the fan-out —
        the inspector never lets a stuck browser tab stall live capture. A
        WebSocket entry appears at 101-connect time, so long-lived sockets
        show up immediately instead of only after they close.
      </p>

      <Anchor id="security">Security</Anchor>
      <Callout variant="note" title="Loopback-only, CSRF-hardened">
        The inspector binds <code>127.0.0.1</code> only — it is never
        reachable from the public URL. Mutating endpoints (currently just
        replay) additionally require the custom header{" "}
        <code>X-Ngstone: 1</code>, which cannot be sent cross-origin without
        CORS approval, plus an <code>Origin</code>/<code>Host</code>{" "}
        validation check. Together these close off both cross-site replay
        and DNS-rebinding attacks against the inspector.
      </Callout>
    </DocsArticle>
  )
}
