import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"

export const metadata: Metadata = {
  title: "Replaying requests",
  description: "Planned design for replaying captured requests — not yet implemented (M5).",
}

const TOC: TocItem[] = [
  { id: "how-replay-works", title: "How replay works" },
  { id: "replaying", title: "Replaying a request" },
  { id: "edit-and-replay", title: "Edit and replay" },
  { id: "limitations", title: "Limitations" },
]

export default function ReplayingRequestsPage() {
  return (
    <DocsArticle href="/docs/guides/replaying-requests" toc={TOC}>
      <h1>Replaying requests</h1>
      <Callout variant="warning" title="Not implemented yet (M5)">
        Replay depends entirely on the request inspector, which doesn&apos;t
        exist yet either — there is no <code>/api/exchanges</code> endpoint,
        no captured-request store, nothing to replay. Everything below is
        the <strong>planned</strong> design for milestone M5, not shipped
        behavior.
      </Callout>
      <p>
        The intent is for every captured exchange in the inspector to be
        re-sendable without touching your browser — replay would reconstruct
        the original request and fire it straight at your local app.
      </p>

      <Anchor id="how-replay-works">How replay works</Anchor>
      <p>
        The plan: the inspector rebuilds the request from what it captured
        — method, URL path and query, headers minus the hop-by-hop ones, and
        body — and sends it <strong>directly to the local app</strong>{" "}
        through the same pooled transport the agent already uses, without
        going back through the edge.
      </p>
      <p>
        That matters because replay would then be deterministic, would work
        even if the tunnel is offline, and would test your app rather than
        the tunnel itself.
      </p>
      <Callout variant="tip" title="Planned: works without a public URL">
        Because replay would never leave your machine, you&apos;d be able to
        keep iterating on a request long after closing the tunnel or
        stepping off the network.
      </Callout>

      <Anchor id="replaying">Replaying a request</Anchor>
      <p>
        The design is to click replay on any exchange in the request list,
        or call the endpoint directly:
      </p>
      <CodeBlock
        language="bash"
        code={`$ curl -X POST http://localhost:4040/api/exchanges/{id}/replay \\
  -H "X-Ngstone: 1"`}
      />
      <p>
        The result would be entered into the store as a new exchange,
        flagged <code>Replayed: true</code>, so it could be compared against
        the original side by side.
      </p>

      <Anchor id="edit-and-replay">Edit and replay</Anchor>
      <p>
        &quot;Edit &amp; replay&quot; is planned to open the captured
        request in an editable form first, so you could tweak the method,
        headers, or body before resending.
      </p>

      <Anchor id="limitations">Limitations</Anchor>
      <p>
        Once built, bodies larger than the inspector&apos;s planned 256 KiB
        capture cap would be marked truncated, with replay disabled for
        them — there&apos;s no way to reconstruct bytes that were never
        captured.
      </p>
      <p>
        Because replay is a mutating action, the design requires the{" "}
        <code>X-Ngstone: 1</code> header plus a matching <code>Origin</code>{" "}
        check — the same protection meant to guard every mutating inspector
        endpoint against cross-site requests.
      </p>
    </DocsArticle>
  )
}
