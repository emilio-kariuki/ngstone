import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"

export const metadata: Metadata = {
  title: "Replaying requests",
  description: "Re-send a captured request straight to your local app.",
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
      <p>
        Every captured exchange in the inspector can be re-sent without
        touching your browser. Replay reconstructs the original request and
        fires it straight at your local app.
      </p>

      <Anchor id="how-replay-works">How replay works</Anchor>
      <p>
        The inspector rebuilds the request from what it captured — method,
        URL path and query, headers minus the hop-by-hop ones, and body — and
        sends it <strong>directly to the local app</strong> through the same
        pooled transport the agent already uses. It does not go back through
        the edge.
      </p>
      <p>
        That matters: replay is deterministic, it works even if the tunnel is
        offline, and it tests your app rather than the tunnel itself.
      </p>
      <Callout variant="tip" title="Works without a public URL">
        Because replay never leaves your machine, you can keep iterating on a
        request long after you&apos;ve closed the tunnel or stepped off the
        network.
      </Callout>

      <Anchor id="replaying">Replaying a request</Anchor>
      <p>
        Click replay on any exchange in the request list, or call the
        endpoint directly:
      </p>
      <CodeBlock
        language="bash"
        code={`$ curl -X POST http://localhost:4040/api/exchanges/{id}/replay \\
  -H "X-Ngstone: 1"`}
      />
      <p>
        The result is entered into the store as a new exchange, flagged{" "}
        <code>Replayed: true</code>, so you can compare it against the
        original side by side.
      </p>

      <Anchor id="edit-and-replay">Edit and replay</Anchor>
      <p>
        &quot;Edit &amp; replay&quot; opens the captured request in an
        editable form first, so you can tweak the method, headers, or body
        before resending — handy for poking at an edge case without
        re-triggering it from the browser.
      </p>

      <Anchor id="limitations">Limitations</Anchor>
      <p>
        Bodies larger than the inspector&apos;s 256 KiB capture cap are
        marked truncated, and replay is disabled for them with an
        explanatory tooltip — there&apos;s no way to reconstruct bytes that
        were never captured.
      </p>
      <p>
        Because replay is a mutating action, it requires the{" "}
        <code>X-Ngstone: 1</code> header plus a matching <code>Origin</code>{" "}
        check — the same protection that guards every mutating inspector
        endpoint against cross-site requests.
      </p>
    </DocsArticle>
  )
}
