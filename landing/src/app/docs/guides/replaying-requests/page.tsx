import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
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
        touching your browser — replay reconstructs the original request and
        fires it straight at your local app.
      </p>

      <Anchor id="how-replay-works">How replay works</Anchor>
      <p>
        Replay rebuilds the request from what was captured — method, URL
        path and query, headers minus the hop-by-hop ones, and body — and
        sends it <strong>directly to your local app</strong>, not back
        through the edge.
      </p>
      <p>
        That means replay is deterministic, works even if the tunnel is
        offline or the edge is unreachable, and tests your app rather than
        the tunnel itself.
      </p>
      <Callout variant="tip" title="Works without a public URL">
        Because replay never leaves your machine, you can keep iterating on
        a request long after closing the tunnel or stepping off the
        network.
      </Callout>

      <Anchor id="replaying">Replaying a request</Anchor>
      <p>
        Select any HTTP exchange in the request list and press{" "}
        <code>r</code>. The result is entered into the list as a new
        exchange, marked <code>↺</code>, so you can compare it against the
        original. While the replay is in flight, the row shows{" "}
        <code>~</code> instead.
      </p>

      <Anchor id="edit-and-replay">Edit and replay</Anchor>
      <p>
        Press <code>e</code> to open the selected request in an editable
        form first — method, URL, headers, and body. <code>tab</code> and{" "}
        <code>shift+tab</code> cycle between fields, <code>ctrl+s</code>{" "}
        sends the edited request, and <code>esc</code> discards the edit and
        closes the form without sending anything.
      </p>

      <Anchor id="limitations">Limitations</Anchor>
      <p>
        Bodies are captured up to 256 KiB. A request body larger than that
        is marked truncated, and <strong>a truncated request body cannot be
        replayed</strong> — the bytes genuinely weren&apos;t kept, and the
        UI says so rather than sending a partial body.
      </p>
      <p>
        WebSocket upgrades aren&apos;t replayable either — <code>r</code>{" "}
        and <code>e</code> do nothing when a <code>WS</code> row is
        selected, since there&apos;s no single request/response pair to
        reconstruct.
      </p>
    </DocsArticle>
  )
}
