import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"

export const metadata: Metadata = {
  title: "Streaming & large transfers",
  description: "Big uploads, downloads, and constant-memory forwarding.",
}

const TOC: TocItem[] = [
  { id: "backpressure", title: "Backpressure and flow control" },
  { id: "constant-memory", title: "Constant memory" },
  { id: "body-limits", title: "Body size limits" },
  { id: "slow-app-timeouts", title: "Timeouts on slow apps" },
]

export default function StreamingLargeTransfersPage() {
  return (
    <DocsArticle href="/docs/guides/streaming-large-transfers" toc={TOC}>
      <h1>Streaming &amp; large transfers</h1>
      <p>
        Nothing about a large upload or download is a special code path in
        ngstone — both proxies are plain <code>io.Copy</code> loops over
        flow-controlled yamux streams, so the same machinery that handles a
        tiny JSON response also handles a gigabyte download.
      </p>

      <Anchor id="backpressure">Backpressure and flow control</Anchor>
      <p>
        A slow browser backpressures all the way down to the app&apos;s
        socket writes. When the reader on one end stops draining, the yamux
        stream&apos;s window fills, the writer blocks, and that block
        propagates straight back through the tunnel — there is no
        application-level buffering anywhere in the path.
      </p>

      <Anchor id="constant-memory">Constant memory</Anchor>
      <p>
        Constant-memory forwarding isn&apos;t just a design goal — it&apos;s
        asserted in CI. A 1 GiB download and a 100 MB streamed body both run
        under a <code>runtime.MemStats</code> check that fails the build if
        memory grows with transfer size instead of staying flat.
      </p>
      <CodeBlock
        language="text"
        code={`1 GiB download  ──►  constant memory (CI-asserted)
100 MB streamed body ──►  constant memory (CI-asserted)`}
      />

      <Anchor id="body-limits">Body size limits</Anchor>
      <p>
        The edge caps request bodies at <strong>256 MiB</strong>. There are
        two enforcement paths, because the obvious single-path
        implementation returns the wrong status code:
      </p>
      <ul>
        <li>
          A declared <code>Content-Length</code> over the cap is rejected{" "}
          <strong>before</strong> the request is proxied — a real{" "}
          <code>413</code>, nothing crosses the tunnel.
        </li>
        <li>
          A chunked or unknown-length body is enforced with{" "}
          <code>MaxBytesReader</code>, which also synthesizes a{" "}
          <code>413</code> once the cap is hit.
        </li>
      </ul>
      <Callout variant="warning" title="A chunked 413 may ship a partial body">
        Because the chunked path trips mid-stream, the agent may already
        have forwarded a partial body to your local app by the time the
        edge returns <code>413</code> to the client. Well-behaved clients
        never hit this; it only matters if you&apos;re debugging a
        truncated request on the app side.
      </Callout>

      <Anchor id="slow-app-timeouts">Timeouts on slow apps</Anchor>
      <p>
        <code>ResponseHeaderTimeout</code> gives your local app{" "}
        <strong>30 seconds</strong> to start responding before the edge gives
        up and returns <code>504</code>. Once headers arrive, though, there
        is no duration limit — downloads and SSE streams can run as long as
        the client stays interested, bounded only by client patience and
        flow control.
      </p>
      <p>
        Under the hood, each yamux stream carries a <strong>1 MiB</strong>{" "}
        receive window, and peak tunnel buffering across all concurrent
        streams tops out at 64 × 1 MiB = <strong>64 MiB</strong> per side —
        the largest single buffer in the system. See{" "}
        <a href="/docs/reference/limits-timeouts">Limits &amp; timeouts</a>{" "}
        for the full table.
      </p>
    </DocsArticle>
  )
}
