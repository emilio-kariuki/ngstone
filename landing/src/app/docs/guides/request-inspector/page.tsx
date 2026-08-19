import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { Card, CardGrid } from "@/components/docs/card"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "Using the request inspector",
  description: "The terminal dashboard that shows every request as it happens.",
}

const TOC: TocItem[] = [
  { id: "opening", title: "Opening the inspector" },
  { id: "layout", title: "Layout" },
  { id: "the-request-list", title: "The request list" },
  { id: "inspecting", title: "Inspecting a request" },
  { id: "bodies-truncation", title: "Bodies and truncation" },
  { id: "har-export", title: "HAR export" },
  { id: "workflow-shortcuts", title: "Workflow shortcuts" },
  { id: "saved-replay-files", title: "Saved replay files" },
  { id: "key-bindings", title: "Key bindings" },
  { id: "plain-output", title: "Plain output instead" },
]

export default function RequestInspectorPage() {
  return (
    <DocsArticle href="/docs/guides/request-inspector" toc={TOC}>
      <h1>Using the request inspector</h1>
      <p>
        There is no web UI and no <code>localhost:4040</code>.{" "}
        <code>ngstone port</code> opens a full-screen terminal dashboard
        (built on Bubble Tea) that shows every request and response as it
        passes through your tunnel — nothing leaves your machine to render
        it.
      </p>

      <Anchor id="opening">Opening the inspector</Anchor>
      <p>
        The inspector opens automatically whenever <code>ngstone port</code>{" "}
        runs with stdout attached to a terminal:
      </p>
      <CodeBlock language="bash" code={`$ ngstone port 3000`} />
      <p>
        It is skipped automatically when stdout is not a terminal — piping
        output, running under CI, or backgrounding the process with{" "}
        <code>&amp;</code> all fall back to plain log lines on stderr instead
        of taking over the screen. See{" "}
        <a href="#plain-output">Plain output instead</a> below.
      </p>

      <Anchor id="layout">Layout</Anchor>
      <p>The dashboard has four parts:</p>
      <ParamTable>
        <Property name="Header" type="">
          Connection state, latency, and the public forwarding URL mapped to
          your local target.
        </Property>
        <Property name="Request list" type="">
          A live, scrollable list of every exchange, newest first.
        </Property>
        <Property name="Detail pane" type="">
          Headers and decoded bodies for whichever request is selected.
        </Property>
        <Property name="Footer" type="">
          Key hints for the current mode.
        </Property>
      </ParamTable>
      <p>
        <code>tab</code> toggles focus between the request list and the
        detail pane. Request history is kept in memory for the life of the
        process and survives tunnel reconnects, so a blip in your network
        connection doesn&apos;t clear what you&apos;ve already captured.
      </p>

      <Anchor id="the-request-list">The request list</Anchor>
      <p>
        Each row shows a method, path, status, and duration. WebSocket
        upgrades show <code>WS</code> in the method column and, once
        connected, live byte counts in both directions instead of a
        duration — because a socket doesn&apos;t have a single duration
        while it&apos;s still open.
      </p>
      <Callout variant="note" title="A WebSocket appears the moment it connects">
        The entry is added to the list as soon as the <code>101</code>{" "}
        upgrade completes, not when the socket eventually closes. A
        long-lived connection shows up right away instead of sitting
        invisible for its entire lifetime.
      </Callout>
      <p>
        Replayed requests are marked with <code>↺</code>; a replay that is
        still in flight shows <code>~</code> instead.
      </p>
      <p>
        Press <code>/</code> to filter the list by method, a status class
        (<code>2xx</code>, <code>4xx</code>, etc.), or a path substring;{" "}
        <code>enter</code> commits the filter, <code>esc</code> cancels it.
      </p>

      <Anchor id="inspecting">Inspecting a request</Anchor>
      <p>
        Moving the selection (<code>↑</code>/<code>k</code>,{" "}
        <code>↓</code>/<code>j</code>) updates the detail pane with the full
        exchange: request and response headers, and both bodies. When the
        detail pane has focus, the same keys — plus <code>pgup</code>/
        <code>pgdown</code> — scroll it instead of moving the list
        selection.
      </p>

      <Anchor id="bodies-truncation">Bodies and truncation</Anchor>
      <p>
        Request and response bodies are captured up to a fixed cap. Beyond
        that, the entry is marked truncated rather than blocking the
        stream — capture observes, it never gates.
      </p>
      <ParamTable>
        <Property name="Capture cap" type="256 KiB per body">
          Bodies larger than this are marked truncated; the stream itself
          keeps flowing at full speed.
        </Property>
      </ParamTable>
      <p>
        <code>gzip</code> and <code>deflate</code> response bodies are
        decoded for display, so a compressed JSON response renders as
        readable JSON rather than a hex dump — the raw bytes are kept
        underneath so replay can still send the original encoding.{" "}
        <code>br</code> and <code>zstd</code> aren&apos;t decoded (they
        aren&apos;t in the Go standard library) and render as binary.
        Binary bodies of any kind render as a hex preview.
      </p>

      <Anchor id="har-export">HAR export</Anchor>
      <p>
        Export the in-memory request history when the process exits with{" "}
        <code>--har</code>:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone port 3000 --har requests.har
$ ngstone up --har project-requests.har`}
      />
      <p>
        The export is HAR 1.2. It includes the captured request and response
        headers, query parameters, timing, and bodies, with binary bodies
        encoded as base64. The inspector keeps the latest 200 exchanges, so
        the export is bounded and is written only when the tunnel exits.
      </p>
      <Callout variant="warning" title="Review HAR files before sharing">
        Authorization, cookie, <code>Set-Cookie</code>, proxy-authorization,
        and <code>X-API-Key</code> headers are replaced with{" "}
        <code>[REDACTED]</code> by default. Pass{" "}
        <code>--har-include-sensitive</code> only when you need those headers.
        Request and response bodies are still included and may contain
        secrets, so inspect the file before uploading or sharing it. The
        output file is created with mode <code>0600</code>.
      </Callout>

      <Anchor id="workflow-shortcuts">Workflow shortcuts</Anchor>
      <p>
        The inspector is also a small response investigation workbench. Press{" "}
        <code>c</code> to copy a redacted cURL command, or{" "}
        <code>C</code> when you explicitly need sensitive headers. After{" "}
        replaying a request with <code>r</code>, press <code>d</code> on the{" "}
        original or replay row to compare response status, headers, and body.
      </p>
      <Callout variant="note" title="Clipboard fallback">
        Copying uses <code>pbcopy</code> on macOS, <code>wl-copy</code> or{" "}
        <code>xclip</code> on Linux, and <code>clip</code> on Windows. If no{" "}
        clipboard command is available, the inspector prints the generated{" "}
        command in its error line so it can still be copied manually.
      </Callout>

      <Anchor id="saved-replay-files">Saved replay files</Anchor>
      <p>
        Press <code>s</code> on an HTTP request to write a private{" "}
        <code>ngstone-replay-&lt;id&gt;.json</code> file in the current{" "}
        directory. It contains the complete captured request, including the{" "}
        body, so treat it like a credential-bearing fixture and keep it out of{" "}
        source control.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone replay ngstone-replay-000000000001.json --target 3000
$ ngstone replay ngstone-replay-000000000001.json --target 3000 --json
$ ngstone replay ngstone-replay-000000000001.json --curl`}
      />
      <p>
        The CLI replay path sends the request directly to the local target,
        never back through the public tunnel. Use <code>--curl</code> to print
        a portable command instead of sending it.
      </p>

      <Anchor id="key-bindings">Key bindings</Anchor>
      <ParamTable>
        <Property name="↑/k, ↓/j" type="">
          Move the selection, or scroll the detail pane when it has focus.
        </Property>
        <Property name="tab" type="">
          Toggle focus between the list and the detail pane.
        </Property>
        <Property name="r" type="">
          Replay the selected request against your local app.
        </Property>
        <Property name="e" type="">
          Edit-and-replay: open a form over method, URL, headers, and body.
        </Property>
        <Property name="c / C" type="">
          Copy a redacted or sensitive cURL command for the selected request.
        </Property>
        <Property name="d" type="">
          Compare a response with its replay; press again to close the diff.
        </Property>
        <Property name="s" type="">
          Save the selected request as a private replay JSON file.
        </Property>
        <Property name="/" type="">
          Filter by method, path substring, or status class.
        </Property>
        <Property name="l" type="">
          Toggle a log pane.
        </Property>
        <Property name="?" type="">
          Toggle full help.
        </Property>
        <Property name="q, ctrl+c" type="">
          Quit.
        </Property>
      </ParamTable>

      <Anchor id="plain-output">Plain output instead</Anchor>
      <p>
        Pass <code>--no-tui</code> to skip the dashboard and log plain text
        to stderr instead — useful for scripts, or when you just want a
        scrolling log:
      </p>
      <CodeBlock language="bash" code={`$ ngstone port 3000 --no-tui`} />
      <CardGrid columns={2}>
        <Card title="Replaying requests" href="/docs/guides/replaying-requests">
          Re-send a captured request straight to your local app.
        </Card>
        <Card title="CLI reference" href="/docs/reference/cli">
          Every <code>ngstone port</code> flag.
        </Card>
      </CardGrid>
    </DocsArticle>
  )
}
