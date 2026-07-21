import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "CLI",
  description: "The ngstone command and its subcommands.",
}

const TOC: TocItem[] = [
  { id: "ngstone-http", title: "ngstone http" },
  { id: "ngstone-token", title: "ngstone token" },
  { id: "ngstone-version", title: "ngstone version" },
  { id: "status-line", title: "Live status line" },
]

export default function CliPage() {
  return (
    <DocsArticle href="/docs/reference/cli" toc={TOC}>
      <h1>CLI</h1>
      <p>
        The <code>ngstone</code> command is built on the stdlib{" "}
        <code>flag</code> package — no cobra, no subcommand framework. There
        are exactly three verbs: <code>http</code>, <code>token</code>, and{" "}
        <code>version</code>.
      </p>

      <Anchor id="ngstone-http">ngstone http</Anchor>
      <p>
        Starts a tunnel to a local port and brings up the inspector
        alongside it.
      </p>
      <CodeBlock language="bash" code={`$ ngstone http <port> [flags]`} />
      <ParamTable>
        <Property name="--subdomain" type="string">
          Request a specific subdomain instead of a random one, e.g.{" "}
          <code>--subdomain api</code> for <code>api.ngstone.site</code>.
        </Property>
        <Property name="--host-header" type="string">
          Rewrite the <code>Host</code> header sent to the local app, e.g.{" "}
          <code>--host-header=localhost:3000</code>. Useful for apps that
          are picky about vhost routing.
        </Property>
        <Property name="--allow-cidr" type="string">
          Restrict the tunnel to an allowlist of client CIDRs instead of
          accepting traffic from anywhere.
        </Property>
        <Property name="--inspect-port" type="int" defaultValue="4040">
          Bind the local inspector to a different port — needed if you run
          more than one <code>ngstone</code> process at once.
        </Property>
        <Property name="--pin" type="string">
          Pin the edge&apos;s certificate by SPKI hash, e.g.{" "}
          <code>--pin sha256/BASE64</code>, checked in addition to normal
          chain validation. Off by default.
        </Property>
      </ParamTable>

      <Anchor id="ngstone-token">ngstone token</Anchor>
      <p>
        <code>ngstone token new</code> generates a fresh auth token — 32
        random bytes, base64url-encoded — for use as{" "}
        <code>NGSTONE_TOKEN</code>.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone token new
nst_••••••••••••••••••••`}
      />

      <Anchor id="ngstone-version">ngstone version</Anchor>
      <p>
        Prints the build&apos;s version string, injected at compile time via{" "}
        <code>-ldflags</code>.
      </p>
      <CodeBlock language="bash" code={`$ ngstone version
ngstone/0.3.0 darwin/amd64`} />

      <Anchor id="status-line">Live status line</Anchor>
      <p>
        While a tunnel runs, <code>ngstone http</code> prints a live status
        line driven directly by session-state events — dialing, connected,
        the assigned URL, and reconnecting — so you always know whether the
        tunnel is actually up without digging through logs.
      </p>
      <CodeBlock
        language="text"
        code={`ngstone  dialing ngstone.site:4443…
ngstone  connected
ngstone  https://amber-fox-42.ngstone.site  →  localhost:3000
ngstone  reconnecting (attempt 2, backoff 1.2s)…`}
      />
    </DocsArticle>
  )
}
