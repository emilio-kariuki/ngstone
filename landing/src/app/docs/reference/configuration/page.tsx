import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "Configuration",
  description: "Flags and environment for both binaries.",
}

const TOC: TocItem[] = [
  { id: "agent-config", title: "Agent (ngstone)" },
  { id: "edge-config", title: "Edge (ngstoned)" },
  { id: "environment", title: "Environment variables" },
  { id: "precedence", title: "Precedence" },
]

export default function ConfigurationPage() {
  return (
    <DocsArticle href="/docs/reference/configuration" toc={TOC}>
      <h1>Configuration</h1>
      <p>
        Both binaries are configured with flags and environment variables
        only — there is no config-file dependency in v1. Everything lives in{" "}
        <code>internal/config</code>.
      </p>

      <Anchor id="agent-config">Agent (ngstone)</Anchor>
      <ParamTable>
        <Property name="NGSTONE_TOKEN" type="env" required>
          The bearer token the agent presents to the edge during{" "}
          <code>Auth</code>. Never a flag — see{" "}
          <a href="#environment">Environment variables</a> below.
        </Property>
        <Property name="--subdomain" type="string">
          Request a specific subdomain instead of a random one.
        </Property>
        <Property name="--host-header" type="string">
          Rewrite the <code>Host</code> header forwarded to the local app.
        </Property>
        <Property name="--allow-cidr" type="string">
          Restrict the tunnel to an allowlist of client CIDRs.
        </Property>
        <Property name="--inspect-port" type="int" defaultValue="4040">
          Port for the local inspector UI and API.
        </Property>
        <Property name="--pin" type="string">
          Optional SPKI pin for the edge&apos;s certificate, e.g.{" "}
          <code>--pin sha256/BASE64</code>, checked in addition to normal
          chain validation.
        </Property>
      </ParamTable>

      <Anchor id="edge-config">Edge (ngstoned)</Anchor>
      <ParamTable>
        <Property name="--domain" type="string" required>
          The base domain to serve, e.g. <code>ngstone.site</code>. Drives
          both the wildcard and apex certificate orders.
        </Property>
        <Property name="--email" type="string" required>
          Contact address for ACME account registration.
        </Property>
        <Property name="token_sha256" type="config">
          The SHA-256 hash of the auth token agents must present. The
          plaintext token never lives on the VPS disk.
        </Property>
      </ParamTable>
      <p>
        Every value in the timeouts and limits table — request timeouts,
        body caps, rate limits, concurrency caps — is flag-overridable on
        the edge. See{" "}
        <a href="/docs/reference/limits-timeouts">Limits &amp; timeouts</a>{" "}
        for the full set and their defaults.
      </p>

      <Anchor id="environment">Environment variables</Anchor>
      <p>
        <code>NGSTONE_TOKEN</code> is the one value that&apos;s deliberately
        environment-only rather than a flag, on the agent side. The edge&apos;s
        equivalent secret, <code>token_sha256</code>, is meant to reach the
        process the same way when run under systemd — via{" "}
        <code>EnvironmentFile=</code>, not a command-line flag.
      </p>
      <Callout variant="danger" title="Never pass secrets as flags">
        <code>/proc/&lt;pid&gt;/cmdline</code> is world-readable on stock
        Linux, so anything passed as an <code>ExecStart</code> flag is
        readable by any local user via <code>ps auxww</code>. Load secrets
        from <code>EnvironmentFile=</code> instead.
      </Callout>

      <Anchor id="precedence">Precedence</Anchor>
      <p>
        With no config-file layer, there&apos;s only one chain to reason
        about: an explicit flag always wins, and anything left unset falls
        back to its documented default (for example, the inspector defaults
        to port <code>4040</code> unless <code>--inspect-port</code> says
        otherwise). The token is the exception — it deliberately has no
        flag form, so there&apos;s nothing for a flag to override.
      </p>
    </DocsArticle>
  )
}
