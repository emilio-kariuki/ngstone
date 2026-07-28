import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "Configuration",
  description: "The agent's config file, and the edge's flags and environment.",
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
        The agent keeps a small JSON config file; the edge is flags and
        environment variables only, with no config-file dependency.
      </p>

      <Anchor id="agent-config">Agent (ngstone)</Anchor>
      <p>
        <code>ngstone auth</code>, <code>ngstone config set</code>, and{" "}
        <code>ngstone logout</code> read and write:
      </p>
      <CodeBlock
        language="text"
        code={`$XDG_CONFIG_HOME/ngstone/config.json
# falls back to ~/.config/ngstone/config.json if XDG_CONFIG_HOME is unset`}
      />
      <ParamTable>
        <Property name="token" type="string">
          Saved by <code>ngstone auth &lt;token&gt;</code> after it verifies
          against the edge. Cleared by <code>ngstone logout</code>.
        </Property>
        <Property name="server" type="string">
          Saved by <code>ngstone auth</code> or{" "}
          <code>ngstone config set server &lt;addr&gt;</code>. Falls back to{" "}
          <code>ngstone.site:4443</code> if never set.
        </Property>
      </ParamTable>
      <p>
        The file is written mode <code>0600</code> inside a{" "}
        <code>0700</code> directory, via a temp-file-plus-rename so a crash
        mid-write can&apos;t corrupt it. See{" "}
        <a href="/docs/reference/cli#ngstone-config">
          <code>ngstone config</code>
        </a>{" "}
        for the commands that read and write it.
      </p>

      <Anchor id="edge-config">Edge (ngstoned)</Anchor>
      <ParamTable>
        <Property name="-domain" type="string" defaultValue="ngstone.site">
          Base domain used to build tunnel hostnames and the two managed
          certificates.
        </Property>
        <Property name="-public" type="string" defaultValue=":443">
          Public HTTPS listen address.
        </Property>
        <Property name="-control" type="string" defaultValue=":4443">
          Control-plane listen address — what the agent dials.
        </Property>
        <Property name="-http" type="string" defaultValue=":80">
          HTTP redirect listen address. Unused with <code>-insecure</code>.
        </Property>
        <Property name="-ops" type="string" defaultValue="127.0.0.1:4041">
          Loopback ops endpoint (<code>expvar</code>, <code>/healthz</code>,
          pprof). Empty disables it.
        </Property>
        <Property name="-public-scheme" type="string" defaultValue="https">
          Scheme advertised in <code>BindOK.URL</code> — <code>http</code>{" "}
          or <code>https</code>.
        </Property>
        <Property name="-token-sha256" type="string" required>
          Hex-encoded SHA-256 of the shared auth token. Defaults to{" "}
          <code>$NGSTONE_TOKEN_SHA256</code>. See{" "}
          <a href="/docs/reference/cli#generating-a-token">
            Generating a token
          </a>
          .
        </Property>
        <Property name="-insecure" type="bool" defaultValue="false">
          Run with no TLS anywhere and no certificate management. Dev/test
          only.
        </Property>
        <Property name="-acme-ca" type="string" defaultValue="staging">
          ACME CA: <code>staging</code> or <code>production</code>. A
          config mistake against production can rate-limit the domain for
          a week.
        </Property>
        <Property name="-cert-email" type="string" required>
          ACME account email. Required unless <code>-insecure</code>.
        </Property>
        <Property name="-cert-storage" type="string">
          <code>certmagic.FileStorage</code> path; must match the systemd{" "}
          <code>StateDirectory</code>.
        </Property>
        <Property name="-cf-api-token" type="string" required>
          Cloudflare API token scoped to <code>Zone:DNS:Edit</code> on the
          one zone. Required unless <code>-insecure</code>. Defaults to{" "}
          <code>$NGSTONE_CF_API_TOKEN</code>.
        </Property>
      </ParamTable>
      <p>
        Every value in the timeouts and limits table — request timeouts,
        body caps, rate limits, concurrency caps — is also flag-overridable
        on the edge (<code>-read-header-timeout</code>,{" "}
        <code>-idle-timeout</code>, <code>-max-header-bytes</code>,{" "}
        <code>-max-body-bytes</code>, <code>-response-header-timeout</code>,{" "}
        <code>-per-ip-rate</code>, <code>-per-ip-burst</code>,{" "}
        <code>-per-ip-lru</code>, <code>-global-inflight</code>,{" "}
        <code>-per-session-inflight</code>, <code>-upgrade-inflight</code>,{" "}
        <code>-per-session-upgrade</code>,{" "}
        <code>-handshake-concurrency</code>, <code>-unauth-sessions</code>).
        See{" "}
        <a href="/docs/reference/limits-timeouts">Limits &amp; timeouts</a>{" "}
        for the full set and their defaults.
      </p>

      <Anchor id="environment">Environment variables</Anchor>
      <ParamTable>
        <Property name="NGSTONE_TOKEN" type="agent env">
          Fallback token source for <code>ngstone port</code>, below a
          <code>--token</code> flag and above the saved config file.
        </Property>
        <Property name="NGSTONE_TOKEN_SHA256" type="edge env">
          Preferred way to pass the token hash to <code>ngstoned</code>{" "}
          instead of <code>-token-sha256</code>.
        </Property>
        <Property name="NGSTONE_CF_API_TOKEN" type="edge env">
          Preferred way to pass the Cloudflare token to{" "}
          <code>ngstoned</code> instead of <code>-cf-api-token</code>.
        </Property>
      </ParamTable>
      <Callout variant="danger" title="Never pass secrets as flags">
        <code>/proc/&lt;pid&gt;/cmdline</code> is world-readable on stock
        Linux, so anything passed as an <code>ExecStart</code> flag is
        readable by any local user via <code>ps auxww</code>. Load secrets
        from <code>EnvironmentFile=</code> instead.
      </Callout>

      <Anchor id="precedence">Precedence</Anchor>
      <p>On the edge, an explicit flag always wins over its environment fallback; anything left unset falls back to its documented default.</p>
      <p>On the agent, resolving the token or server address for <code>ngstone port</code> follows this chain:</p>
      <ParamTable>
        <Property name="1. Flag" type="highest precedence">
          <code>--token</code> / <code>--server</code>.
        </Property>
        <Property name="2. Environment" type="token only">
          <code>NGSTONE_TOKEN</code>. There is no environment override for
          the server address.
        </Property>
        <Property name="3. Config file" type="">
          Whatever <code>ngstone auth</code> or{" "}
          <code>ngstone config set</code> last saved.
        </Property>
        <Property name="4. Default" type="server only" defaultValue="ngstone.site:4443">
          Used only if nothing above set a server address. There is no
          default token — an unresolved token is a hard error.
        </Property>
      </ParamTable>
    </DocsArticle>
  )
}
