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
        <Property name="-domain" type="string" required>
          Base domain used to build tunnel hostnames and the two managed
          certificates, for example <code>example.com</code>. There is no
          default.
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
        <Property name="-dns-provider" type="string" defaultValue="cloudflare">
          DNS provider used for the DNS-01 certificate challenges:{" "}
          <code>cloudflare</code>, <code>route53</code>,{" "}
          <code>digitalocean</code>, <code>hetzner</code>,{" "}
          <code>vultr</code>, <code>ovh</code>, <code>desec</code>, or{" "}
          <code>bunny</code>. Its credentials are read from the environment
          only — see below. <code>-dns-provider help</code> prints the
          providers and the variables each reads, then exits.
        </Property>
        <Property name="-cf-api-token" type="string">
          Legacy flag for the Cloudflare API token, used only with{" "}
          <code>-dns-provider cloudflare</code> when{" "}
          <code>$NGSTONE_CF_API_TOKEN</code> is unset. Prefer the
          environment variable.
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
          <code>-dns-provider cloudflare</code>: API token with{" "}
          <code>Zone</code> / <code>DNS</code> / <code>Edit</code> on the
          zone only. Preferred over <code>-cf-api-token</code>.
        </Property>
        <Property
          name="NGSTONE_AWS_REGION, NGSTONE_AWS_ACCESS_KEY_ID, NGSTONE_AWS_SECRET_ACCESS_KEY"
          type="edge env"
        >
          <code>-dns-provider route53</code>: region and the keys of an IAM
          user allowed <code>route53:ListHostedZonesByName</code>,{" "}
          <code>ListResourceRecordSets</code>,{" "}
          <code>ChangeResourceRecordSets</code>, and <code>GetChange</code>.
        </Property>
        <Property name="NGSTONE_DO_API_TOKEN" type="edge env">
          <code>-dns-provider digitalocean</code>: personal access token
          with domain read and write.
        </Property>
        <Property name="NGSTONE_HETZNER_API_TOKEN" type="edge env">
          <code>-dns-provider hetzner</code>: read and write API token of
          the Hetzner Console project holding the zone. Zones on the
          deprecated <code>dns.hetzner.com</code> must be migrated first.
        </Property>
        <Property name="NGSTONE_VULTR_API_KEY" type="edge env">
          <code>-dns-provider vultr</code>: API key, with the VPS&apos;s IP
          allowed in its access control.
        </Property>
        <Property
          name="NGSTONE_OVH_ENDPOINT, NGSTONE_OVH_APPLICATION_KEY, NGSTONE_OVH_APPLICATION_SECRET, NGSTONE_OVH_CONSUMER_KEY"
          type="edge env"
        >
          <code>-dns-provider ovh</code>: endpoint <code>ovh-eu</code>,{" "}
          <code>ovh-ca</code>, or <code>ovh-us</code>, plus a consumer key
          limited to <code>GET</code>, <code>POST</code>, and{" "}
          <code>DELETE</code> on <code>/domain/zone/*</code>.
        </Property>
        <Property name="NGSTONE_DESEC_TOKEN" type="edge env">
          <code>-dns-provider desec</code>: API token. deSEC&apos;s 3600 s
          minimum TTL and rate limits can make issuance take a few minutes.
        </Property>
        <Property name="NGSTONE_BUNNY_API_KEY" type="edge env">
          <code>-dns-provider bunny</code>: account API key.
        </Property>
      </ParamTable>
      <p>
        Only providers whose <code>libdns</code> module adds and removes
        individual TXT values are supported, because the apex and wildcard
        certificates publish challenges at the same name concurrently.
        GoDaddy, Namecheap, Porkbun, IONOS, Azure, DNSimple, and netcup are
        not; move the zone&apos;s DNS hosting to a supported provider
        instead. See{" "}
        <a href="/docs/guides/edge-vps#dns-provider">Choosing a DNS provider</a>.
      </p>
      <Callout variant="danger" title="Never pass secrets as flags">
        <code>/proc/&lt;pid&gt;/cmdline</code> is world-readable on stock
        Linux, so anything passed as an <code>ExecStart</code> flag is
        readable by any local user via <code>ps auxww</code>. Load secrets
        from <code>EnvironmentFile=</code> instead.
      </Callout>

      <Anchor id="precedence">Precedence</Anchor>
      <p>On the edge, <code>$NGSTONE_TOKEN_SHA256</code> and <code>$NGSTONE_CF_API_TOKEN</code> win over <code>-token-sha256</code> and <code>-cf-api-token</code> when both are set, and other DNS provider credentials come from the environment only. Every other setting is a flag that falls back to its documented default when unset.</p>
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
