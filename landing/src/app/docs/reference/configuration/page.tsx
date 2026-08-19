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
  { id: "project-config", title: "Project (ngstone up)" },
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

      <Anchor id="project-config">Project (ngstone up)</Anchor>
      <p>
        <code>ngstone up</code> starts several tunnels from a checked-in JSON
        project file. It searches the current directory for{" "}
        <code>ngstone.json</code>, then <code>.ngstone.json</code>; use{" "}
        <code>--file</code> to select another path.
      </p>
      <CodeBlock
        language="json"
        code={`{
  "tunnels": {
    "web": {
      "target": "3000",
      "subdomain": "demo",
      "host_header": "demo.localhost:3000",
      "credential_env": "NGSTONE_WEB_TOKEN",
      "multi_connector": true,
      "connector_token_env": "NGSTONE_CONNECTOR_TOKEN",
      "policy_file": "traffic-policy.json",
      "ttl": "2h"
    },
    "grpc": {
      "target": "http://127.0.0.1:50051",
      "http2": true
    },
    "database": {
      "kind": "tcp",
      "target": "5432",
      "remote_port": 15432
    }
  }
}`}
      />
      <ParamTable>
        <Property name="tunnels" type="object" required>
          Map of stable tunnel names to definitions. Names may contain
          letters, numbers, <code>-</code>, <code>_</code>, and <code>.</code>.
        </Property>
        <Property name="kind" type="string" defaultValue="http">
          Either <code>http</code> or <code>tcp</code>.
        </Property>
        <Property name="target" type="string" required>
          Bare local port, <code>host:port</code> for TCP, or a full HTTP URL.
        </Property>
        <Property name="subdomain" type="string">
          Requested public subdomain.
        </Property>
        <Property name="host_header" type="string">
          HTTP-only Host header for the local app. For example, set it to{" "}
          <code>demo.localhost:3000</code> for a tenant-aware local app.
        </Property>
        <Property name="http2" type="bool" defaultValue="false">
          HTTP-only. Forward the tunnel over native HTTP/2. An{" "}
          <code>https://</code> target uses TLS HTTP/2; an{" "}
          <code>http://</code> target uses cleartext h2c. Enable this for
          native gRPC, trailers, streaming, and full-duplex requests.
        </Property>
        <Property name="multi_connector" type="bool" defaultValue="false">
          HTTP-only. Allow multiple agent processes to share the same named
          subdomain and load-balance requests across healthy connectors. Every
          connector must use the same setting and public subdomain; a
          connector must reconnect or drain independently.
        </Property>
        <Property name="connector_token_env" type="string" defaultValue="NGSTONE_CONNECTOR_TOKEN">
          Environment variable name containing the per-tunnel connector
          secret for <code>multi_connector</code> mode. The project file stores
          only the variable name, never the secret itself.
        </Property>
        <Property name="credential_env" type="string">
          Environment variable containing this tunnel&apos;s scoped edge
          credential. The project file stores only the variable name, never
          the token itself. If unset, <code>NGSTONE_TOKEN</code> or the saved
          config token is used.
        </Property>
        <Property name="remote_port" type="int" defaultValue="0">
          TCP-only requested public port; <code>0</code> means assigned.
        </Property>
        <Property name="ttl" type="duration">
          Positive duration such as <code>2h</code>. The tunnel stops when
          the duration from process start expires.
        </Property>
        <Property name="server, server_name, pin" type="string">
          Per-tunnel control-plane and TLS overrides.
        </Property>
        <Property name="transport" type="string" defaultValue="auto">
          Control transport. <code>auto</code> tries raw TLS first and falls
          back to the authenticated WebSocket endpoint on HTTPS port{" "}
          <code>443</code>; use <code>raw</code> or{" "}
          <code>websocket</code> to force one path.
        </Property>
        <Property name="insecure" type="bool" defaultValue="false">
          Disable TLS for development and testing only.
        </Property>
        <Property name="basic_auth_file" type="string">
          HTTP-only path to one <code>user:pass</code> credential per line.
          Relative paths are resolved from the project file directory.
        </Property>
        <Property name="allow_cidr" type="string">
          Comma-separated source CIDRs allowed by the edge.
        </Property>
        <Property name="policy_file" type="string">
          HTTP-only path to a strict JSON traffic policy. Relative paths are
          resolved from the project file directory; rules are evaluated in
          order at the edge.
        </Property>
      </ParamTable>
      <p>
        The project format is strict JSON: unknown fields fail fast. It never
        accepts <code>token</code>; <code>ngstone up</code> resolves the token
        from <code>NGSTONE_TOKEN</code> or the saved credential file, just
        like <code>ngstone port</code>. Keep credential files out of source
        control, and protect any <code>basic_auth_file</code> with mode{" "}
        <code>0600</code>.
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
        <Property name="-admin-token-sha256" type="string">
          Hex-encoded SHA-256 of the management API bearer token. When unset,
          <code>/api/v1</code> accepts only loopback requests. Defaults to{" "}
          <code>$NGSTONE_ADMIN_TOKEN_SHA256</code>. Store only the hash on the
          edge and keep the plaintext token with the operator.
        </Property>
        <Property name="-oidc-issuer, -oidc-client-id" type="string">
          OIDC issuer and client ID. These enable browser management login;
          client secret and cookie secret are read only from{" "}
          <code>NGSTONE_OIDC_CLIENT_SECRET</code> and{" "}
          <code>NGSTONE_OIDC_COOKIE_SECRET</code>.
        </Property>
        <Property name="-oidc-redirect-url" type="string">
          Exact HTTPS callback registered with the OIDC provider, normally{" "}
          <code>https://edge.example.com:4041/api/v1/auth/oidc/callback</code>.
        </Property>
        <Property name="-oidc-admin-groups, -oidc-operator-groups, -oidc-viewer-groups" type="string">
          Comma-separated IdP groups mapped to the <code>admin</code>,{" "}
          <code>operator</code>, and <code>viewer</code> roles. A user must
          match a group unless <code>-oidc-default-role</code> is set.
        </Property>
        <Property name="-oidc-groups-claim" type="string" defaultValue="groups">
          Userinfo claim containing team/group names.
        </Property>
        <Property name="-oidc-allowed-email-domains" type="string">
          Optional comma-separated email domain allow-list.
        </Property>
        <Property name="-oidc-default-role" type="string">
          Optional fallback role for an authenticated user with no matching
          group. Empty by default, which is the least-privilege setting.
        </Property>
        <Property name="-public-scheme" type="string" defaultValue="https">
          Scheme advertised in <code>BindOK.URL</code> — <code>http</code>{" "}
          or <code>https</code>.
        </Property>
        <Property name="-credentials-file" type="path">
          Legacy versioned per-tunnel credential file. The durable database
          backend is preferred for new deployments. Defaults to{" "}
          <code>$NGSTONE_CREDENTIALS_FILE</code>.
        </Property>
        <Property name="-database-url" type="string">
          Durable control-plane database URL. Defaults to{" "}
          <code>$NGSTONE_DATABASE_URL</code> or SQLite at{" "}
          <code>/var/lib/ngstoned/control.db</code> when no legacy credential
          source is configured. Use a PostgreSQL URL for multiple edge servers.
        </Property>
        <Property name="-database-driver" type="string">
          Optional <code>sqlite</code> or <code>postgres</code> override. The
          driver is inferred from the database URL when omitted.
        </Property>
        <Property name="-edge-id" type="string">
          Stable identity for this edge process in connector leases and audit
          events. Defaults to <code>$NGSTONE_EDGE_ID</code> or a generated ID.
        </Property>
        <Property name="-lease-ttl" type="duration" defaultValue="45s">
          Connector lease lifetime. Heartbeats renew it while a connector is
          healthy; an expired lease can be reclaimed by another edge.
        </Property>
        <Property name="-token-sha256" type="string">
          Legacy hex-encoded SHA-256 of the shared auth token. Used only when
          <code>-credentials-file</code> and{" "}
          <code>$NGSTONE_CREDENTIALS_FILE</code> are unset. See{" "}
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
          Fallback token source for <code>ngstone port</code>, <code>tcp</code>,
          and <code>up</code>, below a <code>--token</code> flag where one
          exists and above the saved config file.
        </Property>
        <Property name="NGSTONE_ADMIN_SERVER" type="admin CLI env">
          Default management API URL for <code>ngstone admin</code>. It
          defaults to <code>http://127.0.0.1:4041</code>.
        </Property>
        <Property name="NGSTONE_ADMIN_TOKEN" type="admin CLI env">
          Bearer token for <code>ngstone admin</code>. Prefer this environment
          variable to <code>--token</code> so the secret is not visible in
          process listings.
        </Property>
        <Property name="NGSTONE_OIDC_ISSUER, NGSTONE_OIDC_CLIENT_ID" type="edge env">
          OIDC provider issuer and client ID. Setting any OIDC value activates
          validation of the complete browser-login configuration.
        </Property>
        <Property name="NGSTONE_OIDC_CLIENT_SECRET, NGSTONE_OIDC_COOKIE_SECRET" type="edge env">
          OIDC client secret and at least 32 bytes of random cookie-encryption
          secret. These values have no command-line flag and must stay in the
          root-only environment file.
        </Property>
        <Property name="NGSTONE_OIDC_REDIRECT_URL" type="edge env">
          Exact callback URL registered at the provider.
        </Property>
        <Property name="NGSTONE_OIDC_GROUPS_CLAIM, NGSTONE_OIDC_ADMIN_GROUPS, NGSTONE_OIDC_OPERATOR_GROUPS, NGSTONE_OIDC_VIEWER_GROUPS" type="edge env">
          Group claim and comma-separated role mappings. Admin wins over
          operator, which wins over viewer.
        </Property>
        <Property name="NGSTONE_OIDC_ALLOWED_EMAIL_DOMAINS, NGSTONE_OIDC_DEFAULT_ROLE" type="edge env">
          Optional email-domain allow-list and fallback role. The fallback is
          empty by default, so an unmapped IdP user is rejected.
        </Property>
        <Property name="NGSTONE_TOKEN_SHA256" type="edge env">
          Legacy shared-token hash. Prefer{" "}
          <code>NGSTONE_CREDENTIALS_FILE</code>.
        </Property>
        <Property name="NGSTONE_CREDENTIALS_FILE" type="edge env">
          Compatibility path to the scoped credential file. Use the durable
          database backend for new deployments.
        </Property>
        <Property name="NGSTONE_DATABASE_URL" type="edge env">
          Durable SQLite or PostgreSQL URL. SQLite is the default when neither
          this variable nor a legacy credential source is set.
        </Property>
        <Property name="NGSTONE_DATABASE_DRIVER" type="edge env">
          Optional database driver override: <code>sqlite</code> or{" "}
          <code>postgres</code>.
        </Property>
        <Property name="NGSTONE_EDGE_ID" type="edge env">
          Stable edge identity used for leases and audit records.
        </Property>
        <Property name="NGSTONE_CF_API_TOKEN" type="edge env">
          Preferred way to pass the Cloudflare token to{" "}
          <code>ngstoned</code> instead of <code>-cf-api-token</code>.
        </Property>
        <Property name="NGSTONE_ADMIN_TOKEN_SHA256" type="edge env">
          SHA-256 hash of the management API bearer token. It enables bearer
          authentication for <code>/api/v1</code>; without it, that API is
          loopback-only. Prefer this environment variable to the equivalent
          command-line flag.
        </Property>
        <Property name="-alert-webhook" type="string">
          HTTP(S) webhook for connector, lease, and credential lifecycle
          events. Defaults to <code>$NGSTONE_ALERT_WEBHOOK_URL</code>. The
          optional <code>NGSTONE_ALERT_WEBHOOK_TOKEN</code> is sent as a bearer
          header.
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
      <p>On the agent, resolving the token or server address for direct tunnel commands and <code>ngstone up</code> follows this chain:</p>
      <ParamTable>
        <Property name="1. Flag" type="highest precedence">
          <code>--token</code> / <code>--server</code>.
        </Property>
        <Property name="2. Environment" type="token only">
          <code>credential_env</code> for a project tunnel, otherwise{" "}
          <code>NGSTONE_TOKEN</code>. There is no environment override for the
          server address.
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
