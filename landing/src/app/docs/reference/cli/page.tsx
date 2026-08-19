import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "CLI",
  description: "The ngstone command and its subcommands.",
}

const TOC: TocItem[] = [
  { id: "overview", title: "Overview" },
  { id: "ngstone-auth", title: "ngstone auth" },
  { id: "ngstone-login", title: "ngstone login" },
  { id: "ngstone-doctor", title: "ngstone doctor" },
  { id: "ngstone-credentials", title: "ngstone credentials" },
  { id: "ngstone-admin", title: "ngstone admin" },
  { id: "operator-shortcuts", title: "Operator shortcuts" },
  { id: "ngstone-up", title: "ngstone up" },
  { id: "ngstone-preview", title: "ngstone preview" },
  { id: "ngstone-replay", title: "ngstone replay" },
  { id: "ngstone-port", title: "ngstone port" },
  { id: "ngstone-tcp", title: "ngstone tcp" },
  { id: "ngstone-config", title: "ngstone config" },
  { id: "ngstone-logout", title: "ngstone logout" },
  { id: "ngstone-version", title: "ngstone version" },
  { id: "no-args-and-help", title: "No arguments and -h" },
  { id: "generating-a-token", title: "Scoped credentials & legacy token" },
  { id: "config-file", title: "The config file" },
  { id: "legacy-flags", title: "Legacy flag form" },
]

export default function CliPage() {
  return (
    <DocsArticle href="/docs/reference/cli" toc={TOC}>
      <h1>CLI</h1>
      <p>
        The <code>ngstone</code> command is built on the stdlib{" "}
        <code>flag</code> package — no cobra, no subcommand framework. There
        are seventeen verbs: <code>auth</code>, <code>admin</code>,{" "}
        <code>login</code>, <code>doctor</code>,{" "}
        <code>credentials</code>,{" "}
        <code>status</code>, <code>tunnels</code>, <code>observability</code>,{" "}
        <code>drain</code>,{" "}
        <code>up</code>, <code>preview</code>,{" "}
        <code>port</code>,{" "}
        <code>tcp</code>, <code>config</code>, <code>replay</code>,{" "}
        <code>logout</code>, and <code>version</code>.
      </p>

      <Anchor id="overview">Overview</Anchor>
      <CodeBlock
        language="text"
        code={`ngstone <command> [arguments]

Commands:
  auth <token>            verify and save an auth token
  admin                   manage a self-hosted edge over its ops API
  login                   print the browser URL for OIDC management login
  doctor                  diagnose local configuration and edge connectivity
  status                  show edge health and metrics
  tunnels                 list active tunnels
  observability           show per-tunnel metrics and latency
  drain <hostname>        gracefully drain a tunnel
  credentials             issue, list, or revoke scoped tunnel credentials
  up                      start all tunnels from ngstone.json
  preview <port|url>      start a disposable preview URL
  port <port|url>         expose a local port or URL through the tunnel
  tcp <port|host:port>    expose a raw TCP service through the tunnel
  config                  view or set local configuration
  replay <file>           replay a saved request against a local target
  logout                  remove the saved auth token
  version                 print the ngstone version`}
      />

      <Anchor id="ngstone-auth">ngstone auth</Anchor>
      <p>
        Verifies a token against the edge&apos;s control plane, then saves the
        token and server address to the{" "}
        <a href="#config-file">config file</a>. Nothing is written to disk
        until the edge has confirmed the token is valid.
      </p>
      <CodeBlock language="bash" code={`$ ngstone auth <token>
verified against ngstone.site:4443 and saved`} />
      <ParamTable>
        <Property name="--server" type="string">
          Edge control-plane address to verify against. Defaults to the
          config file&apos;s saved server, or{" "}
          <code>ngstone.site:4443</code> if neither is set.
        </Property>
        <Property name="--transport" type="string" defaultValue="auto">
          Control transport. <code>auto</code> tries raw TLS first and falls
          back to the authenticated WebSocket endpoint on HTTPS port{" "}
          <code>443</code>; use <code>raw</code> or{" "}
          <code>websocket</code> to force one path.
        </Property>
        <Property name="--insecure" type="bool" defaultValue="false">
          Dial the control plane in plaintext. Dev/test only — no
          certificate validation happens at all.
        </Property>
        <Property name="--server-name" type="string">
          TLS <code>ServerName</code>/SNI to verify against. Ignored with{" "}
          <code>--insecure</code>.
        </Property>
        <Property name="--pin" type="string">
          Optional SPKI pin, e.g. <code>--pin sha256/BASE64</code>, checked
          in addition to normal chain validation. Off by default.
        </Property>
      </ParamTable>
      <p>
        A bad token or an unreachable server exits non-zero with a
        specific, actionable message rather than a generic failure.
      </p>

      <Anchor id="ngstone-login">ngstone login</Anchor>
      <p>
        Prints the edge&apos;s browser OIDC login URL. Authentication happens in
        the browser and creates a session for the edge dashboard; it does not
        write an OIDC secret or session cookie to the agent config file. The
        same command is available as <code>ngstone admin login</code>.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone login --server https://edge.example.com:4041
Open this URL in your browser to sign in with OIDC:
https://edge.example.com:4041/api/v1/auth/oidc/start
$ ngstone admin login --json`}
      />
      <ParamTable>
        <Property name="--server" type="string">
          Management API URL. Defaults to <code>NGSTONE_ADMIN_SERVER</code> or
          <code>http://127.0.0.1:4041</code>.
        </Property>
        <Property name="--json" type="bool" defaultValue="false">
          Print a JSON object containing the browser login URL.
        </Property>
      </ParamTable>

      <Anchor id="ngstone-doctor">ngstone doctor</Anchor>
      <p>
        Runs local and remote readiness checks for the agent and self-hosted
        edge. It checks config-file permissions, token presence, transport
        settings, control-plane DNS/TCP reachability, token authentication,
        optional management API health/authentication, and OIDC environment
        configuration.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone doctor
$ ngstone doctor --admin-server https://edge.example.com:4041 --admin-token "$NGSTONE_ADMIN_TOKEN"
$ ngstone doctor --json`}
      />
      <ParamTable>
        <Property name="--server" type="string">
          Control-plane address override. Defaults to the saved config or
          <code>ngstone.site:4443</code>.
        </Property>
        <Property name="--token" type="string">
          Tunnel token override. Defaults to <code>NGSTONE_TOKEN</code> or the
          saved agent config.
        </Property>
        <Property name="--transport" type="string" defaultValue="auto">
          Control transport to validate and use for authentication:
          <code>auto</code>, <code>raw</code>, or <code>websocket</code>.
        </Property>
        <Property name="--admin-server" type="string">
          Optional management API URL. HTTPS is required outside loopback
          unless <code>--insecure</code> is explicitly set.
        </Property>
        <Property name="--admin-token" type="string">
          Management bearer token override. Defaults to{" "}
          <code>NGSTONE_ADMIN_TOKEN</code>.
        </Property>
        <Property name="--timeout" type="duration" defaultValue="5s">
          Maximum time for each network check.
        </Property>
        <Property name="--json" type="bool" defaultValue="false">
          Emit a machine-readable report with <code>ok</code> and a list of
          checks. Exit status is non-zero when any check fails.
        </Property>
      </ParamTable>

      <Anchor id="ngstone-credentials">ngstone credentials</Anchor>
      <p>
        Manages the edge&apos;s versioned per-tunnel credential file. The edge
        stores only token hashes; the plaintext token is printed once by
        <code>issue</code> and cannot be recovered later. Run these commands
        on the edge host as the account that owns the credential file.
      </p>
      <CodeBlock
        language="bash"
        code={"$ ngstone credentials issue --file /var/lib/ngstoned/credentials.json --subdomain demo --ttl 24h\ncredential 7109b9faf3f8b5d38086d3e0566c1296 issued\ntoken: nst_...\n$ ngstone credentials list --file /var/lib/ngstoned/credentials.json\n$ ngstone credentials revoke 7109b9faf3f8b5d38086d3e0566c1296 --file /var/lib/ngstoned/credentials.json"}
      />
      <ParamTable>
        <Property name="issue" type="subcommand">
          Creates an HTTP credential scoped to <code>--subdomain</code>, or a
          TCP credential scoped to <code>--remote-port</code> with{" "}
          <code>--kind tcp</code>. The default TTL is 24 hours and the maximum
          is 720 hours.
        </Property>
        <Property name="list" type="subcommand">
          Prints credential metadata and status. It never prints token
          material; add <code>--json</code> for machine-readable metadata.
        </Property>
        <Property name="revoke &lt;id&gt;" type="subcommand">
          Revokes one credential. The edge notices active sessions on the
          next heartbeat.
        </Property>
        <Property name="--file" type="path">
          Credential file to manage. Defaults to{" "}
          <code>NGSTONE_CREDENTIALS_FILE</code>.
        </Property>
      </ParamTable>

      <Anchor id="ngstone-admin">ngstone admin</Anchor>
      <p>
        Manages a running self-hosted edge through its versioned management API.
        The default server is <code>http://127.0.0.1:4041</code>, so the usual
        VPS workflow is an SSH port-forward followed by these commands:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ssh -L 4041:127.0.0.1:4041 root@example.com
$ ngstone admin status
$ ngstone admin tunnels --json
$ ngstone admin credentials issue --subdomain demo --ttl 24h
$ ngstone admin credentials revoke <credential-id>
$ ngstone admin policies list
$ ngstone admin policies apply --name web --file traffic-policy.json
$ ngstone admin domains list
$ ngstone admin domains add --domain demo.example.org
$ ngstone admin tunnel drain demo`}
      />
      <Anchor id="operator-shortcuts">Operator shortcuts</Anchor>
      <p>
        The common read-only operations have shorter aliases. They use the
        same <code>NGSTONE_ADMIN_SERVER</code>,{" "}
        <code>NGSTONE_ADMIN_TOKEN</code>, <code>--server</code>,{" "}
        <code>--token</code>, and <code>--json</code> options as the matching{" "}
        <code>ngstone admin</code> commands.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone status
$ ngstone tunnels --json
$ ngstone observability
$ ngstone drain demo`}
      />
      <p>
        Successful API responses use a <code>{`{"data": ...}`}</code>{" "}
        envelope. Errors use{" "}
        <code>{`{"error": {"code": ..., "message": ...}}`}</code>. Credential
        issue prints the plaintext token once; list never returns token
        material.
      </p>
      <CodeBlock
        language="text"
        code={`GET    /api/v1/status
GET    /api/v1/tunnels
GET    /api/v1/credentials
POST   /api/v1/credentials
DELETE /api/v1/credentials/{id}
GET    /api/v1/policies
POST   /api/v1/policies
DELETE /api/v1/policies/{id}
GET    /api/v1/domains
POST   /api/v1/domains
DELETE /api/v1/domains/{id}
POST   /api/v1/tunnels/{hostname}/drain`}
      />
      <CodeBlock
        language="bash"
        code={`$ curl -X POST http://127.0.0.1:4041/api/v1/credentials \
    -H 'Content-Type: application/json' \
    -d '{"subdomain":"demo","ttl":"24h"}'
{"data":{"credential":{"id":"0123456789abcdef0123456789abcdef","kind":"http","subdomain":"demo","created_at":"2026-08-18T12:00:00Z","expires_at":"2026-08-19T12:00:00Z"},"token":"nst_<printed-once>"}}`}
      />
      <ParamTable>
        <Property name="status" type="subcommand">
          Show edge health, listeners, certificate state, request metrics,
          active tunnels, and recent events.
        </Property>
        <Property name="tunnels" type="subcommand">
          List active HTTP and TCP tunnels, connector health, capacity, and
          access-policy state.
        </Property>
        <Property name="observability" type="subcommand">
          Show per-tunnel request counts, approximate p50/p95/p99 latency,
          status-code counts, active connectors, reconnects, bytes, and
          credential lifecycle counters. Add <code>--json</code> for
          dashboards and automation.
        </Property>
        <Property name="credentials issue" type="subcommand">
          Issue a scoped HTTP or TCP credential. Use <code>--kind tcp</code>{" "}
          with <code>--remote-port</code> for a TCP tunnel. The default TTL is
          24 hours and the maximum is 30 days.
        </Property>
        <Property name="credentials list" type="subcommand">
          List credential metadata without exposing plaintext tokens.
        </Property>
        <Property name="credentials revoke &lt;id&gt;" type="subcommand">
          Revoke one credential independently of all other tunnels.
        </Property>
        <Property name="tunnel drain &lt;hostname|subdomain&gt;" type="subcommand">
          Gracefully remove a tunnel from routing and ask all of its connectors
          to drain in-flight work.
        </Property>
        <Property name="--server" type="string">
          Management API URL. Defaults to <code>NGSTONE_ADMIN_SERVER</code> or
          <code>http://127.0.0.1:4041</code>.
        </Property>
        <Property name="--token" type="string">
          Bearer token for the management API. Defaults to{" "}
          <code>NGSTONE_ADMIN_TOKEN</code>; prefer the environment so it does
          not appear in process listings.
        </Property>
        <Property name="--json" type="bool" defaultValue="false">
          Emit machine-readable JSON for the selected command.
        </Property>
      </ParamTable>
      <Callout variant="warning" title="Keep the ops listener private">
        Without an admin token hash, the management API accepts only loopback
        requests. With <code>NGSTONE_ADMIN_TOKEN_SHA256</code>, bearer auth is
        required for <code>/api/v1</code>, but the dashboard, metrics, health,
        and pprof endpoints remain separate. With OIDC enabled, browser users
        are mapped to <code>viewer</code>, <code>operator</code>, or{" "}
        <code>admin</code> from IdP groups and mutating requests require CSRF
        protection. Use SSH or a private network with a TLS-authenticated
        proxy; do not publish <code>-ops</code> directly.
      </Callout>

      <Anchor id="ngstone-up">ngstone up</Anchor>
      <p>
        Starts every tunnel in a project file. By default it looks for{" "}
        <code>ngstone.json</code>, then <code>.ngstone.json</code>, in the
        current directory. The project file is separate from the saved
        credentials file; it never accepts a token field.
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
    "grpc": {"target": "http://127.0.0.1:50051", "http2": true},
    "api": {"target": "3001", "subdomain": "api"}
  }
}`}
      />
      <CodeBlock
        language="bash"
        code={`$ ngstone up
web: https://demo.ngstone.site -> http://127.0.0.1:3000
api: https://api.ngstone.site -> http://127.0.0.1:3001

$ ngstone up --file staging.ngstone.json --json
$ ngstone up --json --har requests.har`}
      />
      <CodeBlock
        language="json"
        code={`{"type":"tunnel","time":"2026-08-17T10:00:00Z","name":"web","kind":"http","target":"http://127.0.0.1:3000","state":"online","hostname":"demo.ngstone.site","url":"https://demo.ngstone.site","expires_at":"2026-08-17T12:00:00Z"}`}
      />
      <ParamTable>
        <Property name="--file" type="string">
          Project file to load. Defaults to <code>ngstone.json</code> or{" "}
          <code>.ngstone.json</code> in the current directory.
        </Property>
        <Property name="--json" type="bool" defaultValue="false">
          Emit one JSON Lines status event per tunnel state change to stdout;
          diagnostic logs stay on stderr.
        </Property>
        <Property name="--har" type="string">
          Write captured HTTP exchanges from all project tunnels to this HAR
          file when the process exits.
        </Property>
        <Property name="--har-include-sensitive" type="bool" defaultValue="false">
          Include authorization, cookie, and API-key headers in the HAR. The
          default redacts them.
        </Property>
      </ParamTable>
      <p>
        Each tunnel can set <code>kind</code> (<code>http</code> or{" "}
        <code>tcp</code>), <code>target</code>, <code>subdomain</code>,{" "}
        <code>host_header</code>, <code>remote_port</code>, <code>ttl</code>,{" "}
        <code>server</code>, TLS options, <code>basic_auth_file</code>, and{" "}
        <code>allow_cidr</code>, <code>policy_file</code>, and{" "}
        <code>multi_connector</code>, and <code>credential_env</code>. See the{" "}
        <a href="/docs/reference/configuration#project-config">
          project configuration reference
        </a>.
      </p>

      <Anchor id="ngstone-preview">ngstone preview</Anchor>
      <p>
        Starts a disposable HTTP preview URL. The edge assigns a random
        hostname, and the tunnel always has a positive TTL; the default is
        two hours. This command rejects <code>--subdomain</code> so a preview
        cannot accidentally become a stable named tunnel.
      </p>
      <CodeBlock
        language="bash"
        code={"$ ngstone preview 3000\n$ ngstone preview 3000 --ttl 30m --json\n$ ngstone preview 3000 --ttl 2h --no-tui"}
      />
      <ParamTable>
        <Property name="--ttl" type="duration" defaultValue="2h">
          Required positive lifetime for the preview URL. Set a different
          duration such as <code>30m</code> to shorten it.
        </Property>
        <Property name="--json" type="bool" defaultValue="false">
          Emit JSON Lines status events, including the URL and{" "}
          <code>expires_at</code>.
        </Property>
        <Property name="--no-tui" type="bool" defaultValue="false">
          Log plain output instead of opening the request inspector.
        </Property>
        <Property name="--har" type="string">
          Export captured HTTP exchanges when the preview exits.
        </Property>
        <Property name="--har-include-sensitive" type="bool" defaultValue="false">
          Include sensitive headers in the HAR instead of redacting them.
        </Property>
      </ParamTable>
      <p>
        Preview accepts the target, host-header, auth, access-control, server,
        and TLS flags from <code>ngstone port</code>. It does not accept a
        requested subdomain.
      </p>
      <Callout variant="warning" title="TTL is not access control">
        The preview URL is public while it is live. Add <code>--basic-auth</code>{" "}
        or <code>--allow-cidr</code> when the preview contains private data;
        the TTL only limits how long the URL remains active.
      </Callout>

      <Anchor id="ngstone-replay">ngstone replay</Anchor>
      <p>
        Sends a replay file saved by the request inspector directly to a local
        target. The request never goes back through the public tunnel. Use
        <code>--curl</code> to print a command instead of sending it.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone replay ngstone-replay-000000000001.json --target 3000
$ ngstone replay ngstone-replay-000000000001.json --target 3000 --json
$ ngstone replay ngstone-replay-000000000001.json --curl
$ ngstone replay request.json --curl --target http://127.0.0.1:3000`}
      />
      <ParamTable>
        <Property name="--target" type="port|url">
          Local port or full URL to receive the request. Required unless
          <code>--curl</code> is used; with <code>--curl --target</code>, the
          original host is preserved in the generated command.
        </Property>
        <Property name="--curl" type="bool" defaultValue="false">
          Print a shell-quoted cURL command and exit without sending the
          request.
        </Property>
        <Property name="--include-sensitive" type="bool" defaultValue="false">
          Include authorization, cookie, API-key, and related sensitive
          headers in <code>--curl</code> output. Redaction is the default.
        </Property>
        <Property name="--json" type="bool" defaultValue="false">
          Emit one JSON result containing status, headers, duration, and a
          base64 response body.
        </Property>
        <Property name="--timeout" type="duration" defaultValue="30s">
          Maximum time to wait for the local response.
        </Property>
      </ParamTable>

      <Anchor id="ngstone-port">ngstone port</Anchor>
      <p>
        Starts a tunnel to a local port or URL. This is the command that
        actually opens a connection to the edge and forwards traffic. When
        stdout is a terminal, it also opens a full-screen inspector
        dashboard showing every request and response live, with headers,
        decoded bodies, timing, and replay — see{" "}
        <a href="/docs/guides/request-inspector">Using the request
        inspector</a>.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone port 3000
$ ngstone port http://127.0.0.1:3000
$ ngstone port 3000 --subdomain demo
$ ngstone port 3000 --host-header demo.localhost:3000
$ ngstone port 3000 --subdomain demo --multi-connector`}
      />
      <p>
        The positional argument is either a bare port number (forwarded to{" "}
        <code>http://127.0.0.1:&lt;port&gt;</code>) or a full target URL.
        Flags may appear before or after it.
      </p>
      <ParamTable>
        <Property name="--subdomain, -s" type="string">
          Request a specific subdomain instead of a server-assigned one,
          e.g. <code>--subdomain demo</code> for{" "}
          <code>demo.ngstone.site</code>.
        </Property>
        <Property name="--host-header" type="string">
          Host header sent to the local app. By default, the public tunnel
          hostname is preserved. Set it when the app expects a local tenant
          hostname, e.g. <code>--host-header demo.localhost:3000</code>.
        </Property>
        <Property name="--http2" type="bool" defaultValue="false">
          Use a native HTTP/2 stream to the local target. Use an{" "}
          <code>https://</code> target for TLS HTTP/2 or an{" "}
          <code>http://</code> target for cleartext h2c. This is required for
          native gRPC trailers, streaming, and full-duplex behavior; ordinary
          HTTP/1.1 forwarding remains the default.
        </Property>
        <Property name="--multi-connector" type="bool" defaultValue="false">
          Allow several agent processes to share the same named tunnel and
          load-balance requests across live connectors. Requires an explicit
          <code>--subdomain</code> and a shared per-tunnel connector token;
          use the flag and <code>NGSTONE_CONNECTOR_TOKEN</code> on every
          connector. A connector reconnect or shutdown drains only its own
          in-flight requests. HTTP-only.
        </Property>
        <Property name="--connector-token" type="string">
          Per-tunnel secret used to authorize membership in a
          multi-connector pool. Prefer <code>NGSTONE_CONNECTOR_TOKEN</code> so
          the secret is not exposed in the process command line.
        </Property>
        <Property name="--server" type="string">
          Edge control-plane address override. Defaults to the config file
          or <code>ngstone.site:4443</code>.
        </Property>
        <Property name="--transport" type="string" defaultValue="auto">
          Control transport. <code>auto</code> tries raw TLS first and falls
          back to the authenticated WebSocket endpoint on HTTPS port{" "}
          <code>443</code>; use <code>raw</code> or{" "}
          <code>websocket</code> to force one path.
        </Property>
        <Property name="--token" type="string">
          Auth token override. Defaults to <code>NGSTONE_TOKEN</code> or the
          token saved by <code>ngstone auth</code>.
        </Property>
        <Property name="--insecure" type="bool" defaultValue="false">
          Dial the control plane in plaintext (dev/test only, no
          certificates involved).
        </Property>
        <Property name="--server-name" type="string">
          TLS <code>ServerName</code>/SNI to verify against. Ignored with{" "}
          <code>--insecure</code>.
        </Property>
        <Property name="--pin" type="string">
          Optional SPKI pin, checked in addition to normal chain
          validation. Off by default.
        </Property>
        <Property name="--no-tui" type="bool" defaultValue="false">
          Disable the terminal inspector UI and log plain text to stderr
          instead. The inspector is also skipped automatically whenever
          stdout isn&apos;t a terminal (piping, CI, running under{" "}
          <code>&amp;</code>), so this flag mainly matters when stdout
          <em>is</em> a terminal and you still want plain logs.
        </Property>
        <Property name="--basic-auth" type="string">
          Require HTTP basic auth, <code>user:pass</code>. Repeatable for
          multiple valid credentials. Visible to other local users via{" "}
          <code>ps</code>/<code>/proc</code> for the process&apos;s
          lifetime — prefer <code>--basic-auth-file</code> or{" "}
          <code>NGSTONE_BASIC_AUTH</code>. See{" "}
          <a href="/docs/guides/access-control">Access control</a>.
        </Property>
        <Property name="--basic-auth-file" type="string">
          Path to a file with one <code>user:pass</code> credential per
          line. Safer than <code>--basic-auth</code>.
        </Property>
        <Property name="--allow-cidr" type="string">
          Comma-separated CIDRs allowed to reach the tunnel. Empty allows
          any source.
        </Property>
        <Property name="--policy-file" type="string">
          Load a strict JSON HTTP traffic policy. Rules are evaluated in order
          at the edge; a denied request gets <code>403</code> and is never
          forwarded.
        </Property>
        <Property name="--ttl" type="duration">
          Stop the tunnel after a positive duration such as{" "}
          <code>--ttl 2h</code>. The timer starts when the command starts.
        </Property>
        <Property name="--json" type="bool" defaultValue="false">
          Emit JSON Lines status events to stdout instead of opening the
          inspector.
        </Property>
        <Property name="--har" type="string">
          Write captured HTTP exchanges to this HAR file on exit.
        </Property>
        <Property name="--har-include-sensitive" type="bool" defaultValue="false">
          Include sensitive request and response headers in the HAR instead
          of redacting them.
        </Property>
      </ParamTable>
      <p>
        <code>--basic-auth</code> takes precedence over{" "}
        <code>--basic-auth-file</code>, which takes precedence over{" "}
        <code>NGSTONE_BASIC_AUTH</code> — the first one present is used, and
        they don&apos;t merge. <code>NGSTONE_BASIC_AUTH</code> uses the same
        format as <code>--basic-auth-file</code>: one <code>user:pass</code>{" "}
        credential per line.
      </p>
      <p>
        The native HTTP/2 path is covered by transport tests for gRPC trailers,
        bidirectional streaming, h2c, deadlines and cancellation, large
        messages, and backend connection reuse.
      </p>

      <Anchor id="ngstone-tcp">ngstone tcp</Anchor>
      <p>
        Starts a raw TCP tunnel to a local port or <code>host:port</code>{" "}
        target — for SSH, Postgres, Redis, or anything else that isn&apos;t
        HTTP. See <a href="/docs/guides/tcp-tunnels">TCP tunnels</a> for the
        full picture, including the encryption caveat.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone tcp 22
tcp://amber-fox-42.example.com:14201 -> 127.0.0.1:22

$ ngstone tcp db.local:5432 --remote-port 15432`}
      />
      <p>
        The positional argument is either a bare port number (forwarded to{" "}
        <code>127.0.0.1:&lt;port&gt;</code>) or a <code>host:port</code>{" "}
        target used as-is.
      </p>
      <ParamTable>
        <Property name="--remote-port, -r" type="int" defaultValue="0">
          Requested remote port. <code>0</code> means server-assigned.
        </Property>
        <Property name="--server" type="string">
          Edge control-plane address override. Defaults to the config file
          or <code>ngstone.site:4443</code>.
        </Property>
        <Property name="--transport" type="string" defaultValue="auto">
          Control transport. <code>auto</code> tries raw TLS first and falls
          back to the authenticated WebSocket endpoint on HTTPS port{" "}
          <code>443</code>.
        </Property>
        <Property name="--token" type="string">
          Auth token override. Defaults to <code>NGSTONE_TOKEN</code> or the
          token saved by <code>ngstone auth</code>.
        </Property>
        <Property name="--insecure" type="bool" defaultValue="false">
          Dial the control plane in plaintext (dev/test only, no
          certificates involved).
        </Property>
        <Property name="--server-name" type="string">
          TLS <code>ServerName</code>/SNI to verify against. Ignored with{" "}
          <code>--insecure</code>.
        </Property>
        <Property name="--pin" type="string">
          Optional SPKI pin, checked in addition to normal chain
          validation. Off by default.
        </Property>
        <Property name="--allow-cidr" type="string">
          Comma-separated CIDRs allowed to reach the tunnel. Empty allows
          any source. See{" "}
          <a href="/docs/guides/access-control">Access control</a>. There is
          no <code>--basic-auth</code> for <code>tcp</code> — the edge
          rejects it, since there&apos;s no HTTP request to attach
          credentials to inside a raw TCP stream.
        </Property>
        <Property name="--ttl" type="duration">
          Stop the tunnel after a positive duration such as{" "}
          <code>--ttl 2h</code>.
        </Property>
        <Property name="--json" type="bool" defaultValue="false">
          Emit JSON Lines status events to stdout.
        </Property>
      </ParamTable>
      <Callout variant="note">
        TCP tunnels are opt-in per edge — the operator must set{" "}
        <code>-tcp-ports</code>. See{" "}
        <a href="/docs/guides/edge-vps#tcp-tunnels">Running the edge on a
        VPS</a> for how to enable it.
      </Callout>
      <Callout variant="warning" title="--allow-cidr behind a proxy needs an edge flag too">
        If the edge sits behind a front proxy with <code>-proxy-protocol</code>,{" "}
        <code>--allow-cidr</code> is only trustworthy when the edge is also
        started with <code>-proxy-protocol-trusted &lt;proxy CIDRs&gt;</code>{" "}
        — otherwise a direct client can forge a PROXY header and spoof an
        allowed source IP. See{" "}
        <a href="/docs/guides/edge-vps#behind-a-proxy">Behind an existing
        reverse proxy</a> and{" "}
        <a href="/docs/guides/access-control">Access control</a>.
      </Callout>

      <Anchor id="ngstone-config">ngstone config</Anchor>
      <p>Read or change the local config file without hand-editing JSON.</p>
      <CodeBlock
        language="bash"
        code={`$ ngstone config set server ngstone.site:4443
server set to ngstone.site:4443

$ ngstone config get
token: nst_a1b2…9f3d
server: ngstone.site:4443

$ ngstone config get token
nst_a1b2…9f3d

$ ngstone config path
/home/you/.config/ngstone/config.json`}
      />
      <p>
        <code>config get</code> always redacts the token — the middle of
        the value is replaced with <code>…</code>, only the first and last
        four characters are shown.
      </p>

      <Anchor id="ngstone-logout">ngstone logout</Anchor>
      <p>
        Clears the saved token from the config file. The server address is
        left untouched.
      </p>
      <CodeBlock language="bash" code={`$ ngstone logout
logged out`} />

      <Anchor id="ngstone-version">ngstone version</Anchor>
      <p>
        Prints the build&apos;s version string, injected at compile time via{" "}
        <code>-ldflags</code>.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone version
ngstone v0.1.0 (commit 3f1a9c2, built 2026-06-01T12:00:00Z)`}
      />

      <Anchor id="no-args-and-help">No arguments and -h</Anchor>
      <p>
        Running <code>ngstone</code> with no arguments does not start a
        tunnel — it prints usage to stderr and exits <code>1</code>.{" "}
        <code>-h</code>, <code>--help</code>, and <code>-help</code> print
        the same usage to stdout and exit <code>0</code>.
      </p>

      <Anchor id="generating-a-token">Scoped credentials &amp; legacy token</Anchor>
      <p>
        The preferred path is <code>ngstone credentials issue</code>. It
        creates a short-lived credential scoped to one HTTP subdomain or TCP
        port, stores only its hash, and prints the plaintext once:
      </p>
      <CodeBlock
        language="bash"
        code={"$ ngstone credentials issue --file /var/lib/ngstoned/credentials.json --subdomain demo --ttl 24h\n$ ngstone auth '<token printed once>'"}
      />
      <Callout variant="note" title="Legacy shared-token mode">
        The shared-token one-liner remains for older edges. The edge only ever
        stores the token&apos;s SHA-256 hash, but one token can bind any
        non-denylisted subdomain and cannot be revoked independently.
      </Callout>
      <CodeBlock
        language="bash"
        code={`TOKEN=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
HASH=$(printf '%s' "$TOKEN" | shasum -a 256 | cut -d' ' -f1)   # sha256sum on Linux`}
      />
      <p>
        Keep <code>$TOKEN</code> for <code>ngstone auth</code> on every
        machine that will run the agent, and pass <code>$HASH</code> to the
        edge as <code>-token-sha256</code> (or{" "}
        <code>$NGSTONE_TOKEN_SHA256</code>) only for legacy deployments.
        Prefer one scoped credential per tunnel so expiry and revocation do
        not affect unrelated agents.
      </p>

      <Anchor id="config-file">The config file</Anchor>
      <p>
        <code>ngstone auth</code>, <code>ngstone up</code>, <code>ngstone port</code>,{" "}
        <code>ngstone config</code>, and <code>ngstone logout</code> all
        use the saved credential JSON file:
      </p>
      <CodeBlock
        language="text"
        code={`$XDG_CONFIG_HOME/ngstone/config.json
# falls back to ~/.config/ngstone/config.json if XDG_CONFIG_HOME is unset`}
      />
      <p>
        The file holds <code>token</code> and <code>server</code>. It&apos;s
        written with mode <code>0600</code> inside a <code>0700</code>{" "}
        directory, and saved via a temp-file-plus-rename so a crash
        mid-write can&apos;t corrupt it.
      </p>
      <p>
        <code>ngstone up</code> reads tunnel definitions from its separate
        project file, described in <a href="#ngstone-up">ngstone up</a>;
        project configuration does not belong in this credential file.
      </p>
      <p>Resolution order for both the token and the server address:</p>
      <ParamTable>
        <Property name="1. Flag" type="highest precedence">
          <code>--token</code> / <code>--server</code> on the command
          invoking it.
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
          Used only if nothing above set a server address.
        </Property>
      </ParamTable>

      <Anchor id="legacy-flags">Legacy flag form</Anchor>
      <p>
        A flat-flags invocation is still supported alongside the verbs
        above, mainly for scripts and the e2e test suite written against
        it. It starts a tunnel directly — there&apos;s no config file
        involved.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone -control ADDR -token TOK -target URL -subdomain NAME \\
    -insecure -server-name NAME -pin SPKI -instance-id ID`}
      />
      <ParamTable>
        <Property name="-control" type="string" defaultValue="ngstone.site:4443">
          Edge control-plane address.
        </Property>
        <Property name="-token" type="string">
          Auth token. Falls back to <code>NGSTONE_TOKEN</code> if unset.
        </Property>
        <Property name="-target" type="string" defaultValue="http://127.0.0.1:3000">
          Local target URL to forward requests to.
        </Property>
        <Property name="-subdomain" type="string">
          Requested subdomain. Empty means server-assigned.
        </Property>
        <Property name="-instance-id" type="string">
          Undocumented, testing-only: force a specific instance ID instead
          of generating one.
        </Property>
        <Property name="-insecure" type="bool" defaultValue="false">
          Dial the control plane in plaintext (dev/test only).
        </Property>
        <Property name="-server-name" type="string">
          TLS ServerName/SNI to verify against.
        </Property>
        <Property name="-pin" type="string">
          Optional SPKI pin.
        </Property>
        <Property name="-version" type="bool" defaultValue="false">
          Print version and exit.
        </Property>
      </ParamTable>
      <p>
        Prefer <code>ngstone auth</code> plus <code>ngstone port</code> for
        day-to-day use — the legacy form exists for compatibility, not as
        the recommended path.
      </p>
    </DocsArticle>
  )
}
