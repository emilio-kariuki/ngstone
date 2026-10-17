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
  { id: "ngstone-serve", title: "ngstone serve" },
  { id: "ngstone-start", title: "ngstone start" },
  { id: "ngstone-service", title: "ngstone service" },
  { id: "ngstone-ps", title: "ngstone ps" },
  { id: "ngstone-share", title: "ngstone share" },
  { id: "ngstone-connect", title: "ngstone connect" },
  { id: "ngstone-shares", title: "ngstone shares, unshare, extend, kick" },
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
        <code>flag</code> package — no cobra, no subcommand framework. The
        verbs are <code>auth</code>, <code>admin</code>,{" "}
        <code>login</code>, <code>doctor</code>,{" "}
        <code>credentials</code>,{" "}
        <code>status</code>, <code>tunnels</code>, <code>observability</code>,{" "}
        <code>drain</code>,{" "}
        <code>up</code>, <code>preview</code>,{" "}
        <code>port</code>,{" "}
        <code>tcp</code>, <code>serve</code>, <code>start</code>,{" "}
        <code>service</code>, <code>ps</code>, <code>share</code>,{" "}
        <code>connect</code>, <code>shares</code>, <code>unshare</code>,{" "}
        <code>extend</code>, <code>kick</code>, <code>config</code>,{" "}
        <code>replay</code>,{" "}
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
  share <preset>...       share local databases with teammates via a link
  connect <link>          connect to a shared database through a link
  shares                  list live shares on the edge (--watch tails their events)
  unshare <id>            revoke a share
  extend <id> <duration>  move a share's expiry
  kick <id> <connector>   remove one connector from a share
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
          TLS <code>ServerName</code>/SNI to verify against. Defaults to the
          host in the server address, so <code>example.com:4443</code>{" "}
          verifies <code>example.com</code>. Ignored with{" "}
          <code>--insecure</code>.
        </Property>
        <Property name="--pin" type="string">
          Optional SPKI pin, e.g. <code>--pin sha256/BASE64</code>, checked
          in addition to normal chain validation. Off by default.
        </Property>
      </ParamTable>
      <p>
        For a self-hosted edge, pass its bare domain; the server address is
        saved, so later commands need no flags:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone auth <token> --server example.com:4443
verified against example.com:4443 and saved`}
      />
      <p>
        A bad token or an unreachable server exits non-zero with a
        specific, actionable message rather than a generic failure. Agent
        releases older than the <code>--server-name</code> default need{" "}
        <code>--server-name example.com</code> on every command.
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
          TLS <code>ServerName</code>/SNI to verify against. Defaults to the
          host in the server address, so <code>example.com:4443</code>{" "}
          verifies <code>example.com</code>. Ignored with{" "}
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
          TLS <code>ServerName</code>/SNI to verify against. Defaults to the
          host in the server address, so <code>example.com:4443</code>{" "}
          verifies <code>example.com</code>. Ignored with{" "}
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

      <Anchor id="ngstone-serve">ngstone serve</Anchor>
      <p>
        Shares a directory of files: a built site, a folder of downloads, a
        report. It starts a file server on a loopback port and tunnels it
        exactly as <code>ngstone port</code> would, inspector included.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone serve ./dist --subdomain demo
$ ngstone serve ./dist --spa
$ ngstone serve            # the current directory`}
      />
      <ParamTable>
        <Property name="dir" type="positional" defaultValue=".">
          The directory to share. Directory listings are shown for folders
          without an <code>index.html</code>.
        </Property>
        <Property name="--spa" type="bool" defaultValue="false">
          Single-page app mode: a path with no file and no extension gets{" "}
          <code>index.html</code>, so client-side routes survive a reload.
          Paths with an extension still return <code>404</code> when the
          file is missing.
        </Property>
        <Property name="--subdomain, --basic-auth, --allow-cidr, …" type="flags">
          Every <code>ngstone port</code> flag applies.
        </Property>
      </ParamTable>

      <Anchor id="ngstone-start">ngstone start</Anchor>
      <p>
        Starts every tunnel described in a tunnels file, or only the ones
        named on the command line, in one process. HTTP tunnels share one
        terminal inspector: each row shows its tunnel, the header shows one
        status line per tunnel, and replay goes to the app of the tunnel
        that captured the request.
      </p>
      <CodeBlock
        language="yaml"
        code={`# ngstone.yml
server: example.com:4443
tunnels:
  web:
    port: 3000
    subdomain: demo
  api:
    url: http://127.0.0.1:8080
    basic_auth: ["user:pass"]
    allow_cidr: ["203.0.113.0/24"]
  db:
    kind: tcp
    port: 5432
    remote_port: 15432`}
      />
      <CodeBlock
        language="bash"
        code={`$ ngstone start
$ ngstone start web api`}
      />
      <p>
        HTTP tunnels take <code>port</code> or <code>url</code>, plus{" "}
        <code>subdomain</code>, <code>host_header</code>,{" "}
        <code>basic_auth</code> or <code>basic_auth_file</code>, and{" "}
        <code>allow_cidr</code>. TCP tunnels (<code>kind: tcp</code>) take{" "}
        <code>port</code> or <code>address</code>, plus{" "}
        <code>remote_port</code> and <code>allow_cidr</code>. Unknown keys
        are errors. Each tunnel is its own session, so one failing, for
        example on a taken subdomain, does not stop the others.
      </p>
      <ParamTable>
        <Property name="--config" type="string">
          Tunnels file. Defaults to <code>./ngstone.yml</code>, then{" "}
          <code>tunnels.yml</code> in the config directory.
        </Property>
        <Property name="--server" type="string">
          Edge control-plane address. Defaults to the file&apos;s{" "}
          <code>server</code>, then the config file, then{" "}
          <code>ngstone.site:4443</code>.
        </Property>
        <Property name="--token, --insecure, --server-name, --pin" type="flags">
          As for <code>ngstone port</code>, applied to every tunnel. The
          file can also set <code>server_name</code>.
        </Property>
        <Property name="--no-tui" type="bool" defaultValue="false">
          Print each tunnel&apos;s URL and log plain text to stderr instead
          of opening the inspector.
        </Property>
      </ParamTable>

      <Anchor id="ngstone-service">ngstone service</Anchor>
      <p>
        Runs <code>ngstone start --no-tui</code> as a background service: a
        systemd user unit on Linux, a launchd agent on macOS. It restarts
        on failure and uses the token saved by <code>ngstone auth</code>.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone service install --config ~/work/ngstone.yml
$ ngstone service status
$ ngstone service uninstall`}
      />
      <ParamTable>
        <Property name="install [--config FILE] [name ...]" type="command">
          Checks the tunnels file, the names and the saved token, writes
          the unit or plist, and starts it. A reinstall replaces and
          restarts it. <code>--print</code> shows the definition without
          installing.
        </Property>
        <Property name="status" type="command">
          Runs <code>systemctl --user status</code> or{" "}
          <code>launchctl print</code> for the service.
        </Property>
        <Property name="uninstall" type="command">
          Stops the service and removes its definition.
        </Property>
      </ParamTable>
      <Callout variant="note">
        Logs go to <code>journalctl --user -u ngstone</code> on Linux and{" "}
        <code>~/Library/Logs/ngstone.log</code> on macOS. On Linux, run{" "}
        <code>sudo loginctl enable-linger $USER</code> once so the service
        keeps running after you log out and starts at boot.
      </Callout>

      <Anchor id="ngstone-ps">ngstone ps</Anchor>
      <p>
        Lists the tunnels of every ngstone process running as your user,
        with their state and public URL: the quick way to find the URL of a
        tunnel the background service started, or of a{" "}
        <code>ngstone port</code> left running in another terminal.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone ps
PID    COMMAND  TUNNEL  KIND  STATE   URL                        TARGET                 UP
41200  start    web     http  online  https://demo.example.com   http://127.0.0.1:3000  1h30m
41200  start    db      tcp   online  tcp://example.com:15432    127.0.0.1:5432         1h30m
41377  port     -       http  online  https://amber-fox-42.example.com  http://127.0.0.1:8080  5m`}
      />
      <ParamTable>
        <Property name="--json" type="bool" defaultValue="false">
          Print the raw status of each process as JSON, for scripts.
        </Property>
      </ParamTable>
      <p>
        Each running process serves its status on a unix socket under{" "}
        <code>$XDG_RUNTIME_DIR/ngstone/</code>, or <code>run/</code> next
        to the config file when that variable is unset. Sockets left by a
        crashed process are removed on the next <code>ps</code>.
      </p>

      <Anchor id="ngstone-share">ngstone share</Anchor>
      <p>
        Shares local databases, or any TCP services, through a link that
        expires. Unlike <code>tcp</code> it opens no public port: the only
        way in is <code>ngstone connect</code> with the link. See{" "}
        <a href="/docs/guides/database-sharing">Sharing a database</a>.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone share postgres --expires 2h --label "staging replica"
$ ngstone share postgres redis:6380 --approve --passphrase hunter2 --user readonly
$ ngstone share mysql db.local:3306 --allow-cidr 10.0.0.0/8 --max-uses 3
$ ngstone share tcp:9000 --single-use --idle 30m --audit-log share.jsonl`}
      />
      <p>
        Each positional argument is a target: a preset (<code>postgres</code>,{" "}
        <code>mysql</code>, <code>redis</code>, <code>http</code>) with an
        optional <code>:port</code> or <code>:host:port</code>, or{" "}
        <code>tcp:port</code> / <code>tcp:host:port</code>. Connectors get
        one local listener per target. The older two-argument form{" "}
        <code>share postgres 5433</code> still works for a single target.
        Lines typed into the sharing terminal are commands:{" "}
        <code>y &lt;id&gt;</code> / <code>n &lt;id&gt;</code> answer
        approval requests, <code>kick &lt;id&gt;</code>,{" "}
        <code>extend 1h</code>, <code>q</code>.
      </p>
      <ParamTable>
        <Property name="--expires" type="duration" defaultValue="1h">
          Share lifetime, capped by the edge&apos;s{" "}
          <code>-max-share-ttl</code>.
        </Property>
        <Property name="--label" type="string">
          Label shown to connectors and in listings. Defaults to the first
          preset.
        </Property>
        <Property name="--allow-cidr" type="string">
          Comma-separated CIDRs connectors must come from.
        </Property>
        <Property name="--max-conns" type="int" defaultValue="16">
          Concurrent relayed connections across all connectors.
        </Property>
        <Property name="--max-connectors" type="int" defaultValue="8">
          Concurrent connector agents.
        </Property>
        <Property name="--max-uses" type="int" defaultValue="0">
          How many connector agents may ever join; <code>0</code> is
          unlimited and <code>1</code> is the same as{" "}
          <code>--single-use</code>.
        </Property>
        <Property name="--single-use" type="bool" defaultValue="false">
          Lock the link to the first connector agent that uses it.
        </Property>
        <Property name="--idle" type="duration" defaultValue="0">
          Close the share after this long with no open connection. Minimum
          30s; <code>0</code> never.
        </Property>
        <Property name="--approve" type="bool" defaultValue="false">
          Ask in this terminal before each connector is admitted. The
          connector waits up to 60s for a <code>y</code> or <code>n</code>.
        </Property>
        <Property name="--passphrase" type="string">
          Require connectors to present this passphrase too. Prefer{" "}
          <code>NGSTONE_SHARE_PASSPHRASE</code>, since flags show in{" "}
          <code>ps</code>.
        </Property>
        <Property name="--user" type="string">
          Database user to put in the connection hint connectors see, for
          pointing them at a read-only role.
        </Property>
        <Property name="--secret-file" type="string">
          Reuse the secret stored in this file so the link stays the same
          across runs; created with mode 0600 if missing.{" "}
          <code>NGSTONE_SHARE_SECRET</code> also works.
        </Property>
        <Property name="--audit-log" type="string">
          Append every audit event to this file as JSON Lines.
        </Property>
        <Property name="--server, --token, --insecure, --server-name, --pin" type="various">
          As for <code>ngstone tcp</code>. With <code>--insecure</code> the
          printed hint tells connectors to pass it too.
        </Property>
      </ParamTable>

      <Anchor id="ngstone-connect">ngstone connect</Anchor>
      <p>
        Joins a share and serves its targets on the loopback interface.
        Needs no token and no config file: the link carries the edge address
        and the secret.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone connect ngstone://example.com:4443/s/N7kq...Vb0Q --as alice
$ ngstone connect - < link.txt
$ NGSTONE_SHARE_LINK=ngstone://... ngstone connect --port 15432 --port redis=6380`}
      />
      <ParamTable>
        <Property name="--as" type="string">
          Name the sharer sees for this connector (letters, digits,{" "}
          <code>.</code> <code>_</code> <code>-</code>). Default{" "}
          <code>c1</code>, <code>c2</code>, ...; a taken name gets{" "}
          <code>-2</code> appended.
        </Property>
        <Property name="--port, -p" type="string">
          Local port: <code>N</code> for the first target, or{" "}
          <code>preset=N</code> / <code>t2=N</code> per target; repeatable.
          Default is each preset&apos;s port, or a free port when busy.
        </Property>
        <Property name="--passphrase" type="string">
          Passphrase the share requires. Prompted for when stdin is a
          terminal; <code>NGSTONE_SHARE_PASSPHRASE</code> also works.
        </Property>
        <Property name="--insecure" type="bool" defaultValue="false">
          Dial the edge in plaintext; only for links from an edge running
          with <code>-insecure</code>.
        </Property>
        <Property name="--server-name" type="string">
          TLS <code>ServerName</code>/SNI override. Defaults to the host in
          the link.
        </Property>
        <Property name="--pin" type="string">
          Optional SPKI pin, checked in addition to chain validation.
        </Property>
      </ParamTable>
      <p>
        Exit status is <code>0</code> on Ctrl-C, <code>3</code> when the
        share expired, was revoked, idled out or this connector was kicked,
        and <code>1</code> when the link is invalid, the passphrase could
        not be supplied, or the share&apos;s policy or the sharer refused
        this connector.
      </p>

      <Anchor id="ngstone-shares">ngstone shares, unshare, extend, kick</Anchor>
      <p>
        Manage shares from any terminal that holds the token. Each opens a
        fresh operator session, does one thing, and exits.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone shares                 # every live share, its policy and connectors
$ ngstone shares --json
$ ngstone shares --watch         # every share's audit lines, live, until Ctrl-C
$ ngstone extend sh_7f3a... 2h   # expire two hours from now
$ ngstone kick sh_7f3a... alice  # drop one connector
$ ngstone unshare sh_7f3a...     # revoke`}
      />
      <p>
        All take <code>--server</code>, <code>--token</code>,{" "}
        <code>--insecure</code>, <code>--server-name</code> and{" "}
        <code>--pin</code> like the other verbs. A revoked sharer&apos;s
        terminal says <code>share revoked by another terminal</code> and
        exits 0.
      </p>

      <Anchor id="ngstone-config">ngstone config</Anchor>
      <p>Read or change the local config file without hand-editing JSON.</p>
      <CodeBlock
        language="bash"
        code={`$ ngstone config set server example.com:4443
server set to example.com:4443

$ ngstone config get
token: nst_a1b2…9f3d
server: example.com:4443

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
          TLS ServerName/SNI to verify against. Defaults to the host part
          of <code>-control</code>.
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
