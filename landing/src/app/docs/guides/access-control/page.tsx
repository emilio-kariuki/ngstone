import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "Access control",
  description: "Per-tunnel edge-enforced access controls and HTTP traffic policies.",
}

const TOC: TocItem[] = [
  { id: "basic-auth", title: "HTTP basic auth" },
  { id: "credential-precedence", title: "Credential precedence" },
  { id: "allow-cidr", title: "IP allowlisting" },
  { id: "combining-both", title: "Combining both" },
  { id: "traffic-policies", title: "Traffic policies" },
  { id: "oidc-login", title: "OIDC visitor login" },
  { id: "security-notes", title: "Security notes" },
  { id: "requires-v2", title: "Requires protocol v2" },
]

export default function AccessControlPage() {
  return (
    <DocsArticle href="/docs/guides/access-control" toc={TOC}>
      <h1>Access control</h1>
      <p>
        Two independent, per-tunnel controls, both enforced at the edge
        before a request or connection ever reaches your local app:{" "}
        <strong>HTTP basic auth</strong> gates <code>ngstone port</code>{" "}
        tunnels, and <strong>source-IP allowlisting</strong> gates both{" "}
        <code>ngstone port</code> and <code>ngstone tcp</code>.
      </p>

      <Anchor id="basic-auth">HTTP basic auth</Anchor>
      <p>Require a username and password before the edge forwards anything:</p>
      <CodeBlock
        language="bash"
        code={`$ ngstone port 3000 --basic-auth alice:secret
https://amber-fox-42.example.com (basic auth: 1 credential)`}
      />
      <p>
        Repeat the flag for multiple valid credentials — any one of them
        succeeds:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone port 3000 --basic-auth alice:secret --basic-auth bob:hunter2`}
      />
      <p>
        Load credentials from a file instead — one <code>user:pass</code>{" "}
        pair per line, blank lines and lines starting with <code>#</code>{" "}
        ignored:
      </p>
      <CodeBlock
        filename="creds.txt"
        language="text"
        code={`# staging credentials
alice:secret
bob:hunter2`}
      />
      <CodeBlock language="bash" code={`$ chmod 600 creds.txt
$ ngstone port 3000 --basic-auth-file creds.txt`} />
      <p>
        Or set <code>NGSTONE_BASIC_AUTH</code>, one credential per line, same
        as the file format:
      </p>
      <CodeBlock
        language="bash"
        code={`$ export NGSTONE_BASIC_AUTH=$'alice:secret\\nbob:hunter2'
$ ngstone port 3000`}
      />
      <ParamTable>
        <Property name="--basic-auth" type="string" defaultValue="">
          <code>user:pass</code>. Repeatable for multiple credentials.
        </Property>
        <Property name="--basic-auth-file" type="string" defaultValue="">
          Path to a file with one <code>user:pass</code> credential per line.
        </Property>
        <Property name="NGSTONE_BASIC_AUTH" type="env" defaultValue="">
          One <code>user:pass</code> credential per line.
        </Property>
      </ParamTable>

      <Anchor id="credential-precedence">Credential precedence</Anchor>
      <p>
        Only one source is used — they don&apos;t merge. The first one
        present wins:
      </p>
      <ParamTable>
        <Property name="1. --basic-auth" type="highest precedence">
          Any use of the flag, even once, takes over completely and ignores
          the other two sources.
        </Property>
        <Property name="2. --basic-auth-file" type="">
          Used if <code>--basic-auth</code> was never passed.
        </Property>
        <Property name="3. NGSTONE_BASIC_AUTH" type="lowest precedence">
          Used only if neither flag was passed.
        </Property>
      </ParamTable>

      <Anchor id="allow-cidr">IP allowlisting</Anchor>
      <p>
        Restrict a tunnel to a set of source CIDRs — works for both HTTP and
        raw TCP tunnels:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone tcp 22 --allow-cidr 203.0.113.0/24
tcp://amber-fox-42.example.com:14201 -> 127.0.0.1:22`}
      />
      <p>Comma-separate multiple ranges:</p>
      <CodeBlock
        language="bash"
        code={`$ ngstone port 3000 --allow-cidr 203.0.113.0/24,198.51.100.42/32`}
      />
      <ParamTable>
        <Property name="--allow-cidr" type="string" defaultValue="">
          Comma-separated CIDRs allowed to reach the tunnel. Empty allows any
          source.
        </Property>
      </ParamTable>
      <p>
        A connection from outside every listed range is rejected before it
        reaches your app: <code>403 Forbidden</code> for HTTP, a closed
        connection for TCP.
      </p>

      <Anchor id="combining-both">Combining both</Anchor>
      <p>
        Both controls can apply to the same HTTP tunnel at once. The edge
        checks the source IP first, then basic auth — a request that fails
        the allowlist never gets a chance to present credentials:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone port 3000 --allow-cidr 203.0.113.0/24 --basic-auth alice:secret`}
      />
      <Callout variant="note">
        Basic auth is HTTP-only. <code>ngstone tcp</code> accepts{" "}
        <code>--allow-cidr</code> but rejects <code>--basic-auth</code> at
        bind time — there&apos;s no HTTP request to attach credentials to
        inside a raw TCP stream.
      </Callout>

      <Anchor id="traffic-policies">Traffic policies</Anchor>
      <p>
        Add request-level rules to an HTTP tunnel with a strict JSON policy
        file. Rules can allow, deny or redirect a request, rewrite request
        and response headers, and the policy can answer CORS at the edge:
      </p>
      <CodeBlock
        filename="traffic-policy.json"
        language="json"
        code={`{
  "default_action": "deny",
  "rules": [
    {"action": "redirect", "path_prefix": "/old", "redirect_url": "/new$path", "redirect_status": 308},
    {"action": "allow", "path_prefix": "/public"},
    {"action": "allow", "method": "GET", "path_prefix": "/preview", "header": "X-Preview", "header_value": "yes"},
    {"action": "transform", "path_prefix": "/public",
     "request_headers": {"set": {"X-Env": "preview"}, "remove": ["X-Debug"]},
     "response_headers": {"set": {"Cache-Control": "no-store"}, "remove": ["Server"]}}
  ],
  "cors": {
    "allowed_origins": ["https://app.example.com"],
    "allowed_methods": ["GET", "POST"],
    "allowed_headers": ["Content-Type"],
    "allow_credentials": true,
    "max_age": 600
  }
}`}
      />
      <CodeBlock
        language="bash"
        code={`$ ngstone port 3000 --policy-file traffic-policy.json
$ ngstone preview 3000 --ttl 30m --policy-file traffic-policy.json`}
      />
      <p>
        <code>allow</code>, <code>deny</code> and <code>redirect</code> rules
        are evaluated in order and the first match wins. <code>transform</code>{" "}
        rules never decide: every matching transform rule applies, in file
        order, to requests that are proxied. All rules match against the
        request as the client sent it, so a transform cannot make another
        rule match.
      </p>
      <ParamTable>
        <Property name="default_action" type="string" defaultValue="allow">
          Action for requests that match no deciding rule: <code>allow</code>{" "}
          or <code>deny</code>.
        </Property>
        <Property name="action" type="string" required>
          <code>allow</code>, <code>deny</code>, <code>redirect</code> or{" "}
          <code>transform</code>. A denied request receives{" "}
          <code>403 Forbidden</code> and is never forwarded.
        </Property>
        <Property name="method" type="string">
          Optional HTTP method match, such as <code>GET</code> or{" "}
          <code>POST</code>.
        </Property>
        <Property name="path_prefix" type="string">
          Optional URL-path prefix. Prefixes respect path boundaries, so{" "}
          <code>/api</code> matches <code>/api/users</code> but not{" "}
          <code>/apian</code>.
        </Property>
        <Property name="header, header_value" type="string">
          Optional case-insensitive header name and exact value. Omit{" "}
          <code>header_value</code> to match header presence.
        </Property>
        <Property name="redirect_url" type="string">
          Required for <code>redirect</code>. An absolute path or an{" "}
          <code>http(s)</code> URL. <code>$path</code> (or{" "}
          <code>{"${path}"}</code>) expands to the request path with the
          rule&apos;s <code>path_prefix</code> removed, so{" "}
          <code>/old/a/b</code> becomes <code>/new/a/b</code> above. The query
          string is always appended.
        </Property>
        <Property name="redirect_status" type="int" defaultValue="302">
          <code>301</code>, <code>302</code>, <code>307</code> or{" "}
          <code>308</code>.
        </Property>
        <Property name="request_headers, response_headers" type="object">
          Only on <code>transform</code> rules. Each holds{" "}
          <code>remove</code> (a list of names), <code>set</code> (replace)
          and <code>add</code> (append) maps, applied in that order. Request
          headers change before the request reaches the agent, so your app
          and the inspector see the result; response headers change after
          the agent answers, and the inspector shows what your app sent.
        </Property>
        <Property name="cors" type="object">
          <code>allowed_origins</code> (exact{" "}
          <code>scheme://host[:port]</code> origins, or <code>[&quot;*&quot;]</code>{" "}
          without credentials), <code>allowed_methods</code> (default{" "}
          <code>GET, HEAD, POST</code>), <code>allowed_headers</code>{" "}
          (<code>[&quot;*&quot;]</code> echoes the requested headers),{" "}
          <code>exposed_headers</code>, <code>allow_credentials</code> and{" "}
          <code>max_age</code> in seconds (max 86400).
        </Property>
        <Property name="--policy-file" type="string">
          Load the policy for <code>port</code> or <code>preview</code>. In{" "}
          <code>ngstone.json</code>, use <code>policy_file</code>; relative{" "}
          paths resolve from the project file directory.
        </Property>
      </ParamTable>
      <Callout variant="note" title="CORS at the edge">
        Preflight requests (<code>OPTIONS</code> with <code>Origin</code> and{" "}
        <code>Access-Control-Request-Method</code>) are answered with{" "}
        <code>204</code> before basic auth and before rules run, because
        browsers never send credentials on a preflight; they never reach
        your app. On proxied responses the edge drops any{" "}
        <code>Access-Control-*</code> headers your app set and adds its own
        for allowed origins.
      </Callout>
      <Callout variant="warning" title="Reserved headers">
        Header actions cannot change hop-by-hop headers (
        <code>Connection</code>, <code>Keep-Alive</code>, <code>TE</code>,{" "}
        <code>Trailer</code>, <code>Transfer-Encoding</code>,{" "}
        <code>Upgrade</code>, <code>Proxy-*</code>) or headers the edge owns:{" "}
        <code>Host</code>, <code>Content-Length</code>,{" "}
        <code>Authorization</code>, <code>Forwarded</code>,{" "}
        <code>X-Real-IP</code>, <code>X-Forwarded-*</code> and{" "}
        <code>X-Ngstone-*</code>. With <code>cors</code> set,{" "}
        <code>Access-Control-*</code> response headers belong to it. Such a
        policy is rejected when the tunnel starts.
      </Callout>
      <Callout variant="warning" title="Policies are not authentication">
        A policy can hide paths or restrict methods, but it does not identify
        callers. Combine it with <code>--basic-auth</code>,{" "}
        <code>--allow-cidr</code>, or <code>--oidc</code> when the tunnel must
        be private. Policies{" "}
        are HTTP-only; TCP tunnels reject them.
      </Callout>

      <Anchor id="oidc-login">OIDC visitor login</Anchor>
      <p>
        Require visitors to sign in with your identity provider (Google,
        Keycloak, Okta, Auth0, Dex in front of GitHub, and so on) before the
        edge forwards anything to an HTTP tunnel:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone port 3000 --oidc --oidc-allow-domain example.com --oidc-allow-email contractor@gmail.com`}
      />
      <ParamTable>
        <Property name="--oidc" type="bool" defaultValue="false">
          Turn on the login wall. Without an allow list, any account the
          provider authenticates is let in.
        </Property>
        <Property name="--oidc-allow-email" type="string">
          Verified emails allowed in. Comma-separated or repeatable.
        </Property>
        <Property name="--oidc-allow-domain" type="string">
          Email domains allowed in. Exact domain match only, so subdomains do
          not match. Comma-separated or repeatable.
        </Property>
        <Property name="oidc, oidc_allow_email, oidc_allow_domain" type="project keys">
          The same settings in <code>ngstone.json</code> and{" "}
          <code>ngstone.yml</code>. HTTP tunnels only;{" "}
          <code>kind: tcp</code> rejects them.
        </Property>
      </ParamTable>
      <p>
        A browser <code>GET</code> without a session is redirected to{" "}
        <code>/.ngstone/auth/start</code> on the apex host. Other requests get{" "}
        <code>401</code>. After the provider calls back to the apex host, the
        edge checks the allow list and returns the browser to the tunnel with
        a one-minute, single-use ticket. The tunnel host then sets an
        encrypted, host-only <code>ngstone_visitor_session</code> cookie. The
        edge strips that cookie before proxying. It also deletes any{" "}
        <code>X-Ngstone-User-*</code> header the client sent and sets{" "}
        <code>X-Ngstone-User-Email</code>, <code>X-Ngstone-User-Subject</code>,
        and <code>X-Ngstone-User-Name</code> for your app. Sign out at{" "}
        <code>/.ngstone/auth/logout</code>.
      </p>
      <p>
        Trust those headers only when your app is reachable solely through the
        tunnel. All tunnels share one registrable domain, so{" "}
        <code>SameSite=Lax</code> does not separate sibling tunnels and your app
        still needs its own CSRF and <code>Origin</code> checks. One identity
        provider client is shared by all tunnel owners, so an owner can learn
        the email, subject, and name of anyone who follows a link to their
        walled tunnel. Sessions are stateless and cannot be revoked before they
        expire.
      </p>
      <p>
        The edge operator configures one dedicated OIDC client for visitors,
        separate from the ops-dashboard login:
      </p>
      <CodeBlock
        language="bash"
        code={`export NGSTONE_VISITOR_OIDC_ISSUER=https://accounts.google.com
export NGSTONE_VISITOR_OIDC_CLIENT_ID=ngstone-visitors
export NGSTONE_VISITOR_OIDC_CLIENT_SECRET='provider-client-secret'
export NGSTONE_VISITOR_OIDC_COOKIE_SECRET="$(openssl rand -base64 32)"
# register https://example.com/.ngstone/auth/callback with the provider
ngstoned -domain example.com -cert-email you@example.com`}
      />
      <Callout variant="note" title="Order of checks">
        Source CIDR, then the per-IP rate limit, then basic auth, then the
        login wall, then the traffic policy. Policies see the verified{" "}
        <code>X-Ngstone-User-Email</code> header, so a policy rule can limit a
        path to specific people.
      </Callout>

      <Anchor id="security-notes">Security notes</Anchor>
      <Callout variant="danger" title="Prefer the file or the env var over the flag">
        Command-line arguments are visible to any other local user for the
        lifetime of the process — via <code>ps</code> or{" "}
        <code>/proc/&lt;pid&gt;/cmdline</code> on Linux. On a shared or
        multi-tenant machine, <code>--basic-auth</code> leaks your
        credentials to anyone who can run <code>ps auxww</code>. Use{" "}
        <code>--basic-auth-file</code> (mode <code>0600</code>) or{" "}
        <code>NGSTONE_BASIC_AUTH</code> instead.
      </Callout>
      <p>
        Credentials never cross the wire in plaintext. The agent hashes each{" "}
        <code>user:pass</code> pair with SHA-256 before sending it in the{" "}
        <code>Bind</code> message, and the edge stores and compares only that
        digest — it never sees or stores your password.
      </p>
      <Callout variant="warning" title="Digests are unsalted">
        Identical credentials always hash to the same digest. That&apos;s
        fine against a passive eavesdropper, but a captured digest is still
        subject to an offline dictionary or rainbow-table attack against
        common <code>user:pass</code> combinations. Use strong, unique
        passwords, not a reused low-entropy one.
      </Callout>
      <p>
        <code>--allow-cidr</code> trusts whatever the edge believes is the
        connection&apos;s source IP. Behind a front proxy with{" "}
        <code>-proxy-protocol</code>, that means trusting the PROXY header
        the proxy attaches — and the edge must be told which peers are
        allowed to send one, with <code>-proxy-protocol-trusted &lt;CIDRs&gt;</code>{" "}
        on <code>ngstoned</code>. Without that, or without firewalling the
        public port to the proxy alone, a direct client can open a raw
        connection, forge its own PROXY header, and spoof an allowed source
        IP straight past the allowlist. See{" "}
        <a href="/docs/guides/edge-vps#behind-a-proxy">Behind an existing
        reverse proxy</a>.
      </p>
      <p>
        Once the edge has verified basic auth for a request, it deletes the{" "}
        <code>Authorization</code> header before forwarding — your local app
        and the request inspector never see the credential. If no basic auth
        is configured for that tunnel, <code>Authorization</code> passes
        through untouched, exactly like every other header.
      </p>

      <Anchor id="requires-v2">Requires protocol v2</Anchor>
      <p>
        Access control is carried in wire protocol v2. If an agent requests{" "}
        <code>--basic-auth</code>, <code>--allow-cidr</code>, or a traffic
        policy and the edge
        only negotiates v1, the agent refuses to bind — it fails closed
        rather than silently opening an unprotected tunnel:
      </p>
      <CodeBlock
        language="text"
        code={`ngstone: edge does not support access control or traffic policies (negotiated protocol v1); upgrade ngstoned`}
      />
      <p>
        Upgrade <code>ngstoned</code> to a version that offers protocol{" "}
        <code>2</code> to use either flag. See{" "}
        <a href="/docs/reference/wire-protocol#versioning">Versioning</a> in
        the wire protocol reference.
      </p>
    </DocsArticle>
  )
}
