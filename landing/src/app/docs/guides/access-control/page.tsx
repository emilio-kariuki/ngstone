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
        file. The edge evaluates rules in order and stops at the first match:
      </p>
      <CodeBlock
        filename="traffic-policy.json"
        language="json"
        code={`{
  "default_action": "deny",
  "rules": [
    {"action": "allow", "path_prefix": "/public"},
    {"action": "allow", "method": "GET", "path_prefix": "/preview", "header": "X-Preview", "header_value": "yes"}
  ]
}`}
      />
      <CodeBlock
        language="bash"
        code={`$ ngstone port 3000 --policy-file traffic-policy.json
$ ngstone preview 3000 --ttl 30m --policy-file traffic-policy.json`}
      />
      <ParamTable>
        <Property name="default_action" type="string" defaultValue="allow">
          Action for requests that match no rule: <code>allow</code> or{" "}
          <code>deny</code>.
        </Property>
        <Property name="action" type="string" required>
          Each rule uses <code>allow</code> or <code>deny</code>. A denied
          request receives <code>403 Forbidden</code> and is never forwarded.
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
        <Property name="--policy-file" type="string">
          Load the policy for <code>port</code> or <code>preview</code>. In{" "}
          <code>ngstone.json</code>, use <code>policy_file</code>; relative{" "}
          paths resolve from the project file directory.
        </Property>
      </ParamTable>
      <Callout variant="warning" title="Policies are not authentication">
        A policy can hide paths or restrict methods, but it does not identify
        callers. Combine it with <code>--basic-auth</code> or{" "}
        <code>--allow-cidr</code> when the tunnel must be private. Policies{" "}
        are HTTP-only; TCP tunnels reject them.
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
