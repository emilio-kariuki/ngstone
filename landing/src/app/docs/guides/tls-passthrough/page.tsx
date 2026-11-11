import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "TLS passthrough",
  description: "Route TLS by SNI to a local service that presents its own certificate.",
}

const TOC: TocItem[] = [
  { id: "when-to-use-it", title: "When to use it" },
  { id: "basic-usage", title: "Basic usage" },
  { id: "how-routing-works", title: "How routing works" },
  { id: "certificates", title: "Certificates" },
  { id: "what-applies", title: "What applies and what doesn't" },
  { id: "project-files", title: "Project files" },
  { id: "hostname-conflicts", title: "Hostname conflicts" },
]

export default function TlsPassthroughPage() {
  return (
    <DocsArticle href="/docs/guides/tls-passthrough" toc={TOC}>
      <h1>TLS passthrough</h1>
      <p>
        <code>ngstone port</code> ends TLS at the edge with the edge&apos;s
        wildcard certificate, then forwards plain HTTP to your app.{" "}
        <code>ngstone tls</code> does the opposite: the edge never decrypts
        traffic for a passthrough connection. It reads only the hostname the
        client asked for, then hands the encrypted connection to your local
        service, which runs the TLS handshake with its own certificate. An
        HTTPS request that reaches the edge&apos;s own TLS for that hostname
        (for example on a reused or domain-fronted connection) gets 421 and
        is never forwarded.
      </p>

      <Anchor id="when-to-use-it">When to use it</Anchor>
      <ul>
        <li>The service needs mutual TLS and must see the client certificate.</li>
        <li>Clients pin your certificate, or you need a specific CA or EV certificate.</li>
        <li>The protocol inside TLS isn&apos;t HTTP (IMAPS, LDAPS, a custom TLS protocol).</li>
        <li>The edge must never see the plaintext.</li>
      </ul>

      <Anchor id="basic-usage">Basic usage</Anchor>
      <CodeBlock
        language="bash"
        code={`$ ngstone tls 8443 --subdomain secure
tls://secure.example.com -> 127.0.0.1:8443`}
      />
      <p>Clients connect to the edge on port 443 as usual:</p>
      <CodeBlock
        language="bash"
        code={`$ openssl s_client -connect secure.example.com:443 -servername secure.example.com
$ curl https://secure.example.com/`}
      />
      <p>
        The positional argument is a bare port, forwarded to{" "}
        <code>127.0.0.1:&lt;port&gt;</code>, or a <code>host:port</code>{" "}
        target used as-is. Without <code>--subdomain</code> the edge picks a
        random name.
      </p>
      <ParamTable>
        <Property name="--subdomain, -s" type="string">
          Requested subdomain. Empty means server-assigned.
        </Property>
        <Property name="--allow-cidr" type="string">
          Comma-separated CIDRs allowed to reach the tunnel. Checked against
          the client address, or the PROXY protocol source when the edge is
          behind a trusted proxy.
        </Property>
        <Property name="--ttl" type="duration">
          Stop the tunnel after a positive duration such as{" "}
          <code>--ttl 2h</code>.
        </Property>
        <Property name="--json" type="bool" defaultValue="false">
          Emit JSON Lines status events to stdout.
        </Property>
      </ParamTable>
      <p>
        <code>--server</code>, <code>--transport</code>, <code>--token</code>,{" "}
        <code>--insecure</code>, <code>--server-name</code>, and{" "}
        <code>--pin</code> work as they do for <code>ngstone tcp</code>.
      </p>

      <Anchor id="how-routing-works">How routing works</Anchor>
      <p>
        Every connection to the edge&apos;s public port starts with a peek
        at the TLS ClientHello. The peek is limited to 16 KiB and to the
        edge&apos;s read-header timeout, and it doesn&apos;t consume the
        bytes. A ClientHello larger than that is closed. If the SNI hostname belongs to a <code>tls</code> tunnel, the
        edge opens a stream to your agent, replays the ClientHello, and
        copies bytes both ways. The agent dials your local service and does
        the same.
      </p>
      <p>
        Anything else (another hostname, no SNI, or a connection that
        isn&apos;t TLS) continues to the normal TLS-terminating path
        exactly as before. HTTP tunnels and the agent&apos;s WebSocket
        control fallback share port 443 with passthrough tunnels.
      </p>

      <Anchor id="certificates">Certificates</Anchor>
      <Callout variant="warning" title="Your service needs a certificate for the public hostname">
        Clients verify the certificate against the name they dialed, such as{" "}
        <code>secure.example.com</code>, not <code>localhost</code>. The
        edge&apos;s wildcard certificate is never used for a{" "}
        <code>tls</code> tunnel, so the local service must present a
        certificate for the tunnel hostname that your clients trust.
      </Callout>

      <Anchor id="what-applies">What applies and what doesn&apos;t</Anchor>
      <p>
        Because the edge can&apos;t read the HTTP inside, it rejects{" "}
        <code>--basic-auth</code>, <code>--host-header</code>,{" "}
        <code>--policy-file</code>, <code>--http2</code>, and{" "}
        <code>--multi-connector</code> for <code>tls</code> tunnels. The
        request inspector shows no requests for them. Source-IP allowlists,
        per-IP rate and in-flight limits, PROXY protocol client addresses,
        and the TCP idle timeout all apply.
      </p>

      <Anchor id="project-files">Project files</Anchor>
      <p>
        In <code>ngstone.json</code> for <code>ngstone up</code>:
      </p>
      <CodeBlock
        language="json"
        code={`{
  "tunnels": {
    "secure": {
      "kind": "tls",
      "target": "8443",
      "subdomain": "secure",
      "allow_cidr": "203.0.113.0/24"
    }
  }
}`}
      />
      <p>
        In <code>ngstone.yml</code> for <code>ngstone start</code>:
      </p>
      <CodeBlock
        language="yaml"
        code={`tunnels:
  secure:
    kind: tls
    port: 8443
    subdomain: secure`}
      />
      <p>
        <code>ngstone ps</code>, JSON status output, and the inspector&apos;s
        tunnel list show the kind as <code>tls</code>.
      </p>

      <Anchor id="hostname-conflicts">Hostname conflicts</Anchor>
      <p>
        A hostname is either an HTTP tunnel or a <code>tls</code> tunnel at
        a time. Binding one over a live tunnel of the other kind fails with{" "}
        <code>kind_conflict</code>, and the agent stops instead of retrying.
        Stop the other tunnel or choose another subdomain.
      </p>
    </DocsArticle>
  )
}
