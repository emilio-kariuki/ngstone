import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"

export const metadata: Metadata = {
  title: "TLS & certificates",
  description: "How ngstone issues and serves certificates.",
}

const TOC: TocItem[] = [
  { id: "certmagic-dns01", title: "certmagic + DNS-01" },
  { id: "two-certificates", title: "Two certificates" },
  { id: "control-plane-tls", title: "Control-plane TLS" },
  { id: "agent-verification", title: "Agent verification & pinning" },
  { id: "storage", title: "Storage" },
]

export default function TlsCertificatesPage() {
  return (
    <DocsArticle href="/docs/reference/tls-certificates" toc={TOC}>
      <h1>TLS & certificates</h1>
      <p>
        The edge terminates public TLS itself, using{" "}
        <code>github.com/caddyserver/certmagic</code> with a DNS-01 challenge
        to obtain and renew certificates automatically. There is no manual
        certbot dance and no reload step.
      </p>

      <Anchor id="certmagic-dns01">certmagic + DNS-01</Anchor>
      <p>
        Wildcard certificates for <code>*.ngstone.site</code> are only
        issuable via the DNS-01 challenge type — HTTP-01 and TLS-ALPN-01
        can&apos;t issue wildcards at all. DNS-01 also means individual tunnel
        names never touch a Certificate Transparency log, since one wildcard
        cert covers every tunnel forever.
      </p>
      <p>
        The DNS provider is <code>github.com/libdns/cloudflare</code>, using a
        scoped API token with <code>Zone:DNS:Edit</code> on the single zone —
        the only pluggable seam in the TLS stack; any other{" "}
        <code>libdns</code> provider is a one-line swap.
      </p>
      <Callout variant="danger" title="Pin these dependencies">
        Pin <code>certmagic</code> and <code>libdns/cloudflare</code> to exact
        versions. The <code>libdns</code> v1 interface migration is a live,
        recurring source of &quot;it compiled last month&quot; breakage — this
        is the one dependency pair in the project where a <code>go get -u</code>{" "}
        can take the edge down.
      </Callout>

      <Anchor id="two-certificates">Two certificates</Anchor>
      <p>
        Calling <code>certmagic.ManageSync</code> with both{" "}
        <code>*.ngstone.site</code> and <code>ngstone.site</code> reads like
        one multi-SAN certificate. It isn&apos;t — certmagic does not obtain
        multi-SAN certificates, so that call places two independent ACME
        orders producing two certificates with two independent renewal
        schedules. This is forced anyway: a wildcard cert does not match SNI{" "}
        <code>ngstone.site</code>, so the apex needs its own certificate
        regardless.
      </p>
      <Callout variant="warning" title="The apex can fail independently">
        If the apex order fails (rate limit, DNS hiccup), the wildcard can be
        perfectly healthy while public traffic looks fine — but no agent can
        connect, because the control plane depends on the apex cert.{" "}
        <code>ngstoned</code> performs a startup check that a valid apex cert
        is loadable before <code>:4443</code> begins accepting, and exits
        loudly rather than listening with a cert it can&apos;t serve.{" "}
        <code>/healthz</code> reports both certs&apos; <code>NotAfter</code>{" "}
        separately. Both names also validate through the same{" "}
        <code>_acme-challenge.ngstone.site</code> TXT record, so stagger their
        renewal windows to avoid one order&apos;s cleanup deleting the
        other&apos;s in-flight record.
      </Callout>

      <Anchor id="control-plane-tls">Control-plane TLS</Anchor>
      <p>
        Port <code>:4443</code>, the control plane agents dial into, is
        served by the <strong>apex</strong> certificate (<code>ngstone.site</code>),
        a different certificate from the public wildcard, via{" "}
        <code>tls.Config.GetCertificate</code>. Agents connect to{" "}
        <code>ngstone.site:4443</code>.
      </p>

      <Anchor id="agent-verification">Agent verification & pinning</Anchor>
      <p>
        The agent performs standard WebPKI validation — <code>ServerName:
        &quot;ngstone.site&quot;</code>, system roots. An optional SPKI pin (
        <code>--pin sha256/BASE64</code>) is checked in{" "}
        <code>VerifyPeerCertificate</code> in addition to chain validation. It
        is off by default, since pins combined with auto-renewing certs is a
        footgun unless you also reuse the same key across renewals.
      </p>
      <p>
        Agent authentication is the bearer token, not client certificates.
        mTLS was rejected — it adds a private CA, issuance, and rotation
        ceremony for a single user with zero security gain over a 256-bit
        token carried inside TLS.
      </p>

      <Anchor id="storage">Storage</Anchor>
      <p>
        Certificates are cached on disk via{" "}
        <code>certmagic.FileStorage</code> so an edge restart never blocks on
        Let&apos;s Encrypt:
      </p>
      <CodeBlock
        language="text"
        code={`FileStorage{Path: "/var/lib/private/ngstoned/certs"}  # dir mode 0700`}
      />
      <p>
        This path is not arbitrary under systemd&apos;s{" "}
        <code>DynamicUser</code> — see{" "}
        <a href="/docs/operations/deployment-systemd">
          Deployment & systemd
        </a>
        .
      </p>
    </DocsArticle>
  )
}
