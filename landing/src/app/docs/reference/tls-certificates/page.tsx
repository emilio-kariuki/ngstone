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
        Wildcard certificates for <code>*.example.com</code> are only
        issuable via the DNS-01 challenge type — HTTP-01 and TLS-ALPN-01
        can&apos;t issue wildcards at all. DNS-01 also means individual tunnel
        names never touch a Certificate Transparency log, since one wildcard
        cert covers every tunnel forever.
      </p>
      <p>
        The DNS provider is chosen with <code>-dns-provider</code> — the only
        pluggable seam in the TLS stack. The default is{" "}
        <code>cloudflare</code> (<code>github.com/libdns/cloudflare</code>,
        with a scoped API token holding <code>Zone:DNS:Edit</code> on the
        single zone); <code>route53</code>, <code>digitalocean</code>,{" "}
        <code>hetzner</code>, <code>vultr</code>, <code>ovh</code>,{" "}
        <code>desec</code>, and <code>bunny</code> are also built in.
        Credentials come from the environment only. See{" "}
        <a href="/docs/guides/edge-vps#dns-provider">Choosing a DNS provider</a>{" "}
        for each provider&apos;s variables.
      </p>
      <p>
        A provider is admitted only if its <code>libdns</code> module appends
        TXT values without replacing others at the same name and deletes by
        value, because the two certificates below publish their challenges
        at the same name concurrently. GoDaddy, Namecheap, Porkbun, IONOS,
        Azure, DNSimple, and netcup fail that test and are not supported.
      </p>
      <Callout variant="danger" title="Pin these dependencies">
        Pin <code>certmagic</code> and every <code>libdns</code> provider to
        exact versions. The <code>libdns</code> v1 interface migration is a live,
        recurring source of &quot;it compiled last month&quot; breakage — this
        is the one dependency pair in the project where a <code>go get -u</code>{" "}
        can take the edge down.
      </Callout>

      <Anchor id="two-certificates">Two certificates</Anchor>
      <p>
        Calling <code>certmagic.ManageSync</code> with both{" "}
        <code>*.example.com</code> and <code>example.com</code> reads like
        one multi-SAN certificate. It isn&apos;t — certmagic does not obtain
        multi-SAN certificates, so that call places two independent ACME
        orders producing two certificates with two independent renewal
        schedules. This is forced anyway: a wildcard cert does not match SNI{" "}
        <code>example.com</code>, so the apex needs its own certificate
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
        <code>_acme-challenge.example.com</code> TXT record. Only providers
        that delete by value are supported, so one order&apos;s cleanup
        cannot remove the other&apos;s in-flight record; staggering their
        renewal windows further reduces the overlap.
      </Callout>

      <Anchor id="control-plane-tls">Control-plane TLS</Anchor>
      <p>
        Port <code>:4443</code>, the control plane agents dial into, is
        served by the <strong>apex</strong> certificate (<code>example.com</code>),
        a different certificate from the public wildcard, via{" "}
        <code>tls.Config.GetCertificate</code>. Agents connect to the bare
        domain, <code>example.com:4443</code> — not a subdomain such as{" "}
        <code>edge.example.com</code>, which the apex certificate does not
        cover.
      </p>

      <Anchor id="agent-verification">Agent verification & pinning</Anchor>
      <p>
        The agent performs standard WebPKI validation against system roots.
        The <code>ServerName</code> it verifies defaults to the host part of{" "}
        <code>--server</code>, so <code>--server example.com:4443</code>{" "}
        verifies <code>example.com</code>; <code>--server-name</code>{" "}
        overrides it. An optional SPKI pin (
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
