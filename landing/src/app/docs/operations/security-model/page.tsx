import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { DocsArticle } from "@/components/docs/docs-article"

export const metadata: Metadata = {
  title: "Security model",
  description: "The threat model, and what the token does and doesn't grant.",
}

const TOC: TocItem[] = [
  { id: "assets", title: "Assets" },
  { id: "anonymous-attacker", title: "Anonymous attacker" },
  { id: "leaked-token", title: "Leaked token" },
  { id: "header-spoofing", title: "Header spoofing" },
  { id: "inspector-surface", title: "The inspector's attack surface" },
  { id: "resource-exhaustion", title: "Resource exhaustion" },
  { id: "out-of-scope", title: "Out of scope" },
]

export default function SecurityModelPage() {
  return (
    <DocsArticle href="/docs/operations/security-model" toc={TOC}>
      <h1>Security model</h1>
      <p>
        ngstone is built for a single operator, and its threat model is
        scoped accordingly — it takes tunneling&apos;s inherent exposure
        seriously without pretending to be a general-purpose ingress
        platform with tenant isolation.
      </p>

      <Anchor id="assets">Assets</Anchor>
      <p>What&apos;s actually at stake if something goes wrong:</p>
      <ul>
        <li>The laptop&apos;s local app, and by extension its LAN foothold</li>
        <li>The auth token</li>
        <li>The wildcard domain&apos;s reputation</li>
        <li>Tunneled request and response data in transit</li>
      </ul>

      <Anchor id="anonymous-attacker">Anonymous attacker</Anchor>
      <p>
        An anonymous attacker who has the public URL is exactly an anonymous
        HTTP client of the exposed local app — nothing more. They cannot
        reach the inspector (it&apos;s a terminal UI attached to your own
        process, not a network service — there&apos;s no port to reach),
        any other localhost port (only the configured target is ever
        dialed), or the control plane (token-gated). Whatever residual risk
        remains here is inherent to tunneling itself: if the local app is a
        debug server with a remote code execution bug, the tunnel exposes
        exactly that. Mitigations are a fast, byte-identical 404 for unknown
        or offline hosts (no enumeration oracle), per-IP rate limiting, and
        making this risk explicit in the docs rather than implying a false
        sense of isolation.
      </p>

      <Anchor id="leaked-token">Leaked token</Anchor>
      <Callout variant="danger" title="What a leaked token grants — and doesn't">
        A leaked token grants: binding any non-denylisted subdomain,
        receiving that traffic, and serving phishing content under your
        domain. It does <strong>not</strong> grant: reading other tunnels&apos;
        traffic in flight, shell access to the edge, or control over
        certificates/DNS. Rotation is just a config change and a restart —
        set a new <code>token_sha256</code> and every existing session dies
        at its next reconnect-auth.
      </Callout>

      <Anchor id="header-spoofing">Header spoofing</Anchor>
      <p>
        Inbound <code>Forwarded</code>/<code>X-Forwarded-*</code> headers are
        stripped and re-stamped at the edge, and <code>X-Real-IP</code> is
        stripped explicitly since it isn&apos;t covered by the standard
        library&apos;s automatic delete. The local app can trust these
        headers only because the agent-side proxy is written to preserve
        them on the way through — the same stdlib behavior that strips
        spoofed headers on the edge would silently delete the legitimate
        ones on the agent if it used the same code path unmodified.
      </p>

      <Anchor id="inspector-surface">The inspector&apos;s attack surface</Anchor>
      <p>
        There&apos;s no CSRF or DNS-rebinding story to tell here, because
        there&apos;s no HTTP endpoint to attack: the request inspector is a
        terminal UI (see{" "}
        <a href="/docs/guides/request-inspector">Using the request
        inspector</a>
        ) that renders directly to your own process&apos;s stdout. It
        doesn&apos;t bind a port, doesn&apos;t serve an API, and isn&apos;t
        reachable from a browser tab — a malicious web page has nothing to
        drive.
      </p>

      <Anchor id="resource-exhaustion">Resource exhaustion</Anchor>
      <p>
        Every buffer in the system has a stated cap, including the yamux
        receive windows — easy to omit, since concurrency × window is the
        real ceiling and neither number alone tells the whole story. No code
        path buffers an entire request or response body in memory. The
        unauthenticated surface on <code>:4443</code> is separately capped
        (concurrent handshakes, unauthenticated sessions) so a stranger
        can&apos;t hoard control-plane resources for the price of a bare TCP
        connect.
      </p>

      <Anchor id="out-of-scope">Out of scope</Anchor>
      <p>Accepted gaps for a single-user v1:</p>
      <ul>
        <li>
          Native gRPC and h2c backends — the tunnel carries raw HTTP/1.1
          bytes inside each stream, which structurally cannot survive
          gRPC&apos;s trailers and full-duplex h2 semantics
        </li>
        <li>Volumetric DDoS beyond the VPS&apos;s own capacity</li>
        <li>
          Compromise of the VPS itself — it terminates TLS and sees
          plaintext, so it&apos;s treated as trusted infrastructure
        </li>
        <li>OAuth-grade authentication in front of tunnels</li>
      </ul>
    </DocsArticle>
  )
}
