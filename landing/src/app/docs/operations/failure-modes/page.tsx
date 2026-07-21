import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "Failure modes & recovery",
  description: "What breaks, how it's detected, what happens.",
}

const TOC: TocItem[] = [
  { id: "agent-dies", title: "Agent dies mid-request" },
  { id: "edge-restarts", title: "Edge restarts" },
  { id: "network-partition", title: "Network partition" },
  { id: "slow-app", title: "Slow or hung local app" },
  { id: "oversized-bodies", title: "Oversized request bodies" },
  { id: "cert-failure", title: "Certificate issuance failure" },
]

export default function FailureModesPage() {
  return (
    <DocsArticle href="/docs/operations/failure-modes" toc={TOC}>
      <h1>Failure modes & recovery</h1>
      <p>
        Nothing in ngstone assumes the happy path. Every failure below is
        detected by something specific and handled by something specific —
        not by a generic timeout and a shrug.
      </p>

      <Anchor id="agent-dies">Agent dies mid-request</Anchor>
      <ParamTable>
        <Property name="Detection" type="">
          A stream read/write error on the edge (the session RSTs).
        </Property>
        <Property name="Handling" type="">
          Requests in flight get an immediate <code>502</code> error page;
          the session&apos;s <code>Done()</code> fires and{" "}
          <code>ReleaseSession</code> compare-and-deletes its hostnames, so
          subsequent requests get a cheap <code>404</code>. There is no
          replay — the edge can&apos;t know whether the request was
          idempotent. A restarted agent gets a new <code>InstanceID</code>,
          so it reclaims its name via the dead-holder takeover rule rather
          than the same-identity one.
        </Property>
      </ParamTable>

      <Anchor id="edge-restarts">Edge restarts</Anchor>
      <ParamTable>
        <Property name="Detection" type="">
          The agent&apos;s control-stream reads or keepalive start erroring.
        </Property>
        <Property name="Handling" type="">
          All state is rebuilt from the client side: the agent
          backoff-reconnects, re-authenticates, and re-binds with{" "}
          <code>Takeover: true</code>, restoring the same public URL —
          typically under two seconds downtime with{" "}
          <code>Restart=always</code>. Certificates load from the state
          directory cache, provided the systemd unit is configured
          correctly.
        </Property>
      </ParamTable>

      <Anchor id="network-partition">Network partition</Anchor>
      <ParamTable>
        <Property name="Detection" type="">
          yamux keepalive failure or three missed application pings — about
          45 s either way.
        </Property>
        <Property name="Handling" type="">
          The edge eventually frees the binding, returning 404s. The agent
          doesn&apos;t wait for that: its unchanged <code>InstanceID</code>{" "}
          matches the zombie binding on reconnect, so takeover rule (a)
          rebinds immediately even while the old session still looks alive
          to the edge. The zombie session is sent <code>Evicted</code> and
          force-closed.
        </Property>
      </ParamTable>

      <Anchor id="slow-app">Slow or hung local app</Anchor>
      <ParamTable>
        <Property name="Detection" type="">
          <code>ResponseHeaderTimeout</code> at 30 s.
        </Property>
        <Property name="Handling" type="">
          The public client gets a <code>504</code>; the tunnel session
          itself is unaffected. Slowness after headers have started is
          legal — that&apos;s just streaming — and is bounded only by client
          patience and flow control, not by a server-side timer.
        </Property>
      </ParamTable>

      <Anchor id="oversized-bodies">Oversized request bodies</Anchor>
      <ParamTable>
        <Property name="Detection" type="">
          A <code>Content-Length</code> pre-check for declared-length bodies,{" "}
          <code>MaxBytesReader</code> plus a custom{" "}
          <code>ErrorHandler</code> for chunked ones.
        </Property>
        <Property name="Handling" type="">
          A declared-length body over the 256 MiB cap gets a real{" "}
          <code>413</code> before anything crosses the tunnel. A chunked
          body over the cap is synthesized into a <code>413</code> from{" "}
          <code>*http.MaxBytesError</code> — with the caveat that the agent
          may already have forwarded a partial body to the local app by the
          time that fires.
        </Property>
      </ParamTable>

      <Anchor id="cert-failure">Certificate issuance failure</Anchor>
      <ParamTable>
        <Property name="Detection" type="">
          The startup check on <code>:4443</code> plus{" "}
          <code>/healthz</code> reporting each certificate&apos;s{" "}
          <code>NotAfter</code> separately.
        </Property>
        <Property name="Handling" type="">
          If the apex order fails, public traffic keeps working fine on the
          wildcard cert — but no agent can connect, since the control plane
          depends on the apex cert. <code>ngstoned</code> refuses to accept
          on <code>:4443</code> without a loadable apex cert and exits
          loudly rather than failing mysteriously later.
        </Property>
      </ParamTable>
      <Callout variant="warning" title="A healthy wildcard can mask a dead control plane">
        Public HTTPS traffic looking fine is not proof the control plane is
        healthy. Watch both certificates&apos; <code>NotAfter</code> values on{" "}
        <code>/healthz</code>, not just whether tunnels resolve.
      </Callout>
    </DocsArticle>
  )
}
