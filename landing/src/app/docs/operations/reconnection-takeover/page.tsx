import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"
import { Step, Steps } from "@/components/docs/steps"

export const metadata: Metadata = {
  title: "Reconnection & takeover",
  description: "How tunnels survive sleeps, blips, and restarts.",
}

const TOC: TocItem[] = [
  { id: "instance-identity", title: "Instance identity" },
  { id: "takeover-rules", title: "The takeover rules" },
  { id: "network-transports", title: "Network transports" },
  { id: "reconnect-backoff", title: "Reconnect backoff" },
  { id: "dead-peer-detection", title: "Dead-peer detection" },
  { id: "zombie-bindings", title: "Zombie bindings" },
]

export default function ReconnectionTakeoverPage() {
  return (
    <DocsArticle href="/docs/operations/reconnection-takeover" toc={TOC}>
      <h1>Reconnection & takeover</h1>
      <p>
        Laptops sleep, wifi drops, and VPS processes restart. ngstone is
        built so the same public URL comes back after all three, usually in
        well under the time it takes the dead-peer detector to even notice
        something is wrong.
      </p>

      <Anchor id="instance-identity">Instance identity</Anchor>
      <p>
        Every agent process mints an <code>InstanceID</code> — a stable
        16-byte random hex value — once, at startup. It survives reconnects
        on that process and dies with it; a restarted agent gets a brand new
        one. Every binding in the edge&apos;s registry records the holder&apos;s{" "}
        <code>InstanceID</code>, and that identity is what authorizes taking
        a binding back, not whether the old holder still looks alive.
      </p>

      <Anchor id="takeover-rules">The takeover rules</Anchor>
      <p>
        When a <code>Bind</code> request names a subdomain that&apos;s already
        held, the edge resolves it with three rules, in order:
      </p>
      <Steps>
        <Step title="Same InstanceID — immediate takeover">
          The requester is the same agent process reconnecting past a
          half-open zombie connection. Takeover succeeds instantly,
          regardless of whether the zombie session still looks alive to the
          edge.
        </Step>
        <Step title="Different InstanceID, dead holder — takeover">
          The previous holder&apos;s session has already been detected as
          dead. The new session takes the binding.
        </Step>
        <Step title="Different InstanceID, live holder — rejected">
          The edge returns <code>BindErr{"{subdomain_taken}"}</code>. Two
          separate agents shouldn&apos;t silently fight over a name — liveness
          is only consulted in this one case.
        </Step>
      </Steps>
      <p>
        On any successful takeover the edge sends the old session{" "}
        <code>Evicted{"{hostname, reason: \"takeover\"}"}</code>, force-closes
        it, and rebinds atomically under the registry lock. The evicted agent
        updates its status line instead of continuing to advertise a URL it
        no longer owns.
      </p>
      <p>
        A named tunnel can opt into a connector pool with{" "}
        <code>--multi-connector</code>. In that mode, agents with different{" "}
        <code>InstanceID</code> values join the same explicit subdomain when
        their HTTP/2, access-control, and traffic-policy settings match. A
        reconnect replaces only its own connector; releasing one connector
        stops new selection for it and lets its in-flight requests drain while
        the remaining connectors continue serving traffic.
      </p>

      <Anchor id="network-transports">Network transports</Anchor>
      <p>
        <code>ngstone</code> defaults to <code>--transport auto</code>. It
        tries the raw TLS yamux listener on <code>:4443</code> first, then
        falls back to an authenticated WebSocket carrying the same yamux
        session through <code>/_ngstone/control</code> on HTTPS{" "}
        <code>:443</code>. Use <code>--transport raw</code> or{" "}
        <code>--transport websocket</code> to force a path. QUIC is reserved
        for a later transport mode.
      </p>

      <Anchor id="reconnect-backoff">Reconnect backoff</Anchor>
      <p>
        On any session error the agent enters a reconnect loop using
        decorrelated-jitter backoff from 500 ms up to a 30 s cap. Every
        reconnect attempt sends <code>Takeover: true</code>. Combined with
        rule (a) above, that makes reconnecting after a network partition
        effectively instant — the agent doesn&apos;t sit around waiting out the
        45 s dead-peer detection window before it can have its own name
        back.
      </p>

      <Anchor id="dead-peer-detection">Dead-peer detection</Anchor>
      <ParamTable>
        <Property name="yamux keepalive" type="interval" defaultValue="10s">
          Transport-layer ping. Session kill switch is{" "}
          <code>ConnectionWriteTimeout: 45s</code>.
        </Property>
        <Property name="Control-stream Ping" type="interval" defaultValue="15s">
          Application-layer liveness check; three consecutive misses (≈45 s)
          declares the peer dead.
        </Property>
      </ParamTable>
      <Callout variant="warning" title="Why the write timeout isn't 10s">
        <code>ConnectionWriteTimeout</code> in yamux is a whole-session kill
        switch guarding every data send, not a keepalive knob. Set to 10 s,
        a saturated uplink or flaky hotel wifi mid-download would trip it and
        kill the entire session — every tunnel, every in-flight request —
        presenting as &quot;the tunnel randomly drops under load&quot;. At
        45 s it stays a backstop for genuinely wedged connections while
        liveness comes from the pings instead.
      </Callout>
      <p>
        Both layers converge on roughly 45 seconds worst-case detection —
        but rule (a) above means the binding&apos;s own owner never has to
        wait on that window to reclaim its name.
      </p>

      <Anchor id="zombie-bindings">Zombie bindings</Anchor>
      <p>
        When a session dies, its bindings are released via a
        compare-and-delete, not a blind delete keyed on hostname: each
        hostname is only removed if the registry still shows the dying
        session as its owner. This is what keeps a dying session&apos;s
        eventual cleanup from deleting a binding that a newer session already
        took over — the operation is idempotent, since it can be triggered
        both from the session-death path and from a graceful drain.
      </p>
    </DocsArticle>
  )
}
