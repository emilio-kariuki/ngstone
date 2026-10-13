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
        When a <code>Bind</code> request names a subdomain — or, for a TCP
        tunnel, a port — that&apos;s already held, the edge resolves it with
        three rules, in order:
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
          The edge returns <code>BindErr{"{subdomain_taken}"}</code>, or{" "}
          <code>BindErr{"{port_unavailable}"}</code> for a TCP port. Two
          separate agents shouldn&apos;t silently fight over a name or a port
          — liveness is only consulted in this one case.
        </Step>
      </Steps>
      <p>
        On any successful takeover the edge sends the old session{" "}
        <code>Evicted{"{hostname, reason: \"takeover\"}"}</code>, force-closes
        it, and rebinds atomically under the registry lock. The evicted agent
        updates its status line instead of continuing to advertise a URL it
        no longer owns. For a TCP tunnel, <code>hostname</code> carries the{" "}
        <code>tcp://host:port</code> URL, and the takeover hands the
        port&apos;s existing listener to the new session instead of closing
        and reopening it, so no other process can grab the port in between.
        An empty <code>InstanceID</code> never matches another empty one for
        a TCP port.
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
      <p>
        TCP tunnels get the same instant reconnect. When you didn&apos;t pass{" "}
        <code>--remote-port</code>, the agent remembers the port the edge
        last gave it and requests that port again on reconnect, so the
        advertised <code>tcp://host:port</code> stays the same. If that port
        has since gone to another tunnel, the edge answers{" "}
        <code>port_unavailable</code>. The agent then drops the remembered
        port and binds a fresh one in the same handshake, so the tunnel still
        comes up, at a new address. An explicit <code>--remote-port</code>{" "}
        is never moved: the agent keeps retrying for that port.
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
      <p>
        TCP ports work the same way. A takeover moves the port out of the
        old session&apos;s ownership, so when the old session is finally
        released it closes only the connections it was already relaying and
        leaves the port, and its listener, with the new owner.
      </p>
    </DocsArticle>
  )
}
