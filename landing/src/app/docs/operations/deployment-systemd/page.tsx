import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"

export const metadata: Metadata = {
  title: "Deployment & systemd",
  description: "Run ngstoned as a managed service.",
}

const TOC: TocItem[] = [
  { id: "the-unit", title: "The systemd unit" },
  { id: "dynamicuser-statedirectory", title: "DynamicUser & StateDirectory" },
  { id: "binding-443", title: "Binding to port 443" },
  { id: "secrets", title: "Secrets" },
  { id: "local-ops-dashboard", title: "Local ops dashboard" },
  { id: "restart-behavior", title: "Restart behavior" },
]

export default function DeploymentSystemdPage() {
  return (
    <DocsArticle href="/docs/operations/deployment-systemd" toc={TOC}>
      <h1>Deployment & systemd</h1>
      <p>
        <code>ngstoned</code> is meant to run as a long-lived systemd service
        on the VPS, restarted automatically on crash and surviving reboots
        without re-issuing certificates.
      </p>

      <Anchor id="the-unit">The systemd unit</Anchor>
      <CodeBlock
        filename="ngstoned.service"
        language="ini"
        code={`[Unit]
Description=ngstone edge server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ngstoned --domain ngstone.site --cert-email you@ngstone.site
DynamicUser=yes
StateDirectory=ngstoned
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
EnvironmentFile=/etc/ngstoned/ngstoned.env
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target`}
      />

      <Anchor id="dynamicuser-statedirectory">DynamicUser & StateDirectory</Anchor>
      <p>
        <code>DynamicUser=yes</code> paired with{" "}
        <code>StateDirectory=ngstoned</code> is the mechanism systemd
        provides specifically to make dynamic, unprivileged users work with
        persistent state. systemd creates the directory under{" "}
        <code>/var/lib/private/</code> and re-chowns it to the current
        transient UID on every service start, so the certificate cache
        survives restarts intact even though the UID changes each time.
      </p>
      <p>
        Reference the certificate path via{" "}
        <code>{"${STATE_DIRECTORY}"}/certs</code> (or the systemd-bind-mounted{" "}
        <code>/var/lib/ngstoned/certs</code>) rather than hardcoding{" "}
        <code>/var/lib/private/...</code> — the literal private path silently
        becomes a different, unmanaged directory if <code>DynamicUser</code>{" "}
        is ever removed from the unit.
      </p>

      <Anchor id="binding-443">Binding to port 443</Anchor>
      <p>
        <code>AmbientCapabilities=CAP_NET_BIND_SERVICE</code> lets the process
        bind privileged ports without running as root. It composes cleanly
        with both <code>DynamicUser=yes</code> and{" "}
        <code>NoNewPrivileges=yes</code> — <code>NoNewPrivileges</code> only
        blocks privilege <em>gain</em> via setuid binaries or file
        capabilities; it does not strip an ambient capability the service
        manager itself granted.
      </p>

      <Anchor id="secrets">Secrets</Anchor>
      <Callout variant="danger" title="Never pass secrets as ExecStart flags">
        <code>/proc/&lt;pid&gt;/cmdline</code> is world-readable on stock
        Linux, so a token hash or API token passed as a command-line flag
        is readable by any local user via <code>ps auxww</code>. Put{" "}
        <code>NGSTONE_DATABASE_URL</code>, <code>NGSTONE_EDGE_ID</code>,{" "}
        <code>NGSTONE_CREDENTIALS_FILE</code>,{" "}
        <code>NGSTONE_TOKEN_SHA256</code>,{" "}
        <code>NGSTONE_ADMIN_TOKEN_SHA256</code>, and{" "}
        <code>NGSTONE_CF_API_TOKEN</code> in the unit&apos;s{" "}
        <code>EnvironmentFile=</code> instead — <code>ngstoned</code> reads
        the scoped credential file in preference to the equivalent legacy
        <code>-token-sha256</code>/
        <code>-cf-api-token</code> flags for exactly this reason. (The
        plaintext token itself, <code>NGSTONE_TOKEN</code>, belongs on the
        agent side, not on the VPS.)
      </Callout>
      <p>
        Configure <code>NGSTONE_DATABASE_URL</code> to SQLite for a single edge
        or to the same PostgreSQL URL on every edge in an active/active group,
        with a distinct <code>NGSTONE_EDGE_ID</code> per edge. Issue credentials
        with <code>ngstone admin credentials issue</code> through the loopback
        API. Each credential is limited to one subdomain or TCP port and has a
        bounded TTL; <code>credentials revoke</code> invalidates it
        independently. OIDC browser login is available for team access to the
        management API; configure the provider group mappings and keep the
        client and cookie secrets in <code>EnvironmentFile=</code>. mTLS team
        authentication remains deferred. The management API uses loopback
        access by default; configure <code>NGSTONE_ADMIN_TOKEN_SHA256</code> only
        when a private, TLS-protected automation path is required.
      </p>

      <Anchor id="local-ops-dashboard">Local ops dashboard</Anchor>
      <p>
        By default, <code>ngstoned</code> exposes a read-only operations
        dashboard on <code>127.0.0.1:4041</code>. It shows routed tunnels,
        connector capacity, request counters, per-tunnel latency/status/byte
        metrics, certificate expiry, and recent in-memory edge events. Reach
        it from your workstation with an SSH
        forward:
      </p>
      <p>
        The management API exposes <code>GET /api/v1/observability/tunnels</code>
        and the Prometheus endpoint exposes the same per-tunnel counters.
        Configure <code>NGSTONE_ALERT_WEBHOOK_URL</code> and optionally
        <code>NGSTONE_ALERT_WEBHOOK_TOKEN</code> for non-blocking lifecycle
        alerts covering reconnects, lease loss, and expired or revoked
        credentials.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ssh -L 4041:127.0.0.1:4041 root@example.com
$ open http://127.0.0.1:4041/`}
      />
      <p>
        The same listener serves <code>/api/state</code> as JSON and{" "}
        <code>/metrics</code> in Prometheus text format. Keep the{" "}
        <code>-ops</code> address on loopback. The dashboard remains
        read-only, while <code>/api/v1</code> provides authenticated
        management operations:
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone admin status
$ ngstone admin tunnels --json
$ ngstone admin observability --json
$ ngstone admin credentials issue --subdomain demo --ttl 24h
$ ngstone admin policies list
$ ngstone admin domains list
$ ngstone admin tunnel drain demo`}
      />
      <p>
        The CLI defaults to <code>http://127.0.0.1:4041</code> and is intended
        to run through the SSH forward above. Set{" "}
        <code>NGSTONE_ADMIN_TOKEN</code> when the edge has an admin token hash.
        Set <code>-ops &quot;&quot;</code> to disable the entire listener.
      </p>
      <Callout variant="warning" title="Do not expose the ops listener">
        The bearer token protects only <code>/api/v1</code>. If{" "}
        <code>-ops</code> is changed to a public address, the dashboard,
        <code>/api/state</code>, metrics, health, and pprof remain separate
        endpoints. Put the listener behind a private network, firewall, and
        TLS-authenticated proxy instead.
      </Callout>

      <Anchor id="restart-behavior">Restart behavior</Anchor>
      <p>
        <code>Restart=always</code> means a crash or OOM typically recovers
        in under two seconds. Because certificates are cached under{" "}
        <code>StateDirectory</code>, a restart makes zero ACME traffic —
        provided the unit is configured correctly. Get{" "}
        <code>DynamicUser</code>/<code>StateDirectory</code> wrong and every
        restart instead re-issues against Let&apos;s Encrypt&apos;s rate
        limits, which is the failure this unit is written specifically to
        avoid.
      </p>
    </DocsArticle>
  )
}
