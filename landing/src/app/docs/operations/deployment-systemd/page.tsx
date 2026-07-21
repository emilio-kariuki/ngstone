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
ExecStart=/usr/local/bin/ngstoned --domain ngstone.site --email you@ngstone.site
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
        Linux, so a token passed as a command-line flag is readable by any
        local user via <code>ps auxww</code>. Put{" "}
        <code>NGSTONE_TOKEN</code> in an <code>EnvironmentFile=</code>{" "}
        instead and read it from the environment.
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
