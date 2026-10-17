export type TocItem = { id: string; title: string }

export type NavItem = { title: string; href: string; description: string }

export type NavGroup = { label: string; items: NavItem[] }

export const NAV: NavGroup[] = [
  {
    label: "Getting Started",
    items: [
      {
        title: "Introduction",
        href: "/docs/introduction",
        description: "What ngstone is, and why it exists.",
      },
      {
        title: "Quickstart",
        href: "/docs/quickstart",
        description: "From a fresh VPS to a public URL on your laptop.",
      },
      {
        title: "Installation",
        href: "/docs/installation",
        description: "Install the agent, and build the edge from source.",
      },
      {
        title: "Core Concepts",
        href: "/docs/core-concepts",
        description: "The vocabulary — edge, agent, sessions, streams, bindings.",
      },
    ],
  },
  {
    label: "Guides",
    items: [
      {
        title: "Running the edge on a VPS",
        href: "/docs/guides/edge-vps",
        description: "Stand up ngstoned on a Linux server with TLS.",
      },
      {
        title: "Exposing a local app",
        href: "/docs/guides/expose-local-app",
        description: "Forward a public URL to a port on your machine.",
      },
      {
        title: "TCP tunnels",
        href: "/docs/guides/tcp-tunnels",
        description: "Raw TCP tunnels for SSH, databases, and anything else that isn't HTTP.",
      },
      {
        title: "Sharing a database",
        href: "/docs/guides/database-sharing",
        description: "Hand a teammate a link to a local database that expires on its own.",
      },
      {
        title: "Custom subdomains",
        href: "/docs/guides/custom-subdomains",
        description: "Pick your own name instead of a random one.",
      },
      {
        title: "Access control",
        href: "/docs/guides/access-control",
        description: "Per-tunnel HTTP basic auth and source-IP allowlisting.",
      },
      {
        title: "Using the request inspector",
        href: "/docs/guides/request-inspector",
        description: "The terminal dashboard that shows every request live.",
      },
      {
        title: "Replaying requests",
        href: "/docs/guides/replaying-requests",
        description: "Re-send a captured request straight to your local app.",
      },
      {
        title: "GitHub Actions",
        href: "/docs/guides/github-actions",
        description: "Expose CI services with a checked, TTL-bound preview tunnel.",
      },
      {
        title: "WebSockets & SSE",
        href: "/docs/guides/websockets-sse",
        description: "Long-lived connections — not yet hardened (M4).",
      },
      {
        title: "Streaming & large transfers",
        href: "/docs/guides/streaming-large-transfers",
        description: "Big uploads, downloads, and constant-memory forwarding.",
      },
    ],
  },
  {
    label: "Reference",
    items: [
      {
        title: "CLI",
        href: "/docs/reference/cli",
        description: "The ngstone command and its subcommands.",
      },
      {
        title: "Configuration",
        href: "/docs/reference/configuration",
        description: "The agent's config file, and the edge's flags and environment.",
      },
      {
        title: "The wire protocol",
        href: "/docs/reference/wire-protocol",
        description: "Framing, control messages, and versioning.",
      },
      {
        title: "TLS & certificates",
        href: "/docs/reference/tls-certificates",
        description: "How ngstone issues and serves certificates.",
      },
      {
        title: "Limits & timeouts",
        href: "/docs/reference/limits-timeouts",
        description: "Every cap the edge enforces.",
      },
    ],
  },
  {
    label: "Operations",
    items: [
      {
        title: "Deployment & systemd",
        href: "/docs/operations/deployment-systemd",
        description: "Run ngstoned as a managed service.",
      },
      {
        title: "Reconnection & takeover",
        href: "/docs/operations/reconnection-takeover",
        description: "How tunnels survive sleeps, blips, and restarts.",
      },
      {
        title: "Failure modes & recovery",
        href: "/docs/operations/failure-modes",
        description: "What breaks, how it's detected, what happens.",
      },
      {
        title: "Security model",
        href: "/docs/operations/security-model",
        description: "The threat model, and what the token does and doesn't grant.",
      },
    ],
  },
]

export function flattenNav(): NavItem[] {
  return NAV.flatMap((group) => group.items)
}

export function getAdjacent(href: string): { prev?: NavItem; next?: NavItem } {
  const flat = flattenNav()
  const index = flat.findIndex((item) => item.href === href)
  if (index === -1) return {}
  return { prev: flat[index - 1], next: flat[index + 1] }
}

export function getBreadcrumb(href: string): { group: string; title: string } | null {
  for (const group of NAV) {
    const item = group.items.find((navItem) => navItem.href === href)
    if (item) return { group: group.label, title: item.title }
  }
  return null
}
