import {
  Activity,
  KeyRound,
  Network,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Waves,
  Wifi,
} from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const FEATURES = [
  {
    icon: KeyRound,
    title: "Your domain, your rules",
    description:
      "No third party sees your traffic, no monthly seat pricing, no forced login walls. One wildcard domain gives you infinite custom subdomains.",
  },
  {
    icon: Wifi,
    title: "NAT-friendly by design",
    description:
      "The agent dials out to your VPS — it never connects into your laptop. No inbound firewall holes at home, and it works behind any NAT.",
  },
  {
    icon: Network,
    title: "Multiplexed over one connection",
    description:
      "A single TLS 1.3 connection carries a yamux session; every request gets its own flow-controlled stream. No per-request handshakes anywhere.",
  },
  {
    icon: ShieldCheck,
    title: "Automatic wildcard TLS",
    description:
      "Let's Encrypt wildcard certs via DNS-01. https://anything.yourdomain.com just works, with a valid padlock, auto-renewed.",
  },
  {
    icon: Activity,
    title: "Built-in request inspector",
    description:
      "A local web UI at localhost:4040 shows every request and response live — headers, bodies, timing — and lets you replay or edit-and-replay any of them.",
  },
  {
    icon: Waves,
    title: "Constant-memory streaming",
    description:
      "Bodies are never buffered — a 1 GiB download or 100 MB upload passes through at constant memory. WebSockets and SSE ride the same tunnel and just work.",
  },
  {
    icon: RefreshCw,
    title: "Instant reconnect",
    description:
      "Laptop sleeps or wifi blips? The agent reconnects with the same identity and reclaims its subdomain immediately. Same URL after recovery.",
  },
  {
    icon: ShieldAlert,
    title: "Hardened edge",
    description:
      "Per-IP rate limiting, in-flight caps, slowloris protection, and constant-time token auth. Unknown hosts get a cheap uniform 404.",
  },
];

export function Features() {
  return (
    <section id="features" className="mx-auto max-w-6xl px-6 py-24 sm:py-28">
      <div className="mx-auto max-w-2xl text-center">
        <h2 className="font-display text-3xl font-medium tracking-tight sm:text-4xl">
          Everything ngrok does. None of the strings attached.
        </h2>
        <p className="mt-4 text-balance text-muted-foreground">
          Built for developers who&rsquo;d rather own the whole path from
          browser to laptop than rent a slice of someone else&rsquo;s.
        </p>
      </div>

      <div className="mt-14 grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3">
        {FEATURES.map((feature) => (
          <Card
            key={feature.title}
            className="border-border bg-card/60 transition-all duration-300 hover:-translate-y-0.5 hover:border-primary/30 hover:shadow-lg hover:shadow-black/20"
          >
            <CardHeader>
              <div className="mb-1 w-fit rounded-lg bg-primary/10 p-2 text-primary [&>svg]:h-5 [&>svg]:w-5">
                <feature.icon />
              </div>
              <CardTitle className="text-base">{feature.title}</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm leading-relaxed text-muted-foreground">
                {feature.description}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>
    </section>
  );
}
