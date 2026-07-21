import {
  ArrowDown,
  ArrowLeft,
  ArrowRight,
  ArrowUp,
  Globe,
  Laptop,
  ServerCog,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { cn } from "@/lib/utils";

const STEPS = [
  {
    title: "A browser asks for your subdomain",
    description:
      "A request for https://api.yourdomain.com hits your VPS on port 443, terminated with a wildcard TLS certificate that ngstoned already holds.",
  },
  {
    title: "The edge routes it down the tunnel",
    description:
      "ngstoned looks up the subdomain, finds the matching agent session, and forwards the request as a new stream on that session.",
  },
  {
    title: "Your local app answers, unaware",
    description:
      "The agent receives the stream and proxies it to localhost:3000. The response streams back the same way it came — no buffering, no polling.",
  },
];

function FlowNode({
  icon: Icon,
  title,
  description,
}: {
  icon: LucideIcon;
  title: string;
  description: string;
}) {
  return (
    <div className="flex w-full flex-col items-center gap-3 rounded-xl border border-border bg-card/60 px-6 py-6 text-center xl:w-44">
      <div className="rounded-lg bg-primary/10 p-2.5 text-primary [&>svg]:h-5 [&>svg]:w-5">
        <Icon />
      </div>
      <div>
        <p className="text-sm font-medium text-foreground">{title}</p>
        <p className="mt-1 font-mono text-xs text-muted-foreground">
          {description}
        </p>
      </div>
    </div>
  );
}

function Connector({
  label,
  sublabel,
  reverse = false,
}: {
  label: string;
  sublabel?: string;
  reverse?: boolean;
}) {
  return (
    <div className="flex w-full flex-col items-center gap-2 py-2 xl:w-auto xl:max-w-48 xl:py-0">
      <div className="text-primary xl:hidden">
        {reverse ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />}
      </div>
      <div className="hidden text-primary xl:block">
        {reverse ? <ArrowLeft className="h-4 w-4" /> : <ArrowRight className="h-4 w-4" />}
      </div>
      <p className="text-center text-xs leading-snug text-muted-foreground">
        {label}
      </p>
      {sublabel ? (
        <p className="text-center text-[0.7rem] leading-snug text-muted-foreground/70">
          {sublabel}
        </p>
      ) : null}
    </div>
  );
}

export function HowItWorks() {
  return (
    <section
      id="how-it-works"
      className="mx-auto max-w-6xl px-6 py-24 sm:py-28"
    >
      <div className="mx-auto max-w-2xl text-center">
        <h2 className="font-display text-3xl font-medium tracking-tight sm:text-4xl">
          One connection, dialed from your side
        </h2>
        <p className="mt-4 text-balance text-muted-foreground">
          The agent on your laptop reaches out to your VPS — never the other
          way around. That single connection carries every request.
        </p>
      </div>

      <div className="mt-14 flex flex-col items-center xl:flex-row xl:items-center xl:justify-center">
        <FlowNode
          icon={Globe}
          title="Browser"
          description="https://api.yourdomain.com"
        />
        <Connector label="HTTPS request" />
        <FlowNode
          icon={ServerCog}
          title="Your VPS edge"
          description=":443 · wildcard TLS · ngstoned"
        />
        <Connector
          label="dialed outbound from the agent"
          sublabel="one TLS 1.3 / yamux connection — traffic flows both ways once established"
          reverse
        />
        <FlowNode
          icon={Laptop}
          title="Your laptop"
          description="ngstone agent → localhost:3000"
        />
      </div>

      <div className="mt-16 grid grid-cols-1 gap-8 sm:grid-cols-3">
        {STEPS.map((step, index) => (
          <div key={step.title} className={cn("flex gap-4")}>
            <span className="font-mono text-2xl leading-none text-primary/70">
              {String(index + 1).padStart(2, "0")}
            </span>
            <div>
              <p className="text-sm font-medium text-foreground">
                {step.title}
              </p>
              <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">
                {step.description}
              </p>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
