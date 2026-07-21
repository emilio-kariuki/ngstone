import type { ReactNode } from "react";

function CodeBlock({ children }: { children: ReactNode }) {
  return (
    <pre className="mt-4 overflow-x-auto rounded-lg border border-border bg-card px-5 py-4 font-mono text-sm leading-relaxed text-foreground/90">
      {children}
    </pre>
  );
}

const STEPS = [
  {
    title: "Point DNS at your VPS, and start the edge",
    description:
      "Add a wildcard A record for *.yourdomain.com pointing at your server, then run the edge binary there.",
    code: `$ ngstoned --domain yourdomain.com --email you@yourdomain.com`,
  },
  {
    title: "Set your token",
    description:
      "ngstoned prints a token on first boot. Export it wherever you run the agent, on your dev machine.",
    code: `$ export NGSTONE_TOKEN=nst_••••••••••••••••••••`,
  },
  {
    title: "Start tunneling",
    description:
      "Point the agent at any local port. Add --subdomain to pick your own name instead of a random one.",
    code: `$ ngstone http 3000
→ https://amber-fox-42.yourdomain.com

$ ngstone http 3000 --subdomain api
→ https://api.yourdomain.com`,
  },
];

export function Quickstart() {
  return (
    <section id="quickstart" className="mx-auto max-w-4xl px-6 py-24 sm:py-28">
      <div className="mx-auto max-w-2xl text-center">
        <h2 className="font-display text-3xl font-medium tracking-tight sm:text-4xl">
          From clone to public URL in three commands
        </h2>
        <p className="mt-4 text-balance text-muted-foreground">
          No dashboard, no account creation. Just a binary on your server and
          a binary on your laptop.
        </p>
      </div>

      <ol className="mt-14 flex flex-col gap-10">
        {STEPS.map((step, index) => (
          <li key={step.title} className="flex gap-5">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-primary/30 bg-primary/10 font-mono text-sm text-primary">
              {index + 1}
            </span>
            <div className="min-w-0 flex-1">
              <p className="font-medium text-foreground">{step.title}</p>
              <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
                {step.description}
              </p>
              <CodeBlock>{step.code}</CodeBlock>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
