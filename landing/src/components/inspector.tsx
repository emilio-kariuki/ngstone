import { RotateCw } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const REQUESTS = [
  { method: "GET", path: "/api/health", status: 200, time: "3ms", active: false },
  { method: "POST", path: "/api/orders", status: 201, time: "45ms", active: true },
  { method: "GET", path: "/api/users/482", status: 200, time: "12ms", active: false },
  { method: "GET", path: "/static/app.js", status: 304, time: "8ms", active: false },
  { method: "WS", path: "/socket", status: 101, time: "—", active: false },
  { method: "GET", path: "/api/users?page=2", status: 200, time: "19ms", active: false },
];

export function Inspector() {
  return (
    <section id="inspector" className="mx-auto max-w-6xl px-6 py-24 sm:py-28">
      <div className="mx-auto max-w-2xl text-center">
        <h2 className="font-display text-3xl font-medium tracking-tight sm:text-4xl">
          Watch every request land, live
        </h2>
        <p className="mt-4 text-balance text-muted-foreground">
          A local web UI at localhost:4040 shows every request and response
          as it happens, with headers, bodies, and timing — and lets you
          replay any of them straight to your app.
        </p>
      </div>

      <div className="mt-14 overflow-hidden rounded-xl border border-border bg-card/60 shadow-xl shadow-black/30">
        <div className="grid grid-cols-1 lg:grid-cols-[17rem_1fr]">
          <div className="divide-y divide-border border-b border-border lg:border-r lg:border-b-0">
            {REQUESTS.map((req) => (
              <div
                key={`${req.method}-${req.path}`}
                className={cn(
                  "flex items-center gap-2.5 px-4 py-3",
                  req.active && "bg-primary/10"
                )}
              >
                <Badge
                  variant={req.method === "POST" ? "default" : "secondary"}
                  className="font-mono"
                >
                  {req.method}
                </Badge>
                <span className="flex-1 truncate font-mono text-xs text-foreground">
                  {req.path}
                </span>
                <Badge variant="outline" className="font-mono">
                  {req.status}
                </Badge>
                <span className="w-10 shrink-0 text-right font-mono text-[0.7rem] text-muted-foreground">
                  {req.time}
                </span>
              </div>
            ))}
          </div>

          <div className="flex flex-col p-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-2.5">
                <Badge variant="default" className="font-mono">
                  POST
                </Badge>
                <span className="font-mono text-sm text-foreground">
                  /api/orders
                </span>
                <Badge variant="outline" className="font-mono">
                  201
                </Badge>
              </div>
              <button
                type="button"
                className={cn(buttonVariants({ variant: "outline", size: "sm" }))}
              >
                <RotateCw />
                Replay
              </button>
            </div>

            <div className="mt-6">
              <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
                Headers
              </p>
              <pre className="mt-2 overflow-x-auto rounded-lg border border-border bg-background/60 p-4 font-mono text-xs leading-relaxed text-muted-foreground">
{`content-type: application/json
user-agent: curl/8.6.0
x-forwarded-for: 203.0.113.42
authorization: Bearer •••••••••••`}
              </pre>
            </div>

            <div className="mt-4">
              <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
                Body
              </p>
              <pre className="mt-2 overflow-x-auto rounded-lg border border-border bg-background/60 p-4 font-mono text-xs leading-relaxed text-foreground/90">
{`{
  "id": "ord_7f3a9c",
  "status": "created",
  "total": 42.5
}`}
              </pre>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
