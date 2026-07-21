import { cn } from "@/lib/utils";

type Row = {
  marker?: "replayed" | "replaying";
  method: string;
  path: string;
  status: string;
  time: string;
  active?: boolean;
};

const ROWS: Row[] = [
  { method: "GET", path: "/api/health", status: "200", time: "3ms" },
  {
    marker: "replayed",
    method: "POST",
    path: "/api/orders",
    status: "201",
    time: "45ms",
    active: true,
  },
  { method: "GET", path: "/api/users/482", status: "200", time: "12ms" },
  { method: "GET", path: "/static/app.js", status: "304", time: "8ms" },
  { method: "WS", path: "/socket", status: "101", time: "2.1KiB/860B" },
  {
    marker: "replaying",
    method: "GET",
    path: "/api/users?page=2",
    status: "...",
    time: "-",
  },
];

const methodColor: Record<string, string> = {
  GET: "text-[--chart-2]",
  POST: "text-primary",
  WS: "text-[oklch(0.62_0.19_330)]",
};

function statusColor(status: string) {
  if (status === "..." || status === "-") return "text-muted-foreground";
  const code = Number(status);
  if (code === 101) return "text-[oklch(0.62_0.19_330)]";
  if (code >= 200 && code < 300) return "text-[--chart-2]";
  if (code >= 300 && code < 400) return "text-[oklch(0.68_0.15_230)]";
  if (code >= 400) return "text-destructive";
  return "text-muted-foreground";
}

export function Inspector() {
  return (
    <section id="inspector" className="mx-auto max-w-6xl px-6 py-24 sm:py-28">
      <div className="mx-auto max-w-2xl text-center">
        <h2 className="font-display text-3xl font-medium tracking-tight sm:text-4xl">
          Watch every request land, live
        </h2>
        <p className="mt-4 text-balance text-muted-foreground">
          Run <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[0.85em] text-foreground">ngstone port 3000</code> and
          get a full-screen terminal dashboard — every request and response
          as it happens, with headers, decoded bodies, and timing, plus
          replay and edit-and-replay straight to your app. No browser tab,
          no separate process.
        </p>
      </div>

      <div className="mt-14 overflow-hidden rounded-xl border border-border bg-card shadow-2xl shadow-black/50">
        <div className="flex items-center gap-1.5 border-b border-border bg-background/40 px-4 py-3">
          <span className="h-2.5 w-2.5 rounded-full bg-foreground/15" />
          <span className="h-2.5 w-2.5 rounded-full bg-foreground/15" />
          <span className="h-2.5 w-2.5 rounded-full bg-primary/70" />
          <span className="ml-2 font-mono text-xs text-muted-foreground">
            ngstone port 3000
          </span>
        </div>

        <div className="border-b border-border px-4 py-3 font-mono text-xs leading-relaxed sm:text-sm">
          <div className="flex items-center justify-between">
            <span className="font-semibold text-primary">ngstone</span>
            <span className="text-muted-foreground">(Ctrl+C quit)</span>
          </div>
          <div className="mt-1 text-muted-foreground">
            Session <span className="text-[--chart-2]">online</span>{" "}
            &nbsp;Latency 45ms
          </div>
          <div className="mt-1 text-muted-foreground">
            Forwarding{" "}
            <span className="text-foreground">
              https://amber-fox-42.yourdomain.com
            </span>{" "}
            -&gt; <span className="text-foreground">127.0.0.1:3000</span>
            &nbsp;&middot; 214 total &middot; 1 in-flight
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-[1fr_1.1fr]">
          <div className="divide-y divide-border border-b border-border font-mono text-xs sm:text-sm lg:border-r lg:border-b-0">
            {ROWS.map((row) => (
              <div
                key={`${row.method}-${row.path}`}
                className={cn(
                  "flex items-center gap-2.5 px-4 py-2.5",
                  row.active && "bg-primary/10"
                )}
              >
                <span className="w-4 shrink-0 text-primary">
                  {row.marker === "replayed"
                    ? "↺"
                    : row.marker === "replaying"
                      ? "~"
                      : ""}
                </span>
                <span
                  className={cn(
                    "w-11 shrink-0 font-semibold",
                    methodColor[row.method] ?? "text-muted-foreground"
                  )}
                >
                  {row.method}
                </span>
                <span className="flex-1 truncate text-foreground">
                  {row.path}
                </span>
                <span className={cn("w-9 shrink-0 text-right", statusColor(row.status))}>
                  {row.status}
                </span>
                <span className="w-20 shrink-0 text-right text-muted-foreground">
                  {row.time}
                </span>
              </div>
            ))}
          </div>

          <div className="flex flex-col p-5 font-mono text-xs sm:text-sm">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="font-semibold text-primary">POST</span>
              <span className="text-foreground">/api/orders HTTP/1.1</span>
            </div>

            <div className="mt-4">
              <p className="text-[0.7rem] font-medium tracking-wide text-muted-foreground uppercase">
                Headers
              </p>
              <pre className="mt-1.5 overflow-x-auto rounded-lg border border-border bg-background/60 p-3 leading-relaxed text-muted-foreground">
{`content-type: application/json
user-agent: curl/8.6.0
x-forwarded-for: 203.0.113.42
authorization: Bearer •••••••••••`}
              </pre>
            </div>

            <div className="mt-3">
              <p className="text-[0.7rem] font-medium tracking-wide text-muted-foreground uppercase">
                Body
              </p>
              <pre className="mt-1.5 overflow-x-auto rounded-lg border border-border bg-background/60 p-3 leading-relaxed text-foreground/90">
{`{
  "id": "ord_7f3a9c",
  "status": "created",
  "total": 42.5
}`}
              </pre>
            </div>

            <div className="mt-4 flex items-center gap-2">
              <span className={cn("font-semibold", statusColor("201"))}>
                STATUS 201
              </span>
            </div>
          </div>
        </div>

        <div className="border-t border-border px-4 py-2 font-mono text-[0.7rem] text-muted-foreground sm:text-xs">
          &uarr;&darr; select &nbsp; r replay &nbsp; e edit &amp; replay
          &nbsp; / filter &nbsp; l logs &nbsp; q quit &nbsp; ? help
        </div>
      </div>
    </section>
  );
}
