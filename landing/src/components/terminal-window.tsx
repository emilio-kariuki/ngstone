import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

export function TerminalWindow({
  className,
  children,
}: {
  className?: string;
  children: ReactNode;
}) {
  return (
    <div
      className={cn(
        "overflow-hidden rounded-xl border border-border bg-card shadow-2xl shadow-black/50",
        className
      )}
    >
      <div className="flex items-center gap-1.5 border-b border-border bg-background/40 px-4 py-3">
        <span className="h-2.5 w-2.5 rounded-full bg-foreground/15" />
        <span className="h-2.5 w-2.5 rounded-full bg-foreground/15" />
        <span className="h-2.5 w-2.5 rounded-full bg-primary/70" />
      </div>
      <div className="px-5 py-5 font-mono text-sm leading-relaxed sm:text-base">
        {children}
      </div>
    </div>
  );
}
