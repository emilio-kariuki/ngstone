import type { ReactNode } from "react"
import { Info, Lightbulb, OctagonAlert, TriangleAlert } from "lucide-react"

import { cn } from "@/lib/utils"

export type CalloutVariant = "note" | "tip" | "warning" | "danger" | "info"

const variants: Record<
  CalloutVariant,
  { icon: typeof Info; className: string; iconClassName: string }
> = {
  note: {
    icon: Info,
    className: "border-l-muted-foreground/40 bg-muted/40",
    iconClassName: "text-muted-foreground",
  },
  tip: {
    icon: Lightbulb,
    className: "border-l-primary bg-primary/5",
    iconClassName: "text-primary",
  },
  info: {
    icon: Info,
    className: "border-l-[--chart-2] bg-muted/40",
    iconClassName: "text-[--chart-2]",
  },
  warning: {
    icon: TriangleAlert,
    className: "border-l-primary bg-primary/5",
    iconClassName: "text-primary",
  },
  danger: {
    icon: OctagonAlert,
    className: "border-l-destructive bg-destructive/10",
    iconClassName: "text-destructive",
  },
}

export function Callout({
  variant = "note",
  title,
  children,
}: {
  variant?: CalloutVariant
  title?: string
  children: ReactNode
}) {
  const config = variants[variant]
  const Icon = config.icon

  return (
    <div className={cn("my-6 rounded-md border-l-4 p-4", config.className)}>
      <div className="flex gap-3">
        <Icon className={cn("mt-0.5 size-4 shrink-0", config.iconClassName)} />
        <div className="min-w-0 flex-1">
          {title ? (
            <p className={cn("font-semibold", config.iconClassName)}>{title}</p>
          ) : null}
          <div className="mt-1 text-sm text-foreground/90 first:mt-0">
            {children}
          </div>
        </div>
      </div>
    </div>
  )
}
