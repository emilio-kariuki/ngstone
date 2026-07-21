import type { ReactNode } from "react"

import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

export type PillVariant = "default" | "secondary" | "outline" | "danger" | "info"

const variantMap: Record<PillVariant, { badge?: "default" | "secondary" | "outline"; className?: string }> = {
  default: { badge: "default" },
  secondary: { badge: "secondary" },
  outline: { badge: "outline" },
  danger: { badge: undefined, className: "bg-destructive/10 text-destructive" },
  info: { badge: undefined, className: "bg-[color-mix(in_oklch,var(--chart-2),transparent_85%)] text-[--chart-2]" },
}

export function Pill({
  variant = "default",
  children,
}: {
  variant?: PillVariant
  children: ReactNode
}) {
  const config = variantMap[variant]

  if (config.badge) {
    return <Badge variant={config.badge}>{children}</Badge>
  }

  return (
    <Badge
      variant="outline"
      className={cn("border-transparent", config.className)}
    >
      {children}
    </Badge>
  )
}
