import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

const styles: Record<"h2" | "h3", string> = {
  h2: "mt-12 mb-4 border-t border-border pt-8 font-display text-2xl font-medium tracking-tight text-foreground",
  h3: "mt-8 mb-3 font-sans text-lg font-semibold text-foreground",
}

export function Anchor({
  as = "h2",
  id,
  children,
}: {
  as?: "h2" | "h3"
  id: string
  children: ReactNode
}) {
  const Tag = as

  return (
    <Tag
      id={id}
      className={cn("group flex scroll-mt-24 items-center gap-2", styles[as])}
    >
      {children}
      <a
        href={`#${id}`}
        className="text-primary opacity-0 transition-opacity group-hover:opacity-100"
        aria-label="Link to this section"
      >
        #
      </a>
    </Tag>
  )
}
