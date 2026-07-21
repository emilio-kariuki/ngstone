import type { ReactNode } from "react"
import Link from "next/link"
import type { LucideIcon } from "lucide-react"

import { cn } from "@/lib/utils"

export function Card({
  title,
  icon: Icon,
  href,
  children,
}: {
  title: string
  icon?: LucideIcon
  href?: string
  children?: ReactNode
}) {
  const content = (
    <>
      {Icon ? <Icon className="mb-3 size-5 text-primary" /> : null}
      <p className="font-heading font-medium text-foreground">{title}</p>
      {children ? (
        <p className="mt-1.5 text-sm text-muted-foreground">{children}</p>
      ) : null}
    </>
  )

  const className = "block rounded-xl border border-border bg-card p-5 transition-colors hover:border-primary/40"

  if (href) {
    return (
      <Link href={href} className={className}>
        {content}
      </Link>
    )
  }

  return <div className={className}>{content}</div>
}

export function CardGrid({
  columns = 2,
  children,
}: {
  columns?: 1 | 2 | 3
  children: ReactNode
}) {
  const columnsClass = {
    1: "sm:grid-cols-1",
    2: "sm:grid-cols-2",
    3: "sm:grid-cols-2 lg:grid-cols-3",
  }[columns]

  return (
    <div className={cn("my-6 grid grid-cols-1 gap-4", columnsClass)}>
      {children}
    </div>
  )
}
