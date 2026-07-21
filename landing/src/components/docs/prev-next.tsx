import Link from "next/link"
import { ArrowLeft, ArrowRight } from "lucide-react"

import { getAdjacent } from "@/lib/docs-nav"

export function PrevNext({ href }: { href: string }) {
  const { prev, next } = getAdjacent(href)

  if (!prev && !next) return null

  return (
    <div className="mt-16 grid grid-cols-1 gap-3 border-t border-border pt-8 sm:grid-cols-2">
      {prev ? (
        <Link
          href={prev.href}
          className="group flex flex-col rounded-lg border border-border px-4 py-3 transition-colors hover:bg-muted"
        >
          <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <ArrowLeft className="size-3.5" />
            Previous
          </span>
          <span className="mt-1 text-sm font-medium text-foreground">
            {prev.title}
          </span>
        </Link>
      ) : (
        <div />
      )}
      {next ? (
        <Link
          href={next.href}
          className="group flex flex-col items-end rounded-lg border border-border px-4 py-3 text-right transition-colors hover:bg-muted"
        >
          <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
            Next
            <ArrowRight className="size-3.5" />
          </span>
          <span className="mt-1 text-sm font-medium text-foreground">
            {next.title}
          </span>
        </Link>
      ) : (
        <div />
      )}
    </div>
  )
}
