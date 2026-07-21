import { ChevronRight } from "lucide-react"

import { getBreadcrumb } from "@/lib/docs-nav"

export function Breadcrumbs({ href }: { href: string }) {
  const crumb = getBreadcrumb(href)

  if (!crumb) return null

  return (
    <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
      <span>Docs</span>
      <ChevronRight className="size-3.5" />
      <span>{crumb.group}</span>
      <ChevronRight className="size-3.5" />
      <span className="text-foreground">{crumb.title}</span>
    </div>
  )
}
