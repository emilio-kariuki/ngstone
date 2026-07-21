import type { ReactNode } from "react"

import type { TocItem } from "@/lib/docs-nav"
import { Breadcrumbs } from "@/components/docs/breadcrumbs"
import { PrevNext } from "@/components/docs/prev-next"
import { TableOfContents } from "@/components/docs/table-of-contents"

export function DocsArticle({
  href,
  toc,
  children,
}: {
  href: string
  toc: TocItem[]
  children: ReactNode
}) {
  return (
    <div className="mx-auto flex w-full max-w-[90rem] items-start gap-10 px-6 py-10 lg:px-10">
      <article className="min-w-0 max-w-[46rem] flex-1">
        <Breadcrumbs href={href} />
        <div className="docs-prose">{children}</div>
        <PrevNext href={href} />
      </article>
      <div className="hidden w-56 shrink-0 xl:block">
        <TableOfContents items={toc} />
      </div>
    </div>
  )
}
