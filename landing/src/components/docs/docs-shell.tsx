"use client"

import { useState, type ReactNode } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { Menu } from "lucide-react"

import { buttonVariants } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { DocsSidebar } from "@/components/docs/docs-sidebar"
import { DocsSearch } from "@/components/docs/docs-search"

function DocsTopBar({ onMenu }: { onMenu: () => void }) {
  return (
    <header className="sticky top-0 z-30 h-14 w-full border-b border-border bg-background/80 backdrop-blur-md">
      <div className="flex h-14 items-center justify-between gap-4 px-4 lg:px-6">
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onMenu}
            aria-label="Open navigation"
            className="inline-flex size-8 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-muted hover:text-foreground lg:hidden"
          >
            <Menu className="size-4.5" />
          </button>
          <Link
            href="/"
            className="flex items-center gap-1.5 text-base font-semibold tracking-tight text-foreground"
          >
            ngstone
            <span className="text-primary">.</span>
          </Link>
        </div>
        <div className="flex items-center gap-3">
          <DocsSearch />
          <a
            href="#"
            className={cn(
              buttonVariants({ variant: "outline", size: "sm" }),
              "hidden sm:inline-flex"
            )}
          >
            GitHub
          </a>
        </div>
      </div>
    </header>
  )
}

export function DocsShell({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false)
  const pathname = usePathname()
  const [renderedPathname, setRenderedPathname] = useState(pathname)

  if (pathname !== renderedPathname) {
    setRenderedPathname(pathname)
    setOpen(false)
  }

  return (
    <div className="flex min-h-screen flex-col">
      <DocsTopBar onMenu={() => setOpen(true)} />
      <div className="mx-auto flex w-full max-w-[90rem] flex-1 items-start">
        <DocsSidebar open={open} onClose={() => setOpen(false)} />
        <main className="min-w-0 flex-1">{children}</main>
      </div>
    </div>
  )
}
