"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { ChevronDown } from "lucide-react"

import { NAV, type NavGroup } from "@/lib/docs-nav"
import { cn } from "@/lib/utils"

function SidebarGroup({
  group,
  pathname,
  onNavigate,
}: {
  group: NavGroup
  pathname: string
  onNavigate: () => void
}) {
  const [expanded, setExpanded] = useState(true)

  return (
    <div>
      <button
        type="button"
        onClick={() => setExpanded((value) => !value)}
        className="flex w-full items-center justify-between rounded-md px-3 py-1.5 text-xs font-medium tracking-wide text-muted-foreground uppercase transition-colors hover:text-foreground"
      >
        {group.label}
        <ChevronDown
          className={cn(
            "size-3.5 transition-transform",
            !expanded && "-rotate-90"
          )}
        />
      </button>
      {expanded ? (
        <ul className="mt-1 flex flex-col gap-0.5">
          {group.items.map((item) => {
            const active = item.href === pathname
            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  onClick={onNavigate}
                  className={cn(
                    "block rounded-md border-l-2 px-3 py-1.5 text-sm transition-colors",
                    active
                      ? "border-l-primary bg-primary/10 text-primary"
                      : "border-l-transparent text-muted-foreground hover:text-foreground"
                  )}
                >
                  {item.title}
                </Link>
              </li>
            )
          })}
        </ul>
      ) : null}
    </div>
  )
}

export function DocsSidebar({
  open,
  onClose,
}: {
  open: boolean
  onClose: () => void
}) {
  const pathname = usePathname()

  useEffect(() => {
    if (!open) return
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") onClose()
    }
    window.addEventListener("keydown", onKeyDown)
    return () => window.removeEventListener("keydown", onKeyDown)
  }, [open, onClose])

  return (
    <>
      {open ? (
        <div
          onClick={onClose}
          aria-hidden
          className="fixed inset-0 z-40 bg-background/80 backdrop-blur-sm lg:hidden"
        />
      ) : null}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-50 w-64 shrink-0 -translate-x-full overflow-y-auto border-r border-border bg-background px-3 py-6 transition-transform duration-200 lg:sticky lg:top-14 lg:z-0 lg:h-[calc(100vh-3.5rem)] lg:translate-x-0 lg:bg-transparent",
          open && "translate-x-0"
        )}
      >
        <nav className="flex flex-col gap-6">
          {NAV.map((group) => (
            <SidebarGroup
              key={group.label}
              group={group}
              pathname={pathname}
              onNavigate={onClose}
            />
          ))}
        </nav>
      </aside>
    </>
  )
}
