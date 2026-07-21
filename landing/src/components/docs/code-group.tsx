"use client"

import { useState } from "react"

import { cn } from "@/lib/utils"
import { CopyButton } from "@/components/docs/copy-button"

export type CodeTab = {
  label: string
  code: string
  language?: string
  filename?: string
}

export function CodeGroup({ tabs }: { tabs: CodeTab[] }) {
  const [active, setActive] = useState(0)
  const tab = tabs[active]
  const lines = tab.code.replace(/\n$/, "").split("\n")

  return (
    <div className="my-6 overflow-hidden rounded-lg border border-border bg-card">
      <div className="flex overflow-x-auto border-b border-border">
        {tabs.map((t, index) => (
          <button
            key={t.label}
            type="button"
            onClick={() => setActive(index)}
            className={cn(
              "border-b-2 border-transparent px-4 py-2 font-mono text-xs whitespace-nowrap text-muted-foreground transition-colors",
              index === active && "border-b-primary text-primary"
            )}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div className="relative">
        {tab.filename ? (
          <div className="border-b border-border bg-background/40 px-4 py-2 font-mono text-xs text-muted-foreground">
            {tab.filename}
          </div>
        ) : null}
        <pre
          data-language={tab.language}
          className="overflow-x-auto px-4 py-4 font-mono text-sm leading-relaxed text-foreground/90"
        >
          <code>
            {lines.map((line, index) => (
              <div key={index}>{line || " "}</div>
            ))}
          </code>
        </pre>
        <CopyButton code={tab.code} />
      </div>
    </div>
  )
}
