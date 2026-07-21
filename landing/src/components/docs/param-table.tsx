import type { ReactNode } from "react"

import { Pill } from "@/components/docs/pill"

export function ParamTable({ children }: { children: ReactNode }) {
  return (
    <div className="my-6 overflow-x-auto rounded-lg border border-border">
      <div className="divide-y divide-border">{children}</div>
    </div>
  )
}

export function Property({
  name,
  type,
  required = false,
  defaultValue,
  children,
}: {
  name: string
  type: string
  required?: boolean
  defaultValue?: string
  children?: ReactNode
}) {
  return (
    <div className="px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-sm text-foreground">{name}</span>
        <span className="font-mono text-xs text-muted-foreground">{type}</span>
        {required ? <Pill variant="danger">required</Pill> : null}
        {defaultValue ? (
          <span className="text-xs text-muted-foreground">default: {defaultValue}</span>
        ) : null}
      </div>
      {children ? (
        <div className="mt-1.5 text-sm text-muted-foreground">{children}</div>
      ) : null}
    </div>
  )
}
