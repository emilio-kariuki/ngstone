import type { ReactNode } from "react"
import { Children, isValidElement } from "react"

export function Step({
  children,
}: {
  title: string
  children: ReactNode
}) {
  return <>{children}</>
}

export function Steps({ children }: { children: ReactNode }) {
  const steps = Children.toArray(children).filter(isValidElement)

  return (
    <ol className="my-6 ml-4 flex flex-col gap-8 border-l border-border pl-6">
      {steps.map((step, index) => {
        const props = step.props as { title: string; children: ReactNode }
        return (
          <li key={index} className="relative">
            <span className="absolute -left-[2.05rem] flex h-8 w-8 items-center justify-center rounded-full border border-primary/30 bg-primary/10 font-mono text-sm text-primary">
              {index + 1}
            </span>
            <p className="font-medium text-foreground">{props.title}</p>
            <div className="docs-prose mt-2 [&>*:first-child]:mt-0">
              {props.children}
            </div>
          </li>
        )
      })}
    </ol>
  )
}
