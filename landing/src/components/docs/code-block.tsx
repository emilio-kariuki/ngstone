import { cn } from "@/lib/utils"
import { CopyButton } from "@/components/docs/copy-button"

export function CodeBlock({
  code,
  language,
  filename,
  showLineNumbers = false,
}: {
  code: string
  language?: string
  filename?: string
  showLineNumbers?: boolean
}) {
  const lines = code.replace(/\n$/, "").split("\n")

  return (
    <div className="group relative my-6 overflow-hidden rounded-lg border border-border bg-card">
      {filename ? (
        <div className="flex items-center justify-between border-b border-border bg-background/40 px-4 py-2 font-mono text-xs text-muted-foreground">
          <span>{filename}</span>
          {language ? <span className="text-muted-foreground/70">{language}</span> : null}
        </div>
      ) : null}
      <div className="relative">
        <pre
          data-language={language}
          className="overflow-x-auto px-4 py-4 font-mono text-sm leading-relaxed text-foreground/90"
        >
          <code>
            {lines.map((line, index) => (
              <div key={index} className={cn(showLineNumbers && "flex gap-4")}>
                {showLineNumbers ? (
                  <span className="select-none text-right text-muted-foreground/50" style={{ minWidth: `${String(lines.length).length}ch` }}>
                    {index + 1}
                  </span>
                ) : null}
                <span className="flex-1 whitespace-pre">{line || " "}</span>
              </div>
            ))}
          </code>
        </pre>
        <CopyButton code={code} />
      </div>
    </div>
  )
}
