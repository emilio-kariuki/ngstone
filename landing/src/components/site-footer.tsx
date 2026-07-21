const LINKS = [
  { href: "#", label: "Docs" },
  { href: "#", label: "GitHub" },
  { href: "#", label: "Architecture" },
];

export function SiteFooter() {
  return (
    <footer className="border-t border-border">
      <div className="mx-auto flex max-w-6xl flex-col items-center gap-6 px-6 py-12 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <a
            href="#"
            className="flex items-center gap-1.5 text-lg font-semibold tracking-tight text-foreground"
          >
            ngstone
            <span className="text-primary">.</span>
          </a>
          <p className="mt-2 max-w-xs text-sm text-muted-foreground">
            Your own tunnel. Your own domain. Self-hosted, from the edge on
            down.
          </p>
        </div>

        <nav className="flex gap-6 text-sm text-muted-foreground">
          {LINKS.map((link) => (
            <a
              key={link.label}
              href={link.href}
              className="transition-colors hover:text-foreground"
            >
              {link.label}
            </a>
          ))}
        </nav>
      </div>
    </footer>
  );
}
