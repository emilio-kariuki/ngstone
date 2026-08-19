# ngstone Docs — Build Spec (v1)

Target: add a Mintlify-style three-column `/docs` section to the existing `landing`
Next.js app. This spec is authoritative. The implementer makes no design decisions;
where a choice exists it is made below. Content facts come from
`/Users/mac/projects/ngstone/docs/ARCHITECTURE.md` (cited as §N). The example domain
is always `ngstone.site`. Never invent GitHub URLs, npm packages, pricing, or
testimonials — use `href="#"` where a real URL is unknown.

Hard constraints (project rules):
- **No comments in any source file** — no inline, block, doc, or TODO comments.
- Every nav item must resolve to a real page. `npm run build` and `npm run lint` must pass.
- No horizontal page overflow at any width; wide content scrolls inside its own container.
- Dark-only for v1 (see §2.5). Do not add a functional theme toggle.

---

## 1. Technical approach

### 1.1 Decision: pure-TSX route segments + reusable content primitives. Not MDX.

Reject `@next/mdx` for v1. Rationale:
- Next.js 16.2 runs **Turbopack by default** for `dev` and `build`. MDX requires wiring a
  loader/plugin through the Turbopack pipeline; `@next/mdx` + remark/rehype plugins are a
  recurring source of build breakage and version drift on Turbopack. `landing/AGENTS.md`
  explicitly warns this is "NOT the Next.js you know" — minimize surface that can break.
- Pure `.tsx` pages get full TypeScript type-checking on content and props, zero new
  dependencies, and no build-time content pipeline. The build stays green by construction.
- Content authored as JSX using the primitives below is just as mechanical to write as MDX,
  and prev/next + TOC data live in plain TS the compiler validates.

Trade-off accepted: authors write JSX (`<Callout>`, `<CodeBlock code={...}/>`) instead of
markdown prose. This is fine for a fixed 21-page set maintained in-repo.

### 1.2 Routing

- Shared shell: `src/app/docs/layout.tsx` (Server Component) → renders `<DocsShell>{children}</DocsShell>`.
- One directory per page, **static segments only** (never a `[slug]` dynamic route). Static
  segments avoid the Next 15/16 async-`params` change entirely (`params`/`searchParams` are
  Promises in a dynamic route and would have to be awaited — we sidestep it).
- Page files: `src/app/docs/<path>/page.tsx`, where `<path>` matches the `href` in the nav
  config (§4). Examples: `src/app/docs/introduction/page.tsx`,
  `src/app/docs/guides/websockets-sse/page.tsx`.
- `/docs` itself (`src/app/docs/page.tsx`) redirects to `/docs/introduction` via
  `import { redirect } from "next/navigation"; redirect("/docs/introduction");`.
- Each page exports Next `metadata` (`title`, `description`) — mechanical, values from §4.

### 1.3 TOC population

Per-page **explicit `toc` array**, not runtime DOM scraping. Each page declares:

```ts
const TOC: TocItem[] = [
  { id: "what-is-ngstone", title: "What is ngstone?" },
  { id: "the-two-binaries", title: "The two binaries" },
]
```

Reliable, SSR-friendly, no hydration/observer dependency for correctness. The heading
primitive (`<Anchor>`, §3) renders the matching `id`. Author keeps `toc` ids in sync with
`<Anchor id>` values (verification checklist §6 covers this).

### 1.4 Prev/next + breadcrumbs

Derived from the single nav config in `src/lib/docs-nav.ts`. Helpers:

```ts
export function flattenNav(): NavItem[]                         // groups → ordered flat list
export function getAdjacent(href: string): { prev?: NavItem; next?: NavItem }
export function getBreadcrumb(href: string): { group: string; title: string } | null
```

Each page passes its own `href` to `<DocsArticle href="/docs/...">`, which calls these.
All server-side; no `usePathname` needed for prev/next or breadcrumbs.

---

## 2. Design system (Mintlify layout, ngstone theme)

Reuse existing oklch tokens from `globals.css` (`--primary: oklch(0.72 0.17 52)`, stone
background `oklch(0.16 0.008 60)`, `--border oklch(0.93 0.01 75 / 0.09)`, `--muted-foreground`,
`--card`). Fonts already wired: `--font-display` (Fraunces), `--font-sans` (Instrument Sans),
`--font-mono` (JetBrains Mono).

### 2.1 Layout grid & breakpoints

Three columns on `xl`, two on `lg`, single (drawer) on `< lg`.

| Region | Width | Notes |
|---|---|---|
| Left sidebar | `16rem` (256px), fixed | Sticky, own scroll (`overflow-y-auto`), full viewport height minus top bar. Hidden `< lg`; becomes slide-in drawer. |
| Content column | `max-w-[46rem]` (~736px, ~72ch measure) | Centered in remaining space; horizontal padding `px-6 lg:px-10`. |
| Right TOC rail | `14rem` (224px), fixed | Sticky. Shown only on `xl`. Hidden `< xl`. |
| Top bar | full width, `h-14`, sticky `top-0` | Logo (→ `/`), search trigger, GitHub link (`href="#"`), mobile menu toggle (`< lg`). |

Breakpoints (Tailwind defaults): `lg` = 1024px, `xl` = 1280px.
- `< lg`: sidebar is a drawer toggled from the top bar; TOC hidden; content full width.
- `lg–xl`: sidebar + content, no TOC rail.
- `≥ xl`: all three columns.

Shell structure: top bar spans full width; below it a flex row `[sidebar][main]`, where
`main` renders `{children}` and each page's `<DocsArticle>` internally splits `[prose][toc]`.

Add layout width CSS vars to `globals.css` `@theme` or `:root` if convenient, but Tailwind
utility classes (`w-64`, `max-w-[46rem]`, `w-56`) are sufficient — prefer utilities, add no
new tokens unless a value repeats across ≥3 files.

### 2.2 Spacing scale

Use Tailwind's default scale. Vertical rhythm inside prose: paragraph `mt-4`, `h2` `mt-12
mb-4`, `h3` `mt-8 mb-3`, lists `mt-4 space-y-2`, block elements (callouts, code, tables)
`my-6`. Section content wrapped so first child has no top margin.

### 2.3 Prose typography (`.docs-prose`)

Do **not** add `@tailwindcss/typography` (keep deps frozen; build risk). Hand-roll a
`.docs-prose` component class in `globals.css` under `@layer components`, or apply utilities
directly in primitives. Rules:

- Body: `font-sans text-[0.95rem] leading-7 text-foreground/90`. Measure capped by column
  width (§2.1), ~72ch.
- `h1`: `font-display text-4xl font-medium tracking-tight` (matches landing `h2` treatment).
- `h2`: `font-display text-2xl font-medium tracking-tight`, top border optional (`border-t
  border-border pt-8`) for section separation — apply on `<Anchor as="h2">`.
- `h3`: `font-sans text-lg font-semibold`.
- Headings carry an `id` and a hover-revealed anchor link (§3 `<Anchor>`): a `#` glyph in
  `text-primary` appearing on `group-hover`.
- Links (inline): `text-primary underline underline-offset-4 decoration-primary/40
  hover:decoration-primary`.
- Inline code: `rounded bg-muted px-1.5 py-0.5 font-mono text-[0.85em] text-foreground`.
- Code blocks: see `<CodeBlock>` (§3) — not raw `<pre>`.
- Unordered list: `list-disc pl-5 marker:text-muted-foreground`; ordered: `list-decimal pl-5`.
- Blockquote: `border-l-2 border-primary/40 pl-4 text-muted-foreground italic`.
- Tables (raw prose tables): wrap in `overflow-x-auto`; `th` left-aligned
  `text-muted-foreground font-medium border-b border-border`; `td` `border-b border-border/60
  py-2`. Prefer `<ParamTable>` for parameter docs.
- `strong`: `font-semibold text-foreground`.

### 2.4 Color usage

- Callout accents keyed to variant (§3), each a tint of an existing token — no new palette.
- Sidebar active item: `bg-primary/10 text-primary` with a `2px` left indicator
  (`border-l-2 border-primary`); inactive `text-muted-foreground hover:text-foreground`.
- TOC active: `text-primary`; inactive `text-muted-foreground`.
- Ember accent (`--primary`) reserved for active/interactive state, links, and the logo dot —
  do not flood.

### 2.5 Light/dark decision — dark-only for v1

The app forces `.dark` on `<html>` in `layout.tsx`, and `:root` and `.dark` token blocks in
`globals.css` are **identical**. There is no theme infrastructure. Docs stay **dark-only**.
Do not add a functional theme toggle (would be dead UI). Author all primitives against the
existing tokens so a future light theme is a `globals.css` change only — never hardcode hex
or oklch literals in components; always reference tokens (`bg-card`, `text-muted-foreground`,
`border-border`, etc.). The top bar shows the search trigger and GitHub link only; no
sun/moon control.

---

## 3. Component / primitive API

All under `src/components/docs/`. Default is **Server Component**; `"use client"` is marked
explicitly and kept to the smallest leaf. Reuse `cn` from `@/lib/utils`. Reuse existing
`Badge` from `@/components/ui/badge` where noted.

### DocsShell — `"use client"` — `src/components/docs/docs-shell.tsx`
Owns mobile drawer open state (shared by top bar toggle + sidebar). Renders top bar, sidebar,
and `{children}`. `children` remain server-rendered (passed through).
```ts
function DocsShell({ children }: { children: React.ReactNode }): JSX.Element
```
Internals: `const [open, setOpen] = useState(false)`. Renders `<DocsTopBar onMenu={() => setOpen(true)} />`,
`<DocsSidebar open={open} onClose={() => setOpen(false)} />`, and the `[sidebar][main]` flex row.
Close drawer on route change (`usePathname` effect).

### DocsTopBar — client (part of shell) — inline in `docs-shell.tsx` or own file
```ts
function DocsTopBar({ onMenu }: { onMenu: () => void }): JSX.Element
```
Left: hamburger (`< lg` only, lucide `Menu`) + logo `ngstone` with `<span className="text-primary">.</span>`
linking to `/`. Right: `<DocsSearch />` trigger + GitHub link (`href="#"`,
`buttonVariants({ variant: "outline", size: "sm" })`, label "GitHub"). Sticky, `h-14`,
`border-b border-border bg-background/80 backdrop-blur-md`.

### DocsSidebar — `"use client"` — `src/components/docs/docs-sidebar.tsx`
```ts
function DocsSidebar({ open, onClose }: { open: boolean; onClose: () => void }): JSX.Element
```
- Reads `NAV` from `@/lib/docs-nav`. Renders each `NavGroup` as a labeled section
  (`text-xs font-medium uppercase tracking-wide text-muted-foreground`) with its items.
- Active item via `usePathname()` exact match (§2.4 styling), using `next/link`.
- Groups are collapsible (chevron); default all expanded. Collapse state local `useState`;
  the group containing the active route is always initially expanded.
- `< lg`: rendered as a fixed slide-in drawer with a backdrop; `open` controls visibility,
  backdrop click + `Esc` call `onClose`. `≥ lg`: static sticky column, `open` ignored.

### DocsSearch — `"use client"` — `src/components/docs/docs-search.tsx`
Minimal client-side filter over `flattenNav()` titles. Trigger button styled like a search
box (`text-muted-foreground`, magnifier icon, hint text "Search", right-aligned `⌘K` kbd).
Opens a Base UI `Dialog` (or a plain fixed overlay) listing filtered nav items as links;
selecting navigates and closes. No external index, no network. Keyboard: `⌘K`/`Ctrl-K` opens,
`Esc` closes, arrows optional.
```ts
function DocsSearch(): JSX.Element
```
(P0 requirement: functional title filter. Do not ship a dead placeholder box.)

### DocsArticle — server — `src/components/docs/docs-article.tsx`
Center prose column + right TOC rail + breadcrumbs + prev/next. The per-page wrapper.
```ts
function DocsArticle({
  href,
  toc,
  children,
}: {
  href: string
  toc: TocItem[]
  children: React.ReactNode
}): JSX.Element
```
Layout: a flex row `[article][toc]`. Article column `max-w-[46rem]`:
`<Breadcrumbs href={href} />`, then `<div className="docs-prose">{children}</div>`, then
`<PrevNext href={href} />`. TOC column (`hidden xl:block w-56`): `<TableOfContents items={toc} />`.

### Breadcrumbs — server — `src/components/docs/breadcrumbs.tsx`
```ts
function Breadcrumbs({ href }: { href: string }): JSX.Element
```
`Docs / <group> / <title>` from `getBreadcrumb(href)`; `text-sm text-muted-foreground`, last
crumb `text-foreground`. Separator lucide `ChevronRight` `size-3.5`.

### PrevNext — server — `src/components/docs/prev-next.tsx`
```ts
function PrevNext({ href }: { href: string }): JSX.Element
```
Two `next/link` cards from `getAdjacent(href)`; left = prev (← + title), right = next (title
+ →). Omit the missing side (first/last page). `border-t border-border mt-16 pt-8`, cards
`rounded-lg border border-border px-4 py-3 hover:bg-muted`.

### TableOfContents — `"use client"` — `src/components/docs/table-of-contents.tsx`
```ts
function TableOfContents({ items }: { items: TocItem[] }): JSX.Element
```
Sticky (`sticky top-20`), heading "On this page" (`text-xs uppercase tracking-wide
text-muted-foreground`), then anchor links `href={"#" + id}`. Active-on-scroll via
`IntersectionObserver` over the `id`s (client). If `items` is empty, render nothing.
(Scrollspy is the only reason this is client; static links would work without it, but the
active highlight is expected in the Mintlify pattern.)

### Callout — server — `src/components/docs/callout.tsx`
```ts
type CalloutVariant = "note" | "tip" | "warning" | "danger" | "info"
function Callout({
  variant = "note",
  title,
  children,
}: {
  variant?: CalloutVariant
  title?: string
  children: React.ReactNode
}): JSX.Element
```
Left-accent card `border-l-4 rounded-md p-4 my-6`. Variant → accent color + lucide icon:
- `note` → `Info`, border/icon `text-muted-foreground`, `bg-muted/40`.
- `tip` → `Lightbulb`, `--primary` tint (`border-l-primary text-primary bg-primary/5`).
- `info` → `Info`, `--chart-2` tint (`border-l-[--chart-2]`), muted bg.
- `warning` → `TriangleAlert`, amber via `--primary` at higher chroma is not available; use
  `--primary` (ember) tint — acceptable since ember reads as warning; `bg-primary/5`.
- `danger` → `OctagonAlert`, `--destructive` (`border-l-destructive text-destructive
  bg-destructive/10`).
Title (optional) `font-semibold` in accent color; body `text-sm text-foreground/90`.

### CodeBlock — server — `src/components/docs/code-block.tsx` (+ CopyButton client leaf)
```ts
function CodeBlock({
  code,
  language,
  filename,
  showLineNumbers = false,
}: {
  code: string
  language?: string
  filename?: string
  showLineNumbers?: boolean
}): JSX.Element
```
- Server component. Optional filename bar (`border-b border-border bg-background/40 px-4 py-2
  font-mono text-xs text-muted-foreground`) reusing the terminal-window aesthetic
  (`@/components/terminal-window` is the visual reference).
- Body: `<pre className="overflow-x-auto ... font-mono text-sm leading-relaxed">` wrapping
  `<code>`. No syntax-highlighting library (keep deps frozen); render plain text. `language`
  is accepted, stored as a `data-language` attribute, and shown as a small label in the
  filename bar if present — no highlighter dependency.
- `showLineNumbers`: render a left gutter of line numbers (CSS counters or a mapped column).
- **Copy button is the only client boundary**: `<CopyButton code={code} />`
  (`"use client"`, own file `src/components/docs/copy-button.tsx`) — `navigator.clipboard.writeText`,
  swaps lucide `Copy` → `Check` for ~1.5s. Positioned top-right, `absolute`. CodeBlock stays
  a Server Component; only the button hydrates.
```ts
function CopyButton({ code }: { code: string }): JSX.Element
```

### CodeGroup — `"use client"` — `src/components/docs/code-group.tsx`
Tabbed multi-file / multi-command container.
```ts
type CodeTab = { label: string; code: string; language?: string; filename?: string }
function CodeGroup({ tabs }: { tabs: CodeTab[] }): JSX.Element
```
Tab strip (`border-b border-border`, active tab `text-primary border-b-2 border-primary`),
renders the active tab's code via the same visual as `CodeBlock`, each with its own copy
button. Client for tab state.

### Card + CardGrid — server — `src/components/docs/card.tsx`
Docs-specific cards (distinct from `@/components/ui/card`, which is heavier). Keep simple.
```ts
function Card({
  title,
  icon,
  href,
  children,
}: {
  title: string
  icon?: LucideIcon
  href?: string
  children?: React.ReactNode
}): JSX.Element
function CardGrid({
  columns = 2,
  children,
}: {
  columns?: 1 | 2 | 3
  children: React.ReactNode
}): JSX.Element
```
Card: `rounded-xl border border-border bg-card p-5 hover:border-primary/40 transition-colors`;
if `href`, whole card is a `next/link`. Optional `icon` in `text-primary` above the title
(`font-heading font-medium`), body `text-sm text-muted-foreground`. `LucideIcon` type from
`lucide-react`. CardGrid: `grid gap-4 sm:grid-cols-2` (or `columns` value), single column on
mobile.

### Steps + Step — server — `src/components/docs/steps.tsx`
```ts
function Steps({ children }: { children: React.ReactNode }): JSX.Element
function Step({ title, children }: { title: string; children: React.ReactNode }): JSX.Element
```
Vertical numbered list with a left connector line (`border-l border-border ml-4 pl-6`), each
step a numbered ember badge (reuse the quickstart badge look: `h-8 w-8 rounded-full border
border-primary/30 bg-primary/10 font-mono text-primary`). `Steps` auto-numbers children via
index. Title `font-medium text-foreground`, body prose below.

### ParamTable + Property — server — `src/components/docs/param-table.tsx`
Parameter / field reference (wire protocol, config, inspector API).
```ts
function ParamTable({ children }: { children: React.ReactNode }): JSX.Element
function Property({
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
  children?: React.ReactNode
}): JSX.Element
```
`ParamTable` renders a bordered container (`divide-y divide-border rounded-lg border
border-border`, `overflow-x-auto`). Each `Property` is a row: `name` in `font-mono
text-foreground`, `type` in `font-mono text-xs text-muted-foreground`, a `required` pill
(reuse `<Pill variant="danger">required</Pill>`), optional `defaultValue`
(`text-xs text-muted-foreground`, "default: …"), and `children` as the description.

### Pill — server — `src/components/docs/pill.tsx`
Thin wrapper over existing `Badge` for docs semantics (status labels: `GET`/`POST`, `required`,
version). Reuse `@/components/ui/badge`.
```ts
function Pill({
  variant = "default",
  children,
}: {
  variant?: "default" | "secondary" | "outline" | "danger" | "info"
  children: React.ReactNode
}): JSX.Element
```
Map `danger`→Badge `destructive`, `info`→a `--chart-2`-tinted custom class, others pass
through. Use for HTTP-method labels in the inspector-API page (`GET` outline, `POST` primary).

### Anchor — server — `src/components/docs/anchor.tsx`
Heading with `id` + hover anchor link. Replaces raw `<h2>`/`<h3>` in prose so `toc` ids match.
```ts
function Anchor({
  as = "h2",
  id,
  children,
}: {
  as?: "h2" | "h3"
  id: string
  children: React.ReactNode
}): JSX.Element
```
Renders the tag with `id`, `scroll-mt-24` (so sticky top bar doesn't cover it on jump), a
`group` wrapper, and a trailing `<a href={"#" + id}>` `#` that appears on `group-hover`
(`text-primary opacity-0 group-hover:opacity-100`). Typography per §2.3.

### Client/server summary
| Client (`"use client"`) | Server |
|---|---|
| DocsShell, DocsTopBar, DocsSidebar, DocsSearch, TableOfContents, CopyButton, CodeGroup | layout, DocsArticle, Breadcrumbs, PrevNext, Callout, CodeBlock, Card, CardGrid, Steps, Step, ParamTable, Property, Pill, Anchor, all pages |

---

## 4. Information architecture (the nav config — most important deliverable)

`src/lib/docs-nav.ts`:

```ts
export type TocItem = { id: string; title: string }
export type NavItem = { title: string; href: string; description: string }
export type NavGroup = { label: string; items: NavItem[] }
export const NAV: NavGroup[]
```

Full config (order is authoritative — drives sidebar order + prev/next chain). For each page:
**H1**, one-line description (also the page `metadata.description` and nav `description`),
ordered section headings (= the `toc`, each needs an `<Anchor id>`), and key content bullets
with §citations from `ARCHITECTURE.md`.

### Group: Getting Started

**1. Introduction** — `/docs/introduction`
- Desc: What ngstone is, and why it exists.
- Sections (toc): `what-is-ngstone` "What is ngstone?" · `the-two-binaries` "The two binaries" · `how-a-request-flows` "How a request flows" · `what-v1-covers` "What v1 covers" · `out-of-scope` "Out of scope"
- Content:
  - Personal, self-hosted ngrok replacement; two binaries `ngstoned` (edge, Linux VPS) and `ngstone` (agent + CLI + inspector, macOS), one shared Go module (§ preamble).
  - Agent always dials out (VPS never connects into the laptop — NAT-friendly, no inbound holes); one long-lived TLS TCP connection carries a yamux session; first stream is control, each request its own stream (§1).
  - HTTP/HTTPS tunnels only in v1; wire protocol shaped so raw TCP can be added later without a protocol bump (§ preamble, §3 raw-TCP note).
  - Guiding principles: stdlib-first, boring over clever, one path per feature, everything flow-controlled, nothing unbounded in memory (§ preamble).
  - Out of scope for v1: native gRPC/h2c backends, volumetric DDoS, VPS compromise, OAuth-grade auth in front of tunnels (§9). Use a `<CardGrid>` for the two binaries; `<Callout variant="info">` for out-of-scope.

**2. Quickstart** — `/docs/quickstart`
- Desc: From clone to a public URL in three commands.
- Sections: `prerequisites` "Prerequisites" · `start-the-edge` "Start the edge" · `set-your-token` "Set your token" · `start-tunneling` "Start tunneling" · `next-steps` "Next steps"
- Content:
  - Prerequisites: a Linux VPS, a domain with wildcard DNS (`*.ngstone.site` + apex A records → VPS), Go 1.25 to build (§4, §10 M3).
  - Start the edge: `ngstoned --domain ngstone.site --email you@ngstone.site` on the VPS (§4, §10 M3). Use `<Steps>`.
  - Set your token: edge prints a token on first boot; `export NGSTONE_TOKEN=...` where the agent runs (§4 token hygiene).
  - Start tunneling: `ngstone http 3000` → `https://amber-fox-42.ngstone.site`; `ngstone http 3000 --subdomain api` → `https://api.ngstone.site` (§3 Bind, §6). Use `<CodeBlock>`.
  - Next steps: link cards to Installation, Core Concepts, Request Inspector.

**3. Installation** — `/docs/installation`
- Desc: Build both binaries and put them where they run.
- Sections: `requirements` "Requirements" · `building-from-source` "Building from source" · `installing-the-edge` "Installing the edge (VPS)" · `installing-the-agent` "Installing the agent" · `verifying` "Verifying the install"
- Content:
  - Go 1.25; both binaries built from one module — `cmd/ngstoned` and `cmd/ngstone` (§ preamble, §7 layout).
  - `Makefile` targets: build, test, cross-compile `linux/amd64`, `deploy` (scp) (§7, §10 M6). Use `<CodeGroup>` for macOS build vs Linux cross-compile.
  - Edge runs on the Linux VPS, agent on the macOS dev machine (§ preamble).
  - Version string is `-ldflags`-injected; verify with `ngstone version` (§7 version, §10 M6).

**4. Core Concepts** — `/docs/core-concepts`
- Desc: The vocabulary — edge, agent, sessions, streams, bindings.
- Sections: `the-edge` "The edge (ngstoned)" · `the-agent` "The agent (ngstone)" · `sessions-and-streams` "Sessions and streams" · `bindings-and-registry` "Bindings and the registry" · `instance-identity` "Instance identity" · `the-inspector` "The inspector"
- Content:
  - Agent dials `ngstone.site:4443`; one yamux session per connection; a dedicated control stream plus one data stream per request (§1, §2).
  - `Binding` maps a hostname to the owning agent session; `Registry` is an `RWMutex` over a map with a `bySession` ownership index (§5).
  - `InstanceID` is a stable per-process identity that survives reconnects and authorizes takeover (§3).
  - One agent process = one tunnel + one inspector; multiple tunnels = multiple processes (§6). Use `<CardGrid>` for edge vs agent.

### Group: Guides

**5. Running the edge on a VPS** — `/docs/guides/edge-vps`
- Desc: Stand up ngstoned on a Linux server with TLS.
- Sections: `dns-setup` "DNS setup" · `acme-dns01` "ACME and DNS-01" · `starting-ngstoned` "Starting ngstoned" · `apex-vs-wildcard` "Apex vs wildcard certs" · `health-checks` "Health checks"
- Content:
  - Wildcard `*.ngstone.site` + apex `ngstone.site` A records → VPS IP.
  - DNS-01 challenge via a `libdns` provider (Cloudflare), scoped API token `Zone:DNS:Edit` on the one zone; wildcard certs are only issuable via DNS-01 (§4).
  - Two independent certs (wildcard + apex, two ACME orders, two renewal schedules); the apex cert serves `:4443` and a startup check gates `:4443` on a loadable apex cert (§4).
  - `/healthz` reports both certs' `NotAfter` separately; ops endpoint on `127.0.0.1:4041` (expvar, pprof, reach via `ssh -L`) (§5 listeners, §4). `<Callout variant="warning">` on the apex-cert-fails-but-wildcard-healthy trap. Link to Deployment & systemd.

**6. Exposing a local app** — `/docs/guides/expose-local-app`
- Desc: Forward a public URL to a port on your machine.
- Sections: `basic-usage` "Basic usage" · `how-forwarding-works` "How forwarding works" · `forwarded-headers` "Forwarded headers" · `the-host-header` "The Host header" · `app-not-running` "When the local app isn't running"
- Content:
  - `ngstone http 3000` forwards `https://<name>.ngstone.site` to `localhost:3000`.
  - Per-request: edge opens a yamux stream with a JSON preamble; agent forwards to the local app over a pooled keep-alive transport; bodies stream, never fully buffered (§1, §6).
  - `X-Forwarded-For`/`-Proto`/`-Host` are stamped at the edge and preserved by the agent, so the local app sees the real client IP (§5 header rewriting, §6, §9.5). `<Callout variant="note">` explaining the app can trust XFF.
  - `Host` is preserved by default (what OAuth callbacks / vhost routers expect); `--host-header=localhost:3000` rewrites it for picky apps (§5, §6).
  - Local dial failure → agent synthesizes a `502` with a helpful body ("nothing listening on localhost:3000") (§6).

**7. Custom subdomains** — `/docs/guides/custom-subdomains`
- Desc: Pick your own name instead of a random one.
- Sections: `random-vs-chosen` "Random vs chosen names" · `naming-rules` "Naming rules" · `reserved-names` "Reserved names" · `collisions-and-takeover` "Collisions and takeover"
- Content:
  - Default: server assigns a random name like `amber-fox-42`; `--subdomain api` requests a specific one (§3 Bind).
  - Naming rule: `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` (§3). Show as `<CodeBlock>`.
  - Denylist: `www`, `mail`, `ns1`, `ns2`, `admin`, `api-edge` (§3). Show as `<ParamTable>` or list.
  - Collision: a different, live instance requesting a held name gets `BindErr{subdomain_taken}` (agent exits non-zero for explicit names, or retries a fresh random name); same instance or a dead holder → takeover, old session receives `Evicted` (§3, §8). Link to Reconnection & takeover.

**8. Using the request inspector** — `/docs/guides/request-inspector`
- Desc: See every request and response at localhost:4040.
- Sections: `opening` "Opening the inspector" · `request-list` "The request list" · `inspecting` "Inspecting a request" · `bodies-truncation` "Bodies and truncation" · `live-view` "Live streaming view"
- Content:
  - Inspector binds `127.0.0.1:4040`; single embedded HTML file, vanilla JS + `EventSource` (§6 inspector). `--inspect-port` for a second tunnel.
  - Capture observes, never gates: up to 256 KiB of each body is teed into a ring buffer without blocking the stream (§6 capture).
  - `Content-Encoding` (gzip) is decoded for display; raw bytes kept for replay; binary bodies rendered as hex preview (§6).
  - Ring buffer holds 200 entries (overwrite-oldest); ~100 MiB worst case (§6 store).
  - `ReqID` (edge-minted ULID) joins each inspector entry to the edge's logs (§3, §6). Link to Inspector API + Replaying requests.

**9. Replaying requests** — `/docs/guides/replaying-requests`
- Desc: Re-send a captured request straight to your local app.
- Sections: `how-replay-works` "How replay works" · `replaying` "Replaying a request" · `edit-and-replay` "Edit and replay" · `limitations` "Limitations"
- Content:
  - Replay sends the reconstructed request **directly to the local app** through the pooled transport — not through the edge; deterministic, works offline, tests the app not the tunnel (§6 replay).
  - `POST /api/exchanges/{id}/replay`; result enters the store flagged `Replayed: true` (§6).
  - Edit & replay lets you tweak method / headers / body first (§6).
  - Truncated bodies → replay disabled with an explanatory tooltip (§6). Mutating endpoints require `X-Ngstone: 1` + an `Origin` check (§6, §9.6). `<Callout variant="tip">` on offline replay.

**10. WebSockets & SSE** — `/docs/guides/websockets-sse`
- Desc: Long-lived and streaming connections through the tunnel.
- Sections: `websocket-passthrough` "WebSocket passthrough" · `ws-over-h2` "WebSocket over HTTP/2" · `server-sent-events` "Server-Sent Events" · `in-the-inspector` "How they appear in the inspector"
- Content:
  - `ReverseProxy` handles `Connection: Upgrade` natively: completes the 101, then bidirectional-copies over the same per-request yamux stream, which lives as long as the socket (§5 WebSocket).
  - WS-over-h2 (RFC 8441 extended CONNECT) is not enabled; browsers fall back to HTTP/1.1 for WS automatically (§5). `<Callout variant="note">`.
  - SSE works via `FlushInterval: -1` — bytes flush as they arrive; `text/event-stream` is auto-detected (§1, §6).
  - WebSockets are finalized in the inspector at **101 time**, not at close, so the entry appears the instant the socket opens (§6, §10 M5).

**11. Streaming & large transfers** — `/docs/guides/streaming-large-transfers`
- Desc: Big uploads, downloads, and constant-memory forwarding.
- Sections: `backpressure` "Backpressure and flow control" · `constant-memory` "Constant memory" · `body-limits` "Body size limits" · `slow-app-timeouts` "Timeouts on slow apps"
- Content:
  - Both proxies are `io.Copy` loops over flow-controlled yamux streams; a slow browser backpressures all the way to the app's socket writes — no application-level buffering (§1, §2 backpressure).
  - Constant memory is asserted in CI (`runtime.MemStats`), e.g. a 1 GiB download / 100 MB streamed body (§10 M1, M4).
  - Body cap 256 MiB → `413`: declared-length pre-check (real 413), plus `MaxBytesReader` for chunked bodies (§5, §8). `<Callout variant="warning">` that a chunked 413 may have shipped a partial body.
  - `ResponseHeaderTimeout` 30 s → `504`; post-header duration is unlimited (downloads/SSE), bounded by client patience + flow control (§5 timeouts). yamux window 1 MiB; peak tunnel buffering 64 × 1 MiB = 64 MiB (§5 window budget). Link to Limits & timeouts.

### Group: Reference

**12. CLI** — `/docs/reference/cli`
- Desc: The ngstone command and its subcommands.
- Sections: `ngstone-http` "ngstone http" · `ngstone-token` "ngstone token" · `ngstone-version` "ngstone version" · `status-line` "Live status line"
- Content:
  - `ngstone` uses stdlib `flag`, three verbs `http | token | version`, no cobra (§7).
  - `ngstone http <port>` flags: `--subdomain`, `--host-header`, `--allow-cidr`, `--inspect-port`, `--pin` (§6, §5, §4, §10 M6). Use `<ParamTable>`.
  - `ngstone token new` → 32 random bytes, base64url; also `ngstone version` prints the ldflags version (§4, §7).
  - Live status line is driven by session-state events (dialing / connected / URL / reconnecting) (§6 status, §10 M6). Show example output in `<CodeBlock>`.

**13. Configuration** — `/docs/reference/configuration`
- Desc: Flags and environment for both binaries.
- Sections: `agent-config` "Agent (ngstone)" · `edge-config` "Edge (ngstoned)" · `environment` "Environment variables" · `precedence` "Precedence"
- Content:
  - No config-file dependency in v1 — flags + env only for both binaries (`internal/config`) (§7 config).
  - Agent: `NGSTONE_TOKEN` (env), `--subdomain`, `--host-header`, `--allow-cidr`, `--inspect-port`, `--pin sha256/BASE64` (§4, §6). `<ParamTable>`.
  - Edge: `--domain`, `--email`, `token_sha256` (config), all §5 limits are flag-overridable (§5, §4). `<ParamTable>`.
  - Secrets are never passed as `ExecStart` flags (`/proc/<pid>/cmdline` is world-readable) — use `EnvironmentFile=` (§10 M3). `<Callout variant="danger">`.

**14. The wire protocol** — `/docs/reference/wire-protocol`
- Desc: Framing, control messages, and versioning.
- Sections: `framing` "Framing & encoding" · `envelope` "The message envelope" · `handshake` "Handshake" · `tunnel-lifecycle` "Tunnel lifecycle" · `liveness-shutdown` "Liveness & shutdown" · `stream-preamble` "Stream preamble" · `versioning` "Versioning"
- Content:
  - Framing: `uint32` big-endian payload length + JSON, max frame 64 KiB; data streams carry raw HTTP/1.1 bytes after the preamble — JSON never touches the hot path (§3 framing). `<CodeBlock>` for the frame diagram.
  - Envelope `Msg{ Type, ID, Data }`; per-direction ID spaces (agent odd, edge even) so both peers can initiate; replies echo the request's `ID` (§3 envelope + reply-correlation rule). `<CodeBlock>` for the struct.
  - Handshake `Auth`/`AuthOK`/`AuthErr` (token, `InstanceID`, `ClientVersion`, `ProtoVersions`); first message must be `Auth` within 5 s or the edge closes (§3). `<CodeBlock>`.
  - Tunnel lifecycle `Bind`/`BindOK`/`BindErr`/`Unbind`/`UnbindOK`/`Evicted` (§3). Use `<ParamTable>` for each struct's fields.
  - Liveness `Ping`/`Pong` every 15 s, 3 misses → dead; graceful `Goodbye` (fire-and-forget, `drain_ms`) (§3). `StreamOpen` preamble: `Kind`, `Host`, `ReqID`, `ClientAddr` (§3 preamble).
  - Versioning: single integer major; server picks the max mutual in `AuthOK`; additive JSON fields never bump the version; unknown type/malformed frame → `Error` then close (§3 versioning).

**15. TLS & certificates** — `/docs/reference/tls-certificates`
- Desc: How ngstone issues and serves certificates.
- Sections: `certmagic-dns01` "certmagic + DNS-01" · `two-certificates` "Two certificates" · `control-plane-tls` "Control-plane TLS" · `agent-verification` "Agent verification & pinning" · `storage` "Storage"
- Content:
  - `caddyserver/certmagic` with DNS-01 via `libdns/cloudflare`; wildcard `*.ngstone.site` is only issuable via DNS-01 and keeps tunnel names out of CT logs (§4).
  - Two independent certs: `*.ngstone.site` and apex `ngstone.site` are two separate ACME orders with independent renewals; a wildcard does not match SNI `ngstone.site` (§4). `<Callout variant="warning">` on staggering renewals / shared `_acme-challenge` TXT.
  - `:4443` is served by the **apex** cert; the agent connects to `ngstone.site:4443` (§4).
  - Agent verification: WebPKI (`ServerName: ngstone.site`, system roots); optional SPKI pin via `--pin sha256/BASE64` in addition to chain validation, off by default (§4). Auth is the bearer token, not mTLS (§4).
  - Storage: `FileStorage{Path: "/var/lib/private/ngstoned/certs"}`, dir `0700`; pin `certmagic` + `libdns/cloudflare` to exact versions (§4). `<Callout variant="danger">` on `go get -u` taking the edge down.

**16. Limits & timeouts** — `/docs/reference/limits-timeouts`
- Desc: Every cap the edge enforces.
- Sections: `http-timeouts` "HTTP server timeouts" · `body-limits` "Body limits" · `rate-limiting` "Rate limiting" · `concurrency-window` "Concurrency & the window budget" · `control-plane-caps` "Control-plane caps"
- Content (present the §5 table as `<ParamTable>`s, exact values, no invention):
  - `ReadHeaderTimeout` 10 s, `IdleTimeout` 120 s, `MaxHeaderBytes` 64 KiB, `ResponseHeaderTimeout` 30 s → 504, dial-to-agent 5 s → 502, post-header duration unlimited (§5 table).
  - Body cap 256 MiB → 413 (declared pre-check + chunked `MaxBytesReader`) (§5).
  - Per-IP 20 req/s burst 50, LRU of 10k IPs → 429 (§5).
  - Global in-flight 64, per-session concurrent streams 48, `AcceptBacklog` 512 (above both caps); peak tunnel buffering 64 × 1 MiB = 64 MiB per side — the largest buffer in the system (§5 window budget). `<Callout variant="info">` on why AcceptBacklog is not the concurrency cap.
  - `:4443` caps: 16 concurrent TLS handshakes, 32 unauthenticated sessions; auth attempts 5/IP/min (§5, §3).

**17. The inspector API** — `/docs/reference/inspector-api`
- Desc: The HTTP API behind localhost:4040.
- Sections: `endpoints` "Endpoints" · `exchange-schema` "Exchange schema" · `sse-events` "SSE events" · `security` "Security"
- Content:
  - Endpoints (`<Pill>` method labels): `GET /api/exchanges`, `GET /api/exchanges/{id}`, `POST /api/exchanges/{id}/replay`, `GET /api/events` (SSE), `GET /api/status` (§6).
  - `Exchange` schema: `ID`, `ReqID`, `Kind` (`http`|`upgrade`), `Start`, `Duration`, `Req`, `Resp`, `Replayed`, `Err` (§6 store). `<ParamTable>`.
  - SSE: `GET /api/events` fans out new exchanges; slow subscribers are dropped, never block; a WebSocket appears at 101 connect time (§6).
  - Security: loopback-only bind; mutating endpoints require header `X-Ngstone: 1` + `Origin`/`Host` validation (kills CSRF + DNS rebinding) (§6, §9.6). `<Callout variant="note">`.

### Group: Operations

**18. Deployment & systemd** — `/docs/operations/deployment-systemd`
- Desc: Run ngstoned as a managed service.
- Sections: `the-unit` "The systemd unit" · `dynamicuser-statedirectory` "DynamicUser & StateDirectory" · `binding-443` "Binding to port 443" · `secrets` "Secrets" · `restart-behavior` "Restart behavior"
- Content:
  - `DynamicUser=yes` + `StateDirectory=ngstoned`: systemd creates the dir under `/var/lib/private/` and re-chowns it to the transient UID on every start, so the cert cache survives restarts (§10 M3). `<CodeBlock filename="ngstoned.service">` a full unit.
  - Reference `${STATE_DIRECTORY}/certs`, never a hardcoded `/var/lib/private/...` path (§10 M3).
  - `AmbientCapabilities=CAP_NET_BIND_SERVICE` composes with `DynamicUser=yes` and `NoNewPrivileges=yes` (§10 M3).
  - Secrets via `EnvironmentFile=` (`NGSTONE_TOKEN`), never `ExecStart` flags (§10 M3). `<Callout variant="danger">`.
  - `Restart=always` → typically < 2 s recovery; cached certs mean zero ACME traffic on restart (§8, §10 M3).

**19. Reconnection & takeover** — `/docs/operations/reconnection-takeover`
- Desc: How tunnels survive sleeps, blips, and restarts.
- Sections: `instance-identity` "Instance identity" · `takeover-rules` "The takeover rules" · `reconnect-backoff` "Reconnect backoff" · `dead-peer-detection` "Dead-peer detection" · `zombie-bindings` "Zombie bindings"
- Content:
  - `InstanceID` is minted once per agent process, survives reconnects, dies with the process; a restarted agent gets a new one (§3, §8).
  - Takeover authorized by identity, not liveness: (a) same `InstanceID` → immediate takeover; (b) different `InstanceID` + dead holder → takeover; (c) different `InstanceID` + live holder → `subdomain_taken` (§3). `<Steps>` or `<ParamTable>`.
  - Reconnect: decorrelated-jitter backoff 500 ms → 30 s cap; the agent always sends `Takeover: true`, so rule (a) makes reconnect-after-partition instant rather than waiting out the 45 s dead-peer window (§2, §3).
  - Dead-peer detection: yamux keepalive every 10 s + control-stream `Ping` every 15 s, 3 misses ≈ 45 s; `ConnectionWriteTimeout` 45 s is a session kill switch, deliberately not tight (§2, §3). `<Callout variant="warning">` on the 10 s trap.
  - Zombie bindings: `ReleaseSession` compare-and-deletes and is idempotent, avoiding a dying session deleting the new owner's binding (§5, §11).

**20. Failure modes & recovery** — `/docs/operations/failure-modes`
- Desc: What breaks, how it's detected, what happens.
- Sections: `agent-dies` "Agent dies mid-request" · `edge-restarts` "Edge restarts" · `network-partition` "Network partition" · `slow-app` "Slow or hung local app" · `oversized-bodies` "Oversized request bodies" · `cert-failure` "Certificate issuance failure"
- Content (mirror the §8 table; a `<ParamTable>` or `<Callout>` per row):
  - Agent dies mid-request → in-flight `502`, then cheap `404`; no replay (edge can't know idempotency) (§2, §8).
  - Edge restarts → agent backoff-reconnects, re-`Auth`s, re-`Bind`s with `Takeover: true`, same URL, typically < 2 s (§8).
  - Network partition → the agent does not wait for the 45 s window; unchanged `InstanceID` triggers takeover rule (a), zombie is `Evicted` and force-closed (§8).
  - Slow/hung app → `504` at `ResponseHeaderTimeout` 30 s; session unaffected (§8).
  - Oversized body → `413` (declared or chunked path) (§5, §8).
  - Apex cert fails → public traffic keeps working on the wildcard while no agent can connect; `ngstoned` refuses `:4443` without a loadable apex cert and exits loudly (§4, §8). `<Callout variant="warning">`.

**21. Security model** — `/docs/operations/security-model`
- Desc: The threat model, and what the token does and doesn't grant.
- Sections: `assets` "Assets" · `anonymous-attacker` "Anonymous attacker" · `leaked-token` "Leaked token" · `header-spoofing` "Header spoofing" · `inspector-csrf` "Inspector CSRF & DNS rebinding" · `resource-exhaustion` "Resource exhaustion" · `out-of-scope` "Out of scope"
- Content:
  - Assets: the laptop's local app + LAN foothold, the auth token, the wildcard domain's reputation, tunneled request/response data (§9).
  - Anonymous attacker with the URL is just an HTTP client of the exposed app — no inspector (loopback), no other localhost ports, no control plane (token-gated); residual risk is inherent to tunneling (§9.1).
  - Leaked token grants: bind non-denylisted subdomains, receive that traffic, serve phishing under your domain. Does not grant: reading other tunnels' traffic, edge shell, cert/DNS control. Rotate = new `token_sha256` + restart (§9.3, §8). `<Callout variant="danger">`.
  - Header spoofing: inbound `Forwarded`/`X-Forwarded-*` stripped and re-stamped at the edge; `X-Real-IP` stripped explicitly; the agent preserves them so the app can trust them (§9.5).
  - Inspector CSRF / DNS rebinding: mutating endpoints require the `X-Ngstone` custom header + Origin/Host validation (§9.6).
  - Resource exhaustion: every buffer has a stated cap including yamux receive windows; the `:4443` unauthenticated surface is separately capped (§9.7).
  - Out of scope: native gRPC/h2c, volumetric DDoS beyond VPS capacity, VPS compromise, OAuth-grade tunnel auth (§9).

**Total: 21 pages** across 4 groups (Getting Started 4, Guides 7, Reference 6, Operations 4).

---

## 5. Header / nav integration

- Landing `src/components/site-header.tsx`: add `{ href: "/docs", label: "Docs" }` to
  `NAV_LINKS`. That map renders `<a>` — acceptable for `/docs` (full nav), but prefer a
  `next/link` for this one item to keep client-side navigation. The hash links stay `<a>`.
  Keep the "View on GitHub" button `href="#"`.
- Docs get their **own** header (`DocsTopBar` inside `DocsShell`); the landing `SiteHeader`
  is **not** rendered in `/docs` (the docs `layout.tsx` owns its chrome). This is the
  Mintlify pattern and avoids the landing header's scroll-hash behavior in docs.
- Reuse: logo mark markup (`ngstone` + ember dot), `buttonVariants` from
  `@/components/ui/button`, `Badge` from `@/components/ui/badge`, `cn`, `terminal-window`
  aesthetic for `CodeBlock` filename bars. Fonts/tokens come from the existing `globals.css`
  and `layout.tsx` (docs render inside the same root `<html className="dark">`).

---

## 6. Build / verification checklist

The implementer must satisfy all of:
1. No comments in any source file (project rule) — inline, block, doc, or TODO.
2. `npm run build` passes under Turbopack (Next 16.2). `npm run lint` passes (`eslint`).
3. Every `NAV` item's `href` resolves to a real `page.tsx`; `/docs` redirects to
   `/docs/introduction`. No 404 from any sidebar link, prev/next link, or breadcrumb.
4. Every page's `toc` id matches an `<Anchor id>` actually rendered on that page (no dead TOC
   links; no headings missing from the TOC).
5. `prev`/`next` chain is contiguous across all 21 pages in `NAV` order; first page has no
   prev, last page has no next.
6. Responsive: no horizontal page overflow at 360px, 768px, 1024px, 1280px. Code blocks,
   tables, and `ParamTable`s scroll inside their own `overflow-x-auto` container. Sidebar
   becomes a working drawer below `lg`; TOC hidden below `xl`.
7. `"use client"` appears only on the components listed in §3's client column; pages and the
   other primitives stay Server Components.
8. Copy-to-clipboard works in `CodeBlock`/`CodeGroup` (Copy → Check feedback).
9. No fabricated URLs, npm packages, pricing, or testimonials. Unknown external links are
   `href="#"`. All commands realistic and consistent: `ngstone http 3000`, `ngstoned`,
   `NGSTONE_TOKEN`, `*.ngstone.site` wildcard DNS, example domain `ngstone.site`,
   `ngstone token new`, `--subdomain api`.
10. Dark-only; no functional theme toggle; components reference tokens, never literal colors.
11. All content facts trace to `ARCHITECTURE.md` (§ citations above); do not introduce
    behavior not in that document.

---

## Notes for the implementer (not source comments)

- Author pages by composing primitives; a page is `export const metadata`, a local `TOC`
  array, and a default component returning `<DocsArticle href="..." toc={TOC}>…</DocsArticle>`.
- Keep `docs-nav.ts` the single source of truth; sidebar, breadcrumbs, prev/next, and search
  all read it. If a page exists but is not in `NAV`, it is orphaned (checklist item 3).
- `scroll-mt-24` on `<Anchor>` is required so anchor jumps clear the sticky top bar.
- Do not add dependencies. No MDX, no `@tailwindcss/typography`, no syntax highlighter. Only
  `lucide-react` (already present) for icons and Base UI (already present) if a Dialog is used
  for search.
```
