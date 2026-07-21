import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { CodeBlock } from "@/components/docs/code-block"
import { CodeGroup } from "@/components/docs/code-group"
import { DocsArticle } from "@/components/docs/docs-article"

export const metadata: Metadata = {
  title: "Installation",
  description: "Build both binaries and put them where they run.",
}

const TOC: TocItem[] = [
  { id: "requirements", title: "Requirements" },
  { id: "building-from-source", title: "Building from source" },
  { id: "installing-the-edge", title: "Installing the edge (VPS)" },
  { id: "installing-the-agent", title: "Installing the agent" },
  { id: "verifying", title: "Verifying the install" },
]

export default function InstallationPage() {
  return (
    <DocsArticle href="/docs/installation" toc={TOC}>
      <h1>Installation</h1>
      <p>
        ngstone is one Go module producing two binaries. There&apos;s no
        package manager, no installer script, and no runtime dependency on
        Go once you&apos;ve built — just static binaries you copy where they
        run.
      </p>

      <Anchor id="requirements">Requirements</Anchor>
      <p>
        Go 1.25 to build. That&apos;s it — both <code>cmd/ngstoned</code> and{" "}
        <code>cmd/ngstone</code> live in the same module, so a single{" "}
        <code>go build</code> invocation per binary is all the toolchain you
        need. The Go toolchain only has to be present on whichever machine
        you build on; the compiled binaries carry no runtime dependency on
        it.
      </p>

      <Anchor id="building-from-source">Building from source</Anchor>
      <p>
        The <code>Makefile</code> wraps the common build targets: a local
        build, tests, a Linux/amd64 cross-compile for the VPS, and a{" "}
        <code>deploy</code> target that <code>scp</code>s the result over.
      </p>
      <CodeGroup
        tabs={[
          {
            label: "macOS (agent)",
            language: "bash",
            code: `$ make build
$ ./bin/ngstone version`,
          },
          {
            label: "Linux cross-compile (edge)",
            language: "bash",
            code: `$ GOOS=linux GOARCH=amd64 make build
$ make deploy   # scp the binary to the VPS`,
          },
        ]}
      />
      <p>
        <code>make deploy</code> is the fast path from a source change to a
        binary sitting on the VPS, ready for a systemd restart.
      </p>

      <Anchor id="installing-the-edge">Installing the edge (VPS)</Anchor>
      <p>
        <code>ngstoned</code> runs on the Linux VPS. Cross-compile it for{" "}
        <code>linux/amd64</code> and copy it over, or build directly on the
        VPS if you&apos;d rather not cross-compile. It has no install-time
        dependencies beyond the binary itself and a place to keep its
        certificate cache.
      </p>

      <Anchor id="installing-the-agent">Installing the agent</Anchor>
      <p>
        <code>ngstone</code> runs on your macOS dev machine — it&apos;s the
        agent, the CLI, and the local inspector all in one binary. Build it
        locally with <code>make build</code> and drop it somewhere on your{" "}
        <code>PATH</code>.
      </p>

      <Anchor id="verifying">Verifying the install</Anchor>
      <p>
        Both binaries embed a version string injected at build time via{" "}
        <code>-ldflags</code>. Confirm a build worked with:
      </p>
      <CodeBlock language="bash" code={`$ ngstone version
ngstone/0.3.0 darwin/amd64`} />
    </DocsArticle>
  )
}
