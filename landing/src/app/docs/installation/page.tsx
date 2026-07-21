import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { CodeBlock } from "@/components/docs/code-block"
import { CodeGroup } from "@/components/docs/code-group"
import { DocsArticle } from "@/components/docs/docs-article"

export const metadata: Metadata = {
  title: "Installation",
  description: "Install the agent, and build the edge from source.",
}

const TOC: TocItem[] = [
  { id: "requirements", title: "Requirements" },
  { id: "installing-the-agent", title: "Installing the agent" },
  { id: "installing-the-edge", title: "Installing the edge (VPS)" },
  { id: "building-from-source", title: "Building from source" },
  { id: "verifying", title: "Verifying the install" },
]

export default function InstallationPage() {
  return (
    <DocsArticle href="/docs/installation" toc={TOC}>
      <h1>Installation</h1>
      <p>
        ngstone is one Go module producing two binaries with different
        install stories. The agent (<code>ngstone</code>) has prebuilt
        installs for macOS and Linux. The edge (<code>ngstoned</code>) is
        server infrastructure you build and deploy deliberately — it is
        not something to curl-pipe onto a box.
      </p>

      <Anchor id="requirements">Requirements</Anchor>
      <p>
        Installing the agent via Homebrew or the install script needs
        nothing but the internet — no Go toolchain required. Building
        either binary from source needs Go 1.25; both{" "}
        <code>cmd/ngstoned</code> and <code>cmd/ngstone</code> live in the
        same module, so a single <code>go build</code> invocation per
        binary is all the toolchain you need.
      </p>

      <Anchor id="installing-the-agent">Installing the agent</Anchor>
      <p>
        Two installers are verified working today, both installing just
        the <code>ngstone</code> binary:
      </p>
      <CodeGroup
        tabs={[
          {
            label: "Homebrew",
            language: "bash",
            code: `$ brew install emilio-kariuki/tap/ngstone`,
          },
          {
            label: "curl",
            language: "bash",
            code: `$ curl -fsSL https://raw.githubusercontent.com/emilio-kariuki/ngstone/main/install.sh | sh`,
          },
        ]}
      />
      <Callout variant="note" title="brew install ngstone (short form)">
        <p>
          The short form without the full tap path requires tapping and
          trusting the tap first — Homebrew 6 requires explicit trust for
          third-party taps:
        </p>
        <CodeBlock
          language="bash"
          code={`$ brew tap emilio-kariuki/tap
$ brew trust emilio-kariuki/tap
$ brew install ngstone`}
        />
      </Callout>
      <p>
        The install script detects OS and architecture, downloads the
        matching release binary from{" "}
        <a href="https://github.com/emilio-kariuki/ngstone">
          github.com/emilio-kariuki/ngstone
        </a>{" "}
        (currently <code>v0.1.0</code>), and installs it — no Go toolchain
        touched. Override the version or install directory with the{" "}
        <code>NGSTONE_VERSION</code> and <code>NGSTONE_INSTALL_DIR</code>{" "}
        environment variables.
      </p>

      <Anchor id="installing-the-edge">Installing the edge (VPS)</Anchor>
      <p>
        <code>ngstoned</code> isn&apos;t distributed as a release binary or
        a package — it&apos;s built and copied to the VPS deliberately.
        Cross-compile it for <code>linux/amd64</code> and copy it over, or
        build directly on the VPS if you&apos;d rather not cross-compile.
        It has no install-time dependencies beyond the binary itself and a
        place to keep its certificate cache. See{" "}
        <a href="/docs/operations/deployment-systemd">
          Deployment &amp; systemd
        </a>{" "}
        for running it as a managed service.
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
            label: "Local build (both binaries)",
            language: "bash",
            code: `$ make build
$ ./bin/ngstone version
$ ./bin/ngstoned -version`,
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

      <Anchor id="verifying">Verifying the install</Anchor>
      <p>
        Both binaries embed a version string injected at build time via{" "}
        <code>-ldflags</code>. Confirm a build or install worked with:
      </p>
      <CodeBlock language="bash" code={`$ ngstone version
ngstone v0.1.0 (commit 3f1a9c2, built 2026-06-01T12:00:00Z)`} />
    </DocsArticle>
  )
}
