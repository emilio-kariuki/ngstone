import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"

export const metadata: Metadata = {
  title: "GitHub Actions",
  description: "Expose CI services through a TTL-bound ngstone preview tunnel.",
}

const TOC: TocItem[] = [
  { id: "short-lived-credentials", title: "Short-lived credentials" },
  { id: "command-workflow", title: "Command workflow" },
  { id: "inputs-and-outputs", title: "Inputs and outputs" },
  { id: "security", title: "Security" },
]

export default function GitHubActionsPage() {
  return (
    <DocsArticle href="/docs/guides/github-actions" toc={TOC}>
      <h1>GitHub Actions</h1>
      <p>
        The repository includes a reusable action that downloads a release,
        verifies its checksum, starts an ngstone agent, and waits for its
        public URL. It is designed for preview environments and end-to-end
        tests that need a real public hostname. The recommended mode issues a
        unique credential for the workflow run and revokes it during the
        action post step.
      </p>

      <Anchor id="short-lived-credentials">Short-lived credentials</Anchor>
      <p>
        Give the action a management API URL and bearer token. When{" "}
        <code>subdomain</code> is empty, it generates a run-specific DNS label.
        The post-job cleanup stops the process and revokes the credential even
        when a later workflow step fails:
      </p>
      <CodeBlock
        language="yaml"
        code={`- uses: emilio-kariuki/ngstone@v0.3.2
  id: tunnel
  with:
    target: 3000
    admin-server: https://edge.example.com:4041
    admin-token: \${{ secrets.NGSTONE_ADMIN_TOKEN }}
    ttl: 20m`}
      />

      <Anchor id="command-workflow">Command workflow</Anchor>
      <p>
        A command can run while the tunnel is alive. The action writes{" "}
        <code>NGSTONE_URL</code>,{" "}
        <code>NGSTONE_PID</code>, and <code>NGSTONE_LOG</code> to the job
        environment, then its post step performs cleanup:
      </p>
      <CodeBlock
        language="yaml"
        code={`- uses: emilio-kariuki/ngstone@v0.3.2
  id: tunnel
  with:
    target: 3000
    admin-server: https://edge.example.com:4041
    admin-token: \${{ secrets.NGSTONE_ADMIN_TOKEN }}
    ttl: 20m
    command: npm run e2e -- --base-url "$NGSTONE_URL"`}
      />

      <Anchor id="inputs-and-outputs">Inputs and outputs</Anchor>
      <p>
        <code>target</code> is required. Use <code>admin-server</code> and{" "}
        <code>admin-token</code> for automatic per-run credentials; the legacy{" "}
        <code>token</code> input remains as a compatibility fallback.{" "}
        <code>server</code>, <code>server-name</code>, <code>subdomain</code>,
        <code>transport</code>, <code>host-header</code>, <code>ttl</code>,{" "}
        <code>version</code>, and{" "}
        <code>wait-timeout</code> customize the tunnel. The public URL is
        available as <code>steps.tunnel.outputs.url</code> and{" "}
        <code>NGSTONE_URL</code>.
      </p>

      <Anchor id="security">Security</Anchor>
      <Callout variant="warning" title="Keep management credentials secret">
        Store the management token in GitHub Actions secrets. Pin the action to
        a release tag or commit, do not include credentials in{" "}
        <code>command</code> or logs, and remember that the preview URL is
        public while the tunnel is alive. The TTL limits a leaked or abandoned
        runner. The legacy <code>token</code> input is long-lived and does not
        receive automatic revocation.
      </Callout>
    </DocsArticle>
  )
}
