import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "Webhook verification",
  description:
    "Reject unsigned or badly signed Stripe, GitHub, Slack and HMAC webhooks at the edge.",
}

const TOC: TocItem[] = [
  { id: "quick-start", title: "Quick start" },
  { id: "providers", title: "Providers" },
  { id: "flags", title: "Flags" },
  { id: "project-files", title: "Project files" },
  { id: "rejections", title: "What gets rejected" },
  { id: "security-notes", title: "Security notes" },
]

export default function WebhookVerificationPage() {
  return (
    <DocsArticle href="/docs/guides/webhook-verification" toc={TOC}>
      <h1>Webhook verification</h1>
      <p>
        Webhook testing is one of the most common reasons to open a tunnel,
        and a public webhook URL accepts requests from anyone. With{" "}
        <code>--verify-webhook</code> the edge checks the provider&apos;s
        HMAC-SHA256 signature on every request before forwarding it, so a
        forged or replayed delivery is answered with <code>401</code> and
        never reaches your local app.
      </p>

      <Anchor id="quick-start">Quick start</Anchor>
      <CodeBlock
        language="bash"
        code={`$ export NGSTONE_WEBHOOK_SECRET=whsec_...
$ ngstone port 3000 --verify-webhook stripe --verify-webhook-path /webhooks/stripe`}
      />
      <p>
        Or keep the secret in a file readable only by you:
      </p>
      <CodeBlock
        language="bash"
        code={`$ chmod 600 github.secret
$ ngstone port 3000 --verify-webhook github --verify-webhook-secret-file github.secret`}
      />
      <p>
        The secret is never accepted as a flag value, so it does not show
        up in <code>ps</code> output, and it is never printed in logs,{" "}
        <code>--json</code> events, <code>ngstone ps</code>, HAR exports,
        the edge dashboard or the admin API. Operators only see which
        provider a tunnel verifies.
      </p>

      <Anchor id="providers">Providers</Anchor>
      <ParamTable>
        <Property name="stripe" type="Stripe-Signature">
          Signs <code>timestamp.body</code>; any <code>v1</code> entry may
          match. The <code>t=</code> timestamp must be within the tolerance
          (default 5 minutes).
        </Property>
        <Property name="github" type="X-Hub-Signature-256">
          <code>sha256=</code> followed by the hex HMAC of the body.
        </Property>
        <Property name="slack" type="X-Slack-Signature">
          Signs <code>v0:timestamp:body</code> using{" "}
          <code>X-Slack-Request-Timestamp</code>, which must be within the
          replay window (default 5 minutes).
        </Property>
        <Property name="hmac" type="configurable">
          HMAC-SHA256 of the raw body in a header you name, hex or base64,
          with an optional prefix such as <code>sha256=</code>. Covers
          Shopify, Twilio-style and in-house senders.
        </Property>
      </ParamTable>
      <CodeBlock
        language="bash"
        code={`$ ngstone port 3000 --verify-webhook hmac \\
    --verify-webhook-header X-Shopify-Hmac-Sha256 \\
    --verify-webhook-encoding base64 \\
    --verify-webhook-secret-file shopify.secret`}
      />

      <Anchor id="flags">Flags</Anchor>
      <ParamTable>
        <Property name="--verify-webhook" type="string">
          <code>stripe</code>, <code>github</code>, <code>slack</code> or{" "}
          <code>hmac</code>. HTTP tunnels only.
        </Property>
        <Property name="--verify-webhook-secret-file" type="string">
          File holding the signing secret. Falls back to{" "}
          <code>NGSTONE_WEBHOOK_SECRET</code>.
        </Property>
        <Property name="--verify-webhook-path" type="string" defaultValue="every request">
          Verify every request whose decoded, cleaned path contains this
          prefix starting at any <code>/</code>, ignoring case, so{" "}
          <code>/webhooks/stripe.json</code> and{" "}
          <code>/index.php/webhooks/stripe</code> are checked too. Paths the
          edge cannot classify (encoded slashes or backslashes, bad escapes,
          control bytes, backslashes, <code>;</code>) are always verified.
        </Property>
        <Property name="--verify-webhook-tolerance" type="duration" defaultValue="5m">
          Timestamp tolerance for <code>stripe</code> and <code>slack</code>.
        </Property>
        <Property name="--verify-webhook-header" type="string">
          Signature header for <code>hmac</code>.
        </Property>
        <Property name="--verify-webhook-encoding" type="string" defaultValue="hex">
          <code>hex</code> or <code>base64</code> for <code>hmac</code>.
        </Property>
        <Property name="--verify-webhook-prefix" type="string">
          Prefix before the signature for <code>hmac</code>, such as{" "}
          <code>sha256=</code>.
        </Property>
      </ParamTable>

      <Anchor id="project-files">Project files</Anchor>
      <p>
        <code>ngstone.json</code> and <code>ngstone.yml</code> take a{" "}
        <code>webhook</code> block on an HTTP tunnel. Use{" "}
        <code>secret_file</code> (relative to the project file, mode{" "}
        <code>0600</code>) or <code>secret_env</code>; with neither, the
        agent reads <code>NGSTONE_WEBHOOK_SECRET</code>.
      </p>
      <CodeBlock
        filename="ngstone.yml"
        language="yaml"
        code={`tunnels:
  payments:
    port: 3000
    subdomain: pay
    webhook:
      provider: stripe
      secret_file: stripe.secret
      path_prefix: /webhooks/stripe
      tolerance: 5m
  bot:
    port: 3001
    webhook:
      provider: slack
      secret_env: SLACK_SIGNING_SECRET`}
      />
      <CodeBlock
        filename="ngstone.json"
        language="json"
        code={`{
  "tunnels": {
    "hooks": {
      "target": "3000",
      "webhook": {"provider": "github", "secret_env": "GITHUB_WEBHOOK_SECRET", "path_prefix": "/github"}
    }
  }
}`}
      />

      <Anchor id="rejections">What gets rejected</Anchor>
      <p>
        The edge buffers the body (up to the smaller of its{" "}
        <code>-max-body-bytes</code> limit and 25 MiB), checks the
        signature with a constant-time comparison, then forwards the
        untouched body. Failures get a short plain-text reason:
      </p>
      <CodeBlock
        language="text"
        code={`401 webhook signature rejected: missing signature
401 webhook signature rejected: malformed signature
401 webhook signature rejected: invalid signature
401 webhook signature rejected: timestamp outside tolerance
413 request entity too large`}
      />
      <p>
        Rejections are counted in{" "}
        <code>ngstoned_rejected_webhook_signature_total</code>.
      </p>

      <Anchor id="security-notes">Security notes</Anchor>
      <Callout variant="warning" title="The edge holds the secret">
        Unlike basic auth, which only ever sends a digest, HMAC verification
        needs the signing secret itself, so the agent sends it to the edge
        over the TLS control channel when the tunnel binds. It lives only in
        the edge&apos;s memory and is not written to durable storage. Only
        use this with an edge you operate or trust.
      </Callout>
      <p>
        If you set a path prefix, requests whose path does not contain it
        are forwarded without a check. Leave it empty to verify everything
        the tunnel receives.
        With <code>--multi-connector</code>, every connector must present
        the same webhook settings and secret. An edge too old to verify
        webhooks makes the agent refuse to bind instead of opening an
        unprotected tunnel.
      </p>
    </DocsArticle>
  )
}
