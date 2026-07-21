import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "CLI",
  description: "The ngstone command and its subcommands.",
}

const TOC: TocItem[] = [
  { id: "overview", title: "Overview" },
  { id: "ngstone-auth", title: "ngstone auth" },
  { id: "ngstone-port", title: "ngstone port" },
  { id: "ngstone-config", title: "ngstone config" },
  { id: "ngstone-logout", title: "ngstone logout" },
  { id: "ngstone-version", title: "ngstone version" },
  { id: "no-args-and-help", title: "No arguments and -h" },
  { id: "generating-a-token", title: "Generating a token" },
  { id: "config-file", title: "The config file" },
  { id: "legacy-flags", title: "Legacy flag form" },
]

export default function CliPage() {
  return (
    <DocsArticle href="/docs/reference/cli" toc={TOC}>
      <h1>CLI</h1>
      <p>
        The <code>ngstone</code> command is built on the stdlib{" "}
        <code>flag</code> package — no cobra, no subcommand framework. There
        are five verbs: <code>auth</code>, <code>port</code>,{" "}
        <code>config</code>, <code>logout</code>, and <code>version</code>.
      </p>

      <Anchor id="overview">Overview</Anchor>
      <CodeBlock
        language="text"
        code={`ngstone <command> [arguments]

Commands:
  auth <token>       verify and save an auth token
  port <port|url>    expose a local port or URL through the tunnel
  config             view or set local configuration
  logout             remove the saved auth token
  version            print the ngstone version`}
      />

      <Anchor id="ngstone-auth">ngstone auth</Anchor>
      <p>
        Verifies a token against the edge&apos;s control plane, then saves the
        token and server address to the{" "}
        <a href="#config-file">config file</a>. Nothing is written to disk
        until the edge has confirmed the token is valid.
      </p>
      <CodeBlock language="bash" code={`$ ngstone auth <token>
verified against ngstone.site:4443 and saved`} />
      <ParamTable>
        <Property name="--server" type="string">
          Edge control-plane address to verify against. Defaults to the
          config file&apos;s saved server, or{" "}
          <code>ngstone.site:4443</code> if neither is set.
        </Property>
        <Property name="--insecure" type="bool" defaultValue="false">
          Dial the control plane in plaintext. Dev/test only — no
          certificate validation happens at all.
        </Property>
        <Property name="--server-name" type="string">
          TLS <code>ServerName</code>/SNI to verify against. Ignored with{" "}
          <code>--insecure</code>.
        </Property>
        <Property name="--pin" type="string">
          Optional SPKI pin, e.g. <code>--pin sha256/BASE64</code>, checked
          in addition to normal chain validation. Off by default.
        </Property>
      </ParamTable>
      <p>
        A bad token or an unreachable server exits non-zero with a
        specific, actionable message rather than a generic failure.
      </p>

      <Anchor id="ngstone-port">ngstone port</Anchor>
      <p>
        Starts a tunnel to a local port or URL. This is the command that
        actually opens a connection to the edge and forwards traffic.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone port 3000
$ ngstone port http://127.0.0.1:3000
$ ngstone port 3000 --subdomain demo`}
      />
      <p>
        The positional argument is either a bare port number (forwarded to{" "}
        <code>http://127.0.0.1:&lt;port&gt;</code>) or a full target URL.
        Flags may appear before or after it.
      </p>
      <ParamTable>
        <Property name="--subdomain, -s" type="string">
          Request a specific subdomain instead of a server-assigned one,
          e.g. <code>--subdomain demo</code> for{" "}
          <code>demo.ngstone.site</code>.
        </Property>
        <Property name="--server" type="string">
          Edge control-plane address override. Defaults to the config file
          or <code>ngstone.site:4443</code>.
        </Property>
        <Property name="--token" type="string">
          Auth token override. Defaults to <code>NGSTONE_TOKEN</code> or the
          token saved by <code>ngstone auth</code>.
        </Property>
        <Property name="--insecure" type="bool" defaultValue="false">
          Dial the control plane in plaintext (dev/test only, no
          certificates involved).
        </Property>
        <Property name="--server-name" type="string">
          TLS <code>ServerName</code>/SNI to verify against. Ignored with{" "}
          <code>--insecure</code>.
        </Property>
        <Property name="--pin" type="string">
          Optional SPKI pin, checked in addition to normal chain
          validation. Off by default.
        </Property>
      </ParamTable>

      <Anchor id="ngstone-config">ngstone config</Anchor>
      <p>Read or change the local config file without hand-editing JSON.</p>
      <CodeBlock
        language="bash"
        code={`$ ngstone config set server ngstone.site:4443
server set to ngstone.site:4443

$ ngstone config get
token: nst_a1b2…9f3d
server: ngstone.site:4443

$ ngstone config get token
nst_a1b2…9f3d

$ ngstone config path
/home/you/.config/ngstone/config.json`}
      />
      <p>
        <code>config get</code> always redacts the token — the middle of
        the value is replaced with <code>…</code>, only the first and last
        four characters are shown.
      </p>

      <Anchor id="ngstone-logout">ngstone logout</Anchor>
      <p>
        Clears the saved token from the config file. The server address is
        left untouched.
      </p>
      <CodeBlock language="bash" code={`$ ngstone logout
logged out`} />

      <Anchor id="ngstone-version">ngstone version</Anchor>
      <p>
        Prints the build&apos;s version string, injected at compile time via{" "}
        <code>-ldflags</code>.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone version
ngstone v0.1.0 (commit 3f1a9c2, built 2026-06-01T12:00:00Z)`}
      />

      <Anchor id="no-args-and-help">No arguments and -h</Anchor>
      <p>
        Running <code>ngstone</code> with no arguments does not start a
        tunnel — it prints usage to stderr and exits <code>1</code>.{" "}
        <code>-h</code>, <code>--help</code>, and <code>-help</code> print
        the same usage to stdout and exit <code>0</code>.
      </p>

      <Anchor id="generating-a-token">Generating a token</Anchor>
      <Callout variant="note" title="There is no ngstone token command">
        Token generation is a plain shell one-liner, not a CLI verb. The
        edge only ever stores the token&apos;s SHA-256 hash — the plaintext
        lives on whichever machines run the agent.
      </Callout>
      <CodeBlock
        language="bash"
        code={`TOKEN=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
HASH=$(printf '%s' "$TOKEN" | shasum -a 256 | cut -d' ' -f1)   # sha256sum on Linux`}
      />
      <p>
        Keep <code>$TOKEN</code> for <code>ngstone auth</code> on every
        machine that will run the agent, and pass <code>$HASH</code> to the
        edge as <code>-token-sha256</code> (or{" "}
        <code>$NGSTONE_TOKEN_SHA256</code>). There is exactly one token per
        edge — rotating it invalidates every agent at once, since it
        changes what the edge accepts, not something per-agent.
      </p>

      <Anchor id="config-file">The config file</Anchor>
      <p>
        <code>ngstone auth</code>, <code>ngstone port</code>,{" "}
        <code>ngstone config</code>, and <code>ngstone logout</code> all
        read and write the same JSON file:
      </p>
      <CodeBlock
        language="text"
        code={`$XDG_CONFIG_HOME/ngstone/config.json
# falls back to ~/.config/ngstone/config.json if XDG_CONFIG_HOME is unset`}
      />
      <p>
        The file holds <code>token</code> and <code>server</code>. It&apos;s
        written with mode <code>0600</code> inside a <code>0700</code>{" "}
        directory, and saved via a temp-file-plus-rename so a crash
        mid-write can&apos;t corrupt it.
      </p>
      <p>Resolution order for both the token and the server address:</p>
      <ParamTable>
        <Property name="1. Flag" type="highest precedence">
          <code>--token</code> / <code>--server</code> on the command
          invoking it.
        </Property>
        <Property name="2. Environment" type="token only">
          <code>NGSTONE_TOKEN</code>. There is no environment override for
          the server address.
        </Property>
        <Property name="3. Config file" type="">
          Whatever <code>ngstone auth</code> or{" "}
          <code>ngstone config set</code> last saved.
        </Property>
        <Property name="4. Default" type="server only" defaultValue="ngstone.site:4443">
          Used only if nothing above set a server address.
        </Property>
      </ParamTable>

      <Anchor id="legacy-flags">Legacy flag form</Anchor>
      <p>
        A flat-flags invocation is still supported alongside the verbs
        above, mainly for scripts and the e2e test suite written against
        it. It starts a tunnel directly — there&apos;s no config file
        involved.
      </p>
      <CodeBlock
        language="bash"
        code={`$ ngstone -control ADDR -token TOK -target URL -subdomain NAME \\
    -insecure -server-name NAME -pin SPKI -instance-id ID`}
      />
      <ParamTable>
        <Property name="-control" type="string" defaultValue="ngstone.site:4443">
          Edge control-plane address.
        </Property>
        <Property name="-token" type="string">
          Auth token. Falls back to <code>NGSTONE_TOKEN</code> if unset.
        </Property>
        <Property name="-target" type="string" defaultValue="http://127.0.0.1:3000">
          Local target URL to forward requests to.
        </Property>
        <Property name="-subdomain" type="string">
          Requested subdomain. Empty means server-assigned.
        </Property>
        <Property name="-instance-id" type="string">
          Undocumented, testing-only: force a specific instance ID instead
          of generating one.
        </Property>
        <Property name="-insecure" type="bool" defaultValue="false">
          Dial the control plane in plaintext (dev/test only).
        </Property>
        <Property name="-server-name" type="string">
          TLS ServerName/SNI to verify against.
        </Property>
        <Property name="-pin" type="string">
          Optional SPKI pin.
        </Property>
        <Property name="-version" type="bool" defaultValue="false">
          Print version and exit.
        </Property>
      </ParamTable>
      <p>
        Prefer <code>ngstone auth</code> plus <code>ngstone port</code> for
        day-to-day use — the legacy form exists for compatibility, not as
        the recommended path.
      </p>
    </DocsArticle>
  )
}
