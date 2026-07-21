import type { Metadata } from "next"

import type { TocItem } from "@/lib/docs-nav"
import { Anchor } from "@/components/docs/anchor"
import { Callout } from "@/components/docs/callout"
import { CodeBlock } from "@/components/docs/code-block"
import { DocsArticle } from "@/components/docs/docs-article"
import { ParamTable, Property } from "@/components/docs/param-table"

export const metadata: Metadata = {
  title: "The wire protocol",
  description: "Framing, control messages, and versioning.",
}

const TOC: TocItem[] = [
  { id: "framing", title: "Framing & encoding" },
  { id: "envelope", title: "The message envelope" },
  { id: "handshake", title: "Handshake" },
  { id: "tunnel-lifecycle", title: "Tunnel lifecycle" },
  { id: "liveness-shutdown", title: "Liveness & shutdown" },
  { id: "stream-preamble", title: "Stream preamble" },
  { id: "versioning", title: "Versioning" },
]

export default function WireProtocolPage() {
  return (
    <DocsArticle href="/docs/reference/wire-protocol" toc={TOC}>
      <h1>The wire protocol</h1>
      <p>
        A dedicated control stream carries a small, fully-typed set of JSON
        messages between the agent and the edge. Every other stream — one
        per proxied request — carries a single JSON preamble followed by raw
        bytes.
      </p>

      <Anchor id="framing">Framing &amp; encoding</Anchor>
      <p>
        Every control message and every stream preamble uses the same
        trivial framing: a big-endian length prefix followed by a JSON
        payload.
      </p>
      <CodeBlock
        language="text"
        code={`uint32 big-endian payload length | JSON payload      (max frame: 64 KiB)`}
      />
      <p>
        JSON was chosen over protobuf or gob — it&apos;s greppable in debug
        logs, control-plane volume is a few messages a minute so performance
        is irrelevant, and it avoids codegen for a handful of message types
        owned by one repo. Data streams carry{" "}
        <strong>raw HTTP/1.1 bytes</strong> after the preamble — JSON never
        touches the hot path.
      </p>

      <Anchor id="envelope">The message envelope</Anchor>
      <p>
        Every control-stream message is wrapped in the same envelope:
      </p>
      <CodeBlock
        language="go"
        filename="internal/proto/proto.go"
        code={`type Msg struct {
    Type string          \`json:"type"\`           // discriminator
    ID   uint64          \`json:"id,omitempty"\`   // correlates request→reply;
                                                    // per-direction ID spaces
    Data json.RawMessage \`json:"data,omitempty"\` // type-specific payload
}`}
      />
      <p>
        <code>ID</code> spaces are per-direction — the agent mints odd IDs,
        the edge mints even ones — so both peers can initiate a message
        (both send <code>Ping</code>) without colliding. Replies don&apos;t
        get a fresh ID: a reply carries the{" "}
        <strong>same <code>Msg.ID</code> as the request it answers</strong> —{" "}
        <code>AuthOK</code> echoes <code>Auth</code>&apos;s ID,{" "}
        <code>BindOK</code> echoes <code>Bind</code>&apos;s, <code>Pong</code>{" "}
        echoes <code>Ping</code>&apos;s.
      </p>

      <Anchor id="handshake">Handshake</Anchor>
      <p>
        The first exchange on every control stream. Anything else as the
        first message closes the connection.
      </p>
      <CodeBlock
        language="go"
        code={`type Auth struct {
    Token         string \`json:"token"\`
    InstanceID    string \`json:"instance_id"\`     // stable per agent-process start
    ClientVersion string \`json:"client_version"\`  // e.g. "v0.1.0 (commit 3f1a9c2, built 2026-06-01T12:00:00Z)"
    ProtoVersions []int  \`json:"proto_versions"\`  // [1] — supported protocol majors
}
type AuthOK struct {
    ProtoVersion  int    \`json:"proto_version"\`   // server picks highest mutual
    SessionID     string \`json:"session_id"\`      // minted per session
    ServerVersion string \`json:"server_version"\`
}
type AuthErr struct {
    Code    string \`json:"code"\`    // bad_token, no_common_version
    Message string \`json:"message"\`
}`}
      />
      <p>
        The first message must be <code>Auth</code> within{" "}
        <strong>5 seconds</strong> of TLS establishment, or the edge closes
        the connection. The token check is a constant-time comparison
        against the SHA-256 of the configured token.
      </p>

      <Anchor id="tunnel-lifecycle">Tunnel lifecycle</Anchor>
      <p>
        A bound session can bind, unbind, and be evicted by a takeover — six
        message types cover the whole lifecycle.
      </p>
      <p>
        <strong>Bind / BindOK / BindErr</strong>
      </p>
      <ParamTable>
        <Property name="kind" type="string">
          <code>&quot;http&quot;</code> in v1. <code>&quot;tcp&quot;</code>{" "}
          is reserved for later.
        </Property>
        <Property name="subdomain" type="string">
          Empty string requests a random name, e.g.{" "}
          <code>amber-fox-42</code>.
        </Property>
        <Property name="takeover" type="bool">
          Reclaim a binding — authorized by identity, not liveness.
        </Property>
        <Property name="hostname" type="string">
          Returned in <code>BindOK</code>: the full bound hostname, e.g.{" "}
          <code>api.ngstone.site</code>.
        </Property>
        <Property name="url" type="string">
          Returned in <code>BindOK</code>: the full public URL.
        </Property>
        <Property name="code" type="string">
          Returned in <code>BindErr</code>:{" "}
          <code>subdomain_taken</code>, <code>invalid_subdomain</code>, or{" "}
          <code>kind_unsupported</code>.
        </Property>
      </ParamTable>
      <p>
        <strong>Unbind / UnbindOK / Evicted</strong>
      </p>
      <ParamTable>
        <Property name="hostname" type="string">
          The agent drops one tunnel; the session itself stays up.
        </Property>
        <Property name="reason" type="string">
          Sent only on <code>Evicted</code>: always{" "}
          <code>&quot;takeover&quot;</code> in v1 — this binding was
          reclaimed, stop advertising the URL.
        </Property>
      </ParamTable>

      <Anchor id="liveness-shutdown">Liveness &amp; shutdown</Anchor>
      <p>
        Both peers send <code>Ping</code> on the control stream every{" "}
        <strong>15 seconds</strong>; <code>Pong</code> echoes the ping&apos;s
        timestamp so the sender can log RTT. <strong>Three consecutive
        misses</strong> (≈45 seconds) declares the peer dead.
      </p>
      <CodeBlock
        language="go"
        code={`type Ping struct { TS int64 \`json:"ts_unix_ms"\` }
type Pong struct { TS int64 \`json:"ts_unix_ms"\` } // echoes Ping.TS`}
      />
      <p>
        Graceful shutdown is fire-and-forget by design — there is no{" "}
        <code>GoodbyeOK</code>. The sender starts its own drain timer the
        moment it sends and behaves the same whether or not the peer honored
        the message.
      </p>
      <CodeBlock
        language="go"
        code={`type Goodbye struct {
    Reason  string \`json:"reason"\`   // "shutdown", "reload", "idle"
    DrainMS int    \`json:"drain_ms"\` // sender stops opening new streams
}`}
      />

      <Anchor id="stream-preamble">Stream preamble</Anchor>
      <p>
        Every data stream opens with one JSON frame — the only JSON on that
        stream — before raw bytes take over.
      </p>
      <CodeBlock
        language="go"
        code={`type StreamOpen struct {
    Kind       string \`json:"kind"\`        // "http" v1; "tcp" later
    Host       string \`json:"host"\`        // which binding this request targets
    ReqID      string \`json:"req_id"\`      // edge-minted ULID; ties edge logs ↔
                                             // inspector entries
    ClientAddr string \`json:"client_addr"\` // public client ip:port
}`}
      />
      <p>
        <code>ClientAddr</code> is carried here rather than derived from the
        stream, because a future <code>Kind: &quot;tcp&quot;</code> stream
        has no <code>X-Forwarded-For</code> header to fall back on.
      </p>

      <Anchor id="versioning">Versioning</Anchor>
      <p>
        The protocol uses a single integer major version. The client offers
        the versions it supports in <code>Auth.ProtoVersions</code>; the
        server picks the highest mutual version and returns it in{" "}
        <code>AuthOK.ProtoVersion</code>. v1 ships as <code>1</code>.
      </p>
      <p>
        Additive JSON fields never bump the version — unknown fields are
        simply ignored. Semantic changes do. Within a negotiated version, an
        unknown <code>Msg.Type</code> or a malformed frame gets a generic{" "}
        <code>Error</code> reply and then the session closes — never a
        silent ignore.
      </p>
      <Callout variant="note" title="Error is also a catch-all reply">
        <code>Error{"{"}Code, Message{"}"}</code> is sent as the reply to any
        request the receiver can&apos;t satisfy, and also right before a
        connection is closed for a protocol violation. Codes include{" "}
        <code>unknown_type</code>, <code>malformed</code>,{" "}
        <code>not_bound</code>, and <code>internal</code>.
      </Callout>
    </DocsArticle>
  )
}
