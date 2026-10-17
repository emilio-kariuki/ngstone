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
        per HTTP/1.1 exchange or native HTTP/2 connection — carries a single
        JSON preamble followed by the selected protocol bytes.
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
        owned by one repo. HTTP/1.1 data streams carry{" "}
        <strong>raw HTTP/1.1 bytes</strong> after the preamble; native HTTP/2
        streams carry the HTTP/2 preface and frames. JSON never touches either
        data path.
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
    ProtoVersions []int  \`json:"proto_versions"\`  // [2, 1] — supported protocol majors
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
        the connection. In scoped-credential mode the edge hashes the bearer
        token, checks its expiration and revocation state, and attaches the
        resulting scope to the session. The legacy mode compares the token
        against the configured SHA-256 digest.
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
          <code>&quot;http&quot;</code> or <code>&quot;tcp&quot;</code>. A{" "}
          <code>&quot;tcp&quot;</code> bind skips the subdomain/hostname
          machinery entirely and gets back an allocated port instead — see{" "}
          <a href="/docs/guides/tcp-tunnels">TCP tunnels</a>.
        </Property>
        <Property name="subdomain" type="string">
          Empty string requests a random name, e.g.{" "}
          <code>amber-fox-42</code>. Ignored for <code>kind: &quot;tcp&quot;</code>.
        </Property>
        <Property name="remote_port" type="int">
          <code>kind: &quot;tcp&quot;</code> only. Requested remote port;{" "}
          <code>0</code> means server-assigned.
        </Property>
        <Property name="takeover" type="bool">
          Reclaim a binding — authorized by identity, not liveness.
        </Property>
        <Property name="basic_auth_sha256" type="[]string">
          v2 only. SHA-256 digests, hex-encoded, of{" "}
          <code>user:pass</code> credentials — the edge never sees the
          plaintext. HTTP only; a TCP bind carrying this field is rejected.
          See <a href="/docs/guides/access-control">Access control</a>.
        </Property>
        <Property name="basic_auth_realm" type="string">
          v2 only. <code>WWW-Authenticate</code> realm string. Ignored
          unless <code>basic_auth_sha256</code> is also set; falls back to a
          default realm if empty.
        </Property>
        <Property name="allow_cidrs" type="[]string">
          v2 only. Source CIDRs allowed to reach the tunnel. Applies to both{" "}
          <code>kind: &quot;http&quot;</code> and{" "}
          <code>kind: &quot;tcp&quot;</code>.
        </Property>
        <Property name="policy" type="object">
          v2 only and HTTP-only. Ordered method/path/header allow-or-deny
          rules sent from <code>--policy-file</code>. The edge evaluates the
          policy before opening a request stream.
        </Property>
        <Property name="policy_digest" type="string">
          SHA-256 digest of the normalized policy. The agent includes it in
          <code>Bind</code>, and the edge echoes it in <code>BindOK</code> so
          an older edge cannot silently ignore a policy.
        </Property>
        <Property name="http2" type="bool">
          v2 only and HTTP-only. Selects the native HTTP/2 data path. The edge
          echoes this in <code>BindOK</code>; the agent fails closed if an
          older edge silently ignores the request.
        </Property>
        <Property name="multi_connector" type="bool">
          v2 only and HTTP-only. Requires an explicit subdomain and lets
          multiple sessions join one load-balanced connector pool. Every
          connector must match the pool&apos;s HTTP/2, access-control, and
          traffic-policy settings. The edge echoes this in <code>BindOK</code>.
        </Property>
        <Property name="connector_token_sha256" type="string">
          v2 only and required with <code>multi_connector</code>. SHA-256 hex
          digest of the per-tunnel connector secret. The secret itself is
          never placed in the control message; a mismatch prevents a session
          from joining the pool.
        </Property>
        <Property name="hostname" type="string">
          Returned in <code>BindOK</code>: the full bound hostname, e.g.{" "}
          <code>api.ngstone.site</code>.
        </Property>
        <Property name="url" type="string">
          Returned in <code>BindOK</code>: the full public URL.
        </Property>
        <Property name="port" type="int">
          Returned in <code>BindOK</code> for <code>kind: &quot;tcp&quot;</code>:
          the allocated remote port.
        </Property>
        <Property name="code" type="string">
          Returned in <code>BindErr</code>:{" "}
          <code>subdomain_taken</code>, <code>invalid_subdomain</code>,{" "}
          <code>kind_unsupported</code>, <code>port_unavailable</code>,{" "}
          <code>too_many_binds</code>, <code>invalid_access</code>, or{" "}
          <code>connector_config_mismatch</code>, or{" "}
          <code>credential_scope</code>.
        </Property>
      </ParamTable>
      <Callout variant="note" title="invalid_access">
        Returned when access-control or policy fields fail validation (a
        malformed CIDR, a digest that isn&apos;t 32 bytes, too many
        credentials/CIDRs, an invalid policy, or protected fields on a{" "}
        <code>tcp</code> bind), and also
        when a session negotiated protocol v1 but the <code>Bind</code>{" "}
        carries any protected field — see{" "}
        <a href="#versioning">Versioning</a>.
      </Callout>
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
      <p>
        A scoped credential is revalidated from the credential file on each
        edge heartbeat. If it expires, is revoked, or the file becomes
        unreadable, the edge sends <code>Goodbye</code> and releases the
        session&apos;s bindings. This keeps revocation independent without
        putting the plaintext token on the wire again.
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
    Kind       string \`json:"kind"\`        // "http", "h2", or "tcp"
    Host       string \`json:"host"\`        // which binding this request targets
    ReqID      string \`json:"req_id"\`      // edge-minted ULID; ties edge logs ↔
                                             // inspector entries
    ClientAddr string \`json:"client_addr"\` // public client ip:port
}`}
      />
      <p>
        A <code>Kind: &quot;h2&quot;</code> stream carries a native HTTP/2
        connection after the preamble. The edge opens it with the HTTP/2
        client transport; the agent serves it with an HTTP/2 server, allowing
        request trailers, response trailers, streaming, and full-duplex
        exchanges to pass through. A <code>Kind: &quot;http&quot;</code> stream
        continues to carry one HTTP/1.1 request/response exchange.
      </p>
      <p>
        <code>ClientAddr</code> is carried here rather than derived from the
        stream, because a <code>Kind: &quot;tcp&quot;</code> stream has no{" "}
        <code>X-Forwarded-For</code> header to fall back on.
      </p>

      <Anchor id="versioning">Versioning</Anchor>
      <p>
        The protocol uses a single integer major version, currently{" "}
        <code>3</code>. The agent offers every version it supports in{" "}
        <code>Auth.ProtoVersions</code> — <code>[3, 2, 1]</code> — and the edge
        picks the highest version present in both its own supported list
        and the agent&apos;s offer, returning it in{" "}
        <code>AuthOK.ProtoVersion</code>. An edge that only understands v1
        still negotiates fine with a v2-capable agent; it just settles on{" "}
        <code>1</code>.
      </p>
      <p>
        v2 added the three <code>Bind</code> access-control fields above (
        <code>basic_auth_sha256</code>, <code>basic_auth_realm</code>,{" "}
        <code>allow_cidrs</code>) and the <code>invalid_access</code> error
        code. Access control and traffic policies are hard v2 requirements,
        not best-effort features: if a session negotiates v1, the edge rejects
        a <code>Bind</code> carrying any protected field with{" "}
        <code>invalid_access</code> rather than silently binding without
        protection, and the agent checks this client-side too — it refuses
        to send the <code>Bind</code> at all when{" "}
        <code>--basic-auth</code>, <code>--allow-cidr</code>, or{" "}
        <code>--policy-file</code> was requested but the negotiated version is
        below <code>2</code>. A policy also requires a matching digest in{" "}
        <code>BindOK</code>. Either way the tunnel fails closed instead of
        coming up unprotected.
      </p>
      <p>
        HTTP/2 mode is also v2-only and requires the <code>http2</code> echo in
        <code>BindOK</code>, so an older edge cannot silently fall back to
        HTTP/1.1.
      </p>
      <p>
        v3 added <a href="/docs/guides/database-sharing">database
        sharing</a>: <code>Auth.share_secret</code> as an alternative to{" "}
        <code>token</code>, <code>AuthOK.scope</code> (
        <code>operator</code> or <code>connector</code>), the{" "}
        <code>share</code>/<code>share_ok</code>/<code>share_err</code>,{" "}
        <code>unshare</code>, <code>share_update</code>, <code>kick</code>,{" "}
        <code>approve</code>, <code>list_shares</code>,{" "}
        <code>watch_shares</code>, <code>connect</code>/
        <code>connect_ok</code>/<code>connect_err</code>,{" "}
        <code>share_event</code>, <code>share_closed</code> and{" "}
        <code>share_updated</code> messages, a <code>share</code> stream
        kind and optional <code>share_id</code> and <code>target</code>{" "}
        fields on the stream preamble. A connector-scoped session may send
        only <code>connect</code>,{" "}
        <code>ping</code>, <code>pong</code> and <code>goodbye</code>;
        anything else is answered with <code>forbidden</code> and the
        session closes. The full message set is in{" "}
        <code>docs/SHARE-DESIGN.md</code>.
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
