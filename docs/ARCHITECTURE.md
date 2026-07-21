# ngstone — Architecture Document (v1)

**Status:** revised-post-review · **Owner:** single operator · **Repo:** `/Users/mac/projects/ngstone` (greenfield) · **Go:** 1.25

A personal, self-hosted ngrok replacement. Two binaries — `ngstoned` (edge, Linux VPS) and `ngstone` (agent + CLI + local inspector, macOS dev machine) — one shared module. HTTP/HTTPS tunnels only in v1; the wire protocol is deliberately shaped so raw TCP can be added later without a protocol bump.

Guiding principles, in priority order: **stdlib-first, boring over clever, one path per feature, everything flow-controlled, nothing unbounded in memory.**

---

## 1. System overview & end-to-end data flow

```
                    VPS (Linux)                                Dev machine (macOS)
              ┌──────────────────────┐                     ┌─────────────────────────┐
 browser ───► │ :443  public TLS     │                     │  ngstone agent          │
              │ :80   → 301 https    │   one TLS TCP conn  │   ├─ tunnel session     │
              │ :4443 control TLS ◄──┼─────────────────────┼───┤  (yamux client)      │
              │                      │   yamux session     │   ├─ local proxy        │──► localhost:3000
              │  ngstoned            │   (agent dials out) │   └─ inspector :4040    │
              │   ├─ certmagic       │                     │       (127.0.0.1 only)  │
              │   ├─ registry        │                     └─────────────────────────┘
              │   └─ reverse proxy   │
              └──────────────────────┘
```

The agent **always dials out** (VPS never connects into the laptop — NAT-friendly, no inbound firewall holes at home). One long-lived TLS TCP connection carries a yamux session; the first stream is the control stream; every proxied request gets its own yamux stream.

### One HTTP request, hop by hop

`GET https://api.ngstone.site/users` → app on `localhost:3000`:

1. **Browser → edge :443.** TCP + TLS 1.3 handshake. `certmagic`'s `GetCertificate` serves the wildcard `*.ngstone.site` cert for SNI `api.ngstone.site`. ALPN negotiates `h2` or `http/1.1`; stdlib `http.Server` handles either transparently.
2. **Edge routing.** The handler extracts the host (port stripped, lowercased), does an `RLock`ed map lookup in the `Registry`. Miss → immediate `404` (uniform body, no agent work). Hit → a `*Binding` holding the owning agent's yamux session.
3. **Admission.** Per-IP token bucket and global in-flight semaphore checked (§5). Reject → `429`.
4. **Edge → agent stream open.** `httputil.ReverseProxy` runs with a per-binding `http.Transport` whose `DialContext` opens a **new yamux stream** and writes a one-frame JSON preamble: `{"type":"stream_open","data":{"kind":"http","host":"api.ngstone.site","req_id":"01J8ZQ…","client_addr":"203.0.113.9:51844"}}` — `req_id` correlates edge logs with inspector entries; `client_addr` is carried now because the future `kind:"tcp"` has no `X-Forwarded-For` to fall back on. `DisableKeepAlives: true` → exactly one request per stream, so stream lifetime == request lifetime.
5. **Request serialization.** ReverseProxy writes the request as plain HTTP/1.1 onto the stream (h2 on the public side is downgraded here — fine, the tunnel is private). Headers rewritten first: `X-Forwarded-For` appended, `X-Forwarded-Proto: https`, `X-Forwarded-Host` set; original `Host` preserved by default (§5). Body streams through — never fully buffered on the edge.
6. **Agent accepts the stream**, reads the preamble, then hands the stream to a per-session `http.Server` (via a `net.Listener` adapter that yields yamux streams). Its handler is the **capture middleware** wrapping a second `httputil.ReverseProxy`.
7. **Agent → localhost:3000** over a pooled keep-alive `http.Transport` (§6). Capture middleware tees up to 256 KiB of each body into the inspector ring buffer without blocking the stream (§6).
8. **Response path** is the same pipe in reverse: app → agent proxy → yamux stream → edge proxy → browser. Both proxies are `io.Copy` loops over flow-controlled streams, so a slow browser backpressures all the way to the app's socket writes. `FlushInterval: -1` on the edge proxy means bytes are flushed as they arrive (SSE/streaming just works).
9. **Teardown.** Response completes → yamux stream closed → transport slot freed. The inspector entry (status, timing, capped bodies) is pushed to any open `localhost:4040` SSE subscribers.

Added latency budget: one extra TCP/TLS-encrypted hop + yamux framing ≈ RTT(laptop↔VPS) + ~1 ms. No per-request handshakes anywhere: public keep-alive to edge, persistent yamux session, keep-alive pool to the local app.

---

## 2. Transport: agent ↔ edge

**Decision: `hashicorp/yamux` over a single TLS 1.3 TCP connection (agent dials edge :4443).**

| Option | Verdict | Why rejected / accepted |
|---|---|---|
| **yamux over TLS TCP** | ✅ **chosen** | Symmetric stream opening (either peer can open — critical, since *the edge* initiates per-request streams toward the agent), per-stream flow control with configurable windows, built-in keepalive, ~1k LOC of battle-tested code (Nomad/Consul), zero codegen, trivial to debug. It's a dumb byte-stream multiplexer — exactly the abstraction we need, nothing we don't. (smux is equivalent; yamux wins on maintenance record and window-update semantics.) |
| HTTP/2 streams (`x/net/http2`) | ❌ | h2 streams are request/response-shaped and *client-initiated*; our requests flow edge→agent, so we'd have to run the agent as an h2 *server* on a connection it dialed (`http2.Server.ServeConn` on a client socket). Workable but contorted, flow-control tuning is opaque, and we'd be fighting the library's HTTP semantics to get raw bidirectional streams for future TCP tunnels. Same TCP HOL blocking as yamux, more machinery. |
| WebSocket + mux layer | ❌ | WS only buys traversal of HTTP-only middleboxes between agent and edge. We own both endpoints and the VPS; there is no such middlebox. It adds a dependency and a framing layer, and you *still* need yamux on top for streams. Pure cost. |
| QUIC / HTTP3 (`quic-go`) | ❌ *for v1* | The genuinely tempting one: native streams, no TCP HOL blocking, connection migration. Rejected because: UDP is throttled/blocked on enough hotel/corp networks to matter for a laptop-side agent; userspace QUIC costs CPU on a small VPS; `quic-go` API churn; harder ops debugging. At single-user concurrency, TCP HOL blocking is a rounding error. The `tunnel.Session` interface (§7) is deliberately narrow so QUIC can be slotted in later as `transport=quic` without touching the control protocol. |

**Mechanics:**

- **Per-request streams.** Edge calls `session.OpenStream(ctx, preamble)`; one stream = one HTTP exchange (or, later, one TCP connection). Stream ID space is yamux's; we never expose it.
- **Stream-open cancellation.** Verified against yamux v0.1.2 source, because the obvious reading of this API is wrong in two ways:
  - **`Config.StreamOpenTimeout` is a session killer, not a per-stream deadline.** `setOpenTimeout` fires and calls `s.Close()` — "Close the session to force connection re-establishment". An earlier draft here said to set it to 5 s to match our dial budget; that is actively harmful, converting one slow SYN-ACK into a teardown of *every tunnel on the session*, the same failure class as the `ConnectionWriteTimeout: 10s` trap below. **Leave it at the 75 s default** (or higher) and treat it purely as a wedged-connection backstop.
  - **`OpenStream()` does not wait for the ACK.** It blocks only on the `synCh` semaphore (depth `AcceptBacklog`), then allocates an ID, registers the stream, sends a window update, and returns. The returned stream is *not yet established* — the first write is optimistic. So the only thing ctx must race is `synCh` back-pressure, not a round trip.
  - Therefore the **5 s dial budget lives in our wrapper, not in yamux**: run `OpenStream()` in a goroutine, `select` on ctx, and `Close()` the stream if it lands after cancellation — otherwise a cancelled caller leaks both the stream and its SYN slot. This fails **one request** with a `502` instead of dropping every tunnel. The preamble write gets its own explicit write deadline.
- **Accepting is context-aware.** yamux provides `AcceptStreamWithContext(ctx)`; use it rather than bare `AcceptStream()` so session shutdown unblocks the accept loop cleanly instead of relying on the close error.
- **`Stream.RemoteAddr()` is useless for identifying the public client** — it returns the *session's* underlying TCP remote address, so every stream on a session reports the same value (the edge's own IP as seen by the agent). This is precisely why `StreamOpen.ClientAddr` exists (§3); anything logging a per-request client address must read the preamble, never the stream.
- **A logger must be configured explicitly.** `VerifyConfig` rejects a config with *both* `Logger` and `LogOutput` nil, and rejects having both set — exactly one is required. Left unset, yamux would also write to stderr behind `log/slog`'s back, so route it through a small `yamux.Logger` adapter into slog at debug level.
- **Backpressure.** yamux gives each stream a receive window (we set `MaxStreamWindowSize = 1 MiB`, up from the 256 KiB default, to keep throughput reasonable at ~100 ms RTT: window/RTT ≈ 10 MB/s per stream). Writers block when the window is exhausted, so a slow public client throttles the local app via nothing but blocked `io.Copy`s. No application-level buffering, ever. One honest caveat: the window is itself a buffer — each open stream may hold up to `MaxStreamWindowSize` of received-but-unread bytes, on *both* machines. That product (max concurrent streams × window) is the largest buffer in the system and is budgeted explicitly in the §5 limits table, not left implicit.
- **Head-of-line blocking.** Exists at the TCP layer (one lost packet stalls all streams for one RTT). Accepted: single user, a handful of concurrent requests. The session-level keepalive prevents a *stalled* connection from lingering.
- **Keepalive & dead peers.** yamux `EnableKeepAlive: true, KeepAliveInterval: 10s, ConnectionWriteTimeout: 45s`. The write timeout is deliberately **not** 10 s: in yamux, `ConnectionWriteTimeout` is a whole-session kill switch guarding *every* data send (`waitForSendErr`/`sendNoWait`), not a keepalive knob. At 10 s, a saturated uplink or flaky hotel wifi during one large download would trip `ErrConnectionWriteTimeout` and kill the entire session — every tunnel, every in-flight request — presenting as "tunnel randomly drops under load". 45 s keeps the kill switch for genuinely wedged connections while liveness comes from pings, not from data-write stalls; the yamux shutdown error is logged verbatim so a write-timeout death is distinguishable from a real disconnect. Belt-and-suspenders app-level `ping` on the control stream every 15 s (§3) detects a wedged agent *process* whose kernel still ACKs.
- **Reconnect with in-flight requests.** Requests in flight when the session dies **fail fast**: edge streams error, ReverseProxy returns `502` with a small branded error page. We deliberately do **not** replay them from the edge — the edge cannot know a request is idempotent (a `POST /charge` replay is worse than a 502). The agent reconnects with decorrelated-jitter backoff (500 ms → 30 s cap), re-authenticates, and re-issues `bind` for its tunnel; the public URL is identical after recovery. Users who want retry get it from their HTTP client, where idempotency is knowable.

---

## 3. Control protocol

### Framing & encoding

Every control message (control stream) and every stream preamble (first frame of a data stream) uses the same trivial framing:

```
uint32 big-endian payload length | JSON payload      (max frame: 64 KiB)
```

**Encoding: JSON.** Rejected protobuf (codegen + dependency for ~10 message types owned by one repo compiling both ends in lockstep — negative ROI) and gob (unreadable in logs, painful cross-version evolution). JSON with a tagged envelope is greppable in debug logs, and control-plane volume is a few messages a minute — performance is irrelevant. Data streams carry **raw HTTP/1.1 bytes after the preamble** — JSON never touches the hot path.

```go
// internal/proto/proto.go
type Msg struct {
    Type string          `json:"type"`           // discriminator
    ID   uint64          `json:"id,omitempty"`   // correlates request→reply; per-direction ID spaces
                                                 // (agent-initiated odd, edge-initiated even — both
                                                 // peers send Ping, so one shared space would collide)
    Data json.RawMessage `json:"data,omitempty"` // type-specific payload
}
```

### Message schema (complete v1 set)

```go
// ---- handshake (first exchange on the control stream; anything else → close) ----
type Auth struct {
    Token         string `json:"token"`
    InstanceID    string `json:"instance_id"`     // stable 16-byte random hex minted once per agent
                                                  // process start; survives reconnects, dies with the
                                                  // process. Authorizes takeover (see rules below).
    ClientVersion string `json:"client_version"`  // "ngstone/0.3.0 darwin/amd64"
    ProtoVersions []int  `json:"proto_versions"`  // [1] — client's supported protocol majors
}
type AuthOK struct {
    ProtoVersion  int    `json:"proto_version"`   // server picks highest mutual; none → AuthErr
    SessionID     string `json:"session_id"`      // 16-byte random hex, minted per session
    ServerVersion string `json:"server_version"`
}
type AuthErr struct {
    Code    string `json:"code"`    // bad_token, no_common_version
    Message string `json:"message"`
}

// ---- tunnel lifecycle ----
type Bind struct {
    Kind      string `json:"kind"`                // "http" (v1). "tcp" reserved.
    Subdomain string `json:"subdomain,omitempty"` // "" → server assigns random (e.g. "amber-fox-42")
    Takeover  bool   `json:"takeover,omitempty"`  // reclaim a binding; authorized by identity, not
                                                  // liveness — see conflict rules below
}
type BindOK struct {
    Hostname string `json:"hostname"` // "api.ngstone.site"
    URL      string `json:"url"`      // "https://api.ngstone.site"
}
type BindErr struct {
    Code    string `json:"code"`    // subdomain_taken, invalid_subdomain, kind_unsupported
    Message string `json:"message"`
}
type Unbind   struct { Hostname string `json:"hostname"` } // agent drops one tunnel; session stays up
type UnbindOK struct { Hostname string `json:"hostname"` }

// ---- server → agent notifications ----
type Evicted struct {
    Hostname string `json:"hostname"` // this binding was taken over; stop advertising the URL
    Reason   string `json:"reason"`   // "takeover"
}

// ---- generic failure (reply to any request; also sent before close on protocol violations) ----
type Error struct {
    Code    string `json:"code"`    // unknown_type, malformed, not_bound, internal
    Message string `json:"message"`
}

// ---- liveness (both directions, every 15s; 3 misses → peer declared dead) ----
type Ping struct { TS int64 `json:"ts_unix_ms"` }
type Pong struct { TS int64 `json:"ts_unix_ms"` } // echoes Ping.TS; agent logs RTT

// ---- graceful shutdown ----
// Fire-and-forget by design: there is no GoodbyeOK. The sender starts its own drain timer the
// moment it sends, and its behavior is identical whether or not the peer honored the message
// (unroute/stop-opening, wait out in-flight, close). An ack the sender cannot act on is protocol noise.
type Goodbye struct {
    Reason  string `json:"reason"`   // "shutdown", "reload", "idle"
    DrainMS int    `json:"drain_ms"` // sender stops opening new streams; receiver may finish in-flight
}

// ---- data-stream preamble (first & only frame before raw bytes) ----
type StreamOpen struct {
    Kind       string `json:"kind"`        // "http" v1; "tcp" later — raw bytes follow either way
    Host       string `json:"host"`        // which binding this request targets
    ReqID      string `json:"req_id"`      // edge-minted ULID; correlates edge logs ↔ inspector entries
    ClientAddr string `json:"client_addr"` // public client ip:port — carried now because Kind:"tcp"
                                           // will have no X-Forwarded-For to smuggle it in
}
```

**Raw-TCP future-proofing:** the corner we refuse to paint into is `Bind.Kind` and `StreamOpen.Kind`. A future `Bind{Kind:"tcp", …}` returns a port in `BindOK`, and `StreamOpen{Kind:"tcp"}` is followed by raw bytes instead of HTTP/1.1 bytes; `ClientAddr` already carries what XFF cannot. No framing, versioning, or handshake changes required. Be honest about what this does **not** buy: the "raw HTTP/1.1 bytes inside the stream" choice permanently forecloses native gRPC (trailers + full-duplex h2) and h2c backends for `Kind:"http"` — that is a real v1 protocol limitation, catalogued in §9's out-of-scope list, not a two-field tweak away.

### Protocol rules

- **Reply correlation (frozen in M0):** a reply carries the **same `Msg.ID` as the request it answers** — `AuthOK` echoes `Auth`'s ID, `BindOK` echoes `Bind`'s, `Pong` echoes `Ping`'s. The odd/even per-direction ID spaces exist *only* so both peers can **initiate** without colliding; they do not apply to replies. Minting a fresh ID for a reply would leave the requester correlating by arrival order, which breaks the moment two requests are in flight.
- **Versioning:** single integer protocol major. Client offers a set, server picks the max intersection in `AuthOK`. Additive JSON fields never bump the version (unknown fields are ignored); semantic changes do. v1 ships as `1`. Within a negotiated version, an unknown `Msg.Type` or malformed frame on the control stream gets a generic `Error{unknown_type|malformed}` and then session close — never a silent ignore.
- **Auth:** first message must be `Auth` within 5 s of TLS establishment or the edge closes the conn. Token check is `subtle.ConstantTimeCompare` against the SHA-256 of the configured token. Failures are logged with source IP and rate-limited (max 5 auth attempts / IP / minute).
- **Subdomain assignment & conflict — takeover is authorized by identity, not liveness.** Names validated as `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`, denylist `{www, mail, ns1, ns2, admin, api-edge}`. Every binding records the holder's `Auth.InstanceID`. `Bind` on a name held by another binding resolves as: **(a)** requester's `instance_id` equals the holder's (same agent process reconnecting past a half-open zombie) → takeover succeeds *immediately*, regardless of whether the zombie still looks alive; **(b)** different `instance_id` but the holder's session is dead → takeover succeeds; **(c)** different `instance_id` and the holder is live → `BindErr{subdomain_taken}` — two laptops shouldn't silently fight, and liveness is only consulted in this one case. On any successful takeover the edge sends the old session `Evicted{hostname, reason:"takeover"}`, force-closes it, and rebinds atomically under the registry lock; the evicted agent updates its status line instead of advertising a URL it no longer owns. The agent reconnect flow always sends `Takeover:true` — rule (a) is what makes reconnect-after-partition instant instead of waiting out the 45 s dead-peer window. (An earlier draft gated takeover on the holder being *dead*, which deadlocked the exact half-open-TCP case takeover exists to solve.)
- **Dead-peer detection:** transport layer — yamux keepalive ping every 10 s, with `ConnectionWriteTimeout: 45s` as the session kill switch (§2 — it guards all sends, so it must not be tight); application layer — control-stream `Ping` every 15 s, 3 consecutive misses (45 s) → session torn down, bindings released. Both layers converge on ≈45 s worst-case detection; rule (a) above means the *owner's own* recovery never waits on it.
- **Graceful shutdown:** on SIGTERM the agent sends `Goodbye{drain_ms:15000}` (fire-and-forget, see schema note), the edge immediately unroutes its hostnames (new requests → 404), then waits on that session's in-flight accounting — a per-session `sync.WaitGroup` (§5), not guesswork — racing a 15 s timer, then closes. Edge shutdown mirrors it: `Goodbye` to all agents, unroute, drain, `http.Server.Shutdown`.

---

## 4. TLS & certificates

**Decision: `github.com/caddyserver/certmagic` with DNS-01 via a `libdns` provider.**

- **Why DNS-01:** wildcard certs (`*.ngstone.site`) are only issuable via DNS-01 — HTTP-01/TLS-ALPN-01 cannot do wildcards, and per-subdomain on-demand issuance would leak every tunnel name into CT logs and burn LE rate limits. One wildcard cert covers every *tunnel* forever — but not the apex, see below.
- **Why certmagic over alternatives:** `x/crypto/acme/autocert` has no DNS-01 support — disqualified. Raw `go-acme/lego` works but leaves renewal scheduling, storage locking, and OCSP to us; certmagic is the production core of Caddy and gives all of it in ~20 lines. Rejected "just run certbot + cron" because it adds an external moving part and a reload dance to a single-binary system.
- **DNS provider:** concrete pick `github.com/libdns/cloudflare` (scoped API token, `Zone:DNS:Edit` on the one zone only). Any libdns provider is a one-line swap — the only pluggable seam in the TLS stack.
- **Config:** `DNS01Solver{DNSManager{DNSProvider: &cloudflare.Provider{APIToken: …}}}`, plus `certmagic.DefaultACME.Agreed = true` and `.Email = …` (both required in practice; without them issuance fails at the ACME account step). **Storage:** `certmagic.FileStorage{Path: "/var/lib/private/ngstoned/certs"}` (see the systemd note in M3 — the path is not arbitrary), dir `0700`. In-memory *state* only per the constraints — cached certs on disk are operational material, not state, and mean an edge restart never blocks on Let's Encrypt.
- **Two certificates, not one.** `certmagic.ManageSync(ctx, []string{"*.ngstone.site", "ngstone.site"})` reads like one multi-SAN cert. It is not: **CertMagic does not obtain multi-SAN certificates** — that call places *two independent ACME orders* producing two certs with two independent renewal schedules. This is forced anyway, because **`*.ngstone.site` does not match SNI `ngstone.site`** (RFC 6125: a wildcard covers exactly one left-most label). So the apex cert is not a nicety — it is the certificate the **control plane on :4443 depends on**, and it can fail independently of the wildcard. An earlier draft's "same wildcard cert, one cert path, zero extra ops" was wrong on both counts.
  - Consequence to design for: if the apex order fails (rate limit, DNS hiccup) the wildcard can be perfectly healthy — public traffic looks fine while **no agent can connect**. `ngstoned` therefore performs a **startup check that a valid apex cert is loadable before :4443 begins accepting**, and fails loudly (non-zero exit, explicit log) rather than listening with a cert it cannot serve. `/healthz` reports both certs' NotAfter separately.
  - Both names validate through the **same** `_acme-challenge.ngstone.site` TXT record. Overlapping renewals can therefore have one order's provider-cleanup delete the *other* order's in-flight record. CertMagic serializes issuance per-name but not per-DNS-record, so stagger the two names' renewal windows (offset the apex by a week via an initial manual issuance) and treat a renewal failure as a paging-worthy log line, not a warning.
  - **Pin `certmagic` and `libdns/cloudflare` to exact versions.** The libdns v1 interface migration (`libdns.RR`) versus certmagic's expected provider interface is a live, recurring source of "it compiled last month" breakage. This is the one dependency pair in the project where a `go get -u` can take the edge down.
- **Control-plane TLS (:4443):** served by the **apex** cert (`ngstone.site`), a different certificate from the public wildcard, via `tls.Config.GetCertificate`. Agents connect to `ngstone.site:4443`.
- **Agent-side verification:** standard WebPKI validation (`ServerName: "ngstone.site"`, system roots). **Optional SPKI pin** (`--pin sha256/BASE64`) checked in `VerifyPeerCertificate` *in addition to* chain validation; off by default because pins + auto-renewing certs is a footgun (pin the *key* and reuse it across renewals via certmagic's key reuse if enabled — document loudly).
- **Agent authentication is the bearer token,** not client certs. Rejected mTLS: adds a private CA, issuance, and rotation ceremony for a single user with zero security gain over a 256-bit token inside TLS.

Token hygiene: generated once via `ngstone token new` (32 random bytes, base64url). Edge config stores the SHA-256 (`token_sha256 = "…"`); env var `NGSTONE_TOKEN` on the agent. Plaintext token never lives on the VPS disk.

---

## 5. Edge server internals (`ngstoned`)

### Listeners

| Addr | Purpose |
|---|---|
| `:443` | Public traffic. `tls.Config` from certmagic; `NextProtos: ["h2","http/1.1"]`. One `http.Server`. |
| `:80` | `301` → `https://` (same host+path). Nothing else — DNS-01 means no ACME traffic here. |
| `:4443` | Control plane. Raw `tls.Listener`; accept → 5 s handshake deadline → yamux server session → control-stream auth loop. |
| `127.0.0.1:4041` | Ops endpoint: `expvar` counters, `/healthz`, pprof. Loopback only; reach via `ssh -L`. |

### Routing table

```go
// internal/edge/registry.go
type Registry struct {
    mu        sync.RWMutex
    byHost    map[string]*Binding                       // key: full lowercase hostname
    bySession map[*AgentSession]map[string]struct{}     // ownership index — MUST live here, not on
                                                        // AgentSession, so it is covered by this mutex
}
type Binding struct {
    Hostname   string
    Sess       *AgentSession   // owns the yamux session + a dedicated http.Transport
    InstanceID string          // holder's Auth.InstanceID — authorizes takeover (§3)
    BoundAt    time.Time
    transport  *http.Transport // DialContext → Sess.OpenStream; DisableKeepAlives
}
func (r *Registry) Route(host string) (*Binding, bool)
func (r *Registry) Bind(host string, s *AgentSession, takeover bool) (*Binding, error)
func (r *Registry) ReleaseSession(s *AgentSession) // idempotent; compare-and-delete, see below
```

**Concurrency model: `sync.RWMutex` over a plain map.** Rejected `sync.Map` (untyped, tuned for disjoint-key churn we don't have) and lock-free copy-on-write (complexity with zero payoff — reads are a sub-microsecond `RLock`+lookup, writes happen a few times an hour).

**Two rules that are not optional, both learned the hard way:**

1. **`ReleaseSession` must compare-and-delete, never blind-delete.** The obvious implementation — iterate the session's hostnames and `delete(byHost, h)` — is a use-after-takeover bug. Session A is evicted, B binds `api`, and 20 s later A's read loop finally notices it is dead and deletes `api` *out from under B*. The public URL goes dark while B sits there believing it is bound. Correct:

   ```go
   func (r *Registry) ReleaseSession(s *AgentSession) {
       r.mu.Lock(); defer r.mu.Unlock()
       for h := range r.bySession[s] {
           if b, ok := r.byHost[h]; ok && b.Sess == s { // ← the guard that matters
               delete(r.byHost, h)
           }
       }
       delete(r.bySession, s)
   }
   ```
   It is called from the session-death path *and* from graceful drain, possibly both, so it must be idempotent.

2. **Ownership lives in the `Registry`, not on `AgentSession`.** An earlier draft kept `bindings []*Binding` on `AgentSession`, appended by `Bind` and ranged over by `ReleaseSession` — two goroutines, no shared lock, a data race that directly contradicts §11's "all registry mutations behind one mutex". `bySession` is the fix: one mutex genuinely covers all mutable routing state.

**In-flight requests are counted.** Each `AgentSession` carries a `sync.WaitGroup` incremented in the transport's `DialContext` and decremented on stream close. This is required for graceful drain (§3) — knowing when in-flight reaches zero is by definition per-session accounting, and an earlier draft's "no reference counting needed" only ever held for the *ungraceful* path, where broken streams fail on their own. Drain = unroute, `wg.Wait()` racing a 15 s timer, close.

### Public-side protocol handling

- **HTTP/1.1 and h2:** both terminate in the stdlib `http.Server`; the handler sees a normalized `*http.Request` either way. Inside the tunnel everything is HTTP/1.1 — `httputil.ReverseProxy` does the h2→h1.1 downgrade for free.
- **WebSocket:** `ReverseProxy` handles `Connection: Upgrade` natively (hijacks, completes the 101, then bidirectional-copies) — the upgraded byte stream rides the same per-request yamux stream, which lives as long as the socket. **Caveat:** WS-over-h2 (RFC 8441 extended CONNECT) is not enabled; browsers fall back to HTTP/1.1 for WS automatically. Documented, not worked around.
- **Header rewriting — use `Rewrite` + `SetXForwarded()` here, and understand *why* it works.** When `Rewrite != nil`, `ReverseProxy` **unconditionally deletes** `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host` and `X-Forwarded-Proto` from the outbound request *before* calling your func. On the edge that delete is exactly what we want: it destroys inbound spoof attempts, and `pr.SetXForwarded()` then stamps the truth. (`SetXForwarded` *appends* to any prior XFF — it is only safe because the delete already ran. Do **not** "improve" the edge by switching to `Director`; you would silently start trusting attacker-supplied XFF.) `X-Real-IP` is not in the delete set — strip it explicitly. **`Host` is preserved** (forwarded as the public hostname) — ngrok's default, and what OAuth callbacks/vhost routers expect; `--host-header=localhost:3000` on the agent rewrites it for picky apps. **The agent-side proxy needs the opposite treatment** — see §6, where this same behavior is a footgun.
- **Streaming:** `FlushInterval: -1`; request and response bodies are never buffered on the edge.

### Timeouts & limits (all flag-overridable)

| Knob | Value | Guards against |
|---|---|---|
| `ReadHeaderTimeout` | 10 s | slowloris |
| `IdleTimeout` (public keep-alive) | 120 s | fd exhaustion |
| `MaxHeaderBytes` | 64 KiB | header bombs |
| Declared body cap (`ContentLength` check, pre-proxy) | 256 MiB → real `413` | abuse |
| Streaming body cap (`MaxBytesReader` + `ErrorHandler`) | 256 MiB → `413` via `*http.MaxBytesError` | chunked abuse |
| Dial-to-agent (stream open + preamble) | 5 s → `502` | wedged session |
| `ResponseHeaderTimeout` (transport to agent) | 30 s → `504` | hung local app |
| Post-header response duration | **unlimited** | (deliberate: SSE/downloads; client disconnect cancels the request context) |
| Per-IP rate limit (`golang.org/x/time/rate`) | 20 req/s, burst 50; LRU of 10k IPs | scrapers, dumb DoS |
| Global in-flight semaphore | **64** | total memory ceiling — see the window budget below |
| Per-session concurrent streams | **48**, own semaphore → `429` | one tunnel monopolizing the edge |
| yamux `AcceptBacklog` | **512** (deliberately *above* both caps) | see note |
| **Peak tunnel buffering** | 64 × 1 MiB = **64 MiB** per side | the largest buffer in the system |
| :4443 concurrent TLS handshakes | 16 | unauthenticated handshake flood |
| :4443 unauthenticated sessions | 32 | slow-auth session hoarding |

**The window budget is the real memory ceiling.** yamux allocates a receive buffer per stream that can grow to `MaxStreamWindowSize`. At the original numbers — 1 MiB windows × 512 global in-flight — that is **512 MiB per session, on both the VPS and the laptop**, dwarfing everything else and invalidating §9.7's "every buffer has a cap" and §6's ~100 MiB figure as system-level claims. It appeared nowhere in the original table. Resolution: keep the 1 MiB window (it is what makes single-stream throughput tolerable at 100 ms RTT) and **cut global in-flight to 64**, giving a stated 64 MiB peak. For a single-user tunnel, 64 concurrent in-flight requests is generous; if you ever need more, the trade is explicit — drop to the 256 KiB default window and raise the cap.

**`AcceptBacklog` is not a concurrency limit** — an easy and expensive misreading. On the receiving side it is the depth of `acceptCh`, and when full, `incomingStream()` **RSTs the new stream** ("Backlog exceeded"); on the opening side it is a semaphore over *un-ACKed SYNs*, released in `establishStream()`. Using it as the per-tunnel cap means bursts get RST → a `502` the client cannot interpret, instead of the `429` we intend. So: enforce concurrency with our own per-session semaphore (48) beneath the global one (64), and set `AcceptBacklog` comfortably *above* both (512) so it never becomes the binding constraint.

**The `413` path needs care, because the obvious one returns `502`.** With the body streaming through `RoundTrip`, a `MaxBytesReader` trip surfaces as a request-body read error *inside* `RoundTrip` → `ErrorHandler` → `StatusBadGateway`, and by then the agent has already received the headers and 256 MiB of body. Two mechanisms, in order: (1) reject on `r.ContentLength > cap` **before proxying** — this is the real 413, and it covers every well-behaved client; (2) for chunked/unknown-length bodies, keep `MaxBytesReader` and have a custom `ErrorHandler` type-check `*http.MaxBytesError` to emit `413` and close the connection — documenting that in this path the agent may already have seen a partial body and the local app a partial request.

Unknown-host requests short-circuit to a static `404` before any limiter/proxy work — cheapest path for scanner noise, and identical for "never existed" vs "agent offline" (no enumeration oracle).

---

## 6. Agent internals (`ngstone`)

One process = one tunnel + one inspector (`ngstone http 3000 --subdomain api`). Multiple tunnels → multiple processes (`--inspect-port` to avoid the 4040 collision). Rejected multi-tunnel-per-process for v1: complicates CLI, config, and inspector UX for a need met by a second terminal tab.

### Pipeline

```
yamux stream ─► streamListener (net.Listener adapter)
             ─► http.Server{Handler: capture(proxy)}
                        │
      capture: tee req/resp into Store    proxy: ReverseProxy → http://localhost:3000
                        │                        Transport{MaxIdleConnsPerHost: 8,
             inspector 127.0.0.1:4040             IdleConnTimeout: 90s,
              (embed.FS UI + SSE + replay)        ForceAttemptHTTP2: false}
```

- **Local forwarding:** `httputil.ReverseProxy` with a single pooled `http.Transport` to the local app. `FlushInterval: -1` here too. Local dial failure → agent synthesizes a `502` *with a helpful body* ("ngstone: nothing listening on localhost:3000").
- **The agent's proxy must copy the forwarding headers explicitly. `Director` alone is NOT sufficient** — corrected in M1 after the behavior was observed directly. In the `Rewrite == nil` path, `ReverseProxy.ServeHTTP` *still appends* `req.RemoteAddr`'s IP to `X-Forwarded-For`. Because the agent's `streamConn` reports the preamble's `ClientAddr` as `RemoteAddr` (the whole point of carrying it), that append **duplicates the client**: the local app receives `X-Forwarded-For: 203.0.113.9, 203.0.113.9`, and any rightmost-trusted-hop parser then treats the client's own IP as a trusted proxy. The correct construction is a `Rewrite` that sets the target URL and **copies `Forwarded` and `X-Forwarded-{For,Host,Proto}` from `pr.In` to `pr.Out` verbatim**, never calling `SetXForwarded`. Note this supersedes the original reasoning below, which assumed the agent had only a synthetic yamux address to offer:
- **(Superseded rationale, kept because the underlying stdlib behavior still bites.)** `Director` vs `Rewrite` on the agent (§5). `Rewrite` deletes `Forwarded`/`X-Forwarded-For`/`X-Forwarded-Host`/`X-Forwarded-Proto` before your func runs. On the edge that is a feature; here it would **destroy the client IP the edge just stamped**, and §9.5's promise that "the local app can trust them" would be a lie. Worse, the reflexive fix — calling `SetXForwarded()` on the agent — stamps the *yamux stream's* synthetic `RemoteAddr` as the client IP, so the local app confidently logs a fake address. Rules: the agent uses `Director`, or a `Rewrite` that explicitly copies those four headers from `pr.In` to `pr.Out`; the agent **never** calls `SetXForwarded`. An e2e assertion that the local app observes the *browser's* real IP belongs in M4 — this bug is invisible until someone reads their access log and believes it.
- **Session loop:** dial `ngstone.site:4443` → TLS → yamux client → open control stream → `Auth`/`Bind` → then `for { AcceptStream() }`, each stream: read preamble, hand to the HTTP server. Control-stream reader handles `Pong`/`Goodbye`; any session error tears everything down and enters the backoff-reconnect loop (§2). The CLI status line is driven by session-state events.

### Capture pipeline (the part that must not wreck streaming)

Design rule: **capture observes, never gates.**

- Request body: wrapped in a `cappedTee` — an `io.Reader` that copies bytes into `buf` until the 256 KiB cap, then sets `Truncated=true` and passes bytes through untouched. Streaming throughput unaffected (a memcpy on the same goroutine, not a pipe). **The buffer grows geometrically up to the cap; it is not preallocated.** `make([]byte, 0, 256<<10)` per body would be 256 KiB eagerly allocated to capture a 200-byte JSON response, ×2 per exchange, ×64 concurrent — 32 MiB of garbage to hold a few kilobytes of actual data.
- Response: `http.ResponseWriter` wrapper recording status + headers + the same capped tee on writes; it forwards `Flush()` and `Unwrap()` (for `ResponseController`) so SSE flushing and hijack still work. *(Verified against Go 1.25 source: `ReverseProxy` reaches `Hijack` via `http.NewResponseController(rw)`, which walks `Unwrap()` — so this genuinely works, and `flushInterval()` already forces `-1` for `text/event-stream` and `ContentLength == -1` even if you forget to set it.)*
- **WebSockets bypass the capture wrapper entirely — handle them explicitly or they record blank.** `handleUpgradeResponse` hijacks (via `Unwrap`, reaching the raw yamux stream) and then writes the 101 *and every subsequent byte* directly to the hijacked conn. The wrapper never sees `WriteHeader`, never sees a single `Write`. Left alone, every WS entry in the inspector shows status `0`, no response headers, an empty body, and a `Duration` equal to the socket's lifetime — with **nothing emitted to SSE until the socket closes, possibly hours later**. This is the nastiest defect in the design because every interface assertion passes: §11's "exercised by `httptest` interface-assertions" would not catch it. Fix: the capture wrapper records the hijack in its `Hijack`/`Unwrap` path and **finalizes an `Exchange{Kind:"upgrade"}` immediately at 101 time** with the request and response headers, so the entry appears the instant the socket opens; byte counts are updated afterwards via a counting `net.Conn` wrapper. WS frame payloads are **never** teed into the 256 KiB body buffer — a long-lived socket would otherwise pin one indefinitely.
- **Decode `Content-Encoding` for display, keep raw bytes for replay.** Captured bodies are whatever the app sent — for most real apps, `gzip`. With only a content-type/UTF-8 sniff, every gzipped JSON response renders as a hex dump, which makes the inspector useless on precisely the apps you care about. Decompress for the UI; store the raw bytes; and on replay send the *original* request without re-applying an encoding the client didn't ask for.
- On completion, an immutable `*Exchange` is finalized into the store:

```go
// internal/inspect/store.go
type Exchange struct {
    ID        string        // ULID (see §7 — the monotonic entropy reader needs locking)
    ReqID     string        // from StreamOpen.ReqID — joins this entry to the edge's logs
    Kind      string        // "http" | "upgrade" (WebSocket: finalized at 101, not at close)
    Start     time.Time
    Duration  time.Duration
    Req       CapturedReq   // method, URL, proto, header, body []byte, bodySize int64, truncated bool
    Resp      CapturedResp  // status, header, body []byte, bodySize, truncated
    Replayed  bool          // true if created via replay
    Err       string        // non-empty if the exchange failed
}
type Store struct {
    mu   sync.Mutex
    ring []*Exchange                  // fixed cap 200, overwrite-oldest
    head int
    subs map[chan *Exchange]struct{}  // SSE fan-out; slow subs get dropped, never block
}
```

Hard memory ceiling for the store: 200 × (2 × 256 KiB) ≈ 100 MiB *worst case*, and far less in practice now that buffers grow on demand rather than being preallocated. Note this is the **inspector's** ceiling only — the system-level ceiling is dominated by the yamux window budget in §5. Binary bodies (after `Content-Encoding` decoding) are detected by content-type/UTF-8 sniff and rendered as hex preview.

### Inspector UI & replay (`127.0.0.1:4040`)

- **One embedded HTML file** (`embed.FS`), vanilla JS + `EventSource`. No framework, no build step, no npm — a request table and a detail pane don't justify a toolchain in a Go repo.
- API: `GET /api/exchanges`, `GET /api/exchanges/{id}`, `POST /api/exchanges/{id}/replay`, `GET /api/events` (SSE), `GET /api/status`.
- **Replay:** reconstructs the request from the capture (method, URL path+query, headers minus hop-by-hop, body) and sends it **directly to the local app** through the same pooled transport — not through the edge (deterministic, works offline, tests the app rather than the tunnel). Result enters the store flagged `Replayed: true`. Truncated bodies → replay disabled with an explanatory tooltip. "Edit & replay" lets you tweak method/headers/body first.
- **Local security:** binds `127.0.0.1` only; mutating endpoints require header `X-Ngstone: 1` and an `Origin` check — kills cross-site `POST` replay and DNS rebinding.

---

## 7. Repository layout & core types

```
ngstone/
├── go.mod                          # module github.com/owner/ngstone; go 1.25
├── cmd/
│   ├── ngstoned/main.go            # edge: flags/env → edge.Server → run
│   └── ngstone/main.go             # CLI: subcommands http|token|version (stdlib flag; no cobra — 3 verbs)
├── internal/
│   ├── proto/
│   │   ├── proto.go                # Msg envelope + all message structs (§3)
│   │   └── framing.go              # ReadMsg/WriteMsg: uint32-BE length + JSON, 64 KiB cap
│   ├── tunnel/
│   │   ├── session.go              # Session over yamux; OpenStream/AcceptStream with preamble handling
│   │   └── listener.go             # streamListener: net.Listener adapter over accepted streams
│   ├── edge/
│   │   ├── server.go               # wires listeners, certmagic, registry, proxy; Run(ctx)
│   │   ├── registry.go             # Registry/Binding (§5)
│   │   ├── control.go              # :4443 accept loop, auth handshake, bind/ping/goodbye state machine
│   │   ├── proxy.go                # public handler: route → limits → ReverseProxy; error pages
│   │   ├── tlsconf.go              # certmagic + libdns/cloudflare wiring
│   │   └── limits.go               # per-IP limiter LRU + global semaphore
│   ├── agent/
│   │   ├── agent.go                # lifecycle: dial/auth/bind/accept + reconnect backoff loop
│   │   ├── proxy.go                # local ReverseProxy + pooled transport + capture hook
│   │   └── status.go               # session state events → CLI output
│   ├── inspect/
│   │   ├── store.go                # Exchange ring buffer + SSE fan-out
│   │   ├── capture.go              # cappedTee reader, ResponseWriter recorder middleware
│   │   ├── replay.go               # rebuild & resend captured requests
│   │   ├── server.go               # 127.0.0.1:4040 HTTP API
│   │   └── ui/index.html           # embedded single-file UI
│   ├── config/config.go            # flags+env for both binaries (no config-file dep in v1)
│   └── version/version.go          # ldflags-injected version string
└── Makefile                        # build, test, cross-compile linux/amd64, deploy scp target
```

**Dependency budget (exhaustive):** `hashicorp/yamux`, `caddyserver/certmagic` + `libdns/cloudflare` (**both pinned to exact versions** — §4), `golang.org/x/time/rate`, `golang.org/x/sync/errgroup` + `semaphore`, `hashicorp/golang-lru/v2` (the per-IP limiter's 10k-entry LRU — an earlier draft called the list exhaustive while quietly needing this), `oklog/ulid/v2`. Everything else is stdlib (`net/http`, `httputil`, `crypto/tls`, `compress/gzip`, `log/slog`, `embed`, `expvar`).

> `ulid`'s monotonic entropy reader is **not goroutine-safe**. IDs are minted concurrently on both the edge (per request) and the agent (per exchange), so wrap it in `ulid.LockedMonotonicReader` — or accept torn IDs under load, which is exactly the kind of bug that only shows up in the artifact you use to debug other bugs.

### Core interfaces & structs (the load-bearing five)

```go
// internal/tunnel/session.go — the transport seam (yamux today, QUIC someday)
type Session interface {
    // OpenStream opens a data stream and writes the preamble. Edge-side hot path.
    // ctx is honored by us, NOT by yamux: see §2 — the open runs in a goroutine and
    // the stream is closed if ctx wins the race, or it leaks with its SYN slot.
    OpenStream(ctx context.Context, pre proto.StreamOpen) (net.Conn, error)
    // AcceptStream blocks for the next inbound data stream, preamble already parsed. Agent-side.
    AcceptStream() (net.Conn, proto.StreamOpen, error)
    Control() *proto.Conn        // framed Msg codec over the dedicated control stream
    Done() <-chan struct{}       // closed when the session is dead, any cause
    Close(reason string) error
}

// internal/proto/framing.go — one codec, both binaries
type Conn struct { /* rw net.Conn; wmu sync.Mutex */ }
func (c *Conn) Read() (Msg, error)
func (c *Conn) Write(typ string, id uint64, data any) error

// internal/edge/control.go — server-side view of one authenticated agent
type AgentSession struct {
    ID         string        // session id, minted per connection
    InstanceID string        // from Auth — stable across this agent process's reconnects (§3)
    Sess       tunnel.Session
    Remote     netip.AddrPort
    inflight   sync.WaitGroup // per-session request accounting; required for graceful drain (§5)
    // NOTE: owned hostnames deliberately live in Registry.bySession, under the registry
    // mutex — keeping them here was a data race against ReleaseSession.
}

// internal/edge/registry.go
func (r *Registry) Bind(host string, s *AgentSession, takeover bool) (*Binding, error)

// internal/inspect/store.go
func (s *Store) Add(e *Exchange)
func (s *Store) Subscribe(ctx context.Context) <-chan *Exchange
```

---

## 8. Failure modes

| Failure | Detection | Handling |
|---|---|---|
| **Agent process dies mid-request** | Stream read/write error on edge (session RST) | In-flight requests → `502` error page immediately; session `Done()` fires; `ReleaseSession` **compare-and-deletes** hostnames (§5) → subsequent requests get the cheap `404`. No replay (§2). A restarted agent gets a *new* `InstanceID`, so it reclaims its name via the dead-holder rule, not the same-identity rule. |
| **Edge restarts** (deploy, OOM, reboot) | Agent's control read / keepalive errors | All state rebuilt by clients: agent backoff-reconnects, re-`Auth`s, re-`Bind`s with `Takeover:true` → same URL, typically < 2 s downtime with `systemd Restart=always`. Certs come from the `StateDirectory` cache — **provided the systemd unit is correct** (M3); get it wrong and every restart re-issues against LE rate limits. |
| **Network partition** (laptop sleeps, ISP blip) | yamux keepalive or 3 missed app pings (≈45 s either way) | Edge frees bindings (→ 404s). The agent does **not** wait for that: on reconnect its unchanged `InstanceID` matches the zombie binding's, so takeover rule (a) rebinds immediately even while the old session still looks alive (§3). The zombie is sent `Evicted` and force-closed. |
| **Slow/hung local app** | `ResponseHeaderTimeout` 30 s | `504` to the public client; tunnel/session unaffected. Post-header slowness is legal (streaming) and bounded by client patience + flow control. |
| **Saturated uplink during a large transfer** | yamux `ErrConnectionWriteTimeout`, logged verbatim | With `ConnectionWriteTimeout` at 45 s rather than 10 s, a stalled send no longer kills the whole session (§2). If it *does* fire, the verbatim log distinguishes "we killed it" from a real disconnect — otherwise this presents as "the tunnel randomly drops under load", which is miserable to diagnose. |
| **Oversized request body** | `ContentLength` pre-check; else `MaxBytesReader` + `ErrorHandler` | Declared-length → real `413`, nothing crosses the tunnel. Chunked → `413` synthesized from `*http.MaxBytesError`, with the caveat that the agent may already have forwarded a partial body (§5). The naive `MaxBytesReader`-only design returned `502` *after* shipping 256 MiB. |
| **Subdomain collision** | `Registry.Bind` under lock | Different `InstanceID` + live holder → `BindErr{subdomain_taken}`; agent prints the error and exits non-zero (explicit name) or retries with a fresh random name (auto-assigned). Same `InstanceID`, or dead holder → `Takeover` succeeds, old session gets `Evicted`. |
| **Apex cert fails to issue/renew** | Startup check + `/healthz` per-cert `NotAfter` | Public traffic keeps working on the wildcard while **no agent can connect** — so `ngstoned` refuses to accept on :4443 without a loadable apex cert and exits loudly rather than failing mysteriously (§4). |
| **Token leak** | Anomalous auth source IPs in edge logs (every auth logged with IP + result) | Blast radius (§9): attacker can bind tunnels and serve content under your wildcard — no shell, no data. Recovery: set new `token_sha256`, restart — every session dies at reconnect-auth. Auth attempts per-IP rate-limited (5/min). |
| **Abusive public traffic** | Limiter counters on `expvar` | Layered: unknown-host fast-404 → per-IP token bucket `429` → global in-flight cap 512 → header/body/time limits. Volumetric DoS is the VPS provider's problem (accepted). Optional `--allow-cidr` flips a tunnel to allowlist-only. |

---

## 9. Security model

**Assets:** the laptop's local app + LAN foothold, the auth token, the wildcard domain's reputation, tunneled request/response data.

1. **Anonymous attacker with the public URL** — is exactly an anonymous HTTP client of the exposed local app, nothing more. They cannot reach the inspector (loopback-only), other localhost ports (only the configured target is dialed), or the control plane (token-gated). Residual risk is *inherent to tunneling*: if the local app is a debug server with RCE, the tunnel exposes it. Mitigations: fast-404 non-enumeration, per-IP rate limiting, and loud docs.
2. **Subdomain enumeration** — unknown and offline hosts return byte-identical 404s. The wildcard cert means individual tunnel names never appear in CT logs (a real advantage of DNS-01 wildcard over per-name issuance).
3. **Leaked token** — grants: bind any non-denylisted subdomain, receive that traffic, serve phishing under your domain. Does **not** grant: reading other tunnels' traffic in flight, edge shell access, cert/DNS control. Rotation is a config change + restart. Tokens never appear in logs (redacted at the slog layer); only the hash lives on the VPS.
4. **MITM agent↔edge** — TLS 1.3 with WebPKI validation (+ optional SPKI pin); token only ever sent inside the tunnel TLS.
5. **Header spoofing** — inbound `Forwarded`/`X-Forwarded-*` are stripped by `Rewrite` and replaced by `SetXForwarded` at the edge; `X-Real-IP` is stripped explicitly (it is not in the stdlib delete set). The local app can trust them **only if the agent-side proxy preserves them** — see §6, where the same stdlib behavior silently deletes them if you use `Rewrite` on the agent.
6. **Malicious web page attacking the inspector (CSRF / DNS rebinding)** — mutating endpoints require the `X-Ngstone` custom header (unsendable cross-origin without CORS approval) + Origin/Host validation on all inspector routes.
7. **Resource exhaustion** — every buffer has a stated cap, *including the yamux receive windows* (§5 table) that an earlier draft omitted while claiming completeness; no code path buffers an entire body. The unauthenticated surface on :4443 is separately capped (concurrent handshakes, unauthenticated sessions) so a stranger cannot hoard control-plane resources for the cost of a TCP connect.

Out of scope, accepted for a single-user v1:

- **Native gRPC and h2c backends.** The tunnel carries raw HTTP/1.1 bytes inside each stream, so gRPC's trailers and full-duplex h2 semantics cannot survive it — this is a structural protocol limitation, not a tuning problem, and supporting it later costs an h2-capable data path, not just a new `StreamOpen.Kind`. (§11 previously listed "gRPC-web that stalls" as a debugging smell, which badly understated this.)
- Volumetric DDoS beyond the VPS's capacity.
- Compromise of the VPS itself (it terminates TLS and sees plaintext — treat it as trusted infrastructure).
- OAuth-grade auth in front of tunnels (v1.1 candidate: edge-enforced basic auth per tunnel via a `Bind` option — the `Data` envelope permits it additively).

---

## 10. Build order

> **Sequencing note.** M3 originally put a wildcard on a public VPS with *zero* protection — no per-IP limit, no in-flight cap, no `MaxHeaderBytes`, no body cap, no `ReadHeaderTimeout`, no spoof-stripping (all M4). Scanners find a fresh wildcard within hours. The §5 limits table and header handling therefore move **into M3**; only the genuinely protocol-shaped work (WebSocket, SSE, branded error pages) stays in M4. Likewise the JSON-tag fixes in §3 are the one *non-additive* schema change, so they must land in M0 or they become a breaking change against a deployed agent.

- **M0 — Protocol core.** `internal/proto` complete: all message types **with correct json tags on every struct** (`AuthErr`/`BindErr`/`Unbind` had none — the only breaking fix in the set, so it lands here), per-direction `Msg.ID` spaces, `Error`/`Evicted`/`UnbindOK`, `StreamOpen.ReqID`/`ClientAddr`. Framed codec, round-trip + fuzz tests (`go test -fuzz` on `ReadMsg` — malformed frames must error, never panic or over-allocate). **Done:** in-memory pipe performs Auth→AuthOK→Bind→BindOK→Ping→Pong; an unknown `Msg.Type` yields `Error{unknown_type}` then close; fuzzer runs clean for 5 min.
- **M1 — Static tunnel, localhost.** `tunnel.Session` over yamux, minimal edge (plain TCP, no TLS, hardcoded token, single hardcoded binding) + minimal agent. **Done:** `curl -H 'Host: demo.ngstone.site' http://127.0.0.1:8443/` returns a response from a local test server across two processes; a 100 MB streamed body passes with constant memory (asserted via `runtime.MemStats` in an e2e test).
- **M2 — Real control plane.** Auth (hashed token, constant-time, `InstanceID`), dynamic bind/unbind, random-name assignment, identity-based takeover + `Evicted`, heartbeats, dead-peer detection, agent reconnect loop, per-session in-flight accounting and graceful drain. **Done:** the partition matrix is scripted and green — `kill -9` the agent mid-request (502 → 404 → recovery), **`SIGSTOP` the agent and reconnect from a second process with the same `InstanceID` (rebinds immediately, does not wait out the 45 s dead-peer window)**, `pfctl`/iptables DROP, edge restart; a *different* instance requesting a live name gets `subdomain_taken`; a takeover victim receives `Evicted` and stops advertising its URL; SIGTERM on either side drains in-flight requests to completion, then closes.
- **M3 — Production TLS + public exposure.** certmagic DNS-01 (LE **staging** first, then prod) for **both** the wildcard and the apex, apex-cert startup check gating :4443, :80 redirect, the full §5 timeout/limit table, per-IP limiter, global + per-session semaphores, header rewriting and spoof-stripping, :4443 handshake/unauthenticated-session caps, Makefile `deploy`. Systemd unit: **`StateDirectory=ngstoned`** (systemd owns the directory across restarts) with `FileStorage` pointed at `/var/lib/private/ngstoned/certs`, plus `AmbientCapabilities=CAP_NET_BIND_SERVICE` and `ProtectSystem=strict`. *`DynamicUser=yes` + `ReadWritePaths=/var/lib/ngstoned` — the original prescription — does not work: the dynamic UID changes across restarts, the directory ends up owned by a stale UID, the cert cache is effectively lost, and every restart re-issues against Let's Encrypt rate limits. `DynamicUser` also cannot bind :80/:443 without the ambient capability.* **Done:** `https://anything.ngstone.site` loads from a phone on LTE with a valid padlock; `systemctl restart` three times in a row serves the cached certs with zero ACME traffic (assert this — it is the check that catches the systemd bug); a synthetic flood gets `429`; a slowloris client is evicted at 10 s.
- **M4 — Real-web robustness.** WebSocket passthrough, SSE/chunked flushing, streaming correctness end to end, branded 404/502/504 pages, `413` on both the declared and chunked paths, expvar ops endpoint. **Done:** e2e suite passes a WS echo session, a 60 s SSE stream, a 1 GiB download at constant memory, a 300 MiB upload rejected with a real `413`, **and an assertion that the local app sees the browser's real IP in `X-Forwarded-For`** (the agent-side `Rewrite` footgun from §6).
- **M5 — Inspector + replay.** Capture middleware, ring store, 4040 API + embedded UI, SSE live view, replay + edit-and-replay, `Content-Encoding` decoding, CSRF protections. **Done:** localhost:4040 shows live entries with bodies while browsing the public URL; **a WebSocket appears in the list the moment it connects, not when it closes**; a gzipped JSON response renders as readable JSON, not hex; replaying a captured POST hits the local app identically (asserted by a recording test server); a streamed 50 MB response shows "truncated" and streams at full speed. Re-run the entire M4 suite through the inspector-wrapped path — this is the milestone most likely to silently break streaming.
- **M6 — Polish & cut v1.0.** CLI UX (`ngstone http 3000`, live status line, `token new`), `--host-header`, `--allow-cidr`, slog levels, `-ldflags` versioning, cross-compile matrix, README with threat-model notes. **Done:** a fresh VPS + fresh laptop go zero-to-shared-URL following only the README, in under 15 minutes.

---

## 11. The three things that will bite hardest

1. **The parts of `net/http` that do the right thing *around* your code instead of *through* it.** This is the theme behind the majority of the review's findings, and interface assertions do not catch any of them. `handleUpgradeResponse` hijacks and writes past your `ResponseWriter` wrapper, so WebSockets record blank (§6). `Rewrite` deletes `X-Forwarded-*` *before* your callback runs — correct on the edge, destructive on the agent (§5, §6). `MaxBytesReader` tripping inside `RoundTrip` becomes a `502`, not the `413` you wrote in the table (§5). **Avoidance:** for every stdlib hook, write down *when* it runs relative to your code, not just what it does; assert on observable behavior (does the local app see the real client IP? does the WS entry appear at connect time?) rather than on interfaces being present; run the whole M4 suite again through the M5 inspector path.
2. **The reconnect / zombie-binding state machine.** Half-open TCP means the edge can believe a dead agent is alive for tens of seconds while the real agent is trying to rebind its own name. Naive code either double-binds, locks the owner out of their own subdomain (the original liveness-gated takeover did exactly this), or lets a dying session's cleanup delete the *new* owner's binding. **Avoidance:** takeover authorized by `InstanceID`, not by liveness and not by token (§3); ownership state inside `Registry` under one mutex; `ReleaseSession` compare-and-deletes and is idempotent (§5); the partition matrix (`kill -9`, `SIGSTOP`, `pfctl`/iptables DROP, edge restart) scripted as e2e tests in **M2**.
3. **Unbounded memory hiding in "just a proxy" — including in the parts you didn't write.** Every tunnel OOM traces to a buffer someone didn't know they had. The original draft caught its own tees and fan-outs but declared "every buffer has a cap" while the **yamux receive windows** quietly allowed 512 MiB per session (§5) — the biggest buffer in the system, in a dependency, invisible in application code. **Avoidance:** the §5 limits table states the *product* (concurrency × window), not just per-item caps, and is a checklist enforced by tests; the M1 constant-memory assertion runs in CI forever; capture buffers grow geometrically and cannot exceed their cap by construction; SSE fan-out drops slow subscribers instead of blocking; `io.ReadAll` banned outside the inspector's capped paths via `forbidigo`.
