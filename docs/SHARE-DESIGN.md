# Secure temporary database sharing — design

**Status:** implemented · **Scope:** `ngstone share`, `ngstone connect`, protocol v3, edge share registry

Temporarily expose a local PostgreSQL, MySQL or Redis (or any TCP service) to named teammates without opening a public database port. Both sides run the `ngstone` agent and dial out to the edge over TLS; the edge joins the two sessions and copies bytes. Shares expire, carry access policies, and produce an audit trail in the sharer's terminal and in the edge log.

This document builds on [ARCHITECTURE.md](ARCHITECTURE.md) and reuses its vocabulary. Where it says "today", it describes the code before this feature landed.

---

## 1. Goals and non-goals

**Goals**

- Share a local TCP service with named teammates **without opening a port on the VPS reachable from the internet**. A share has no public listener: the only way in is a connector session authenticated by the link's secret.
- Encrypted on every hop the bytes cross the internet: from the sharer to the edge and from the connector to the edge, both over the existing control-plane TLS.
- Shares end on their own: a fixed expiry chosen by the sharer and enforced by the edge, plus instant revocation (Ctrl-C on the sharer).
- Access policies the sharer can state up front: which source networks may connect, how many connectors and connections at once, single-use links.
- Auditing: the sharer sees every connector join and leave and every connection open and close, with address, duration and byte counts. The edge logs the same events.
- Keep the project's principles: stdlib-first, one path per feature, everything flow-controlled, nothing unbounded in memory, no persistent state on the edge.

**Non-goals (v1)**

- **Named users or SSO.** The edge has no accounts. Identity is possession of a share link plus network policy. Adding identity providers is a separate project.
- **Query-level auditing or read-only enforcement.** That requires parsing each database's wire protocol. Use database roles for that; the share tells you who connected and when, the database tells you what they ran.
- **End-to-end encryption past the edge.** The edge terminates TLS on both sessions and copies bytes between them, so an operator who controls the VPS can read the traffic. Enable the database's own TLS (`sslmode=require` and friends) when the VPS is not fully trusted. Encrypting agent-to-agent is a possible follow-up and does not change this design's wire shape.
- **Durable, searchable audit history.** v1 writes events to the sharer's terminal, an optional local JSON Lines file, and the edge log.
- **A hosted multi-tenant service.** This is for teams that trust one edge that one of them operates, which is ngstone's single-operator model.

---

## 2. What the user sees

### Sharer

```
$ ngstone share postgres --expires 2h --label "staging replica"
share     staging replica  postgres  127.0.0.1:5432
expires   in 2h (14:03 UTC)   policy: allow all, 16 conns, 8 connectors
link      ngstone://example.com:4443/s/N7kq…Vb0Q

send the link to a teammate; they run:  ngstone connect <link>

14:01:02  share live         id sh_7f3a…
14:01:03  connector joined   203.0.113.9            id c1
14:01:04  conn #1   open     203.0.113.9            via c1
14:05:11  conn #1   closed   4m07s     12.3 MiB up   482.0 KiB down
```

`postgres`, `mysql` and `redis` are presets for ports 5432, 3306 and 6379 on `127.0.0.1`; an optional second argument overrides the target (`ngstone share postgres 5433`, `ngstone share postgres db.local:5432`). `ngstone share tcp 9000` and `ngstone share tcp host:port` share any other service. Ctrl-C revokes the share; connectors are told within a second and told why.

Flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--expires DURATION` | `1h` | Share lifetime, capped by the edge's `-max-share-ttl` (default 24h). |
| `--label TEXT` | preset name | Shown to connectors. |
| `--allow-cidr LIST` | allow all | Connector source networks, comma-separated CIDRs. |
| `--max-conns N` | 16 | Concurrent relayed connections across all connectors (edge cap 64). |
| `--max-connectors N` | 8 | Concurrent connector agents (edge cap 32). |
| `--single-use` | off | The link locks to the first connector agent that uses it. |
| `--audit-log PATH` | off | Append every audit event as a JSON line. |

Plus the usual `--server`, `--token`, `--insecure`, `--server-name`, `--pin`.

### Connector

```
$ ngstone connect ngstone://example.com:4443/s/N7kq…Vb0Q
connecting to example.com:4443
connected  "staging replica" (postgres)  expires in 1h58m (14:03 UTC)
listening  127.0.0.1:5432  ->  psql "postgres://127.0.0.1:5432/"
```

The connector opens a listener on the loopback interface only, on the preset's port, falling back to the next free port when that one is busy (`--port` overrides). Every local connection becomes one tunnel stream. When the share expires or is revoked, the connector prints why and exits with status 3; open database connections are cut.

The link carries the edge address, so no `ngstone auth` or config is needed on the connector's machine. `ngstone connect -` reads the link from standard input and `NGSTONE_SHARE_LINK` from the environment, for people who do not want the secret in shell history.

---

## 3. Architecture

### Roles

```
 sharer laptop                              VPS (ngstoned)                        teammate laptop
┌──────────────────────┐      TLS       ┌───────────────────────────┐      TLS      ┌──────────────────────┐
│ ngstone share        │───────────────►│ :4443 control             │◄──────────────│ ngstone connect      │
│  ├ control stream    │     yamux      │  ├ share registry         │     yamux     │  ├ control stream    │
│  └ tcpServer         │◄── stream ─────│  │  (hash → share)        │──── stream ──►│  └ 127.0.0.1:5432    │
│     → 127.0.0.1:5432 │                │  └ pipe: connector        │               │     listener         │
└──────────────────────┘                │     stream ⇄ sharer stream│               └──────────────────────┘
                                        └───────────────────────────┘
```

Both agents dial out, exactly as today's agent does. There is no new listener on the VPS. The edge never opens a public port for a share.

### How a connection flows

1. `psql` connects to `127.0.0.1:5432` on the teammate's machine.
2. The connector opens a yamux stream to the edge with the preamble `{"type":"stream_open","data":{"kind":"share","host":"sh_7f…","share_id":"sh_7f…","req_id":"…","client_addr":"127.0.0.1:51844"}}`.
3. The edge checks the stream belongs to a share the connector was admitted to, takes a slot from the share's connection semaphore, the connector session's stream budget, the sharer session's stream budget, the connector IP's per-IP cap and the global share-connection cap, then opens a stream to the **sharer's** session with the existing TCP preamble: `{"kind":"tcp","host":"sh_7f….share","req_id":"…","client_addr":"<connector ip:port>","share_id":"sh_7f…"}`.
4. The sharer agent's existing TCP server accepts the stream and dials its fixed target, `127.0.0.1:5432`. It does not read the host; the share path reuses it unchanged.
5. The edge copies bytes both ways with the same half-close and idle-timeout handling as TCP tunnels. Flow control is yamux's: a slow reader throttles the database's socket writes and nothing else.
6. Either side closing ends the connection. The edge reports duration and byte counts to the sharer.

What is new on the edge: it accepts streams **from** an agent for the first time. Today only the edge opens data streams. yamux is symmetric, so this is an accept loop per connector session, nothing more. Operator sessions share the same accept loop and close any stream they are sent, so a leaked token still cannot push streams into the edge.

### What is reused

| Need | Existing piece |
| --- | --- |
| Dial, TLS, pin, reconnect with backoff | `internal/agent` dial and backoff |
| Multiplexed streams, preamble framing | `internal/tunnel`, `internal/proto` |
| Accepting edge-opened streams and dialing the local target | `agent.tcpServer` (unchanged) |
| Byte piping with half-close and idle timeout | `edge.idleDeadline`, `closeWrite` |
| Per-session stream and in-flight budgets, drain | `AgentSession.streamSem`, `inflightTracker` |
| Per-IP concurrency cap and auth rate limiting | `perIPInflight`, `authRateLimiter` |
| Token hashing and constant-time comparison | `authenticate` |

---

## 4. Protocol (v3)

Protocol v3 is additive: new message types and new optional fields. An edge that only speaks v2 answers an unknown type with `error{unknown_type}` and closes, and the agent turns that into "this edge does not support sharing; upgrade `ngstoned`". Version negotiation is unchanged.

### Share secret and link

The **sharer** mints the secret: 32 random bytes, base64url without padding. The edge stores only its SHA-256, the same arrangement as the edge token.

```
ngstone://<edge-host>:<port>/s/<base64url(secret)>
```

`<edge-host>` doubles as the TLS server name, so a link cannot point a connector at an edge whose certificate says something else. `--insecure` on `ngstone connect` is the only way to reach a plaintext dev edge; the link never encodes it.

Because the sharer holds the secret, it can re-register the same share after a reconnect or an edge restart and the link keeps working. Connectors that lose the share (`sharer_gone`, `edge_shutdown`) retry with backoff until the expiry they were told at join time.

### New and changed messages

```go
// ---- sharer → edge ----
type Share struct {
    Kind          string   `json:"kind"`                     // "tcp"
    SecretSHA256  string   `json:"secret_sha256"`
    Label         string   `json:"label,omitempty"`
    Preset        string   `json:"preset,omitempty"`         // postgres | mysql | redis | tcp
    DefaultPort   int      `json:"default_port"`
    ExpiresAtMS   int64    `json:"expires_at_unix_ms"`
    MaxConns      int      `json:"max_conns,omitempty"`
    MaxConnectors int      `json:"max_connectors,omitempty"`
    SingleUse     bool     `json:"single_use,omitempty"`
    AllowCIDRs    []string `json:"allow_cidrs,omitempty"`
}
type ShareOK struct {
    ShareID     string `json:"share_id"`           // "sh_" + 16 hex
    ExpiresAtMS int64  `json:"expires_at_unix_ms"`
}
type ShareErr struct{ Code, Message string } // share_ttl_too_long, too_many_shares, share_taken,
                                             // invalid_share, feature_unsupported
type Unshare struct{ ShareID string }        // revoke now → UnshareOK

// ---- connector → edge ----
// Auth gains one field. Exactly one of Token and ShareSecret is set.
type Auth struct {
    Token         string `json:"token,omitempty"`
    ShareSecret   string `json:"share_secret,omitempty"`
    InstanceID    string `json:"instance_id"`
    ClientVersion string `json:"client_version"`
    ProtoVersions []int  `json:"proto_versions"`
}
// AuthOK gains Scope: "operator" (today's token) or "connector" (share secret).
type Connect struct{}                                 // "admit me to the share my secret names"
type ConnectOK struct {
    ShareID     string `json:"share_id"`
    ConnectorID string `json:"connector_id"`           // "c1", "c2", … per share
    Label       string `json:"label"`
    Preset      string `json:"preset"`
    DefaultPort int    `json:"default_port"`
    ExpiresAtMS int64  `json:"expires_at_unix_ms"`
}
type ConnectErr struct{ Code, Message string } // share_not_found, share_full, share_locked,
                                               // forbidden_cidr

// ---- edge → sharer (audit) ----
type ShareEvent struct {
    ShareID     string `json:"share_id"`
    Event       string `json:"event"` // connector_joined, connector_left, conn_open,
                                      // conn_close, conn_rejected, closed
    AtMS        int64  `json:"at_unix_ms"`
    ConnectorID string `json:"connector_id,omitempty"`
    ConnID      int    `json:"conn_id,omitempty"`
    ClientAddr  string `json:"client_addr,omitempty"`
    DurationMS  int64  `json:"duration_ms,omitempty"`
    BytesUp     int64  `json:"bytes_up,omitempty"`
    BytesDown   int64  `json:"bytes_down,omitempty"`
    Reason      string `json:"reason,omitempty"`
}

// ---- edge → connector ----
type ShareClosed struct {
    ShareID string `json:"share_id"`
    Reason  string `json:"reason"` // expired, revoked, sharer_gone, edge_shutdown
}

// ---- data-stream preamble gains one optional field ----
type StreamOpen struct {
    Kind       string `json:"kind"`        // "http" | "tcp" | "share"
    Host       string `json:"host"`
    ReqID      string `json:"req_id"`
    ClientAddr string `json:"client_addr"`
    ShareID    string `json:"share_id,omitempty"`
}
```

Reply correlation is unchanged: every reply carries the request's `Msg.ID`. `ShareEvent` and `ShareClosed` are notifications with edge-minted IDs, like `Evicted` today.

### A connector session, end to end

```
connector → edge   auth{share_secret, instance_id, proto_versions:[3,2,1]}
edge → connector   auth_ok{proto_version:3, scope:"connector"}
connector → edge   connect{}
edge → connector   connect_ok{share_id, connector_id:"c1", label:"staging replica", preset:"postgres", default_port:5432, expires_at}
edge → sharer      share_event{event:"connector_joined", connector_id:"c1", client_addr}
…
connector opens stream, preamble stream_open{kind:"share", share_id}
edge → sharer      share_event{event:"conn_open", conn_id:1, connector_id:"c1", client_addr}
edge opens stream to sharer, preamble stream_open{kind:"tcp", host:"sh_….share", share_id, client_addr}
… bytes …
edge → sharer      share_event{event:"conn_close", conn_id:1, duration_ms, bytes_up, bytes_down}
```

A connector-scoped session that sends `bind`, `share`, `unshare` or anything but `connect`, `ping`, `pong` and `goodbye` gets `error{forbidden}` and is closed. An operator session that sends `connect` gets the same.

---

## 5. Edge

### Share registry

`internal/edge/share.go`, in memory only, mirroring `Registry`:

```go
type share struct {
    id          string
    secretHash  [32]byte
    owner       *AgentSession            // sharer
    label, preset string
    defaultPort int
    expiresAt   time.Time
    policy      sharePolicy              // maxConns, maxConnectors, singleUse, allow []netip.Prefix
    lockedTo    string                   // instance id, single-use

    connectors  map[*AgentSession]*connectorInfo
    conns       map[*shareConn]struct{}
    connSem     *globalSemaphore         // policy.maxConns
    nextConnID, nextConnectorID int
    expiry      *time.Timer
    closed      bool
}

type shareRegistry struct {
    mu      sync.Mutex
    byHash  map[[32]byte]*share
    byID    map[string]*share
    byOwner map[*AgentSession]map[string]*share
    maxTTL  time.Duration                // -max-share-ttl, default 24h
}
```

Lookup by presented secret is `byHash[sha256(secret)]`. The hash of attacker-controlled input leaks nothing usable, and the existing auth rate limiter (5 failures per IP per minute) applies to share-secret authentication exactly as it does to tokens.

**Registration rules.** `share` from a sharer session:

- `expires_at` further out than now plus `-max-share-ttl` → `share_ttl_too_long`.
- More than 8 live shares on the session → `too_many_shares`.
- A share with this hash already exists and is **owned by a different instance_id** → `share_taken`. Same `instance_id` (the sharer reconnecting) replaces the old share; its connectors are told `sharer_gone` and reconnect on their own. This is the same identity-not-liveness rule as `Bind` takeover.
- Otherwise the share is registered, an expiry timer armed, and `share_ok` returned.

**Admission rules.** `connect` from a connector session, under the registry lock:

- share closed or expired → `share_not_found`
- connector address outside `allow_cidrs` → `forbidden_cidr`
- single-use and locked to another instance → `share_locked`
- `max_connectors` reached → `share_full`

**Teardown.** `closeShare(sh, reason)` is the one path: mark closed, remove from the maps, stop the timer, send the sharer `share_event{closed, reason}`, send every connector `share_closed{reason}`, give every relayed connection an immediate deadline, wait up to two seconds for the relays to report `conn_close`, then close the connector sessions. It is idempotent. It runs from the expiry timer (`expired`), `unshare` (`revoked`), the sharer's `goodbye` (`revoked`), the sharer's control loop exiting any other way (`sharer_gone`), and edge shutdown (`edge_shutdown`).

A connector session that ends removes it from its share and sends the sharer `connector_left` with the session duration.

### Relay admission, in order

Each connector stream is admitted against every budget it consumes, and each rejection is reported to the sharer as `conn_rejected` with the reason:

1. connector IP's `perIPInflight` (shared with HTTP and TCP tunnels)
2. global share-connection semaphore (256)
3. the share's `max_conns`
4. the connector session's per-session stream cap
5. the sharer session's per-session stream cap
6. share still live at registration time
7. stream open to the sharer within the 5 s dial budget

Both sessions' in-flight trackers count the relay, so graceful drain on either side waits for it.

### Limits

| Knob | Value |
| --- | --- |
| `-max-share-ttl` | 24h |
| shares per session | 8 |
| `max_conns` per share | 16 default, 64 max |
| `max_connectors` per share | 8 default, 32 max |
| global relayed connections | 256 |
| idle relayed connection | `-tcp-idle-timeout` (30 min) |
| label | 128 printable bytes |

Memory follows the §5 window budget in ARCHITECTURE.md: a relayed connection holds two yamux streams on the edge, so the stated ceiling is 256 × 2 × 1 MiB.

---

## 6. Agent

**Sharer mode** is the TCP agent with a `ShareSpec`: the handshake sends `share` instead of `bind`, the control loop forwards `share_event`s to the CLI, and the data path is the unchanged `tcpServer`. Expiry arrives as `share_event{closed, expired}` and ends the process cleanly. The spec's expiry is absolute, so re-registration after a reconnect keeps the original deadline, and the agent refuses to re-register a share that has already expired.

**Connector** (`agent.Connector`) is a new, small type: dial, `auth{share_secret}`, `connect`, then a loopback listener that lives for the process and relays each accepted connection over the session that is live at that moment. While disconnected, local connections are refused immediately rather than queued, the way a down database would. It reconnects with a slower backoff (2 s base) than the operator agent so a connector waiting for its sharer stays under the edge's auth rate limit, and it stops retrying once the expiry it was told has passed.

---

## 7. Security model additions

- **Link holder** can reach exactly one local service through the sharer's agent, for at most the share's lifetime, subject to the share's policy. They cannot bind tunnels, register shares, or open streams to anything but their share: connector sessions are scope-checked on every control message and every stream.
- **Edge token holder** gains nothing new: operator sessions cannot `connect` and any stream they push into the edge is closed.
- **Anyone on the network** sees TLS to the edge in both directions. There is no public port to scan; a share has no listener.
- **The VPS operator** sees plaintext, as with every tunnel. Use the database's own TLS when that matters.
- **Brute force** on the secret is 256 bits behind a per-IP rate limit; the limiter counts bad share secrets like bad tokens.
- **Logs** never contain the secret or its hash; the share id is the only identifier.

---

## 8. Failure modes

| Failure | What happens |
| --- | --- |
| Sharer laptop sleeps | Edge heartbeat kills the session in ≈45 s; connectors get `sharer_gone` and retry until the share expires. The sharer re-registers on reconnect with the same secret, and the same link works again. |
| Edge restarts | All shares are forgotten. Sharer reconnects and re-registers; connectors retry; the link keeps working. Open database connections are cut on both sides. |
| Connector loses connectivity | Its local listener stays up; new local connections fail fast until it rejoins; the sharer sees `connector_left` and later `connector_joined`. |
| Share expires mid-query | Both sides cut the connection within a second; the sharer prints `share expired`, the connector exits 3. |
| Sharer presses Ctrl-C | `goodbye` → `revoked` to every connector within a second. |
| Link leaked | Revoke with Ctrl-C. A new `ngstone share` mints a new secret. |

---

## 9. Build order and done criteria

1. **Protocol.** v3 types, codes, `KindShare`, `Auth.ShareSecret`, `AuthOK.Scope`, `StreamOpen.ShareID`; round-trip tests. *Done.*
2. **Edge.** Share registry, connector auth and scope checks, accept loop per session, relay with full admission, expiry timer, teardown reasons, `-max-share-ttl`. *Done:* in-process tests drive a sharer and a connector through the real control loops, relay bytes, and verify forbidden messages, `max_conns`, revocation and goodbye teardown.
3. **Agent.** Sharer mode on the existing agent, `agent.Connector`, secret and link helpers. *Done.*
4. **CLI.** `ngstone share`, `ngstone connect`, audit log, stdin and environment link input. *Done.*
5. **End to end.** Subprocess tests cover the happy path with byte accounting, Ctrl-C revocation with an open connection, expiry, single-use locking, `--allow-cidr` rejection, and an edge restart under a live share. *Done.*
