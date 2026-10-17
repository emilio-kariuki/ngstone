# Secure temporary database sharing — design

**Status:** implemented · **Scope:** `ngstone share`, `ngstone connect`, `ngstone shares|unshare|extend|kick`, protocol v3, edge share registry

Temporarily expose a local PostgreSQL, MySQL or Redis (or any TCP service, or several at once) to named teammates without opening a public database port. Both sides run the `ngstone` agent and dial out to the edge over TLS; the edge joins the two sessions and copies bytes. Shares expire, carry access policies, can require a passphrase or the sharer's approval, and produce an audit trail in the sharer's terminal, in any watching terminal, and on the edge.

This document builds on [ARCHITECTURE.md](ARCHITECTURE.md) and reuses its vocabulary. Where it says "today", it describes the code before this feature landed.

---

## 1. Goals and non-goals

**Goals**

- Share local TCP services with named teammates **without opening a port on the VPS reachable from the internet**. A share has no public listener: the only way in is a connector session authenticated by the link's secret.
- Encrypted on every hop the bytes cross the internet: from the sharer to the edge and from the connector to the edge, both over the existing control-plane TLS.
- Shares end on their own: a fixed expiry chosen by the sharer and enforced by the edge, an optional idle timeout, plus instant revocation from the sharing terminal or any other terminal holding the token.
- Access policies the sharer can state up front: which source networks may connect, how many connectors and connections at once, how many connector joins in total, a passphrase, and per-connection approval.
- Auditing: the sharer sees every connector join and leave and every connection open and close, with name, address, duration and byte counts. Any operator terminal can watch the same stream for every share, and the edge can append it to a file.
- Keep the project's principles: stdlib-first, one path per feature, everything flow-controlled, nothing unbounded in memory, no persistent state on the edge.

**Non-goals (v1)**

- **Named users or SSO.** The edge has no accounts. A connector's name is what it claims; identity is possession of the link, the passphrase if set, network policy, and the sharer's approval if required. Adding identity providers is a separate project.
- **Query-level auditing or read-only enforcement.** That requires parsing each database's wire protocol. `--user` only puts a role into the hint connectors see; the database enforces it.
- **End-to-end encryption past the edge.** The edge terminates TLS on both sessions and copies bytes between them, so an operator who controls the VPS can read the traffic. Enable the database's own TLS (`sslmode=require` and friends) when the VPS is not fully trusted.
- **Durable, searchable audit history.** The edge's `-share-audit-log` is an append-only JSON Lines file, nothing more.
- **A hosted multi-tenant service.** Every operator session holds the same token and may manage every share.

---

## 2. What the user sees

### Sharer

```
$ ngstone share postgres --expires 2h --label "staging replica" --approve
share     staging replica  postgres 127.0.0.1:5432
expires   in 2h (14:03 UTC)   policy: allow all, 16 conns, 8 connectors, approval required
link      ngstone://example.com:4443/s/N7kq…Vb0Q

send the link to a teammate; they run:  ngstone connect <link>
commands here:  y <id> / n <id> (approve)   kick <id>   extend 1h   q

14:01:02  share live         id sh_7f3a…
14:01:03  approve?           203.0.113.9            alice wants to connect: type  y alice  or  n alice
y alice
14:01:05  approved alice
14:01:05  connector joined   203.0.113.9            alice
14:01:06  conn #1   open     203.0.113.9            via alice
14:05:11  conn #1   closed   4m07s     12.3 MiB up   482.0 KiB down
```

Targets are positional. `postgres`, `mysql`, `redis` and `http` are presets for ports 5432, 3306, 6379 and 8080 on `127.0.0.1`; `tcp` has no default. A target may name its own address: `ngstone share postgres redis:6380 tcp:db.local:27017`. The old two-argument form `ngstone share postgres 5433` still works for a single target. Connectors get one local listener per target.

Lines typed into the sharing terminal are commands: `y <id>` and `n <id>` answer approval requests (bare `y`/`n` answers the oldest), `kick <id>` removes a connector, `extend 1h` moves the expiry, `q` quits. Ctrl-C revokes the share; connectors are told within a second and told why.

Flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--expires DURATION` | `1h` | Share lifetime, capped by the edge's `-max-share-ttl` (default 24h). |
| `--label TEXT` | first preset | Shown to connectors and in listings. |
| `--allow-cidr LIST` | allow all | Connector source networks, comma-separated CIDRs. |
| `--max-conns N` | 16 | Concurrent relayed connections across all connectors (edge cap 64). |
| `--max-connectors N` | 8 | Concurrent connector agents (edge cap 32). |
| `--max-uses N` | unlimited | Connector joins allowed over the share's life. `1` is `--single-use`. |
| `--single-use` | off | The link locks to the first connector agent that uses it. |
| `--idle DURATION` | off | Close the share after this long with no open connection (minimum 30s). |
| `--approve` | off | Every connect waits for `y`/`n` in this terminal, for up to 60s. |
| `--passphrase TEXT` | off | Connectors must present it too. `NGSTONE_SHARE_PASSPHRASE` keeps it out of `ps`. |
| `--user NAME` | off | Database user in the hint connectors see, for pointing at a read-only role. |
| `--secret-file PATH` | mint | Reuse the secret in this file, so the link stays the same across runs. Created with mode 0600 if missing. `NGSTONE_SHARE_SECRET` also works. |
| `--audit-log PATH` | off | Append every audit event as a JSON line. |

Plus the usual `--server`, `--token`, `--insecure`, `--server-name`, `--pin`.

### Connector

```
$ ngstone connect ngstone://example.com:4443/s/N7kq…Vb0Q --as alice
connecting to example.com:4443
14:01:05  waiting for the sharer to approve this connection
connected  "staging replica" as alice  expires in 1h58m (14:03 UTC)
listening  127.0.0.1:5432          postgres  ->  psql "postgres://readonly@127.0.0.1:5432/"
listening  127.0.0.1:6379          redis     ->  redis-cli -p 6379
```

The connector listens on the loopback interface only, on each target's preset port, falling back to a free port when that one is busy. `--port 5433` overrides the first target, `--port redis=6380` or `--port t2=6380` a specific one; the flag repeats. Every local connection becomes one tunnel stream to the edge.

The connector prints a status line when activity changes (open and total connections, bytes each way, time left), warns five minutes and one minute before expiry, and reports extensions. When the share expires, is revoked, idles out, or this connector is kicked, it prints why and exits with status 3; open database connections are cut. A passphrase missing or wrong is prompted for when stdin is a terminal, else it exits 1 (`--passphrase`, `NGSTONE_SHARE_PASSPHRASE`).

The link carries the edge address, so no `ngstone auth` or config is needed on the connector's machine. `ngstone connect -` reads the link from standard input and `NGSTONE_SHARE_LINK` from the environment.

### Managing shares from any terminal

```
$ ngstone shares
sh_7f3a…  staging replica          postgres,redis       expires in 1h52m (14:03 UTC)  (this session)
                      policy: 16 conns, 8 connectors, approval;  1 open connections
                      connector alice        203.0.113.9            joined 4m ago
$ ngstone extend sh_7f3a… 2h
$ ngstone kick sh_7f3a… alice
$ ngstone unshare sh_7f3a…
$ ngstone shares --watch        # every share's audit lines, live
$ ngstone shares --json
```

These open a fresh operator session with the saved token, so they work from a second terminal or a script while the share runs elsewhere. There is one operator, so every share is theirs to manage.

---

## 3. Architecture

### Roles

```
 sharer laptop                              VPS (ngstoned)                        teammate laptop
┌──────────────────────┐      TLS       ┌───────────────────────────┐      TLS      ┌──────────────────────┐
│ ngstone share        │───────────────►│ :4443 control             │◄──────────────│ ngstone connect      │
│  ├ control stream    │     yamux      │  ├ share registry         │     yamux     │  ├ control stream    │
│  └ tcpServer         │◄── stream ─────│  │  (hash → share)        │──── stream ──►│  ├ 127.0.0.1:5432    │
│     → 127.0.0.1:5432 │                │  └ pipe: connector        │               │  └ 127.0.0.1:6379    │
│     → 127.0.0.1:6379 │                │     stream ⇄ sharer stream│               └──────────────────────┘
└──────────────────────┘                └───────────────────────────┘
          ▲                                        ▲
          └── ngstone shares / unshare / extend / kick / --watch (any operator session)
```

Both agents dial out, exactly as today's agent does. There is no new listener on the VPS. The edge never opens a public port for a share.

### How a connection flows

1. `psql` connects to `127.0.0.1:5432` on the teammate's machine.
2. The connector opens a yamux stream to the edge with the preamble `{"type":"stream_open","data":{"kind":"share","host":"sh_7f…","share_id":"sh_7f…","target":"t1","req_id":"…","client_addr":"127.0.0.1:51844"}}`.
3. The edge checks the stream belongs to a share the connector was admitted to and names one of its targets, takes a slot from the share's connection semaphore, the connector session's stream budget, the sharer session's stream budget, the connector IP's per-IP cap and the global share-connection cap, then opens a stream to the **sharer's** session with the existing TCP preamble plus `share_id` and `target`.
4. The sharer agent's TCP server accepts the stream, resolves the target id to the local address the sharer configured, and dials it. Plain TCP tunnels keep their fixed target; the share path adds only the resolver.
5. The edge copies bytes both ways with the same half-close and idle-timeout handling as TCP tunnels. Flow control is yamux's: a slow reader throttles the database's socket writes and nothing else.
6. Either side closing ends the connection. The edge reports duration and byte counts to the sharer and to watchers.

What is new on the edge: it accepts streams **from** an agent. Today only the edge opens data streams. yamux is symmetric, so this is an accept loop per connector session, nothing more. Operator sessions share the same accept loop and close any stream they are sent, so a leaked token still cannot push streams into the edge.

### What is reused

| Need | Existing piece |
| --- | --- |
| Dial, TLS, pin, reconnect with backoff | `internal/agent` dial and backoff |
| Multiplexed streams, preamble framing | `internal/tunnel`, `internal/proto` |
| Accepting edge-opened streams and dialing the local target | `agent.tcpServer` (gains a target resolver) |
| Byte piping with half-close and idle timeout | `edge.idleDeadline`, `closeWrite` |
| Per-session stream and in-flight budgets, drain | `AgentSession.streamSem`, `inflightTracker` |
| Per-IP concurrency cap and auth rate limiting | `perIPInflight`, `authRateLimiter` |
| Token hashing and constant-time comparison | `authenticate` |

---

## 4. Protocol (v3)

Protocol v3 is additive: new message types and new optional fields. An edge that only speaks v2 answers an unknown type with `error{unknown_type}` and closes, and the agent turns that into "this edge does not support sharing; upgrade `ngstoned`". Version negotiation is unchanged.

### Share secret, link and passphrase

The **sharer** mints the secret: 32 random bytes, base64url without padding. The edge stores only its SHA-256, the same arrangement as the edge token.

```
ngstone://<edge-host>:<port>/s/<base64url(secret)>
```

`<edge-host>` doubles as the TLS server name, so a link cannot point a connector at an edge whose certificate says something else. `--insecure` on `ngstone connect` is the only way to reach a plaintext dev edge; the link never encodes it.

A passphrase is a second factor the link does not carry. The sharer sends `sha256(hex(sha256(secret)) + ":" + passphrase)`; the connector sends the passphrase in `connect`; the edge recomputes and compares in constant time, and a mismatch counts against the per-IP auth limiter like a bad token.

Because the sharer holds the secret, it can re-register the same share after a reconnect or an edge restart and the link keeps working. With `--secret-file` the same holds across sharer *restarts*. Connectors that lose the share (`sharer_gone`, `edge_shutdown`) retry with backoff until the expiry they were told at join time.

### Messages

```go
// ---- sharer → edge ----
type ShareTarget struct {
    ID          string `json:"id"`                  // "t1", "t2", … assigned by the sharer
    Preset      string `json:"preset"`              // postgres | mysql | redis | http | tcp
    Label       string `json:"label,omitempty"`
    DefaultPort int    `json:"default_port"`        // connector's default local port
    User        string `json:"user,omitempty"`      // hint only
}
type Share struct {
    Kind             string        `json:"kind"`                        // "tcp"
    SecretSHA256     string        `json:"secret_sha256"`
    Label            string        `json:"label,omitempty"`
    Targets          []ShareTarget `json:"targets"`                     // 1..8
    ExpiresAtMS      int64         `json:"expires_at_unix_ms"`
    MaxConns         int           `json:"max_conns,omitempty"`
    MaxConnectors    int           `json:"max_connectors,omitempty"`
    MaxUses          int           `json:"max_uses,omitempty"`          // 1 = single use
    SingleUse        bool          `json:"single_use,omitempty"`
    AllowCIDRs       []string      `json:"allow_cidrs,omitempty"`
    IdleTimeoutMS    int64         `json:"idle_timeout_ms,omitempty"`   // ≥ 30 000
    Approve          bool          `json:"approve,omitempty"`
    PassphraseSHA256 string        `json:"passphrase_sha256,omitempty"`
}
type ShareOK  struct{ ShareID string; ExpiresAtMS int64 }
type ShareErr struct{ Code, Message string }       // share_ttl_too_long, too_many_shares, share_taken,
                                                   // invalid_share, feature_unsupported, share_not_found

// ---- management, from any operator session ----
type Unshare     struct{ ShareID string }                        // → UnshareOK
type ShareUpdate struct{ ShareID string; ExpiresAtMS int64 }     // → ShareOK | ShareErr
type Kick        struct{ ShareID, ConnectorID string }           // → KickOK | Error{no_such_connector}
type Approve     struct{ ShareID, ConnectorID string; Allow bool } // → ApproveOK | Error{no_such_connector}
type ListShares  struct{}                                        // → SharesOK{Shares []ShareInfo}
type WatchShares struct{}                                        // → WatchOK, then every share's ShareEvents

// ---- connector → edge ----
// Auth gains ShareSecret; exactly one of Token and ShareSecret is set.
// AuthOK gains Scope: "operator" or "connector".
type Connect struct {
    Name       string `json:"name,omitempty"`        // how the sharer sees this connector
    Passphrase string `json:"passphrase,omitempty"`
}
type ConnectOK struct {
    ShareID     string        `json:"share_id"`
    ConnectorID string        `json:"connector_id"`   // the name, made unique, or "cN"
    Label       string        `json:"label"`
    Targets     []ShareTarget `json:"targets"`
    ExpiresAtMS int64         `json:"expires_at_unix_ms"`
}
type ConnectErr struct{ Code, Message string }     // share_not_found, share_full, share_locked,
                                                   // share_uses_exhausted, forbidden_cidr, bad_passphrase,
                                                   // approval_denied, approval_timeout

// ---- edge → sharer and watchers (audit) ----
type ShareEvent struct {
    ShareID     string `json:"share_id"`
    Event       string `json:"event"` // connector_joined, connector_left, conn_open, conn_close,
                                      // conn_rejected, connect_pending, extended, registered, closed
    AtMS        int64  `json:"at_unix_ms"`
    ConnectorID string `json:"connector_id,omitempty"`
    ConnID      int    `json:"conn_id,omitempty"`
    Target      string `json:"target,omitempty"`
    ClientAddr  string `json:"client_addr,omitempty"`
    DurationMS  int64  `json:"duration_ms,omitempty"`
    BytesUp     int64  `json:"bytes_up,omitempty"`
    BytesDown   int64  `json:"bytes_down,omitempty"`
    Reason      string `json:"reason,omitempty"`
    ExpiresAtMS int64  `json:"expires_at_unix_ms,omitempty"` // extended, registered
    Label       string `json:"label,omitempty"`              // watchers and the audit file
}

// ---- edge → connector ----
type ShareClosed  struct{ ShareID, Reason string }  // expired, revoked, idle, kicked, sharer_gone, edge_shutdown
type ShareUpdated struct{ ShareID string; ExpiresAtMS int64 }

// ---- data-stream preamble gains two optional fields ----
type StreamOpen struct {
    Kind, Host, ReqID, ClientAddr string
    ShareID string `json:"share_id,omitempty"`
    Target  string `json:"target,omitempty"`
}
```

Reply correlation is unchanged: every reply carries the request's `Msg.ID`. `ShareEvent`, `ShareClosed` and `ShareUpdated` are notifications with edge-minted IDs, like `Evicted` today.

A connector-scoped session may send only `connect`, `ping`, `pong` and `goodbye`; anything else gets `error{forbidden}` and the session closes. An operator session that sends `connect` gets the same.

---

## 5. Edge

### Share registry

`internal/edge/share.go`, in memory only, mirroring `Registry`: one mutex over every share, keyed by secret hash, by id and by owner session, plus the set of watching sessions.

**Registration rules.** `share` from a sharer session:

- `expires_at` further out than now plus `-max-share-ttl` → `share_ttl_too_long`.
- More than 8 live shares on the session → `too_many_shares`.
- A share with this hash already exists and is **owned by a different instance_id** → `share_taken`. Same `instance_id` (the sharer reconnecting) replaces the old share; its connectors are told `sharer_gone` and reconnect on their own. This is the same identity-not-liveness rule as `Bind` takeover.
- Otherwise the share is registered, an expiry timer armed, an idle timer armed if requested, and `share_ok` returned. Watchers get `registered`.

**Admission.** `connect` from a connector session runs in two steps so the sharer's approval can sit between them:

1. *admit*, under the registry lock: share live; passphrase matches if set; address inside `allow_cidrs`; single-use lock; `max_uses` not exhausted; connector count below `max_connectors` counting parked connects. Reserves the connector id: the requested name if it is `[A-Za-z0-9][A-Za-z0-9._-]{0,31}` and free, with `-2`, `-3`… appended when taken, else `cN`.
2. *approval*, only with `approve`: the sharer gets `connect_pending`; the edge waits up to 60s for `approve{allow}` on a goroutine so the connector's heartbeat keeps flowing; `kick` of a pending id denies it. Then *join* records the member, counts a use, and replies `connect_ok`.

**Teardown.** `closeShare(sh, reason)` is the one path: mark closed, remove from the maps, stop the timers, deny pending approvals, send the sharer `closed`, send every connector `share_closed{reason}`, give every relayed connection an immediate deadline, wait up to two seconds for the relays to report `conn_close`, then close the connector sessions. It is idempotent. It runs from the expiry timer (`expired`), the idle timer (`idle`), `unshare` (`revoked`), the sharer's `goodbye` (`revoked`), the sharer's control loop exiting any other way (`sharer_gone`), and edge shutdown (`edge_shutdown`). `kick` runs the same steps for one connector with reason `kicked`.

**Idle.** The idle timer is armed whenever the share has no open relayed connection and stopped when one opens, so a share that is in use never idles out.

**Management.** `unshare`, `share_update`, `kick`, `approve` and `list_shares` are accepted from any operator session, not only the owner: there is one token and therefore one operator. `watch_shares` adds the session to the watcher set; every `ShareEvent` is written to the owner, to each watcher other than the owner, and to the edge's `-share-audit-log` file, with the share's label filled in.

### Relay admission, in order

Each connector stream is admitted against every budget it consumes, and each rejection is reported to the sharer as `conn_rejected` with the reason:

1. the preamble names a target of the share (a single-target share accepts an empty target)
2. connector IP's `perIPInflight` (shared with HTTP and TCP tunnels)
3. global share-connection semaphore (256)
4. the share's `max_conns`
5. the connector session's per-session stream cap
6. the sharer session's per-session stream cap
7. share still live at registration time
8. stream open to the sharer within the 5 s dial budget

Both sessions' in-flight trackers count the relay, so graceful drain on either side waits for it.

### Limits and flags

| Knob | Value |
| --- | --- |
| `-max-share-ttl` | 24h |
| `-share-audit-log` | off |
| shares per session | 8 |
| targets per share | 8 |
| `max_conns` per share | 16 default, 64 max |
| `max_connectors` per share | 8 default, 32 max |
| approval wait | 60s |
| idle timeout floor | 30s |
| global relayed connections | 256 |
| idle relayed connection | `-tcp-idle-timeout` (30 min) |
| label, connector name | 128 printable bytes, 32 chars |

Memory follows the §5 window budget in ARCHITECTURE.md: a relayed connection holds two yamux streams on the edge, so the stated ceiling is 256 × 2 × 1 MiB.

---

## 6. Agent

**Sharer mode** is the TCP agent with a `ShareSpec`: the handshake sends `share` instead of `bind`, the control loop forwards `share_event`s to the CLI, and the data path is the `tcpServer` with a resolver from target id to local address. The spec's expiry is absolute and updated by `extended` events, so re-registration after a reconnect keeps the current deadline. While a session is live the agent exposes `Approve`, `Kick` and `Extend`, which the terminal commands call; replies to those, including errors, are routed back as events rather than ending the session.

**Connector** (`agent.Connector`): dial, `auth{share_secret}`, `connect{name, passphrase}`, then one loopback listener per target that lives for the process and relays each accepted connection over the session that is live at that moment, tagging the stream with the target id. It keeps byte and connection counters for the status line, tracks the expiry through `share_updated`, and retries with a slower backoff (2 s base) so a connector waiting for its sharer stays under the edge's auth rate limit. A connect that gets no reply within two seconds tells the user it is probably waiting on the sharer.

**Operator** (`agent.Operator`): one fresh session per call for `shares`, `unshare`, `extend` and `kick`, and a long-lived one for `--watch`.

---

## 7. Security model additions

- **Link holder** can reach exactly the share's targets through the sharer's agent, for at most the share's lifetime, subject to the share's policy, and only after any passphrase and approval. They cannot bind tunnels, register shares, list or manage shares, or open streams to anything but their share.
- **Edge token holder** can manage every share (list, extend, revoke, kick, watch) but cannot `connect`, and any stream they push into the edge is closed.
- **Anyone on the network** sees TLS to the edge in both directions. There is no public port to scan; a share has no listener.
- **The VPS operator** sees plaintext, as with every tunnel. Use the database's own TLS when that matters.
- **Brute force** on the secret is 256 bits behind a per-IP rate limit; bad secrets and bad passphrases both count against it.
- **Connector names** are claims for the audit trail, not authentication. Approval mode is where a human checks them.
- **Logs** never contain the secret, its hash, or the passphrase; the share id is the only identifier.

---

## 8. Failure modes

| Failure | What happens |
| --- | --- |
| Sharer laptop sleeps | Edge heartbeat kills the session in ≈45 s; connectors get `sharer_gone` and retry until the share expires. The sharer re-registers on reconnect with the same secret, and the same link works again. |
| Edge restarts | All shares are forgotten. Sharer reconnects and re-registers; connectors retry; the link keeps working. Open database connections are cut on both sides. |
| Connector loses connectivity | Its local listeners stay up; new local connections fail fast until it rejoins; the sharer sees `connector_left` and later `connector_joined`. |
| Share expires mid-query | Both sides cut the connection within a second; the sharer prints `share expired`, the connector exits 3. Connectors warn at 5 and 1 minutes; `extend` from either terminal postpones it. |
| Nobody uses the share | With `--idle`, the edge closes it after that long with no open connection; both sides say so. |
| Sharer presses Ctrl-C, or anyone runs `unshare` | `revoked` to every connector within a second; the sharer's terminal says which it was. |
| Sharer did not answer an approval | The connector is refused with `approval_timeout` after 60s and exits 1. |
| Link leaked | Revoke from any terminal. Without `--secret-file`, a new `ngstone share` mints a new secret; with it, delete the file first. |

---

## 9. Build order and done criteria

1. **Protocol.** v3 types, codes, `KindShare`, `Auth.ShareSecret`, `AuthOK.Scope`, `StreamOpen.ShareID`/`Target`; round-trip tests. *Done.*
2. **Edge.** Share registry, connector auth and scope checks, accept loop per session, relay with full admission, expiry and idle timers, teardown reasons, management from any operator session, watchers, `-max-share-ttl`, `-share-audit-log`. *Done:* in-process tests drive a sharer and a connector through the real control loops, relay bytes, and verify forbidden messages, `max_conns`, names, passphrase, uses, extend, idle, revocation and goodbye teardown.
3. **Agent.** Sharer mode with a target resolver and terminal management, `agent.Connector` with per-target listeners and counters, `agent.Operator`, secret and link helpers. *Done.*
4. **CLI.** `ngstone share` with multi-target syntax and terminal commands, `ngstone connect` with names, passphrase prompt, per-target ports and a status line, `ngstone shares|unshare|extend|kick`. *Done.*
5. **End to end.** Subprocess tests cover the happy path with byte accounting, Ctrl-C revocation with an open connection, expiry, single-use locking, `--allow-cidr` rejection, an edge restart under a live share, the management verbs including kick and unshare from another terminal, multi-target with approval and passphrase, `--watch` with the edge audit file, and a stable link via `--secret-file`. *Done.*
