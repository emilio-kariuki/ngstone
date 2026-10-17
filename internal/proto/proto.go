package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync/atomic"

	"ngstone/internal/policy"
)

// PassphraseDigest is Share.PassphraseSHA256: the passphrase bound to the
// share's secret digest, so the same passphrase on two shares yields two
// values. The edge only ever holds the secret's hash, which is why the
// binding uses the hex digest rather than the secret itself.
func PassphraseDigest(secretSHA256Hex, passphrase string) string {
	sum := sha256.Sum256([]byte(secretSHA256Hex + ":" + passphrase))
	return hex.EncodeToString(sum[:])
}

const ProtoVersion = 3

var SupportedVersions = []int{3, 2, 1}

const (
	TypeAuth       = "auth"
	TypeAuthOK     = "auth_ok"
	TypeAuthErr    = "auth_err"
	TypeBind       = "bind"
	TypeBindOK     = "bind_ok"
	TypeBindErr    = "bind_err"
	TypeUnbind     = "unbind"
	TypeUnbindOK   = "unbind_ok"
	TypeEvicted    = "evicted"
	TypeError      = "error"
	TypePing       = "ping"
	TypePong       = "pong"
	TypeGoodbye    = "goodbye"
	TypeStreamOpen = "stream_open"

	// Protocol v3: temporary sharing of a local TCP service with a peer that
	// holds a share link instead of the operator token.
	TypeShare       = "share"
	TypeShareOK     = "share_ok"
	TypeShareErr    = "share_err"
	TypeUnshare     = "unshare"
	TypeUnshareOK   = "unshare_ok"
	TypeConnect     = "connect"
	TypeConnectOK   = "connect_ok"
	TypeConnectErr  = "connect_err"
	TypeShareEvent  = "share_event"
	TypeShareClosed = "share_closed"

	// Share management from an operator session (the sharer's own, or
	// any other session holding the token).
	TypeListShares   = "list_shares"
	TypeSharesOK     = "shares_ok"
	TypeShareUpdate  = "share_update"
	TypeKick         = "kick"
	TypeKickOK       = "kick_ok"
	TypeApprove      = "approve"
	TypeApproveOK    = "approve_ok"
	TypeWatchShares  = "watch_shares"
	TypeWatchOK      = "watch_ok"
	TypeShareUpdated = "share_updated" // edge -> connector
)

const (
	CodeBadToken                = "bad_token"
	CodeNoCommonVersion         = "no_common_version"
	CodeSubdomainTaken          = "subdomain_taken"
	CodeInvalidSubdomain        = "invalid_subdomain"
	CodeKindUnsupported         = "kind_unsupported"
	CodeUnknownType             = "unknown_type"
	CodeMalformed               = "malformed"
	CodeNotBound                = "not_bound"
	CodeInternal                = "internal"
	CodePortUnavailable         = "port_unavailable"
	CodeTooManyBinds            = "too_many_binds"
	CodeInvalidAccess           = "invalid_access"
	CodeConnectorConfigMismatch = "connector_config_mismatch"
	CodeCredentialScope         = "credential_scope"

	// v3 share codes.
	CodeBadShare           = "bad_share"            // AuthErr: unknown, expired or revoked share secret
	CodeInvalidShare       = "invalid_share"        // ShareErr: malformed share request
	CodeShareTTLTooLong    = "share_ttl_too_long"   // ShareErr: expires_at beyond the edge's -max-share-ttl
	CodeTooManyShares      = "too_many_shares"      // ShareErr: per-session share cap reached
	CodeShareTaken         = "share_taken"          // ShareErr: same secret registered by another instance
	CodeShareNotFound      = "share_not_found"      // UnshareErr/ConnectErr: no such live share
	CodeShareFull          = "share_full"           // ConnectErr: max_connectors reached
	CodeShareLocked        = "share_locked"         // ConnectErr: single-use share locked to another connector
	CodeForbidden          = "forbidden"            // Error: message not allowed for this session's scope
	CodeForbiddenCIDR      = "forbidden_cidr"       // ConnectErr: connector address outside allow_cidrs
	CodeFeatureUnsupported = "feature_unsupported"  // ShareErr: edge negotiated a protocol without sharing
	CodeBadPassphrase      = "bad_passphrase"       // ConnectErr: share needs a passphrase and this one is wrong or missing
	CodeApprovalDenied     = "approval_denied"      // ConnectErr: the sharer said no
	CodeApprovalTimeout    = "approval_timeout"     // ConnectErr: the sharer did not answer in time
	CodeNoSuchConnector    = "no_such_connector"    // Kick/Approve: connector id not on this share
	CodeShareUsesExhausted = "share_uses_exhausted" // ConnectErr: max_uses reached
)

// Session scopes reported in AuthOK.Scope.
const (
	ScopeOperator  = "operator"
	ScopeConnector = "connector"
)

// Share lifecycle reasons carried by ShareClosed.Reason and ShareEvent.Reason.
const (
	ShareReasonExpired      = "expired"
	ShareReasonRevoked      = "revoked"
	ShareReasonSharerGone   = "sharer_gone"
	ShareReasonEdgeShutdown = "edge_shutdown"
	ShareReasonIdle         = "idle"   // share: no connection for idle_timeout
	ShareReasonKicked       = "kicked" // connector: removed by the sharer
)

// ShareEvent.Event values.
const (
	ShareEventConnectorJoined = "connector_joined"
	ShareEventConnectorLeft   = "connector_left"
	ShareEventConnOpen        = "conn_open"
	ShareEventConnClose       = "conn_close"
	ShareEventConnRejected    = "conn_rejected"
	ShareEventClosed          = "closed"
	ShareEventExtended        = "extended"        // ExpiresAtMS carries the new expiry
	ShareEventConnectPending  = "connect_pending" // approval needed; answer with Approve
	ShareEventRegistered      = "registered"      // watchers only: a share came up
)

const (
	KindHTTP  = "http"
	KindHTTP2 = "h2"
	KindTCP   = "tcp"
	// KindShare marks a data stream a connector opens toward the edge; the
	// edge relays it to the sharer as a KindTCP stream.
	KindShare = "share"
)

const GoodbyeReasonCredentialInactive = "tunnel credential is inactive"

type Msg struct {
	Type string          `json:"type"`
	ID   uint64          `json:"id,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Auth carries exactly one of Token (operator scope) or ShareSecret
// (connector scope, v3). ShareSecret is the base64url secret from a share
// link; the edge hashes it and looks the share up by hash.
type Auth struct {
	Token         string `json:"token,omitempty"`
	ShareSecret   string `json:"share_secret,omitempty"`
	InstanceID    string `json:"instance_id"`
	ClientVersion string `json:"client_version"`
	ProtoVersions []int  `json:"proto_versions"`
}

type AuthOK struct {
	ProtoVersion  int    `json:"proto_version"`
	SessionID     string `json:"session_id"`
	ServerVersion string `json:"server_version"`
	// Scope is "operator" for token auth and "connector" for share-secret
	// auth. Empty means operator (edges older than v3).
	Scope string `json:"scope,omitempty"`
}

type AuthErr struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Bind struct {
	Kind                 string `json:"kind"`
	Name                 string `json:"name,omitempty"`
	Subdomain            string `json:"subdomain,omitempty"`
	RemotePort           int    `json:"remote_port,omitempty"`
	Takeover             bool   `json:"takeover,omitempty"`
	HTTP2                bool   `json:"http2,omitempty"`
	MultiConnector       bool   `json:"multi_connector,omitempty"`
	ConnectorTokenSHA256 string `json:"connector_token_sha256,omitempty"`

	BasicAuthSHA256 []string       `json:"basic_auth_sha256,omitempty"`
	BasicAuthRealm  string         `json:"basic_auth_realm,omitempty"`
	AllowCIDRs      []string       `json:"allow_cidrs,omitempty"`
	Policy          *policy.Policy `json:"policy,omitempty"`
	PolicyDigest    string         `json:"policy_digest,omitempty"`
}

type BindOK struct {
	Hostname       string `json:"hostname"`
	URL            string `json:"url"`
	Port           int    `json:"port,omitempty"`
	HTTP2          bool   `json:"http2,omitempty"`
	MultiConnector bool   `json:"multi_connector,omitempty"`
	PolicyDigest   string `json:"policy_digest,omitempty"`
}

type BindErr struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Unbind struct {
	Hostname string `json:"hostname"`
}

type UnbindOK struct {
	Hostname string `json:"hostname"`
}

type Evicted struct {
	Hostname string `json:"hostname"`
	Reason   string `json:"reason"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Ping struct {
	TS int64 `json:"ts_unix_ms"`
}

type Pong struct {
	TS int64 `json:"ts_unix_ms"`
}

type Goodbye struct {
	Reason  string `json:"reason"`
	DrainMS int    `json:"drain_ms"`
}

type StreamOpen struct {
	Kind       string `json:"kind"`
	Host       string `json:"host"`
	ReqID      string `json:"req_id"`
	ClientAddr string `json:"client_addr"`
	// ShareID is set on streams that belong to a share (v3), in both
	// directions: connector -> edge (Kind "share") and edge -> sharer
	// (Kind "tcp"). Target names the share target the stream is for.
	ShareID string `json:"share_id,omitempty"`
	Target  string `json:"target,omitempty"`
}

// ---- v3: sharer -> edge ----

// ShareTarget is one local service inside a share. A share with several
// targets gives the connector one local listener per target.
type ShareTarget struct {
	ID          string `json:"id"`              // "t1", "t2", ... assigned by the sharer
	Preset      string `json:"preset"`          // postgres, mysql, redis, http, tcp
	Label       string `json:"label,omitempty"` // defaults to the preset name
	DefaultPort int    `json:"default_port"`    // port the connector listens on by default
	User        string `json:"user,omitempty"`  // database user hint shown to connectors
}

// Share registers a share. The sharer mints the secret and sends only its
// SHA-256 (hex); the plaintext secret lives in the link and on the sharer.
type Share struct {
	Kind         string        `json:"kind"`
	SecretSHA256 string        `json:"secret_sha256"`
	Label        string        `json:"label,omitempty"`
	Targets      []ShareTarget `json:"targets"`
	ExpiresAtMS  int64         `json:"expires_at_unix_ms"`

	MaxConns      int      `json:"max_conns,omitempty"`
	MaxConnectors int      `json:"max_connectors,omitempty"`
	MaxUses       int      `json:"max_uses,omitempty"` // connector joins allowed over the share's life; 1 = single use
	SingleUse     bool     `json:"single_use,omitempty"`
	AllowCIDRs    []string `json:"allow_cidrs,omitempty"`
	IdleTimeoutMS int64    `json:"idle_timeout_ms,omitempty"` // close the share after this long with no open connection
	Approve       bool     `json:"approve,omitempty"`         // every connect waits for the sharer's approval
	// PassphraseSHA256 is hex(sha256(secret + ":" + passphrase)); the
	// connector must present the passphrase in Connect.
	PassphraseSHA256 string `json:"passphrase_sha256,omitempty"`
	// E2E says the sharer encrypts relayed streams end to end with a key
	// derived from the secret, so connectors must do the same.
	E2E bool `json:"e2e,omitempty"`
}

type ShareOK struct {
	ShareID     string `json:"share_id"`
	ExpiresAtMS int64  `json:"expires_at_unix_ms"`
}

type ShareErr struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Unshare struct {
	ShareID string `json:"share_id"`
}

type UnshareOK struct {
	ShareID string `json:"share_id"`
}

// ShareUpdate changes a live share's expiry. Reply is ShareOK or ShareErr.
type ShareUpdate struct {
	ShareID     string `json:"share_id"`
	ExpiresAtMS int64  `json:"expires_at_unix_ms"`
}

// Kick removes one connector from a share.
type Kick struct {
	ShareID     string `json:"share_id"`
	ConnectorID string `json:"connector_id"`
}

type KickOK struct {
	ShareID     string `json:"share_id"`
	ConnectorID string `json:"connector_id"`
}

// Approve answers a connect_pending event.
type Approve struct {
	ShareID     string `json:"share_id"`
	ConnectorID string `json:"connector_id"`
	Allow       bool   `json:"allow"`
}

type ApproveOK struct {
	ShareID     string `json:"share_id"`
	ConnectorID string `json:"connector_id"`
}

// ListShares asks for every live share on the edge (one operator, one
// token, so every share is the operator's).
type ListShares struct{}

type ConnectorInfo struct {
	ID       string `json:"id"`
	Addr     string `json:"addr"`
	JoinedMS int64  `json:"joined_unix_ms"`
}

type ShareInfo struct {
	ShareID       string          `json:"share_id"`
	Label         string          `json:"label"`
	Targets       []ShareTarget   `json:"targets"`
	ExpiresAtMS   int64           `json:"expires_at_unix_ms"`
	CreatedAtMS   int64           `json:"created_at_unix_ms"`
	Mine          bool            `json:"mine"` // registered by the asking session
	MaxConns      int             `json:"max_conns"`
	MaxConnectors int             `json:"max_connectors"`
	MaxUses       int             `json:"max_uses,omitempty"`
	Uses          int             `json:"uses"`
	AllowCIDRs    []string        `json:"allow_cidrs,omitempty"`
	IdleTimeoutMS int64           `json:"idle_timeout_ms,omitempty"`
	Approve       bool            `json:"approve,omitempty"`
	Passphrase    bool            `json:"passphrase,omitempty"`
	E2E           bool            `json:"e2e,omitempty"`
	Connectors    []ConnectorInfo `json:"connectors"`
	OpenConns     int             `json:"open_conns"`
}

type SharesOK struct {
	Shares []ShareInfo `json:"shares"`
}

// WatchShares subscribes an operator session to every share's events.
type WatchShares struct{}

type WatchOK struct{}

// ---- v3: connector -> edge ----

// Connect joins the share whose secret authenticated this session.
type Connect struct {
	Name       string `json:"name,omitempty"`       // how the sharer sees this connector
	Passphrase string `json:"passphrase,omitempty"` // required when the share set one
}

type ConnectOK struct {
	ShareID     string        `json:"share_id"`
	ConnectorID string        `json:"connector_id"`
	Label       string        `json:"label"`
	Targets     []ShareTarget `json:"targets"`
	ExpiresAtMS int64         `json:"expires_at_unix_ms"`
	E2E         bool          `json:"e2e,omitempty"`
}

type ConnectErr struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ---- v3: edge -> sharer (audit) ----

type ShareEvent struct {
	ShareID     string `json:"share_id"`
	Event       string `json:"event"`
	AtMS        int64  `json:"at_unix_ms"`
	ConnectorID string `json:"connector_id,omitempty"`
	ConnID      int    `json:"conn_id,omitempty"`
	Target      string `json:"target,omitempty"`
	ClientAddr  string `json:"client_addr,omitempty"`
	DurationMS  int64  `json:"duration_ms,omitempty"`
	BytesUp     int64  `json:"bytes_up,omitempty"`
	BytesDown   int64  `json:"bytes_down,omitempty"`
	Reason      string `json:"reason,omitempty"`
	ExpiresAtMS int64  `json:"expires_at_unix_ms,omitempty"`
	Label       string `json:"label,omitempty"` // watchers: which share this is
}

// ---- v3: edge -> connector ----

type ShareClosed struct {
	ShareID string `json:"share_id"`
	Reason  string `json:"reason"`
}

type ShareUpdated struct {
	ShareID     string `json:"share_id"`
	ExpiresAtMS int64  `json:"expires_at_unix_ms"`
}

var knownTypes = map[string]bool{
	TypeAuth:       true,
	TypeAuthOK:     true,
	TypeAuthErr:    true,
	TypeBind:       true,
	TypeBindOK:     true,
	TypeBindErr:    true,
	TypeUnbind:     true,
	TypeUnbindOK:   true,
	TypeEvicted:    true,
	TypeError:      true,
	TypePing:       true,
	TypePong:       true,
	TypeGoodbye:    true,
	TypeStreamOpen: true,

	TypeShare:       true,
	TypeShareOK:     true,
	TypeShareErr:    true,
	TypeUnshare:     true,
	TypeUnshareOK:   true,
	TypeConnect:     true,
	TypeConnectOK:   true,
	TypeConnectErr:  true,
	TypeShareEvent:  true,
	TypeShareClosed: true,

	TypeListShares:   true,
	TypeSharesOK:     true,
	TypeShareUpdate:  true,
	TypeKick:         true,
	TypeKickOK:       true,
	TypeApprove:      true,
	TypeApproveOK:    true,
	TypeWatchShares:  true,
	TypeWatchOK:      true,
	TypeShareUpdated: true,
}

func KnownType(t string) bool {
	return knownTypes[t]
}

type IDGen struct {
	next uint64
}

func NewAgentIDGen() *IDGen {
	return &IDGen{next: 1}
}

func NewEdgeIDGen() *IDGen {
	return &IDGen{next: 2}
}

func (g *IDGen) Next() uint64 {
	return atomic.AddUint64(&g.next, 2) - 2
}
