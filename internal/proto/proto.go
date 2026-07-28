package proto

import (
	"encoding/json"
	"sync/atomic"
)

const ProtoVersion = 2

var SupportedVersions = []int{2, 1}

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
)

const (
	CodeBadToken         = "bad_token"
	CodeNoCommonVersion  = "no_common_version"
	CodeSubdomainTaken   = "subdomain_taken"
	CodeInvalidSubdomain = "invalid_subdomain"
	CodeKindUnsupported  = "kind_unsupported"
	CodeUnknownType      = "unknown_type"
	CodeMalformed        = "malformed"
	CodeNotBound         = "not_bound"
	CodeInternal         = "internal"
	CodePortUnavailable  = "port_unavailable"
	CodeTooManyBinds     = "too_many_binds"
	CodeInvalidAccess    = "invalid_access"
)

const (
	KindHTTP = "http"
	KindTCP  = "tcp"
)

type Msg struct {
	Type string          `json:"type"`
	ID   uint64          `json:"id,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

type Auth struct {
	Token         string `json:"token"`
	InstanceID    string `json:"instance_id"`
	ClientVersion string `json:"client_version"`
	ProtoVersions []int  `json:"proto_versions"`
}

type AuthOK struct {
	ProtoVersion  int    `json:"proto_version"`
	SessionID     string `json:"session_id"`
	ServerVersion string `json:"server_version"`
}

type AuthErr struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Bind struct {
	Kind       string `json:"kind"`
	Subdomain  string `json:"subdomain,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	Takeover   bool   `json:"takeover,omitempty"`

	BasicAuthSHA256 []string `json:"basic_auth_sha256,omitempty"`
	BasicAuthRealm  string   `json:"basic_auth_realm,omitempty"`
	AllowCIDRs      []string `json:"allow_cidrs,omitempty"`
}

type BindOK struct {
	Hostname string `json:"hostname"`
	URL      string `json:"url"`
	Port     int    `json:"port,omitempty"`
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
