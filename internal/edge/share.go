package edge

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"ngstone/internal/proto"
)

// Sharing (protocol v3). A sharer session registers a share: the SHA-256 of
// a secret it minted, one or more local targets, an expiry and a policy. A
// connector session authenticates with the plaintext secret, joins the
// share, and opens data streams toward the edge; the edge opens a matching
// stream toward the sharer and copies bytes both ways. Nothing here is
// persisted: an edge restart forgets every share, and the sharer
// re-registers on reconnect.
//
// Any operator session (same token) may list, extend, revoke and kick, so a
// second terminal can manage shares a first one started.

const (
	DefaultMaxShareTTL = 24 * time.Hour

	maxSharesPerSession       = 8
	maxShareLabelLen          = 128
	maxShareTargets           = 8
	maxConnectorNameLen       = 32
	defaultShareMaxConns      = 16
	defaultShareMaxConnectors = 8
	maxShareMaxConns          = 64
	maxShareMaxConnectors     = 32
	// maxGlobalShareConns caps relayed connections across all shares, the
	// same role maxGlobalTCPConns plays for TCP tunnels.
	maxGlobalShareConns = 256
	// shareForceCloseGrace bounds how long closing a share waits for its
	// relay goroutines after their streams were given an immediate deadline.
	shareForceCloseGrace = 2 * time.Second
	// approvalTimeout is how long a connect waits for the sharer to answer
	// a connect_pending event.
	approvalTimeout = 60 * time.Second
	// minShareIdleTimeout keeps --idle from closing a share between two
	// quick queries.
	minShareIdleTimeout = 30 * time.Second
)

var (
	errShareTTLTooLong = errors.New("edge: share_ttl_too_long")
	errTooManyShares   = errors.New("edge: too_many_shares")
	errShareTaken      = errors.New("edge: share_taken")
	errShareNotFound   = errors.New("edge: share_not_found")
	errShareFull       = errors.New("edge: share_full")
	errShareLocked     = errors.New("edge: share_locked")
	errShareForbidden  = errors.New("edge: forbidden_cidr")
	errShareClosed     = errors.New("edge: share closed")
	errBadPassphrase   = errors.New("edge: bad_passphrase")
	errUsesExhausted   = errors.New("edge: share_uses_exhausted")
	errNoSuchConnector = errors.New("edge: no_such_connector")
)

var (
	metricActiveShares             = expvar.NewInt("ngstoned_active_shares")
	metricActiveShareConnectors    = expvar.NewInt("ngstoned_active_share_connectors")
	metricActiveShareConns         = expvar.NewInt("ngstoned_active_share_conns")
	metricShareRejectedGlobalCap   = expvar.NewInt("ngstoned_share_rejected_global_cap_total")
	metricShareRejectedShareCap    = expvar.NewInt("ngstoned_share_rejected_share_cap_total")
	metricShareConnectRejected     = expvar.NewInt("ngstoned_share_connect_rejected_total")
	metricShareRejectedSessionCap  = expvar.NewInt("ngstoned_share_rejected_session_cap_total")
	metricShareRejectedPerIPCap    = expvar.NewInt("ngstoned_share_rejected_per_ip_cap_total")
	metricShareRejectedDialFailure = expvar.NewInt("ngstoned_share_rejected_dial_total")
)

var connectorNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)
var targetIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,15}$`)

type sharePolicy struct {
	maxConns      int
	maxConnectors int
	maxUses       int // 0 = unlimited
	allow         []netip.Prefix
	idleTimeout   time.Duration
	approve       bool
	hasPassphrase bool
	passHash      [32]byte
}

type connectorInfo struct {
	id       string
	joinedAt time.Time
	addr     netip.AddrPort
}

// shareConn is one relayed connection: the connector's stream into the edge
// and the edge's stream into the sharer.
type shareConn struct {
	id        int
	connector *AgentSession
	target    string
	client    net.Conn // connector -> edge stream
	upstream  net.Conn // edge -> sharer stream
	done      chan struct{}
}

// pendingConnect is a connect waiting on the sharer's approval.
type pendingConnect struct {
	session *AgentSession
	id      string
	answer  chan bool
}

type share struct {
	id         string
	secretHash [32]byte
	owner      *AgentSession
	kind       string
	label      string
	targets    []proto.ShareTarget
	createdAt  time.Time
	expiresAt  time.Time
	policy     sharePolicy
	e2e        bool
	lockedTo   string // single-use: instance id of the first connector

	connectors      map[*AgentSession]*connectorInfo
	pending         map[string]*pendingConnect // by connector id
	conns           map[*shareConn]struct{}
	connSem         *globalSemaphore
	uses            int
	nextConnID      int
	nextConnectorID int
	expiry          *time.Timer
	idle            *time.Timer
	closed          bool
	closeReason     string
}

func (sh *share) target(id string) (proto.ShareTarget, bool) {
	for _, t := range sh.targets {
		if t.ID == id {
			return t, true
		}
	}
	return proto.ShareTarget{}, false
}

// shareRegistry holds every live share. One mutex covers all share state,
// including per-share membership, mirroring Registry: writes are rare and
// reads are a map lookup.
type shareRegistry struct {
	mu       sync.Mutex
	byHash   map[[32]byte]*share
	byID     map[string]*share
	byOwner  map[*AgentSession]map[string]*share
	watchers map[*AgentSession]struct{}
	maxTTL   time.Duration
	onExpire func(sh *share)
	onIdle   func(sh *share)
	now      func() time.Time
}

func newShareRegistry(maxTTL time.Duration) *shareRegistry {
	if maxTTL <= 0 {
		maxTTL = DefaultMaxShareTTL
	}
	return &shareRegistry{
		byHash:   make(map[[32]byte]*share),
		byID:     make(map[string]*share),
		byOwner:  make(map[*AgentSession]map[string]*share),
		watchers: make(map[*AgentSession]struct{}),
		maxTTL:   maxTTL,
		now:      time.Now,
	}
}

func shareSecretHash(secret string) [32]byte {
	return sha256.Sum256([]byte(secret))
}

func validShareLabel(label string) bool {
	if len(label) > maxShareLabelLen {
		return false
	}
	for _, r := range label {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func validSharePreset(preset string) bool {
	switch preset {
	case "postgres", "mysql", "redis", "http", "tcp":
		return true
	}
	return false
}

func decodeHash(hexDigest string) ([32]byte, bool) {
	var out [32]byte
	raw, err := hex.DecodeString(hexDigest)
	if err != nil || len(raw) != sha256.Size {
		return out, false
	}
	copy(out[:], raw)
	return out, true
}

// validateShare turns a Share request into a share, or reports why it is
// rejected. It does not touch the registry.
func (r *shareRegistry) validateShare(req proto.Share, now time.Time) (*share, error) {
	if req.Kind != proto.KindTCP {
		return nil, fmt.Errorf("share kind must be %q", proto.KindTCP)
	}
	hash, ok := decodeHash(req.SecretSHA256)
	if !ok {
		return nil, errors.New("secret_sha256 must be a 64-character hex SHA-256")
	}
	if !validShareLabel(req.Label) {
		return nil, fmt.Errorf("label must be printable and at most %d bytes", maxShareLabelLen)
	}
	if len(req.Targets) == 0 {
		return nil, errors.New("a share needs at least one target")
	}
	if len(req.Targets) > maxShareTargets {
		return nil, fmt.Errorf("at most %d targets per share", maxShareTargets)
	}
	seen := map[string]bool{}
	for _, t := range req.Targets {
		if !targetIDRe.MatchString(t.ID) {
			return nil, fmt.Errorf("invalid target id %q", t.ID)
		}
		if seen[t.ID] {
			return nil, fmt.Errorf("duplicate target id %q", t.ID)
		}
		seen[t.ID] = true
		if !validSharePreset(t.Preset) {
			return nil, fmt.Errorf("unknown preset %q", t.Preset)
		}
		if !validShareLabel(t.Label) || !validShareLabel(t.User) {
			return nil, errors.New("target label and user must be printable")
		}
		if t.DefaultPort < 0 || t.DefaultPort > 65535 {
			return nil, errors.New("default_port out of range")
		}
	}
	if req.MaxConns < 0 || req.MaxConns > maxShareMaxConns {
		return nil, fmt.Errorf("max_conns must be between 1 and %d", maxShareMaxConns)
	}
	if req.MaxConnectors < 0 || req.MaxConnectors > maxShareMaxConnectors {
		return nil, fmt.Errorf("max_connectors must be between 1 and %d", maxShareMaxConnectors)
	}
	if req.MaxUses < 0 {
		return nil, errors.New("max_uses must not be negative")
	}
	if len(req.AllowCIDRs) > maxAccessCIDRs {
		return nil, fmt.Errorf("too many allow_cidrs entries (max %d)", maxAccessCIDRs)
	}
	var allow []netip.Prefix
	for _, c := range req.AllowCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("invalid allow_cidrs entry %q", c)
		}
		allow = append(allow, p)
	}
	if req.IdleTimeoutMS < 0 {
		return nil, errors.New("idle_timeout_ms must not be negative")
	}
	idle := time.Duration(req.IdleTimeoutMS) * time.Millisecond
	if idle > 0 && idle < minShareIdleTimeout {
		return nil, fmt.Errorf("idle timeout must be at least %s", minShareIdleTimeout)
	}
	var passHash [32]byte
	hasPass := req.PassphraseSHA256 != ""
	if hasPass {
		passHash, ok = decodeHash(req.PassphraseSHA256)
		if !ok {
			return nil, errors.New("passphrase_sha256 must be a 64-character hex SHA-256")
		}
	}

	expiresAt := time.UnixMilli(req.ExpiresAtMS)
	if req.ExpiresAtMS <= 0 || !expiresAt.After(now) {
		return nil, errors.New("expires_at_unix_ms must be in the future")
	}
	if expiresAt.After(now.Add(r.maxTTL)) {
		return nil, errShareTTLTooLong
	}

	policy := sharePolicy{
		maxConns:      req.MaxConns,
		maxConnectors: req.MaxConnectors,
		maxUses:       req.MaxUses,
		allow:         allow,
		idleTimeout:   idle,
		approve:       req.Approve,
		hasPassphrase: hasPass,
		passHash:      passHash,
	}
	if req.SingleUse && policy.maxUses == 0 {
		policy.maxUses = 1
	}
	if policy.maxConns == 0 {
		policy.maxConns = defaultShareMaxConns
	}
	if policy.maxConnectors == 0 {
		policy.maxConnectors = defaultShareMaxConnectors
	}

	targets := make([]proto.ShareTarget, len(req.Targets))
	copy(targets, req.Targets)
	for i := range targets {
		if targets[i].Label == "" {
			targets[i].Label = targets[i].Preset
		}
	}

	return &share{
		secretHash: hash,
		kind:       req.Kind,
		label:      req.Label,
		targets:    targets,
		createdAt:  now,
		expiresAt:  expiresAt,
		policy:     policy,
		e2e:        req.E2E,
		connectors: make(map[*AgentSession]*connectorInfo),
		pending:    make(map[string]*pendingConnect),
		conns:      make(map[*shareConn]struct{}),
		connSem:    newGlobalSemaphore(int64(policy.maxConns)),
	}, nil
}

// register adds a validated share owned by as. A share with the same hash
// registered by the same instance (the sharer reconnecting) is replaced; its
// connectors are told sharer_gone and reconnect on their own. The replaced
// share is returned so the caller can close it outside the lock.
func (r *shareRegistry) register(as *AgentSession, sh *share) (replaced *share, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.byHash[sh.secretHash]; ok {
		if existing.owner.InstanceID != as.InstanceID {
			return nil, errShareTaken
		}
		r.removeLocked(existing)
		replaced = existing
	}
	if len(r.byOwner[as]) >= maxSharesPerSession {
		if replaced != nil {
			r.addLocked(replaced)
		}
		return nil, errTooManyShares
	}

	sh.owner = as
	for {
		sh.id = "sh_" + randomHex(8)
		if _, taken := r.byID[sh.id]; !taken {
			break
		}
	}
	r.addLocked(sh)
	r.armExpiryLocked(sh)
	r.armIdleLocked(sh)
	metricActiveShares.Add(1)
	return replaced, nil
}

func (r *shareRegistry) armExpiryLocked(sh *share) {
	if sh.expiry != nil {
		sh.expiry.Stop()
	}
	if r.onExpire == nil {
		return
	}
	cb := r.onExpire
	sh.expiry = time.AfterFunc(time.Until(sh.expiresAt), func() { cb(sh) })
}

// armIdleLocked starts the idle timer when the share has no open relayed
// connection; addConn stops it.
func (r *shareRegistry) armIdleLocked(sh *share) {
	if sh.policy.idleTimeout <= 0 || r.onIdle == nil || len(sh.conns) > 0 || sh.closed {
		return
	}
	if sh.idle != nil {
		sh.idle.Stop()
	}
	cb := r.onIdle
	sh.idle = time.AfterFunc(sh.policy.idleTimeout, func() { cb(sh) })
}

func (r *shareRegistry) addLocked(sh *share) {
	r.byHash[sh.secretHash] = sh
	r.byID[sh.id] = sh
	if r.byOwner[sh.owner] == nil {
		r.byOwner[sh.owner] = make(map[string]*share)
	}
	r.byOwner[sh.owner][sh.id] = sh
}

func (r *shareRegistry) removeLocked(sh *share) {
	if cur, ok := r.byHash[sh.secretHash]; ok && cur == sh {
		delete(r.byHash, sh.secretHash)
	}
	if cur, ok := r.byID[sh.id]; ok && cur == sh {
		delete(r.byID, sh.id)
	}
	if owned, ok := r.byOwner[sh.owner]; ok {
		delete(owned, sh.id)
		if len(owned) == 0 {
			delete(r.byOwner, sh.owner)
		}
	}
}

// lookup finds a live share by its plaintext secret.
func (r *shareRegistry) lookup(secret string) (*share, bool) {
	hash := shareSecretHash(secret)
	r.mu.Lock()
	defer r.mu.Unlock()
	sh, ok := r.byHash[hash]
	if !ok || sh.closed || !sh.expiresAt.After(r.now()) {
		return nil, false
	}
	return sh, true
}

func (r *shareRegistry) byShareID(id string) (*share, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	sh, ok := r.byID[id]
	if !ok || sh.closed {
		return nil, false
	}
	return sh, true
}

// extend moves a live share's expiry. The new deadline must be in the
// future and within maxTTL of now.
func (r *shareRegistry) extend(sh *share, expiresAt time.Time) ([]*AgentSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if sh.closed {
		return nil, errShareClosed
	}
	if !expiresAt.After(now) {
		return nil, errors.New("expires_at_unix_ms must be in the future")
	}
	if expiresAt.After(now.Add(r.maxTTL)) {
		return nil, errShareTTLTooLong
	}
	sh.expiresAt = expiresAt
	r.armExpiryLocked(sh)
	connectors := make([]*AgentSession, 0, len(sh.connectors))
	for as := range sh.connectors {
		connectors = append(connectors, as)
	}
	return connectors, nil
}

// connectorID picks the id the sharer will see: the requested name,
// sanitized and made unique among live connectors, or cN.
func (sh *share) connectorIDLocked(name string) string {
	if name == "" || !connectorNameRe.MatchString(name) {
		sh.nextConnectorID++
		return "c" + strconv.Itoa(sh.nextConnectorID)
	}
	inUse := func(id string) bool {
		for _, ci := range sh.connectors {
			if ci.id == id {
				return true
			}
		}
		_, pending := sh.pending[id]
		return pending
	}
	if !inUse(name) {
		return name
	}
	for i := 2; ; i++ {
		candidate := name + "-" + strconv.Itoa(i)
		if len(candidate) > maxConnectorNameLen {
			candidate = candidate[:maxConnectorNameLen-len(strconv.Itoa(i))-1] + "-" + strconv.Itoa(i)
		}
		if !inUse(candidate) {
			return candidate
		}
	}
}

// admit checks everything about a connector that does not depend on the
// sharer's approval: liveness, passphrase, allow list, single-use lock,
// use count and connector count. It reserves the connector id on success;
// when p is non-nil (approval required) the reservation is parked under
// that id in the same critical section, so two connectors asking for the
// same name cannot both be handed it.
func (r *shareRegistry) admit(sh *share, as *AgentSession, req proto.Connect, p *pendingConnect) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if sh.closed || !sh.expiresAt.After(r.now()) {
		return "", errShareClosed
	}
	if existing, ok := sh.connectors[as]; ok {
		return existing.id, nil
	}
	if sh.policy.hasPassphrase {
		got, _ := decodeHash(proto.PassphraseDigest(hex.EncodeToString(sh.secretHash[:]), req.Passphrase))
		if req.Passphrase == "" || subtle.ConstantTimeCompare(got[:], sh.policy.passHash[:]) != 1 {
			return "", errBadPassphrase
		}
	}
	if len(sh.policy.allow) > 0 && !prefixesContain(sh.policy.allow, as.Remote.Addr()) {
		return "", errShareForbidden
	}
	if sh.policy.maxUses == 1 {
		if sh.lockedTo == "" {
			sh.lockedTo = as.InstanceID
		} else if sh.lockedTo != as.InstanceID {
			return "", errShareLocked
		}
	} else if sh.policy.maxUses > 0 && sh.uses >= sh.policy.maxUses {
		return "", errUsesExhausted
	}
	if len(sh.connectors)+len(sh.pending) >= sh.policy.maxConnectors {
		return "", errShareFull
	}
	id := sh.connectorIDLocked(req.Name)
	if p != nil {
		p.id = id
		sh.pending[id] = p
	}
	return id, nil
}

// join records as as a member under the reserved id. admit must have
// succeeded first; the share may have closed in between.
func (r *shareRegistry) join(sh *share, as *AgentSession, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sh.closed {
		return errShareClosed
	}
	if _, ok := sh.connectors[as]; ok {
		return nil
	}
	delete(sh.pending, id)
	if len(sh.connectors) >= sh.policy.maxConnectors {
		return errShareFull
	}
	sh.connectors[as] = &connectorInfo{id: id, joinedAt: r.now(), addr: as.Remote}
	sh.uses++
	as.share.Store(sh)
	as.connectorID = id
	metricActiveShareConnectors.Add(1)
	return nil
}

func (r *shareRegistry) removePending(sh *share, id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(sh.pending, id)
}

// resolvePending answers a pending connect; it reports whether one existed.
func (r *shareRegistry) resolvePending(sh *share, id string, allow bool) bool {
	r.mu.Lock()
	p, ok := sh.pending[id]
	if ok {
		delete(sh.pending, id)
	}
	r.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case p.answer <- allow:
	default:
	}
	return true
}

// disconnect removes as from sh and reports whether it was a member.
func (r *shareRegistry) disconnect(sh *share, as *AgentSession) (*connectorInfo, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ci, ok := sh.connectors[as]
	if !ok {
		return nil, false
	}
	delete(sh.connectors, as)
	metricActiveShareConnectors.Add(-1)
	return ci, true
}

// connectorByID finds a live connector session by its id.
func (r *shareRegistry) connectorByID(sh *share, id string) (*AgentSession, *connectorInfo, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for as, ci := range sh.connectors {
		if ci.id == id {
			return as, ci, true
		}
	}
	return nil, nil, false
}

// addConn registers a relayed connection and hands out its id. It fails once
// the share is closed so a stream racing the close is dropped instead of
// relayed past revocation.
func (r *shareRegistry) addConn(sh *share, sc *shareConn) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sh.closed {
		return 0, errShareClosed
	}
	if _, member := sh.connectors[sc.connector]; !member {
		return 0, errShareClosed
	}
	sh.nextConnID++
	sc.id = sh.nextConnID
	sh.conns[sc] = struct{}{}
	if sh.idle != nil {
		sh.idle.Stop()
		sh.idle = nil
	}
	metricActiveShareConns.Add(1)
	return sc.id, nil
}

// idleNow reports whether sh is live with no open relayed connection, so
// an idle timer that fired just as a connection opened does nothing.
func (r *shareRegistry) idleNow(sh *share) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !sh.closed && len(sh.conns) == 0
}

func (r *shareRegistry) removeConn(sh *share, sc *shareConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := sh.conns[sc]; ok {
		delete(sh.conns, sc)
		metricActiveShareConns.Add(-1)
	}
	r.armIdleLocked(sh)
}

// close marks sh closed and removes it from the registry, returning the
// connectors and relayed connections the caller must tear down. It is
// idempotent: a second call returns ok=false.
func (r *shareRegistry) close(sh *share, reason string) (connectors []*AgentSession, pending []*pendingConnect, conns []*shareConn, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sh.closed {
		return nil, nil, nil, false
	}
	sh.closed = true
	sh.closeReason = reason
	if sh.expiry != nil {
		sh.expiry.Stop()
	}
	if sh.idle != nil {
		sh.idle.Stop()
	}
	r.removeLocked(sh)
	for as := range sh.connectors {
		connectors = append(connectors, as)
	}
	for _, p := range sh.pending {
		pending = append(pending, p)
	}
	for sc := range sh.conns {
		conns = append(conns, sc)
	}
	sh.connectors = make(map[*AgentSession]*connectorInfo)
	sh.pending = make(map[string]*pendingConnect)
	metricActiveShareConnectors.Add(-int64(len(connectors)))
	metricActiveShares.Add(-1)
	return connectors, pending, conns, true
}

// sharesOwnedBy returns the live shares as registered, for teardown.
func (r *shareRegistry) sharesOwnedBy(as *AgentSession) []*share {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*share, 0, len(r.byOwner[as]))
	for _, sh := range r.byOwner[as] {
		out = append(out, sh)
	}
	return out
}

func (r *shareRegistry) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byID)
}

// list describes every live share, oldest first.
func (r *shareRegistry) list(asker *AgentSession) []proto.ShareInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]proto.ShareInfo, 0, len(r.byID))
	for _, sh := range r.byID {
		if sh.closed {
			continue
		}
		info := proto.ShareInfo{
			ShareID:       sh.id,
			Label:         sh.label,
			Targets:       append([]proto.ShareTarget(nil), sh.targets...),
			ExpiresAtMS:   sh.expiresAt.UnixMilli(),
			CreatedAtMS:   sh.createdAt.UnixMilli(),
			Mine:          sh.owner == asker,
			MaxConns:      sh.policy.maxConns,
			MaxConnectors: sh.policy.maxConnectors,
			MaxUses:       sh.policy.maxUses,
			Uses:          sh.uses,
			IdleTimeoutMS: sh.policy.idleTimeout.Milliseconds(),
			Approve:       sh.policy.approve,
			Passphrase:    sh.policy.hasPassphrase,
			E2E:           sh.e2e,
			Connectors:    []proto.ConnectorInfo{},
			OpenConns:     len(sh.conns),
		}
		for _, p := range sh.policy.allow {
			info.AllowCIDRs = append(info.AllowCIDRs, p.String())
		}
		for _, ci := range sh.connectors {
			info.Connectors = append(info.Connectors, proto.ConnectorInfo{ID: ci.id, Addr: ci.addr.String(), JoinedMS: ci.joinedAt.UnixMilli()})
		}
		sort.Slice(info.Connectors, func(i, j int) bool { return info.Connectors[i].JoinedMS < info.Connectors[j].JoinedMS })
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAtMS < out[j].CreatedAtMS })
	return out
}

func (r *shareRegistry) addWatcher(as *AgentSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.watchers[as] = struct{}{}
}

func (r *shareRegistry) removeWatcher(as *AgentSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.watchers, as)
}

func (r *shareRegistry) watcherList() []*AgentSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*AgentSession, 0, len(r.watchers))
	for as := range r.watchers {
		out = append(out, as)
	}
	return out
}

// ---- edge-side audit file ----

// shareAuditLog appends one JSON object per share event to a file, so an
// operator has a record that outlives the sharer's terminal.
type shareAuditLog struct {
	mu sync.Mutex
	w  io.Writer
	c  io.Closer
}

func openShareAuditLog(path string) (*shareAuditLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &shareAuditLog{w: f, c: f}, nil
}

func (l *shareAuditLog) write(ev proto.ShareEvent) {
	if l == nil {
		return
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.w.Write(append(b, '\n'))
}

func (l *shareAuditLog) close() {
	if l == nil || l.c == nil {
		return
	}
	l.c.Close()
}

// ---- server-side handlers ----

func (s *Server) handleShare(as *AgentSession, ctrl *proto.Conn, id uint64, req proto.Share) {
	if as.NegotiatedVersion < 3 {
		ctrl.Write(proto.TypeShareErr, id, proto.ShareErr{Code: proto.CodeFeatureUnsupported, Message: "sharing requires protocol v3"})
		return
	}
	sh, err := s.shares.validateShare(req, time.Now())
	if err != nil {
		code := proto.CodeInvalidShare
		if errors.Is(err, errShareTTLTooLong) {
			code = proto.CodeShareTTLTooLong
			err = fmt.Errorf("expiry exceeds this edge's maximum share lifetime of %s", s.shares.maxTTL)
		}
		ctrl.Write(proto.TypeShareErr, id, proto.ShareErr{Code: code, Message: err.Error()})
		return
	}
	replaced, err := s.shares.register(as, sh)
	if err != nil {
		switch {
		case errors.Is(err, errShareTaken):
			ctrl.Write(proto.TypeShareErr, id, proto.ShareErr{Code: proto.CodeShareTaken, Message: "this share secret is registered by another agent"})
		case errors.Is(err, errTooManyShares):
			ctrl.Write(proto.TypeShareErr, id, proto.ShareErr{Code: proto.CodeTooManyShares, Message: fmt.Sprintf("at most %d live shares per session", maxSharesPerSession)})
		default:
			ctrl.Write(proto.TypeShareErr, id, proto.ShareErr{Code: proto.CodeInternal, Message: err.Error()})
		}
		return
	}
	if replaced != nil {
		s.closeShare(replaced, proto.ShareReasonSharerGone)
	}
	slog.Info("edge: share registered", "share_id", sh.id, "session_id", as.ID, "label", sh.label, "targets", shareTargetsSummary(sh.targets), "expires_at", sh.expiresAt.UTC().Format(time.RFC3339), "max_conns", sh.policy.maxConns, "max_connectors", sh.policy.maxConnectors, "max_uses", sh.policy.maxUses, "approve", sh.policy.approve, "passphrase", sh.policy.hasPassphrase, "e2e", sh.e2e, "allow_cidrs", len(sh.policy.allow))
	s.notifyWatchers(sh, proto.ShareEvent{ShareID: sh.id, Event: proto.ShareEventRegistered, AtMS: time.Now().UnixMilli(), ExpiresAtMS: sh.expiresAt.UnixMilli(), Label: sh.label})
	ctrl.Write(proto.TypeShareOK, id, proto.ShareOK{ShareID: sh.id, ExpiresAtMS: sh.expiresAt.UnixMilli()})
}

func (s *Server) handleUnshare(as *AgentSession, ctrl *proto.Conn, id uint64, req proto.Unshare) {
	sh, ok := s.shares.byShareID(req.ShareID)
	if !ok {
		ctrl.Write(proto.TypeError, id, proto.Error{Code: proto.CodeShareNotFound, Message: "no such live share"})
		return
	}
	slog.Info("edge: share revoked", "share_id", sh.id, "by_session", as.ID, "owner_session", sh.owner.ID)
	s.closeShare(sh, proto.ShareReasonRevoked)
	ctrl.Write(proto.TypeUnshareOK, id, proto.UnshareOK{ShareID: sh.id})
}

func (s *Server) handleShareUpdate(as *AgentSession, ctrl *proto.Conn, id uint64, req proto.ShareUpdate) {
	sh, ok := s.shares.byShareID(req.ShareID)
	if !ok {
		ctrl.Write(proto.TypeShareErr, id, proto.ShareErr{Code: proto.CodeShareNotFound, Message: "no such live share"})
		return
	}
	expiresAt := time.UnixMilli(req.ExpiresAtMS)
	connectors, err := s.shares.extend(sh, expiresAt)
	if err != nil {
		code := proto.CodeInvalidShare
		if errors.Is(err, errShareTTLTooLong) {
			code = proto.CodeShareTTLTooLong
			err = fmt.Errorf("expiry exceeds this edge's maximum share lifetime of %s", s.shares.maxTTL)
		} else if errors.Is(err, errShareClosed) {
			code = proto.CodeShareNotFound
		}
		ctrl.Write(proto.TypeShareErr, id, proto.ShareErr{Code: code, Message: err.Error()})
		return
	}
	slog.Info("edge: share extended", "share_id", sh.id, "by_session", as.ID, "expires_at", expiresAt.UTC().Format(time.RFC3339))
	s.notifySharer(sh, proto.ShareEvent{ShareID: sh.id, Event: proto.ShareEventExtended, AtMS: time.Now().UnixMilli(), ExpiresAtMS: expiresAt.UnixMilli()})
	for _, c := range connectors {
		c.Sess.Control().Write(proto.TypeShareUpdated, c.IDGen.Next(), proto.ShareUpdated{ShareID: sh.id, ExpiresAtMS: expiresAt.UnixMilli()})
	}
	ctrl.Write(proto.TypeShareOK, id, proto.ShareOK{ShareID: sh.id, ExpiresAtMS: expiresAt.UnixMilli()})
}

func (s *Server) handleKick(as *AgentSession, ctrl *proto.Conn, id uint64, req proto.Kick) {
	sh, ok := s.shares.byShareID(req.ShareID)
	if !ok {
		ctrl.Write(proto.TypeError, id, proto.Error{Code: proto.CodeShareNotFound, Message: "no such live share"})
		return
	}
	if s.shares.resolvePending(sh, req.ConnectorID, false) {
		ctrl.Write(proto.TypeKickOK, id, proto.KickOK{ShareID: sh.id, ConnectorID: req.ConnectorID})
		return
	}
	victim, ci, ok := s.shares.connectorByID(sh, req.ConnectorID)
	if !ok {
		ctrl.Write(proto.TypeError, id, proto.Error{Code: proto.CodeNoSuchConnector, Message: "no such connector on this share"})
		return
	}
	slog.Info("edge: connector kicked", "share_id", sh.id, "connector_id", ci.id, "by_session", as.ID)
	s.dropConnector(sh, victim, proto.ShareReasonKicked)
	ctrl.Write(proto.TypeKickOK, id, proto.KickOK{ShareID: sh.id, ConnectorID: ci.id})
}

// dropConnector removes one connector: its relayed connections are cut, it
// is told share_closed{reason}, and its session closes.
func (s *Server) dropConnector(sh *share, victim *AgentSession, reason string) {
	ci, ok := s.shares.disconnect(sh, victim)
	if !ok {
		return
	}
	s.shares.mu.Lock()
	var conns []*shareConn
	for sc := range sh.conns {
		if sc.connector == victim {
			conns = append(conns, sc)
		}
	}
	s.shares.mu.Unlock()
	now := time.Now()
	for _, sc := range conns {
		sc.client.SetDeadline(now)
		if sc.upstream != nil {
			sc.upstream.SetDeadline(now)
		}
	}
	victim.Sess.Control().Write(proto.TypeShareClosed, victim.IDGen.Next(), proto.ShareClosed{ShareID: sh.id, Reason: reason})
	s.notifySharer(sh, proto.ShareEvent{
		ShareID:     sh.id,
		Event:       proto.ShareEventConnectorLeft,
		AtMS:        now.UnixMilli(),
		ConnectorID: ci.id,
		ClientAddr:  victim.Remote.String(),
		DurationMS:  now.Sub(ci.joinedAt).Milliseconds(),
		Reason:      reason,
	})
	deadline := time.After(shareForceCloseGrace)
	for _, sc := range conns {
		select {
		case <-sc.done:
		case <-deadline:
		}
	}
	victim.Sess.Close("connector " + reason)
}

func (s *Server) handleApprove(as *AgentSession, ctrl *proto.Conn, id uint64, req proto.Approve) {
	sh, ok := s.shares.byShareID(req.ShareID)
	if !ok {
		ctrl.Write(proto.TypeError, id, proto.Error{Code: proto.CodeShareNotFound, Message: "no such live share"})
		return
	}
	if !s.shares.resolvePending(sh, req.ConnectorID, req.Allow) {
		ctrl.Write(proto.TypeError, id, proto.Error{Code: proto.CodeNoSuchConnector, Message: "no connect is waiting under that id"})
		return
	}
	ctrl.Write(proto.TypeApproveOK, id, proto.ApproveOK{ShareID: sh.id, ConnectorID: req.ConnectorID})
}

func (s *Server) handleListShares(as *AgentSession, ctrl *proto.Conn, id uint64) {
	ctrl.Write(proto.TypeSharesOK, id, proto.SharesOK{Shares: s.shares.list(as)})
}

func (s *Server) handleWatchShares(as *AgentSession, ctrl *proto.Conn, id uint64) {
	s.shares.addWatcher(as)
	ctrl.Write(proto.TypeWatchOK, id, proto.WatchOK{})
}

func connectErrFor(err error) (code, msg string) {
	switch {
	case errors.Is(err, errShareClosed):
		return proto.CodeShareNotFound, "share has expired or been revoked"
	case errors.Is(err, errBadPassphrase):
		return proto.CodeBadPassphrase, "this share needs a passphrase, and the one given does not match"
	case errors.Is(err, errShareForbidden):
		return proto.CodeForbiddenCIDR, "your address is not allowed by this share's policy"
	case errors.Is(err, errShareLocked):
		return proto.CodeShareLocked, "this single-use link is already in use by another connector"
	case errors.Is(err, errUsesExhausted):
		return proto.CodeShareUsesExhausted, "this link has been used as many times as it allows"
	case errors.Is(err, errShareFull):
		return proto.CodeShareFull, "this share has reached its connector limit"
	}
	return proto.CodeInternal, err.Error()
}

func (s *Server) handleConnect(as *AgentSession, ctrl *proto.Conn, id uint64, req proto.Connect) {
	sh := as.pendingShare
	if sh == nil {
		ctrl.Write(proto.TypeConnectErr, id, proto.ConnectErr{Code: proto.CodeShareNotFound, Message: "share is no longer available"})
		return
	}
	var p *pendingConnect
	if sh.policy.approve {
		p = &pendingConnect{session: as, answer: make(chan bool, 1)}
	}
	connectorID, err := s.shares.admit(sh, as, req, p)
	if err != nil {
		if errors.Is(err, errBadPassphrase) {
			// A wrong passphrase is a credential failure; count it like a
			// bad token so it cannot be guessed at line rate.
			s.authLimiter.recordFailure(as.Remote.Addr().String())
		}
		s.rejectConnect(sh, as, ctrl, id, req.Name, err)
		return
	}
	if p == nil {
		s.finishConnect(sh, as, ctrl, id, connectorID)
		return
	}

	// Approval-gated: the connect is parked under its id and the sharer is
	// asked. The wait runs off the control loop so the connector's
	// heartbeat keeps flowing.
	s.notifySharer(sh, proto.ShareEvent{
		ShareID:     sh.id,
		Event:       proto.ShareEventConnectPending,
		AtMS:        time.Now().UnixMilli(),
		ConnectorID: connectorID,
		ClientAddr:  as.Remote.String(),
	})
	go func() {
		timer := time.NewTimer(approvalTimeout)
		defer timer.Stop()
		select {
		case allow := <-p.answer:
			if allow {
				s.finishConnect(sh, as, ctrl, id, connectorID)
				return
			}
			s.shares.removePending(sh, connectorID)
			s.rejectConnectCode(sh, as, ctrl, id, connectorID, proto.CodeApprovalDenied, "the sharer declined this connection")
		case <-timer.C:
			s.shares.removePending(sh, connectorID)
			s.rejectConnectCode(sh, as, ctrl, id, connectorID, proto.CodeApprovalTimeout, "the sharer did not answer in time")
		case <-as.Done():
			s.shares.removePending(sh, connectorID)
		}
	}()
}

func (s *Server) finishConnect(sh *share, as *AgentSession, ctrl *proto.Conn, id uint64, connectorID string) {
	if err := s.shares.join(sh, as, connectorID); err != nil {
		s.rejectConnect(sh, as, ctrl, id, connectorID, err)
		return
	}
	slog.Info("edge: connector joined", "share_id", sh.id, "connector_id", connectorID, "session_id", as.ID, "ip", as.Remote.Addr())
	s.notifySharer(sh, proto.ShareEvent{
		ShareID:     sh.id,
		Event:       proto.ShareEventConnectorJoined,
		AtMS:        time.Now().UnixMilli(),
		ConnectorID: connectorID,
		ClientAddr:  as.Remote.String(),
	})
	ctrl.Write(proto.TypeConnectOK, id, proto.ConnectOK{
		ShareID:     sh.id,
		ConnectorID: connectorID,
		Label:       sh.label,
		Targets:     append([]proto.ShareTarget(nil), sh.targets...),
		ExpiresAtMS: sh.expiresAt.UnixMilli(),
		E2E:         sh.e2e,
	})
}

func (s *Server) rejectConnect(sh *share, as *AgentSession, ctrl *proto.Conn, id uint64, who string, err error) {
	code, msg := connectErrFor(err)
	s.rejectConnectCode(sh, as, ctrl, id, who, code, msg)
}

func (s *Server) rejectConnectCode(sh *share, as *AgentSession, ctrl *proto.Conn, id uint64, who, code, msg string) {
	metricShareConnectRejected.Add(1)
	slog.Warn("edge: share connect rejected", "share_id", sh.id, "session_id", as.ID, "ip", as.Remote.Addr(), "code", code)
	s.notifySharer(sh, proto.ShareEvent{
		ShareID:     sh.id,
		Event:       proto.ShareEventConnRejected,
		AtMS:        time.Now().UnixMilli(),
		ConnectorID: who,
		ClientAddr:  as.Remote.String(),
		Reason:      code,
	})
	ctrl.Write(proto.TypeConnectErr, id, proto.ConnectErr{Code: code, Message: msg})
}

// releaseShares tears down everything a session owns or belongs to. It runs
// on every control-loop exit and must be idempotent.
func (s *Server) releaseShares(as *AgentSession, reason string) {
	if s.shares == nil {
		return
	}
	s.shares.removeWatcher(as)
	for _, sh := range s.shares.sharesOwnedBy(as) {
		s.closeShare(sh, reason)
	}
	if sh := as.share.Load(); sh != nil {
		if ci, ok := s.shares.disconnect(sh, as); ok {
			slog.Info("edge: connector left", "share_id", sh.id, "connector_id", ci.id, "session_id", as.ID)
			s.notifySharer(sh, proto.ShareEvent{
				ShareID:     sh.id,
				Event:       proto.ShareEventConnectorLeft,
				AtMS:        time.Now().UnixMilli(),
				ConnectorID: ci.id,
				ClientAddr:  as.Remote.String(),
				DurationMS:  time.Since(ci.joinedAt).Milliseconds(),
			})
		}
	}
}

// closeShare ends a share: the sharer gets a closed event, every connector
// gets ShareClosed and is disconnected, pending approvals are denied, and
// every relayed connection is cut.
func (s *Server) closeShare(sh *share, reason string) {
	connectors, pending, conns, ok := s.shares.close(sh, reason)
	if !ok {
		return
	}
	slog.Info("edge: share closed", "share_id", sh.id, "reason", reason, "connectors", len(connectors), "conns", len(conns))

	s.notifySharer(sh, proto.ShareEvent{
		ShareID: sh.id,
		Event:   proto.ShareEventClosed,
		AtMS:    time.Now().UnixMilli(),
		Reason:  reason,
	})

	for _, p := range pending {
		select {
		case p.answer <- false:
		default:
		}
	}
	for _, c := range connectors {
		c.Sess.Control().Write(proto.TypeShareClosed, c.IDGen.Next(), proto.ShareClosed{ShareID: sh.id, Reason: reason})
	}
	for _, sc := range conns {
		now := time.Now()
		sc.client.SetDeadline(now)
		if sc.upstream != nil {
			sc.upstream.SetDeadline(now)
		}
	}
	// Give relays a moment to finish and report conn_close before the
	// connector sessions are closed under them.
	deadline := time.After(shareForceCloseGrace)
	for _, sc := range conns {
		select {
		case <-sc.done:
		case <-deadline:
		}
	}
	for _, c := range connectors {
		c.Sess.Close("share " + reason)
	}
}

// notifySharer writes an audit event to the sharer's control stream, to
// every watching operator session, and to the edge audit file. The control
// stream has its own write mutex; events are small and the sharer reads
// continuously, so a write only blocks on a wedged peer, which the
// heartbeat kills.
func (s *Server) notifySharer(sh *share, ev proto.ShareEvent) {
	if owner := sh.owner; owner != nil {
		_ = owner.Sess.Control().Write(proto.TypeShareEvent, owner.IDGen.Next(), ev)
	}
	s.notifyWatchers(sh, ev)
}

func (s *Server) notifyWatchers(sh *share, ev proto.ShareEvent) {
	ev.Label = sh.label
	s.shareAudit.write(ev)
	for _, w := range s.shares.watcherList() {
		if w == sh.owner {
			continue
		}
		_ = w.Sess.Control().Write(proto.TypeShareEvent, w.IDGen.Next(), ev)
	}
}

// serveConnectorStreams accepts data streams a connector opens and relays
// each one to the sharer. It returns when the session or ctx ends.
func (s *Server) serveConnectorStreams(ctx context.Context, as *AgentSession) {
	for {
		stream, err := as.Sess.AcceptRaw(ctx)
		if err != nil {
			return
		}
		go s.handleShareStream(as, stream)
	}
}

// rejectStreams closes any data stream an operator session tries to push
// into the edge; only the edge opens streams toward operator agents.
func (s *Server) rejectStreams(ctx context.Context, as *AgentSession) {
	for {
		stream, err := as.Sess.AcceptRaw(ctx)
		if err != nil {
			return
		}
		slog.Warn("edge: operator session opened a stream toward the edge; closing", "session_id", as.ID)
		stream.Close()
	}
}

func (s *Server) handleShareStream(as *AgentSession, stream net.Conn) {
	pre, err := readSharePreamble(stream)
	if err != nil {
		stream.Close()
		return
	}
	sh := as.share.Load()
	if sh == nil || pre.Kind != proto.KindShare || pre.ShareID != sh.id {
		slog.Warn("edge: share stream rejected", "session_id", as.ID, "kind", pre.Kind, "share_id", pre.ShareID)
		stream.Close()
		return
	}
	target := pre.Target
	if target == "" && len(sh.targets) == 1 {
		target = sh.targets[0].ID
	}
	if _, ok := sh.target(target); !ok {
		slog.Warn("edge: share stream for unknown target", "session_id", as.ID, "share_id", sh.id, "target", pre.Target)
		stream.Close()
		return
	}
	s.relayShareConn(sh, as, stream, target, pre.ReqID)
}

func readSharePreamble(stream net.Conn) (proto.StreamOpen, error) {
	if err := stream.SetReadDeadline(time.Now().Add(dialBudget)); err != nil {
		return proto.StreamOpen{}, err
	}
	m, err := proto.ReadMsg(stream)
	if err != nil {
		return proto.StreamOpen{}, err
	}
	if m.Type != proto.TypeStreamOpen {
		return proto.StreamOpen{}, fmt.Errorf("edge: unexpected preamble type %q", m.Type)
	}
	pre, err := proto.Decode[proto.StreamOpen](m)
	if err != nil {
		return proto.StreamOpen{}, err
	}
	if err := stream.SetReadDeadline(time.Time{}); err != nil {
		return proto.StreamOpen{}, err
	}
	return pre, nil
}

// relayShareConn admits one connector stream against every budget it
// consumes, opens the matching stream to the sharer and copies bytes until
// either side closes.
func (s *Server) relayShareConn(sh *share, as *AgentSession, client net.Conn, target, reqID string) {
	owner := sh.owner
	clientAddr := as.Remote.String()
	if reqID == "" {
		reqID = randomHex(8)
	}

	reject := func(reason string) {
		slog.Warn("edge: share connection rejected", "share_id", sh.id, "connector_id", as.connectorID, "reason", reason)
		s.notifySharer(sh, proto.ShareEvent{
			ShareID:     sh.id,
			Event:       proto.ShareEventConnRejected,
			AtMS:        time.Now().UnixMilli(),
			ConnectorID: as.connectorID,
			Target:      target,
			ClientAddr:  clientAddr,
			Reason:      reason,
		})
		client.Close()
	}

	releaseIP, ok := s.perIP.acquire(as.Remote.Addr().String())
	if !ok {
		metricShareRejectedPerIPCap.Add(1)
		reject("per_ip_cap")
		return
	}
	defer releaseIP()

	if !s.shareSem.tryAcquire() {
		metricShareRejectedGlobalCap.Add(1)
		reject("global_cap")
		return
	}
	defer s.shareSem.release()

	if !sh.connSem.tryAcquire() {
		metricShareRejectedShareCap.Add(1)
		reject("max_conns")
		return
	}
	defer sh.connSem.release()

	if !as.tryAcquireStream() {
		metricShareRejectedSessionCap.Add(1)
		reject("connector_session_cap")
		return
	}
	defer as.releaseStream()

	if !owner.tryAcquireStream() {
		metricShareRejectedSessionCap.Add(1)
		reject("sharer_session_cap")
		return
	}
	defer owner.releaseStream()

	sc := &shareConn{connector: as, target: target, client: client, done: make(chan struct{})}
	defer close(sc.done)
	if _, err := s.shares.addConn(sh, sc); err != nil {
		reject("share_closed")
		return
	}
	defer s.shares.removeConn(sh, sc)

	owner.inflight.Add(1)
	defer owner.inflight.Done()
	as.inflight.Add(1)
	defer as.inflight.Done()

	dialCtx, cancel := context.WithTimeout(context.Background(), dialBudget)
	upstream, err := owner.Sess.OpenStream(dialCtx, proto.StreamOpen{
		Kind:       proto.KindTCP,
		Host:       sh.id + ".share",
		ReqID:      reqID,
		ClientAddr: clientAddr,
		ShareID:    sh.id,
		Target:     target,
	})
	cancel()
	if err != nil {
		metricShareRejectedDialFailure.Add(1)
		reject("sharer_unreachable")
		return
	}
	sc.upstream = upstream
	// A close that raced the dial has already swept sc.conns; honour it.
	if _, live := s.shares.byShareID(sh.id); !live {
		upstream.Close()
		reject("share_closed")
		return
	}

	start := time.Now()
	s.notifySharer(sh, proto.ShareEvent{
		ShareID:     sh.id,
		Event:       proto.ShareEventConnOpen,
		AtMS:        start.UnixMilli(),
		ConnectorID: as.connectorID,
		ConnID:      sc.id,
		Target:      target,
		ClientAddr:  clientAddr,
	})

	idle := newIdleDeadline(s.cfg.Limits.TCPIdleTimeout, client, upstream)
	var up, down atomic.Int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(upstream, idle.reader(client))
		up.Store(n)
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, idle.reader(upstream))
		down.Store(n)
		closeWrite(client)
	}()
	wg.Wait()
	upstream.Close()
	client.Close()

	s.notifySharer(sh, proto.ShareEvent{
		ShareID:     sh.id,
		Event:       proto.ShareEventConnClose,
		AtMS:        time.Now().UnixMilli(),
		ConnectorID: as.connectorID,
		ConnID:      sc.id,
		Target:      target,
		ClientAddr:  clientAddr,
		DurationMS:  time.Since(start).Milliseconds(),
		BytesUp:     up.Load(),
		BytesDown:   down.Load(),
	})
}

// shareTargetsSummary renders targets for log lines.
func shareTargetsSummary(ts []proto.ShareTarget) string {
	parts := make([]string, 0, len(ts))
	for _, t := range ts {
		parts = append(parts, t.ID+"="+t.Preset)
	}
	return strings.Join(parts, ",")
}
