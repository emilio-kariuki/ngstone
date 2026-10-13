package edge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"ngstone/internal/proto"
)

// Sharing (protocol v3). A sharer session registers a share: the SHA-256 of
// a secret it minted, a label, an expiry and a policy. A connector session
// authenticates with the plaintext secret, joins the share, and opens data
// streams toward the edge; the edge opens a matching stream toward the
// sharer and copies bytes both ways. Nothing here is persisted: an edge
// restart forgets every share, and the sharer re-registers on reconnect.

const (
	DefaultMaxShareTTL = 24 * time.Hour

	maxSharesPerSession       = 8
	maxShareLabelLen          = 128
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

type sharePolicy struct {
	maxConns      int
	maxConnectors int
	singleUse     bool
	allow         []netip.Prefix
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
	client    net.Conn // connector -> edge stream
	upstream  net.Conn // edge -> sharer stream
	done      chan struct{}
}

type share struct {
	id          string
	secretHash  [32]byte
	owner       *AgentSession
	kind        string
	label       string
	preset      string
	defaultPort int
	expiresAt   time.Time
	policy      sharePolicy
	lockedTo    string // single-use: instance id of the first connector

	connectors      map[*AgentSession]*connectorInfo
	conns           map[*shareConn]struct{}
	connSem         *globalSemaphore
	nextConnID      int
	nextConnectorID int
	expiry          *time.Timer
	closed          bool
	closeReason     string
}

// shareRegistry holds every live share. One mutex covers all share state,
// including per-share membership, mirroring Registry: writes are rare and
// reads are a map lookup.
type shareRegistry struct {
	mu       sync.Mutex
	byHash   map[[32]byte]*share
	byID     map[string]*share
	byOwner  map[*AgentSession]map[string]*share
	maxTTL   time.Duration
	onExpire func(sh *share)
	now      func() time.Time
}

func newShareRegistry(maxTTL time.Duration) *shareRegistry {
	if maxTTL <= 0 {
		maxTTL = DefaultMaxShareTTL
	}
	return &shareRegistry{
		byHash:  make(map[[32]byte]*share),
		byID:    make(map[string]*share),
		byOwner: make(map[*AgentSession]map[string]*share),
		maxTTL:  maxTTL,
		now:     time.Now,
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
	case "", "postgres", "mysql", "redis", "tcp":
		return true
	}
	return false
}

// validateShare turns a Share request into a share, or reports why it is
// rejected. It does not touch the registry.
func (r *shareRegistry) validateShare(req proto.Share, now time.Time) (*share, error) {
	if req.Kind != proto.KindTCP {
		return nil, fmt.Errorf("share kind must be %q", proto.KindTCP)
	}
	raw, err := hex.DecodeString(req.SecretSHA256)
	if err != nil || len(raw) != sha256.Size {
		return nil, errors.New("secret_sha256 must be a 64-character hex SHA-256")
	}
	var hash [32]byte
	copy(hash[:], raw)

	if !validShareLabel(req.Label) {
		return nil, fmt.Errorf("label must be printable and at most %d bytes", maxShareLabelLen)
	}
	if !validSharePreset(req.Preset) {
		return nil, fmt.Errorf("unknown preset %q", req.Preset)
	}
	if req.DefaultPort < 0 || req.DefaultPort > 65535 {
		return nil, errors.New("default_port out of range")
	}
	if req.MaxConns < 0 || req.MaxConns > maxShareMaxConns {
		return nil, fmt.Errorf("max_conns must be between 1 and %d", maxShareMaxConns)
	}
	if req.MaxConnectors < 0 || req.MaxConnectors > maxShareMaxConnectors {
		return nil, fmt.Errorf("max_connectors must be between 1 and %d", maxShareMaxConnectors)
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
		singleUse:     req.SingleUse,
		allow:         allow,
	}
	if policy.maxConns == 0 {
		policy.maxConns = defaultShareMaxConns
	}
	if policy.maxConnectors == 0 {
		policy.maxConnectors = defaultShareMaxConnectors
	}

	return &share{
		secretHash:  hash,
		kind:        req.Kind,
		label:       req.Label,
		preset:      req.Preset,
		defaultPort: req.DefaultPort,
		expiresAt:   expiresAt,
		policy:      policy,
		connectors:  make(map[*AgentSession]*connectorInfo),
		conns:       make(map[*shareConn]struct{}),
		connSem:     newGlobalSemaphore(int64(policy.maxConns)),
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
			// Undo the removal so the old share stays live.
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

	if r.onExpire != nil {
		cb := r.onExpire
		sh.expiry = time.AfterFunc(time.Until(sh.expiresAt), func() { cb(sh) })
	}
	metricActiveShares.Add(1)
	return replaced, nil
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

func (r *shareRegistry) ownedBy(as *AgentSession, id string) (*share, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	sh, ok := r.byOwner[as][id]
	if !ok || sh.closed {
		return nil, false
	}
	return sh, true
}

// connect admits a connector session to sh under its policy and returns the
// connector id.
func (r *shareRegistry) connect(sh *share, as *AgentSession) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if sh.closed || !sh.expiresAt.After(r.now()) {
		return "", errShareClosed
	}
	if existing, ok := sh.connectors[as]; ok {
		return existing.id, nil
	}
	if len(sh.policy.allow) > 0 && !prefixesContain(sh.policy.allow, as.Remote.Addr()) {
		return "", errShareForbidden
	}
	if sh.policy.singleUse {
		if sh.lockedTo == "" {
			sh.lockedTo = as.InstanceID
		} else if sh.lockedTo != as.InstanceID {
			return "", errShareLocked
		}
	}
	if len(sh.connectors) >= sh.policy.maxConnectors {
		return "", errShareFull
	}
	sh.nextConnectorID++
	ci := &connectorInfo{
		id:       "c" + strconv.Itoa(sh.nextConnectorID),
		joinedAt: r.now(),
		addr:     as.Remote,
	}
	sh.connectors[as] = ci
	as.share.Store(sh)
	as.connectorID = ci.id
	metricActiveShareConnectors.Add(1)
	return ci.id, nil
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
	metricActiveShareConns.Add(1)
	return sc.id, nil
}

func (r *shareRegistry) removeConn(sh *share, sc *shareConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := sh.conns[sc]; ok {
		delete(sh.conns, sc)
		metricActiveShareConns.Add(-1)
	}
}

// close marks sh closed and removes it from the registry, returning the
// connectors and relayed connections the caller must tear down. It is
// idempotent: a second call returns ok=false.
func (r *shareRegistry) close(sh *share, reason string) (connectors []*AgentSession, conns []*shareConn, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sh.closed {
		return nil, nil, false
	}
	sh.closed = true
	sh.closeReason = reason
	if sh.expiry != nil {
		sh.expiry.Stop()
	}
	r.removeLocked(sh)
	for as := range sh.connectors {
		connectors = append(connectors, as)
	}
	for sc := range sh.conns {
		conns = append(conns, sc)
	}
	sh.connectors = make(map[*AgentSession]*connectorInfo)
	metricActiveShareConnectors.Add(-int64(len(connectors)))
	metricActiveShares.Add(-1)
	return connectors, conns, true
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

// ---- server-side handlers ----

func (s *Server) shareReg() *shareRegistry {
	return s.shares
}

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
	slog.Info("edge: share registered", "share_id", sh.id, "session_id", as.ID, "preset", sh.preset, "label", sh.label, "expires_at", sh.expiresAt.UTC().Format(time.RFC3339), "max_conns", sh.policy.maxConns, "max_connectors", sh.policy.maxConnectors, "single_use", sh.policy.singleUse, "allow_cidrs", len(sh.policy.allow))
	ctrl.Write(proto.TypeShareOK, id, proto.ShareOK{ShareID: sh.id, ExpiresAtMS: sh.expiresAt.UnixMilli()})
}

func (s *Server) handleUnshare(as *AgentSession, ctrl *proto.Conn, id uint64, req proto.Unshare) {
	sh, ok := s.shares.ownedBy(as, req.ShareID)
	if !ok {
		ctrl.Write(proto.TypeError, id, proto.Error{Code: proto.CodeShareNotFound, Message: "no such live share"})
		return
	}
	s.closeShare(sh, proto.ShareReasonRevoked)
	ctrl.Write(proto.TypeUnshareOK, id, proto.UnshareOK{ShareID: sh.id})
}

func (s *Server) handleConnect(as *AgentSession, ctrl *proto.Conn, id uint64) {
	sh := as.pendingShare
	if sh == nil {
		ctrl.Write(proto.TypeConnectErr, id, proto.ConnectErr{Code: proto.CodeShareNotFound, Message: "share is no longer available"})
		return
	}
	connectorID, err := s.shares.connect(sh, as)
	if err != nil {
		metricShareConnectRejected.Add(1)
		var code, msg string
		switch {
		case errors.Is(err, errShareClosed):
			code, msg = proto.CodeShareNotFound, "share has expired or been revoked"
		case errors.Is(err, errShareForbidden):
			code, msg = proto.CodeForbiddenCIDR, "your address is not allowed by this share's policy"
		case errors.Is(err, errShareLocked):
			code, msg = proto.CodeShareLocked, "this single-use link is already in use by another connector"
		case errors.Is(err, errShareFull):
			code, msg = proto.CodeShareFull, "this share has reached its connector limit"
		default:
			code, msg = proto.CodeInternal, err.Error()
		}
		slog.Warn("edge: share connect rejected", "share_id", sh.id, "session_id", as.ID, "ip", as.Remote.Addr(), "code", code)
		s.notifySharer(sh, proto.ShareEvent{
			ShareID:    sh.id,
			Event:      proto.ShareEventConnRejected,
			AtMS:       time.Now().UnixMilli(),
			ClientAddr: as.Remote.String(),
			Reason:     code,
		})
		ctrl.Write(proto.TypeConnectErr, id, proto.ConnectErr{Code: code, Message: msg})
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
		Preset:      sh.preset,
		DefaultPort: sh.defaultPort,
		ExpiresAtMS: sh.expiresAt.UnixMilli(),
	})
}

// releaseShares tears down everything a session owns or belongs to. It runs
// on every control-loop exit and must be idempotent.
func (s *Server) releaseShares(as *AgentSession, reason string) {
	if s.shares == nil {
		return
	}
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
// gets ShareClosed and is disconnected, and every relayed connection is cut.
func (s *Server) closeShare(sh *share, reason string) {
	connectors, conns, ok := s.shares.close(sh, reason)
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

// notifySharer writes an audit event to the sharer's control stream. The
// control stream has its own write mutex; events are small and the sharer
// reads continuously, so a write only blocks on a wedged peer, which the
// heartbeat kills.
func (s *Server) notifySharer(sh *share, ev proto.ShareEvent) {
	owner := sh.owner
	if owner == nil {
		return
	}
	_ = owner.Sess.Control().Write(proto.TypeShareEvent, owner.IDGen.Next(), ev)
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
	s.relayShareConn(sh, as, stream, pre.ReqID)
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
func (s *Server) relayShareConn(sh *share, as *AgentSession, client net.Conn, reqID string) {
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

	sc := &shareConn{connector: as, client: client, done: make(chan struct{})}
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
		ClientAddr:  clientAddr,
		DurationMS:  time.Since(start).Milliseconds(),
		BytesUp:     up.Load(),
		BytesDown:   down.Load(),
	})
}
