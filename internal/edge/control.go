package edge

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"ngstone/internal/credentials"
	"ngstone/internal/proto"
	"ngstone/internal/storage"
	"ngstone/internal/tunnel"
	"ngstone/internal/version"
)

var (
	authDeadline      = 5 * time.Second
	heartbeatInterval = 15 * time.Second
	heartbeatMisses   = 3
	drainTimeout      = 15 * time.Second
)

const authLimiterMaxIPs = 10000

type AgentSession struct {
	ID                string
	InstanceID        string
	Sess              tunnel.Session
	Remote            netip.AddrPort
	IDGen             *proto.IDGen
	NegotiatedVersion int
	// Scope is proto.ScopeOperator for token auth and proto.ScopeConnector
	// for share-secret auth. A connector may only connect, ping and say
	// goodbye; every other control message is forbidden.
	Scope string

	inflight         inflightTracker
	streamSem        *globalSemaphore
	upgradeStreamSem *globalSemaphore

	Credential          *credentials.Credential
	leaseMu             sync.Mutex
	durableLeases       map[string]string
	durableLeaseNum     atomic.Int64
	lastHeartbeat       atomic.Int64
	observabilityMu     sync.Mutex
	observabilityEvents map[string]struct{}

	// pendingShare is the share whose secret authenticated a connector
	// session; share is set once Connect admits it. connectorID is the id
	// the sharer sees in audit events.
	pendingShare *share
	share        atomic.Pointer[share]
	connectorID  string
}

func (a *AgentSession) isConnector() bool {
	return a.Scope == proto.ScopeConnector
}

func (a *AgentSession) Done() <-chan struct{} {
	return a.Sess.Done()
}

func (a *AgentSession) markHeartbeat() {
	if a == nil {
		return
	}
	a.lastHeartbeat.Store(time.Now().UnixNano())
}

func (a *AgentSession) healthy(now time.Time) bool {
	if a == nil || isSessionDead(a) {
		return false
	}
	last := a.lastHeartbeat.Load()
	if last == 0 {
		return true
	}
	timeout := heartbeatInterval * time.Duration(heartbeatMisses)
	if timeout <= 0 {
		return false
	}
	return now.Sub(time.Unix(0, last)) <= timeout
}

func (a *AgentSession) tryAcquireStream() bool {
	if a.streamSem == nil {
		return true
	}
	return a.streamSem.tryAcquire()
}

func (a *AgentSession) releaseStream() {
	if a.streamSem != nil {
		a.streamSem.release()
	}
}

func (a *AgentSession) tryAcquireUpgrade() bool {
	if a.upgradeStreamSem == nil {
		return true
	}
	return a.upgradeStreamSem.tryAcquire()
}

func (a *AgentSession) releaseUpgrade() {
	if a.upgradeStreamSem != nil {
		a.upgradeStreamSem.release()
	}
}

func (a *AgentSession) claimObservabilityEvent(event string) bool {
	if a == nil {
		return false
	}
	a.observabilityMu.Lock()
	defer a.observabilityMu.Unlock()
	if a.observabilityEvents == nil {
		a.observabilityEvents = make(map[string]struct{})
	}
	if _, ok := a.observabilityEvents[event]; ok {
		return false
	}
	a.observabilityEvents[event] = struct{}{}
	return true
}

func negotiateVersion(offered []int) (int, bool) {
	for _, sv := range proto.SupportedVersions {
		for _, ov := range offered {
			if ov == sv {
				return sv, true
			}
		}
	}
	return 0, false
}

type authRateLimiter struct {
	mu       sync.Mutex
	attempts *lru.Cache[string, []time.Time]
}

func newAuthRateLimiter() *authRateLimiter {
	c, err := lru.New[string, []time.Time](authLimiterMaxIPs)
	if err != nil {
		panic(err)
	}
	return &authRateLimiter{attempts: c}
}

const maxAuthFailuresPerMinute = 5

func rateLimitKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	if addr.Is4() || addr.Is4In6() {
		return addr.String()
	}
	prefix, err := addr.Prefix(48)
	if err != nil {
		return addr.String()
	}
	return prefix.Masked().String()
}

func (l *authRateLimiter) allowed(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := rateLimitKey(ip)
	l.prune(key)
	times, _ := l.attempts.Get(key)
	return len(times) < maxAuthFailuresPerMinute
}

func (l *authRateLimiter) recordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := rateLimitKey(ip)
	l.prune(key)
	times, _ := l.attempts.Get(key)
	times = append(times, time.Now())
	l.attempts.Add(key, times)
}

func (l *authRateLimiter) prune(key string) {
	times, ok := l.attempts.Get(key)
	if !ok {
		return
	}
	cutoff := time.Now().Add(-time.Minute)
	kept := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		l.attempts.Remove(key)
		return
	}
	l.attempts.Add(key, kept)
}

func (s *Server) acceptControl() bool {
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	if s.controlDraining {
		return false
	}
	s.controlConns.Add(1)
	return true
}

func (s *Server) serveControl(ctx context.Context, ln net.Listener) error {
	var backoff time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if backoff == 0 {
					backoff = 5 * time.Millisecond
				} else {
					backoff *= 2
				}
				if backoff > time.Second {
					backoff = time.Second
				}
				slog.Warn("edge: control accept error, retrying", "err", err, "backoff", backoff)
				timer := time.NewTimer(backoff)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return nil
				}
				continue
			}
			return err
		}
		backoff = 0
		if !s.unauthSem.tryAcquire() {
			conn.Close()
			continue
		}
		if !s.acceptControl() {
			conn.Close()
			s.unauthSem.release()
			continue
		}
		go func() {
			defer s.controlConns.Done()
			var once sync.Once
			release := func() { once.Do(s.unauthSem.release) }
			defer release()
			s.handleControlConn(ctx, conn, release)
		}()
	}
}

func (s *Server) handleControlConn(ctx context.Context, conn net.Conn, releaseUnauth func()) {
	s.handleControlConnTransport(ctx, conn, releaseUnauth, s.tlsMgr != nil)
}

func (s *Server) handleControlConnTransport(ctx context.Context, conn net.Conn, releaseUnauth func(), applyTLS bool) {
	ip := remoteIP(conn)

	deadline := time.Now().Add(authDeadline)
	if err := conn.SetReadDeadline(deadline); err != nil {
		conn.Close()
		return
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		conn.Close()
		return
	}

	if applyTLS && s.tlsMgr != nil {
		if !s.handshakeSem.tryAcquire() {
			conn.Close()
			return
		}
		tlsConn := tls.Server(conn, s.tlsMgr.ApexTLSConfig())
		hctx, cancel := context.WithDeadline(ctx, deadline)
		err := tlsConn.HandshakeContext(hctx)
		cancel()
		s.handshakeSem.release()
		if err != nil {
			slog.Warn("edge: control TLS handshake failed", "ip", ip, "err", err)
			conn.Close()
			return
		}
		conn = tlsConn
	}

	sess, err := tunnel.Server(conn)
	if err != nil {
		slog.Warn("edge: control session setup failed", "ip", ip, "err", err)
		conn.Close()
		return
	}

	remote, _ := netip.ParseAddrPort(conn.RemoteAddr().String())

	authCtx, cancelAuth := context.WithDeadline(ctx, deadline)
	as, err := s.authenticate(authCtx, sess, ip, remote, deadline)
	cancelAuth()
	if err != nil {
		sess.Close("auth failed")
		return
	}
	releaseUnauth()

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		sess.Close("clear read deadline failed")
		return
	}
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		sess.Close("clear write deadline failed")
		return
	}

	metricActiveSessions.Add(1)
	s.controlLoop(ctx, as)
}

func remoteIP(conn net.Conn) string {
	addrPort, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return addrPort.Addr().String()
}

func (s *Server) authenticate(ctx context.Context, sess tunnel.Session, ip string, remote netip.AddrPort, deadline time.Time) (*AgentSession, error) {
	ctrl := sess.Control()
	if err := ctrl.SetReadDeadline(deadline); err != nil {
		return nil, err
	}

	if !s.authLimiter.allowed(ip) {
		slog.Warn("edge: auth attempt", "ip", ip, "result", "rate_limited")
		return nil, errors.New("edge: auth rate limited")
	}

	msg, err := ctrl.Read()
	if err != nil {
		slog.Warn("edge: auth attempt", "ip", ip, "result", "no_auth_message", "err", err)
		return nil, err
	}
	if msg.Type != proto.TypeAuth {
		ctrl.Write(proto.TypeError, msg.ID, proto.Error{Code: proto.CodeMalformed, Message: "expected auth as first message"})
		slog.Warn("edge: auth attempt", "ip", ip, "result", "unexpected_first_message", "type", msg.Type)
		return nil, fmt.Errorf("edge: expected auth, got %q", msg.Type)
	}
	auth, err := proto.Decode[proto.Auth](msg)
	if err != nil {
		ctrl.Write(proto.TypeError, msg.ID, proto.Error{Code: proto.CodeMalformed, Message: "malformed auth"})
		slog.Warn("edge: auth attempt", "ip", ip, "result", "malformed", "err", err)
		return nil, err
	}

	if auth.Token != "" && auth.ShareSecret != "" {
		ctrl.Write(proto.TypeError, msg.ID, proto.Error{Code: proto.CodeMalformed, Message: "auth carries both token and share_secret"})
		slog.Warn("edge: auth attempt", "ip", ip, "result", "malformed", "err", "both token and share_secret")
		return nil, errors.New("edge: auth carries both token and share_secret")
	}

	scope := proto.ScopeOperator
	var pending *share
	var credential *credentials.Credential
	if auth.ShareSecret != "" {
		scope = proto.ScopeConnector
		// Hashing attacker-controlled input and looking the digest up leaks
		// nothing usable about the secret; the per-IP auth limiter above
		// applies to share-secret failures exactly as it does to tokens.
		sh, ok := s.shares.lookup(auth.ShareSecret)
		if !ok {
			s.authLimiter.recordFailure(ip)
			ctrl.Write(proto.TypeAuthErr, msg.ID, proto.AuthErr{Code: proto.CodeBadShare, Message: "unknown, expired or revoked share link"})
			slog.Warn("edge: auth attempt", "ip", ip, "result", "bad_share")
			return nil, errors.New("edge: bad share secret")
		}
		pending = sh
	} else if s.credentialStore != nil {
		validated, err := s.credentialStore.ValidateContext(ctx, auth.Token, time.Now())
		if err != nil {
			s.authLimiter.recordFailure(ip)
			ctrl.Write(proto.TypeAuthErr, msg.ID, proto.AuthErr{Code: proto.CodeBadToken, Message: "bad token"})
			slog.Warn("edge: auth attempt", "ip", ip, "result", "bad_token")
			return nil, errors.New("edge: bad token")
		}
		credential = &validated
	} else {
		sum := sha256.Sum256([]byte(auth.Token))
		if subtle.ConstantTimeCompare(sum[:], s.cfg.TokenSHA256) != 1 {
			s.authLimiter.recordFailure(ip)
			ctrl.Write(proto.TypeAuthErr, msg.ID, proto.AuthErr{Code: proto.CodeBadToken, Message: "bad token"})
			slog.Warn("edge: auth attempt", "ip", ip, "result", "bad_token")
			return nil, errors.New("edge: bad token")
		}
	}

	negotiated, ok := negotiateVersion(auth.ProtoVersions)
	if !ok {
		ctrl.Write(proto.TypeAuthErr, msg.ID, proto.AuthErr{Code: proto.CodeNoCommonVersion, Message: "no common protocol version"})
		slog.Warn("edge: auth attempt", "ip", ip, "result", "no_common_version", "offered", auth.ProtoVersions)
		return nil, errors.New("edge: no common protocol version")
	}
	if scope == proto.ScopeConnector && negotiated < 3 {
		ctrl.Write(proto.TypeAuthErr, msg.ID, proto.AuthErr{Code: proto.CodeNoCommonVersion, Message: "share links require protocol v3"})
		slog.Warn("edge: auth attempt", "ip", ip, "result", "no_common_version", "offered", auth.ProtoVersions, "scope", scope)
		return nil, errors.New("edge: connector offered no v3")
	}

	as := &AgentSession{
		ID:                randomHex(8),
		InstanceID:        auth.InstanceID,
		Sess:              sess,
		Remote:            remote,
		IDGen:             proto.NewEdgeIDGen(),
		NegotiatedVersion: negotiated,
		Scope:             scope,
		Credential:        credential,
		streamSem:         newGlobalSemaphore(s.limitsOrDefault().PerSessionInFlight),
		upgradeStreamSem:  newGlobalSemaphore(s.limitsOrDefault().PerSessionUpgradeInFlight),
		pendingShare:      pending,
	}
	as.markHeartbeat()

	if err := ctrl.Write(proto.TypeAuthOK, msg.ID, proto.AuthOK{
		ProtoVersion:  negotiated,
		SessionID:     as.ID,
		ServerVersion: "ngstoned/" + version.Version,
		Scope:         scope,
	}); err != nil {
		return nil, err
	}

	if err := ctrl.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}

	slog.Info("edge: auth attempt", "ip", ip, "result", "ok", "scope", scope, "instance_id", auth.InstanceID, "session_id", as.ID)
	s.recordEvent("info", "agent authenticated", map[string]string{
		"session_id":  as.ID,
		"instance_id": as.InstanceID,
	})
	return as, nil
}

func (s *Server) controlLoop(ctx context.Context, as *AgentSession) {
	defer func() {
		s.registry.ReleaseSession(as)
		s.releaseTCP(as)
		s.releaseShares(as, proto.ShareReasonSharerGone)
		s.releaseDurableSession(as)
		as.Sess.Close("control loop exited")
		metricActiveSessions.Add(-1)
		s.recordEvent("info", "control session closed", map[string]string{
			"session_id":  as.ID,
			"instance_id": as.InstanceID,
		})
	}()

	ctrl := as.Sess.Control()
	idgen := as.IDGen

	// Data streams opened by the peer: a connector's are relayed to its
	// sharer, an operator's are closed, since only the edge opens streams
	// toward an operator agent. Either loop ends with the session.
	acceptCtx, cancelAccept := context.WithCancel(ctx)
	defer cancelAccept()
	if as.isConnector() {
		go s.serveConnectorStreams(acceptCtx, as)
	} else {
		go s.rejectStreams(acceptCtx, as)
	}

	type readResult struct {
		msg proto.Msg
		err error
	}
	msgCh := make(chan readResult)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			m, err := ctrl.Read()
			select {
			case msgCh <- readResult{m, err}:
			case <-stop:
				return
			}
			if err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	awaitingPong := false
	misses := 0

	for {
		select {
		case <-ctx.Done():
			s.drainOnShutdown(as, ctrl)
			return
		case rr := <-msgCh:
			if rr.err != nil {
				slog.Info("edge: control connection closed", "session_id", as.ID, "err", rr.err)
				return
			}
			as.markHeartbeat()
			m := rr.msg
			if as.isConnector() && !connectorMaySend(m.Type) {
				ctrl.Write(proto.TypeError, m.ID, proto.Error{Code: proto.CodeForbidden, Message: fmt.Sprintf("%q is not allowed on a connector session", m.Type)})
				slog.Warn("edge: connector sent a forbidden message", "session_id", as.ID, "type", m.Type)
				return
			}
			if as.Credential != nil && !credentialMaySend(m.Type) {
				ctrl.Write(proto.TypeError, m.ID, proto.Error{Code: proto.CodeForbidden, Message: fmt.Sprintf("%q is not allowed with a scoped tunnel credential", m.Type)})
				return
			}
			switch m.Type {
			case proto.TypeBind:
				bind, err := proto.Decode[proto.Bind](m)
				if err != nil {
					ctrl.Write(proto.TypeError, m.ID, proto.Error{Code: proto.CodeMalformed, Message: "malformed bind"})
					return
				}
				s.handleBind(ctx, as, ctrl, m.ID, bind)
			case proto.TypeShare:
				req, err := proto.Decode[proto.Share](m)
				if err != nil {
					ctrl.Write(proto.TypeError, m.ID, proto.Error{Code: proto.CodeMalformed, Message: "malformed share"})
					return
				}
				s.handleShare(as, ctrl, m.ID, req)
			case proto.TypeUnshare:
				req, err := proto.Decode[proto.Unshare](m)
				if err != nil {
					ctrl.Write(proto.TypeError, m.ID, proto.Error{Code: proto.CodeMalformed, Message: "malformed unshare"})
					return
				}
				s.handleUnshare(as, ctrl, m.ID, req)
			case proto.TypeConnect:
				if !as.isConnector() {
					ctrl.Write(proto.TypeError, m.ID, proto.Error{Code: proto.CodeForbidden, Message: "connect requires a share-link session"})
					return
				}
				req, _ := proto.Decode[proto.Connect](m) // an empty payload is a plain connect
				s.handleConnect(as, ctrl, m.ID, req)
			case proto.TypeShareUpdate:
				req, err := proto.Decode[proto.ShareUpdate](m)
				if err != nil {
					ctrl.Write(proto.TypeError, m.ID, proto.Error{Code: proto.CodeMalformed, Message: "malformed share_update"})
					return
				}
				s.handleShareUpdate(as, ctrl, m.ID, req)
			case proto.TypeKick:
				req, err := proto.Decode[proto.Kick](m)
				if err != nil {
					ctrl.Write(proto.TypeError, m.ID, proto.Error{Code: proto.CodeMalformed, Message: "malformed kick"})
					return
				}
				s.handleKick(as, ctrl, m.ID, req)
			case proto.TypeApprove:
				req, err := proto.Decode[proto.Approve](m)
				if err != nil {
					ctrl.Write(proto.TypeError, m.ID, proto.Error{Code: proto.CodeMalformed, Message: "malformed approve"})
					return
				}
				s.handleApprove(as, ctrl, m.ID, req)
			case proto.TypeListShares:
				s.handleListShares(as, ctrl, m.ID)
			case proto.TypeWatchShares:
				s.handleWatchShares(as, ctrl, m.ID)
			case proto.TypeUnbind:
				ub, err := proto.Decode[proto.Unbind](m)
				if err != nil {
					ctrl.Write(proto.TypeError, m.ID, proto.Error{Code: proto.CodeMalformed, Message: "malformed unbind"})
					return
				}
				s.registry.Unbind(ub.Hostname, as)
				s.releaseDurableLease(as, durableLeaseKey("http", ub.Hostname, 0), "")
				ctrl.Write(proto.TypeUnbindOK, m.ID, proto.UnbindOK{Hostname: ub.Hostname})
			case proto.TypePing:
				p, err := proto.Decode[proto.Ping](m)
				if err != nil {
					ctrl.Write(proto.TypeError, m.ID, proto.Error{Code: proto.CodeMalformed, Message: "malformed ping"})
					return
				}
				ctrl.Write(proto.TypePong, m.ID, proto.Pong{TS: p.TS})
			case proto.TypePong:
				awaitingPong = false
				misses = 0
			case proto.TypeGoodbye:
				gb, _ := proto.Decode[proto.Goodbye](m)
				s.handleGoodbye(as, gb)
				return
			default:
				ctrl.Write(proto.TypeError, m.ID, proto.Error{Code: proto.CodeUnknownType, Message: fmt.Sprintf("unknown type %q", m.Type)})
				return
			}
		case <-ticker.C:
			if as.Credential != nil {
				if s.credentialStore == nil {
					_ = ctrl.Write(proto.TypeGoodbye, idgen.Next(), proto.Goodbye{
						Reason:  proto.GoodbyeReasonCredentialInactive,
						DrainMS: int(drainTimeout / time.Millisecond),
					})
					return
				}
				now := time.Now()
				active, err := s.credentialStore.ActiveContext(ctx, as.Credential.ID, now)
				if err != nil {
					if errors.Is(err, credentials.ErrNotFound) {
						s.recordCredentialEvent(as, "credential_revoked")
					}
					_ = ctrl.Write(proto.TypeGoodbye, idgen.Next(), proto.Goodbye{
						Reason:  proto.GoodbyeReasonCredentialInactive,
						DrainMS: int(drainTimeout / time.Millisecond),
					})
					return
				}
				if !active {
					event := "credential_revoked"
					if !now.Before(as.Credential.ExpiresAt) {
						event = "credential_expired"
					}
					s.recordCredentialEvent(as, event)
					_ = ctrl.Write(proto.TypeGoodbye, idgen.Next(), proto.Goodbye{
						Reason:  proto.GoodbyeReasonCredentialInactive,
						DrainMS: int(drainTimeout / time.Millisecond),
					})
					return
				}
			}
			if err := s.renewDurableSession(as); err != nil {
				s.recordSessionAlert(as, "connector_lease_lost", nil)
				_ = ctrl.Write(proto.TypeGoodbye, idgen.Next(), proto.Goodbye{
					Reason:  "connector lease is no longer active",
					DrainMS: int(drainTimeout / time.Millisecond),
				})
				return
			}
			if awaitingPong {
				misses++
				if misses >= heartbeatMisses {
					slog.Warn("edge: agent heartbeat timeout", "session_id", as.ID)
					s.recordEvent("warn", "agent heartbeat timeout", map[string]string{
						"session_id": as.ID,
					})
					return
				}
			}
			if err := ctrl.Write(proto.TypePing, idgen.Next(), proto.Ping{TS: time.Now().UnixMilli()}); err != nil {
				return
			}
			awaitingPong = true
		}
	}
}

// connectorMaySend lists the control messages a share-link session may send.
func connectorMaySend(typ string) bool {
	switch typ {
	case proto.TypeConnect, proto.TypePing, proto.TypePong, proto.TypeGoodbye:
		return true
	}
	return false
}

func credentialMaySend(typ string) bool {
	switch typ {
	case proto.TypeBind, proto.TypeUnbind, proto.TypePing, proto.TypePong, proto.TypeGoodbye:
		return true
	}
	return false
}

func (s *Server) handleGoodbye(as *AgentSession, gb proto.Goodbye) {
	slog.Info("edge: agent goodbye", "session_id", as.ID, "reason", gb.Reason)
	s.recordEvent("info", "agent requested drain", map[string]string{
		"session_id": as.ID,
		"reason":     gb.Reason,
	})
	s.registry.ReleaseSession(as)
	s.releaseTCP(as)
	// A sharer that says goodbye is revoking on purpose (Ctrl-C), so its
	// connectors are told "revoked" and stop, rather than "sharer_gone" and
	// retry.
	s.releaseShares(as, proto.ShareReasonRevoked)
	s.releaseDurableSession(as)
	s.waitInflight(as)
}

func (s *Server) releaseTCP(as *AgentSession) {
	if s.tcpMgr != nil {
		s.tcpMgr.releaseSession(as)
	}
}

func (s *Server) drainOnShutdown(as *AgentSession, ctrl *proto.Conn) {
	slog.Info("edge: shutting down, draining session", "session_id", as.ID)
	s.drainSession(as, ctrl, "edge shutting down")
}

func (s *Server) drainSession(as *AgentSession, ctrl *proto.Conn, reason string) {
	if as == nil {
		return
	}
	if ctrl != nil && as.IDGen != nil {
		_ = ctrl.Write(proto.TypeGoodbye, as.IDGen.Next(), proto.Goodbye{
			Reason:  reason,
			DrainMS: int(drainTimeout / time.Millisecond),
		})
	}
	if s.registry != nil {
		s.registry.ReleaseSession(as)
	}
	s.releaseTCP(as)
	s.releaseShares(as, proto.ShareReasonEdgeShutdown)
	s.releaseDurableSession(as)
	s.waitInflight(as)
}

func (s *Server) waitInflight(as *AgentSession) {
	as.inflight.waitTimeout(drainTimeout)
}

func bindHasAccessFields(bind proto.Bind) bool {
	return len(bind.BasicAuthSHA256) > 0 || bind.BasicAuthRealm != "" || len(bind.AllowCIDRs) > 0 || bind.Policy != nil || bind.PolicyDigest != "" || bind.HTTP2 || bind.MultiConnector || bind.ConnectorTokenSHA256 != ""
}

func validateConnectorTokenDigest(bind proto.Bind) (string, error) {
	if !bind.MultiConnector {
		if bind.ConnectorTokenSHA256 != "" {
			return "", errors.New("connector token is only valid with multiple-connector mode")
		}
		return "", nil
	}
	if len(bind.ConnectorTokenSHA256) != sha256.Size*2 {
		return "", errors.New("multiple connectors require a SHA-256 connector token digest")
	}
	if _, err := hex.DecodeString(bind.ConnectorTokenSHA256); err != nil {
		return "", errors.New("multiple connectors require a valid SHA-256 connector token digest")
	}
	return strings.ToLower(bind.ConnectorTokenSHA256), nil
}

func (s *Server) handleBind(ctx context.Context, as *AgentSession, ctrl *proto.Conn, id uint64, bind proto.Bind) {
	if err := s.validateCredentialBind(ctx, as, bind); err != nil {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeCredentialScope, Message: err.Error()})
		return
	}
	if as.Credential != nil && as.Credential.Kind == credentials.KindPreview {
		bind.Subdomain = "preview-" + as.Credential.ID
		bind.Takeover = false
	}
	if as.NegotiatedVersion < 2 && bindHasAccessFields(bind) {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInvalidAccess, Message: "access control, traffic policies, HTTP/2 tunnels, or multiple connectors require protocol v2"})
		return
	}
	if bind.Kind == proto.KindTCP {
		s.handleBindTCP(as, ctrl, id, bind)
		return
	}
	if bind.Kind != proto.KindHTTP {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeKindUnsupported, Message: "kind not supported"})
		return
	}
	connectorTokenDigest, err := validateConnectorTokenDigest(bind)
	if err != nil {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInvalidAccess, Message: err.Error()})
		return
	}

	ac, err := buildAccessControl(bind)
	if err != nil {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInvalidAccess, Message: err.Error()})
		return
	}
	trafficPolicy, err := buildTrafficPolicy(bind)
	if err != nil {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInvalidAccess, Message: err.Error()})
		return
	}

	subdomain := normalizeHost(bind.Subdomain)

	if subdomain == "" {
		if bind.MultiConnector {
			ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInvalidSubdomain, Message: "multiple connectors require an explicit subdomain"})
			return
		}
		if s.storage != nil {
			for attempt := 0; attempt < 100; attempt++ {
				candidate := normalizeHost(s.randomName())
				if !validSubdomain(candidate) {
					continue
				}
				hostname := candidate + "." + s.cfg.Domain
				lease, leaseErr := s.acquireDurableLease(as, bind, hostname, 0, trafficPolicy)
				if leaseErr != nil {
					if errors.Is(leaseErr, storage.ErrTunnelConflict) {
						continue
					}
					code, message := durableLeaseError(leaseErr)
					ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: code, Message: message})
					return
				}
				binding, evicted, bindErr := s.registry.BindWithOptions(BindOptions{
					Host:                 hostname,
					Session:              as,
					Access:               ac,
					TrafficPolicy:        trafficPolicy,
					HTTP2:                bind.HTTP2,
					MultiConnector:       bind.MultiConnector,
					ConnectorTokenDigest: connectorTokenDigest,
				})
				if bindErr != nil {
					s.releaseDurableLease(as, durableLeaseKey("http", hostname, 0), lease.ID)
					if errors.Is(bindErr, ErrSubdomainTaken) {
						continue
					}
					ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInternal, Message: bindErr.Error()})
					return
				}
				binding.setDurableID(lease.TunnelID)
				as.rememberDurableLease(durableLeaseKey("http", hostname, 0), lease.ID)
				s.recordLeaseAcquired(as, lease)
				s.finishBind(finishBindOptions{ID: id, Control: ctrl, Hostname: hostname, Evicted: evicted, PolicyDigest: bind.PolicyDigest, HTTP2: bind.HTTP2, MultiConnector: bind.MultiConnector})
				s.recordEvent("info", "tunnel bound", map[string]string{
					"hostname":   hostname,
					"session_id": as.ID,
				})
				return
			}
			ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInternal, Message: "could not allocate a durable tunnel name"})
			return
		}
		hostname, evicted, err := assignRandomHostname(s.registry, hostnameOptions{
			Session:        as,
			Domain:         s.cfg.Domain,
			Generate:       s.randomName,
			Access:         ac,
			TrafficPolicy:  trafficPolicy,
			HTTP2:          bind.HTTP2,
			MultiConnector: bind.MultiConnector,
		})
		if err != nil {
			ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInternal, Message: err.Error()})
			return
		}
		s.finishBind(finishBindOptions{ID: id, Control: ctrl, Hostname: hostname, Evicted: evicted, PolicyDigest: bind.PolicyDigest, HTTP2: bind.HTTP2, MultiConnector: bind.MultiConnector})
		s.recordEvent("info", "tunnel bound", map[string]string{
			"hostname":   hostname,
			"session_id": as.ID,
		})
		return
	}

	if !validSubdomain(subdomain) {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInvalidSubdomain, Message: "invalid subdomain"})
		return
	}

	hostname := subdomain + "." + s.cfg.Domain
	var lease storage.Lease
	if s.storage != nil {
		var leaseErr error
		lease, leaseErr = s.acquireDurableLease(as, bind, hostname, 0, trafficPolicy)
		if leaseErr != nil {
			code, message := durableLeaseError(leaseErr)
			ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: code, Message: message})
			return
		}
	}
	binding, evicted, err := s.registry.BindWithOptions(BindOptions{
		Host:                 hostname,
		Session:              as,
		Takeover:             bind.Takeover,
		Access:               ac,
		TrafficPolicy:        trafficPolicy,
		HTTP2:                bind.HTTP2,
		MultiConnector:       bind.MultiConnector,
		ConnectorTokenDigest: connectorTokenDigest,
	})
	if err != nil {
		if lease.ID != "" {
			s.releaseDurableLease(as, durableLeaseKey("http", hostname, 0), lease.ID)
		}
		if errors.Is(err, ErrSubdomainTaken) {
			ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeSubdomainTaken, Message: "subdomain already in use"})
			return
		}
		if errors.Is(err, ErrConnectorConfigMismatch) {
			ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeConnectorConfigMismatch, Message: "connector settings do not match the existing tunnel"})
			return
		}
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInternal, Message: err.Error()})
		return
	}
	binding.setDurableID(lease.TunnelID)
	as.rememberDurableLease(durableLeaseKey("http", hostname, 0), lease.ID)
	s.recordLeaseAcquired(as, lease)
	s.finishBind(finishBindOptions{ID: id, Control: ctrl, Hostname: hostname, Evicted: evicted, PolicyDigest: bind.PolicyDigest, HTTP2: bind.HTTP2, MultiConnector: bind.MultiConnector})
	s.recordEvent("info", "tunnel bound", map[string]string{
		"hostname":   hostname,
		"session_id": as.ID,
	})
}

func (s *Server) validateCredentialBind(ctx context.Context, as *AgentSession, bind proto.Bind) error {
	if as.Credential == nil {
		return nil
	}
	if s.credentialStore == nil {
		return errors.New("tunnel credential is inactive")
	}
	active, err := s.credentialStore.ActiveContext(ctx, as.Credential.ID, time.Now())
	if err != nil || !active {
		return errors.New("tunnel credential is inactive")
	}
	if as.Credential.Kind == credentials.KindPreview {
		if bind.Kind != proto.KindHTTP || bind.Subdomain != "" || bind.RemotePort != 0 || bind.MultiConnector || bind.ConnectorTokenSHA256 != "" {
			return errors.New("preview credentials permit only a server-assigned HTTP tunnel")
		}
		return nil
	}
	switch bind.Kind {
	case proto.KindHTTP:
		if as.Credential.Kind != credentials.KindHTTP || normalizeHost(bind.Subdomain) != as.Credential.Subdomain {
			return errors.New("tunnel credential is scoped to another HTTP subdomain")
		}
	case proto.KindTCP:
		if as.Credential.Kind != credentials.KindTCP || bind.RemotePort != as.Credential.RemotePort {
			return errors.New("tunnel credential is scoped to another TCP port")
		}
	default:
		return errors.New("tunnel credential is scoped to another tunnel kind")
	}
	return nil
}

func (s *Server) handleBindTCP(as *AgentSession, ctrl *proto.Conn, id uint64, bind proto.Bind) {
	if s.tcpMgr == nil {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeKindUnsupported, Message: "tcp tunnels not enabled"})
		return
	}
	if len(bind.BasicAuthSHA256) > 0 || bind.Policy != nil || bind.PolicyDigest != "" || bind.HTTP2 || bind.MultiConnector || bind.ConnectorTokenSHA256 != "" {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInvalidAccess, Message: "basic auth, traffic policies, HTTP/2, and multiple connectors are not supported for tcp tunnels"})
		return
	}
	ac, err := buildAccessControl(bind)
	if err != nil {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInvalidAccess, Message: err.Error()})
		return
	}
	var lease storage.Lease
	if s.storage != nil && bind.RemotePort != 0 {
		lease, err = s.acquireDurableLease(as, bind, s.cfg.Domain, bind.RemotePort, nil)
		if err != nil {
			ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodePortUnavailable, Message: "requested port is already in use"})
			return
		}
	}
	port, err := s.tcpMgr.bind(as, bind.RemotePort, s.cfg.Domain, ac.prefixes())
	if err != nil {
		if lease.ID != "" {
			s.releaseDurableLease(as, durableLeaseKey("tcp", s.cfg.Domain, bind.RemotePort), lease.ID)
		}
		if errors.Is(err, errTooManyBinds) {
			ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeTooManyBinds, Message: "too many tcp binds for this session"})
			return
		}
		if errors.Is(err, errPortUnavailable) {
			ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodePortUnavailable, Message: "requested port unavailable"})
			return
		}
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInternal, Message: err.Error()})
		return
	}
	if s.storage != nil && lease.ID == "" {
		lease, err = s.acquireDurableLease(as, bind, s.cfg.Domain, port, nil)
		if err != nil {
			s.tcpMgr.releasePort(as, port)
			ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodePortUnavailable, Message: "allocated port is already in use"})
			return
		}
	}
	if lease.ID != "" {
		s.tcpMgr.setTunnelID(as, port, lease.TunnelID)
	}
	as.rememberDurableLease(durableLeaseKey("tcp", s.cfg.Domain, port), lease.ID)
	s.recordLeaseAcquired(as, lease)
	ctrl.Write(proto.TypeBindOK, id, proto.BindOK{
		Hostname: s.cfg.Domain,
		URL:      "tcp://" + s.cfg.Domain + ":" + strconv.Itoa(port),
		Port:     port,
	})
	s.recordEvent("info", "tcp tunnel bound", map[string]string{
		"hostname":   s.cfg.Domain,
		"port":       strconv.Itoa(port),
		"session_id": as.ID,
	})
}

type finishBindOptions struct {
	ID             uint64
	Control        *proto.Conn
	Hostname       string
	Evicted        *AgentSession
	PolicyDigest   string
	HTTP2          bool
	MultiConnector bool
}

func (s *Server) finishBind(opts finishBindOptions) {
	if opts.Evicted != nil {
		opts.Evicted.Sess.Control().Write(proto.TypeEvicted, opts.Evicted.IDGen.Next(), proto.Evicted{
			Hostname: opts.Hostname,
			Reason:   "takeover",
		})
		opts.Evicted.Sess.Close("takeover")
	}
	opts.Control.Write(proto.TypeBindOK, opts.ID, proto.BindOK{
		Hostname:       opts.Hostname,
		URL:            s.cfg.PublicScheme + "://" + opts.Hostname,
		HTTP2:          opts.HTTP2,
		MultiConnector: opts.MultiConnector,
		PolicyDigest:   opts.PolicyDigest,
	})
}
