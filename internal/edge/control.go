package edge

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
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

	inflight         inflightTracker
	streamSem        *globalSemaphore
	upgradeStreamSem *globalSemaphore
}

func (a *AgentSession) Done() <-chan struct{} {
	return a.Sess.Done()
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

func (s *Server) acceptControl(ctx context.Context, ln net.Listener) error {
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
		s.controlConns.Add(1)
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

	if s.tlsMgr != nil {
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

	as, err := s.authenticate(sess, ip, remote, deadline)
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

func (s *Server) authenticate(sess tunnel.Session, ip string, remote netip.AddrPort, deadline time.Time) (*AgentSession, error) {
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

	sum := sha256.Sum256([]byte(auth.Token))
	if subtle.ConstantTimeCompare(sum[:], s.cfg.TokenSHA256) != 1 {
		s.authLimiter.recordFailure(ip)
		ctrl.Write(proto.TypeAuthErr, msg.ID, proto.AuthErr{Code: proto.CodeBadToken, Message: "bad token"})
		slog.Warn("edge: auth attempt", "ip", ip, "result", "bad_token")
		return nil, errors.New("edge: bad token")
	}

	version, ok := negotiateVersion(auth.ProtoVersions)
	if !ok {
		ctrl.Write(proto.TypeAuthErr, msg.ID, proto.AuthErr{Code: proto.CodeNoCommonVersion, Message: "no common protocol version"})
		slog.Warn("edge: auth attempt", "ip", ip, "result", "no_common_version", "offered", auth.ProtoVersions)
		return nil, errors.New("edge: no common protocol version")
	}

	as := &AgentSession{
		ID:                randomHex(8),
		InstanceID:        auth.InstanceID,
		Sess:              sess,
		Remote:            remote,
		IDGen:             proto.NewEdgeIDGen(),
		NegotiatedVersion: version,
		streamSem:         newGlobalSemaphore(s.limitsOrDefault().PerSessionInFlight),
		upgradeStreamSem:  newGlobalSemaphore(s.limitsOrDefault().PerSessionUpgradeInFlight),
	}

	if err := ctrl.Write(proto.TypeAuthOK, msg.ID, proto.AuthOK{
		ProtoVersion:  version,
		SessionID:     as.ID,
		ServerVersion: "ngstoned/m2",
	}); err != nil {
		return nil, err
	}

	if err := ctrl.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}

	slog.Info("edge: auth attempt", "ip", ip, "result", "ok", "instance_id", auth.InstanceID, "session_id", as.ID)
	return as, nil
}

func (s *Server) controlLoop(ctx context.Context, as *AgentSession) {
	defer func() {
		s.registry.ReleaseSession(as)
		s.releaseTCP(as)
		as.Sess.Close("control loop exited")
		metricActiveSessions.Add(-1)
	}()

	ctrl := as.Sess.Control()
	idgen := as.IDGen

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
			m := rr.msg
			switch m.Type {
			case proto.TypeBind:
				bind, err := proto.Decode[proto.Bind](m)
				if err != nil {
					ctrl.Write(proto.TypeError, m.ID, proto.Error{Code: proto.CodeMalformed, Message: "malformed bind"})
					return
				}
				s.handleBind(as, ctrl, m.ID, bind)
			case proto.TypeUnbind:
				ub, err := proto.Decode[proto.Unbind](m)
				if err != nil {
					ctrl.Write(proto.TypeError, m.ID, proto.Error{Code: proto.CodeMalformed, Message: "malformed unbind"})
					return
				}
				s.registry.Unbind(ub.Hostname, as)
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
			if awaitingPong {
				misses++
				if misses >= heartbeatMisses {
					slog.Warn("edge: agent heartbeat timeout", "session_id", as.ID)
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

func (s *Server) handleGoodbye(as *AgentSession, gb proto.Goodbye) {
	slog.Info("edge: agent goodbye", "session_id", as.ID, "reason", gb.Reason)
	s.registry.ReleaseSession(as)
	s.releaseTCP(as)
	s.waitInflight(as)
}

func (s *Server) releaseTCP(as *AgentSession) {
	if s.tcpMgr != nil {
		s.tcpMgr.releaseSession(as)
	}
}

func (s *Server) drainOnShutdown(as *AgentSession, ctrl *proto.Conn) {
	slog.Info("edge: shutting down, draining session", "session_id", as.ID)
	ctrl.Write(proto.TypeGoodbye, as.IDGen.Next(), proto.Goodbye{
		Reason:  "edge shutting down",
		DrainMS: int(drainTimeout / time.Millisecond),
	})
	s.registry.ReleaseSession(as)
	s.releaseTCP(as)
	s.waitInflight(as)
}

func (s *Server) waitInflight(as *AgentSession) {
	as.inflight.waitTimeout(drainTimeout)
}

func bindHasAccessFields(bind proto.Bind) bool {
	return len(bind.BasicAuthSHA256) > 0 || bind.BasicAuthRealm != "" || len(bind.AllowCIDRs) > 0
}

func (s *Server) handleBind(as *AgentSession, ctrl *proto.Conn, id uint64, bind proto.Bind) {
	if as.NegotiatedVersion < 2 && bindHasAccessFields(bind) {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInvalidAccess, Message: "access control requires protocol v2"})
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

	ac, err := buildAccessControl(bind)
	if err != nil {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInvalidAccess, Message: err.Error()})
		return
	}

	subdomain := normalizeHost(bind.Subdomain)

	if subdomain == "" {
		hostname, evicted, err := assignRandomHostname(s.registry, as, false, s.cfg.Domain, s.randomName, ac)
		if err != nil {
			ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInternal, Message: err.Error()})
			return
		}
		s.finishBind(id, ctrl, hostname, evicted)
		return
	}

	if !validSubdomain(subdomain) {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInvalidSubdomain, Message: "invalid subdomain"})
		return
	}

	hostname := subdomain + "." + s.cfg.Domain
	_, evicted, err := s.registry.Bind(hostname, as, bind.Takeover, ac)
	if err != nil {
		if errors.Is(err, ErrSubdomainTaken) {
			ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeSubdomainTaken, Message: "subdomain already in use"})
			return
		}
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInternal, Message: err.Error()})
		return
	}
	s.finishBind(id, ctrl, hostname, evicted)
}

func (s *Server) handleBindTCP(as *AgentSession, ctrl *proto.Conn, id uint64, bind proto.Bind) {
	if s.tcpMgr == nil {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeKindUnsupported, Message: "tcp tunnels not enabled"})
		return
	}
	if len(bind.BasicAuthSHA256) > 0 {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInvalidAccess, Message: "basic auth is not supported for tcp tunnels"})
		return
	}
	ac, err := buildAccessControl(bind)
	if err != nil {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInvalidAccess, Message: err.Error()})
		return
	}
	port, err := s.tcpMgr.bind(as, bind.RemotePort, s.cfg.Domain, ac.prefixes())
	if err != nil {
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
	ctrl.Write(proto.TypeBindOK, id, proto.BindOK{
		Hostname: s.cfg.Domain,
		URL:      "tcp://" + s.cfg.Domain + ":" + strconv.Itoa(port),
		Port:     port,
	})
}

func (s *Server) finishBind(id uint64, ctrl *proto.Conn, hostname string, evicted *AgentSession) {
	if evicted != nil {
		evicted.Sess.Control().Write(proto.TypeEvicted, evicted.IDGen.Next(), proto.Evicted{
			Hostname: hostname,
			Reason:   "takeover",
		})
		evicted.Sess.Close("takeover")
	}
	ctrl.Write(proto.TypeBindOK, id, proto.BindOK{
		Hostname: hostname,
		URL:      s.cfg.PublicScheme + "://" + hostname,
	})
}
