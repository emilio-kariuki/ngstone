package edge

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

var (
	authDeadline      = 5 * time.Second
	heartbeatInterval = 15 * time.Second
	heartbeatMisses   = 3
	drainTimeout      = 15 * time.Second
)

type AgentSession struct {
	ID         string
	InstanceID string
	Sess       tunnel.Session
	Remote     netip.AddrPort

	inflight sync.WaitGroup
}

func (a *AgentSession) Done() <-chan struct{} {
	return a.Sess.Done()
}

func negotiateVersion(offered []int) (int, bool) {
	for _, v := range offered {
		if v == proto.ProtoVersion {
			return v, true
		}
	}
	return 0, false
}

type authRateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

func newAuthRateLimiter() *authRateLimiter {
	return &authRateLimiter{attempts: make(map[string][]time.Time)}
}

const maxAuthFailuresPerMinute = 5

func (l *authRateLimiter) allowed(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(ip)
	return len(l.attempts[ip]) < maxAuthFailuresPerMinute
}

func (l *authRateLimiter) recordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(ip)
	l.attempts[ip] = append(l.attempts[ip], time.Now())
}

func (l *authRateLimiter) prune(ip string) {
	cutoff := time.Now().Add(-time.Minute)
	times := l.attempts[ip]
	kept := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(l.attempts, ip)
		return
	}
	l.attempts[ip] = kept
}

func (s *Server) acceptControl(ctx context.Context, ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleControlConn(ctx, conn)
	}
}

func (s *Server) handleControlConn(ctx context.Context, conn net.Conn) {
	ip := remoteIP(conn)

	deadline := time.Now().Add(authDeadline)
	if err := conn.SetReadDeadline(deadline); err != nil {
		conn.Close()
		return
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
		ID:         randomHex(8),
		InstanceID: auth.InstanceID,
		Sess:       sess,
		Remote:     remote,
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
		as.Sess.Close("control loop exited")
	}()

	ctrl := as.Sess.Control()
	idgen := proto.NewEdgeIDGen()

	type readResult struct {
		msg proto.Msg
		err error
	}
	msgCh := make(chan readResult)
	go func() {
		for {
			m, err := ctrl.Read()
			msgCh <- readResult{m, err}
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

	done := make(chan struct{})
	go func() {
		as.inflight.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(drainTimeout):
	}
}

func (s *Server) handleBind(as *AgentSession, ctrl *proto.Conn, id uint64, bind proto.Bind) {
	if bind.Kind != proto.KindHTTP {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeKindUnsupported, Message: "kind not supported"})
		return
	}

	subdomain := normalizeHost(bind.Subdomain)

	if subdomain == "" {
		hostname, evicted, err := assignRandomHostname(s.registry, as, bind.Takeover, s.cfg.Domain, randomSubdomain)
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
	_, evicted, err := s.registry.Bind(hostname, as, bind.Takeover)
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

func (s *Server) finishBind(id uint64, ctrl *proto.Conn, hostname string, evicted *AgentSession) {
	if evicted != nil {
		evicted.Sess.Control().Write(proto.TypeEvicted, proto.NewEdgeIDGen().Next(), proto.Evicted{
			Hostname: hostname,
			Reason:   "takeover",
		})
		evicted.Sess.Close("takeover")
	}
	ctrl.Write(proto.TypeBindOK, id, proto.BindOK{
		Hostname: hostname,
		URL:      "http://" + hostname,
	})
}
