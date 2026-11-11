package edge

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"expvar"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/storage"
)

const (
	maxClientHelloBytes = 16 << 10
	maxGlobalTLSConns   = 256
)

var (
	errNotClientHello      = errors.New("edge: connection did not start with a TLS ClientHello")
	errClientHelloTooLarge = errors.New("edge: TLS ClientHello exceeds the peek limit")
	errClientHelloCaptured = errors.New("edge: ClientHello captured")
)

var (
	metricTLSPassthroughConns      = expvar.NewInt("ngstoned_tls_passthrough_conns_total")
	metricTLSRejectedGlobalCap     = expvar.NewInt("ngstoned_tls_rejected_global_cap_total")
	metricTLSRejectedNoConnector   = expvar.NewInt("ngstoned_tls_rejected_no_connector_total")
	metricTLSRejectedForbiddenCIDR = expvar.NewInt("ngstoned_tls_rejected_forbidden_cidr_total")
	metricTLSRejectedRateLimited   = expvar.NewInt("ngstoned_tls_rejected_rate_limited_total")
)

type helloRecorder struct {
	r        io.Reader
	max      int
	buf      bytes.Buffer
	err      error
	tooLarge bool
}

func (h *helloRecorder) Read(p []byte) (int, error) {
	if h.err != nil {
		return 0, h.err
	}
	remaining := h.max - h.buf.Len()
	if remaining <= 0 {
		h.tooLarge = true
		return 0, errClientHelloTooLarge
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	n, err := h.r.Read(p)
	h.buf.Write(p[:n])
	if err != nil {
		h.err = err
	}
	return n, err
}

type helloSniffConn struct {
	r io.Reader
}

func (c helloSniffConn) Read(p []byte) (int, error)     { return c.r.Read(p) }
func (helloSniffConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (helloSniffConn) Close() error                     { return nil }
func (helloSniffConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (helloSniffConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (helloSniffConn) SetDeadline(time.Time) error      { return nil }
func (helloSniffConn) SetReadDeadline(time.Time) error  { return nil }
func (helloSniffConn) SetWriteDeadline(time.Time) error { return nil }

func peekClientHello(r io.Reader, max int) (string, []byte, error) {
	rec := &helloRecorder{r: r, max: max}
	var serverName string
	captured := false
	err := tls.Server(helloSniffConn{r: rec}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			serverName = hello.ServerName
			captured = true
			return nil, errClientHelloCaptured
		},
	}).Handshake()
	peeked := rec.buf.Bytes()
	switch {
	case captured:
		return normalizeHost(serverName), peeked, nil
	case rec.tooLarge:
		return "", peeked, errClientHelloTooLarge
	case rec.err != nil:
		return "", peeked, rec.err
	case err != nil:
		return "", peeked, errNotClientHello
	default:
		return "", peeked, errNotClientHello
	}
}

type replayConn struct {
	net.Conn
	buf       []byte
	forwarded bool
}

func (c *replayConn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		if len(c.buf) == 0 {
			c.buf = nil
		}
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *replayConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

type sniListener struct {
	net.Listener
	srv     *Server
	timeout time.Duration
	maxPeek int
	sem     *globalSemaphore

	ready chan net.Conn
	done  chan struct{}
	once  sync.Once
	mu    sync.Mutex
	err   error
}

func (s *Server) newSNIListener(inner net.Listener) *sniListener {
	l := &sniListener{
		Listener: inner,
		srv:      s,
		timeout:  s.limitsOrDefault().ReadHeaderTimeout,
		maxPeek:  maxClientHelloBytes,
		sem:      newGlobalSemaphore(maxGlobalTLSConns),
		ready:    make(chan net.Conn),
		done:     make(chan struct{}),
	}
	if l.timeout <= 0 {
		l.timeout = DefaultReadHeaderTimeout
	}
	if s.peers != nil {
		s.peers.public = l
	}
	go l.acceptLoop()
	return l
}

func (l *sniListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case <-l.done:
		l.mu.Lock()
		err := l.err
		l.mu.Unlock()
		return nil, err
	}
}

func (l *sniListener) Close() error {
	err := l.Listener.Close()
	l.fail(net.ErrClosed)
	return err
}

func (l *sniListener) fail(err error) {
	l.once.Do(func() {
		l.mu.Lock()
		l.err = err
		l.mu.Unlock()
		close(l.done)
	})
}

func (l *sniListener) acceptLoop() {
	backoff := 5 * time.Millisecond
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			select {
			case <-l.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				l.fail(err)
				return
			}
			slog.Warn("edge: public accept error", "err", err, "backoff", backoff)
			t := time.NewTimer(backoff)
			select {
			case <-t.C:
			case <-l.done:
				t.Stop()
				return
			}
			backoff = min(backoff*2, time.Second)
			continue
		}
		backoff = 5 * time.Millisecond
		go l.classify(c)
	}
}

func (l *sniListener) peek(c net.Conn) (string, []byte, error) {
	if err := c.SetReadDeadline(time.Now().Add(l.timeout)); err != nil {
		return "", nil, err
	}
	return peekClientHello(c, l.maxPeek)
}

func clearReadDeadline(c net.Conn) bool {
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		c.Close()
		return false
	}
	return true
}

func (l *sniListener) classify(c net.Conn) {
	serverName, peeked, err := l.peek(c)
	if err != nil && !errors.Is(err, errNotClientHello) {
		c.Close()
		return
	}
	replay := &replayConn{Conn: c, buf: peeked}
	if err != nil || serverName == "" || l.srv.registry == nil {
		if clearReadDeadline(c) {
			l.deliver(replay)
		}
		return
	}
	if b, ok := l.srv.registry.RouteTLS(serverName); ok {
		if clearReadDeadline(c) {
			l.srv.serveTLSPassthrough(b, serverName, replay, l.sem)
		}
		return
	}
	_, local := l.srv.registry.Route(serverName)
	if !clearReadDeadline(c) {
		return
	}
	if !local && l.srv.peers != nil && l.srv.peers.eligible(serverName) {
		l.srv.peers.forward(replay, serverName)
		return
	}
	l.deliver(replay)
}

func (l *sniListener) classifyForwarded(c net.Conn) {
	serverName, peeked, err := l.peek(c)
	if err != nil || serverName == "" || l.srv.registry == nil {
		l.refuse(c)
		return
	}
	replay := &replayConn{Conn: c, buf: peeked}
	if b, ok := l.srv.registry.RouteTLS(serverName); ok {
		if l.acceptForwarded(c) {
			l.srv.serveTLSPassthrough(b, serverName, replay, l.sem)
		}
		return
	}
	if _, local := l.srv.registry.Route(serverName); !local {
		l.refuse(c)
		return
	}
	replay.forwarded = true
	if l.acceptForwarded(c) {
		l.deliver(replay)
	}
}

func (l *sniListener) acceptForwarded(c net.Conn) bool {
	if !writePeerStatus(c, peerStatusAccept) {
		c.Close()
		return false
	}
	return clearReadDeadline(c)
}

func (l *sniListener) refuse(c net.Conn) {
	writePeerStatus(c, peerStatusNotOwner)
	c.Close()
}

func (l *sniListener) deliver(replay *replayConn) {
	select {
	case l.ready <- replay:
	case <-l.done:
		replay.Close()
	}
}

func (s *Server) serveTLSPassthrough(b *Binding, host string, client *replayConn, sem *globalSemaphore) {
	defer client.Close()
	started := time.Now()
	ip := remoteIP(client)

	var ac *accessControl
	if snapshot := b.snapshot.Load(); snapshot != nil {
		ac = snapshot.access
	}
	if len(ac.prefixes()) > 0 {
		addr, err := netip.ParseAddr(ip)
		if err != nil || !ac.allowIP(addr) {
			metricRejectedForbiddenCIDR.Add(1)
			metricTLSRejectedForbiddenCIDR.Add(1)
			return
		}
	}
	if !s.perIPLimiter.allow(ip) {
		metricRejectedRateLimited.Add(1)
		metricTLSRejectedRateLimited.Add(1)
		return
	}
	releaseIP, ok := s.perIP.acquire(ip)
	if !ok {
		metricRejectedPerIPCap.Add(1)
		return
	}
	defer releaseIP()
	if !sem.tryAcquire() {
		metricTLSRejectedGlobalCap.Add(1)
		return
	}
	defer sem.release()

	connector, ok := b.selectConnector(false)
	if !ok {
		metricRejectedSessionCap.Add(1)
		metricTLSRejectedNoConnector.Add(1)
		return
	}
	as := connector.sess
	defer as.releaseStream()
	as.inflight.Add(1)
	defer as.inflight.Done()

	dialCtx, cancel := context.WithTimeout(context.Background(), dialBudget)
	stream, err := as.Sess.OpenStream(dialCtx, proto.StreamOpen{
		Kind:       proto.KindTLS,
		Host:       host,
		ReqID:      randomHex(8),
		ClientAddr: client.RemoteAddr().String(),
	})
	cancel()
	if err != nil {
		slog.Debug("edge: tls passthrough stream open failed", "host", host, "err", err)
		return
	}
	defer stream.Close()
	metricTLSPassthroughConns.Add(1)

	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-as.Done():
			client.Close()
			stream.Close()
		case <-finished:
		}
	}()

	bytesIn, bytesOut := splice(client, stream, s.limitsOrDefault().TCPIdleTimeout, 0)
	s.observability.observeTCP(b.durableTunnelID(), host, time.Since(started), bytesIn, bytesOut)
}

func splice(client, upstream net.Conn, idle, grace time.Duration) (in, out int64) {
	deadline := newIdleDeadline(idle, client, upstream)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		in, _ = io.Copy(upstream, deadline.reader(client))
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		out, _ = io.Copy(client, deadline.reader(upstream))
		closeWrite(client)
		if grace > 0 {
			deadline.capRead(client, time.Now().Add(grace))
		}
	}()
	wg.Wait()
	return in, out
}

func tlsTunnelURL(hostname, publicAddr string) string {
	_, port, err := net.SplitHostPort(publicAddr)
	if err != nil || port == "" || port == "443" {
		return "tls://" + hostname
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "tls://" + hostname
	}
	return "tls://" + net.JoinHostPort(hostname, port)
}

func tlsBindHasUnsupportedFields(bind proto.Bind) bool {
	return len(bind.BasicAuthSHA256) > 0 || bind.BasicAuthRealm != "" || bind.Policy != nil || bind.PolicyDigest != "" || bind.HTTP2 || bind.MultiConnector || bind.ConnectorTokenSHA256 != "" || bind.RemotePort != 0 || bind.OIDC != nil || bind.Webhook != nil
}

func (s *Server) handleBindTLS(as *AgentSession, ctrl *proto.Conn, id uint64, bind proto.Bind) {
	if tlsBindHasUnsupportedFields(bind) {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInvalidAccess, Message: "basic auth, OIDC visitor login, webhook verification, traffic policies, HTTP/2, multiple connectors, and remote ports are not supported for tls tunnels"})
		return
	}
	ac, err := buildAccessControl(bind)
	if err != nil {
		ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInvalidAccess, Message: err.Error()})
		return
	}

	subdomain := normalizeHost(bind.Subdomain)
	if subdomain != "" {
		if !validSubdomain(subdomain) {
			ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInvalidSubdomain, Message: "invalid subdomain"})
			return
		}
		hostname := subdomain + "." + s.cfg.Domain
		if s.visitor.servesHost(hostname) {
			ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInvalidSubdomain, Message: "subdomain is reserved"})
			return
		}
		evicted, bindErr := s.bindTLSHost(as, bind, hostname, ac)
		if bindErr != nil {
			ctrl.Write(proto.TypeBindErr, id, *bindErr)
			return
		}
		s.finishBindTLS(as, ctrl, id, hostname, evicted)
		return
	}

	for attempt := 0; attempt < maxRandomAttempts; attempt++ {
		candidate := normalizeHost(s.randomName())
		if !validSubdomain(candidate) {
			continue
		}
		hostname := candidate + "." + s.cfg.Domain
		if s.visitor.servesHost(hostname) {
			continue
		}
		evicted, bindErr := s.bindTLSHost(as, bind, hostname, ac)
		if bindErr == nil {
			s.finishBindTLS(as, ctrl, id, hostname, evicted)
			return
		}
		if bindErr.Code == proto.CodeSubdomainTaken || bindErr.Code == proto.CodeKindConflict {
			continue
		}
		ctrl.Write(proto.TypeBindErr, id, *bindErr)
		return
	}
	ctrl.Write(proto.TypeBindErr, id, proto.BindErr{Code: proto.CodeInternal, Message: "could not allocate a tls tunnel name"})
}

func (s *Server) bindTLSHost(as *AgentSession, bind proto.Bind, hostname string, ac *accessControl) (*AgentSession, *proto.BindErr) {
	key := durableLeaseKey("tls", hostname, 0)
	var lease storage.Lease
	if s.storage != nil {
		var err error
		lease, err = s.acquireDurableLease(as, bind, hostname, 0, nil)
		if err != nil {
			code, message := durableLeaseError(err)
			return nil, &proto.BindErr{Code: code, Message: message}
		}
	}
	binding, evicted, err := s.registry.BindWithOptions(BindOptions{
		Host:     hostname,
		Session:  as,
		Takeover: bind.Takeover,
		Access:   ac,
		TLS:      true,
	})
	if err != nil {
		if lease.ID != "" {
			s.releaseDurableLease(as, key, lease.ID)
		}
		switch {
		case errors.Is(err, ErrKindConflict):
			return nil, &proto.BindErr{Code: proto.CodeKindConflict, Message: "subdomain is already bound to an http tunnel"}
		case errors.Is(err, ErrSubdomainTaken):
			return nil, &proto.BindErr{Code: proto.CodeSubdomainTaken, Message: "subdomain already in use"}
		default:
			return nil, &proto.BindErr{Code: proto.CodeInternal, Message: err.Error()}
		}
	}
	binding.setDurableID(lease.TunnelID)
	as.rememberDurableLease(key, lease.ID)
	s.recordLeaseAcquired(as, lease)
	return evicted, nil
}

func (s *Server) finishBindTLS(as *AgentSession, ctrl *proto.Conn, id uint64, hostname string, evicted *AgentSession) {
	if evicted != nil {
		evicted.Sess.Control().Write(proto.TypeEvicted, evicted.IDGen.Next(), proto.Evicted{
			Hostname: hostname,
			Reason:   "takeover",
		})
		evicted.Sess.Close("takeover")
	}
	ctrl.Write(proto.TypeBindOK, id, proto.BindOK{
		Hostname: hostname,
		URL:      tlsTunnelURL(hostname, s.cfg.PublicAddr),
	})
	s.recordEvent("info", "tls tunnel bound", map[string]string{
		"hostname":   hostname,
		"session_id": as.ID,
	})
}
