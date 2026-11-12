package edge

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/storage"
)

type tcpRecorder struct {
	fx   *tcpFixture
	hits atomic.Int64
	pre  atomic.Pointer[proto.StreamOpen]
}

func (pc *peerCluster) tcpEdge(t *testing.T, id, bindAddr string) (*peerEdge, *tcpRecorder) {
	t.Helper()
	rec := &tcpRecorder{}
	rec.fx = newTCPFixture(t, func(c net.Conn, pre proto.StreamOpen) {
		rec.pre.Store(&pre)
		rec.hits.Add(1)
		echoHandler(c, pre)
	})
	t.Cleanup(rec.fx.cleanup)
	rec.fx.mgr.bindAddr = bindAddr
	return pc.edgeWith(t, id, rec.fx.mgr), rec
}

func (e *peerEdge) leaseTCP(t *testing.T, port int) {
	t.Helper()
	_, err := e.store.AcquireLease(context.Background(), storage.LeaseRequest{
		Hostname:   e.srv.cfg.Domain,
		Kind:       "tcp",
		RemotePort: port,
		EdgeID:     e.id,
		OwnerID:    "owner",
		InstanceID: "inst-" + e.id,
		SessionID:  fmt.Sprintf("sess-%s-%d", e.id, port),
		ExpiresAt:  time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("acquire tcp lease %d on %s: %v", port, e.id, err)
	}
}

func freePorts(t *testing.T, n int) []int {
	t.Helper()
	lns := make([]net.Listener, 0, n)
	ports := make([]int, 0, n)
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("freePorts: %v", err)
		}
		lns = append(lns, ln)
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
	}
	for _, ln := range lns {
		ln.Close()
	}
	return ports
}

func expectPortRefused(t *testing.T, port int) {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err == nil {
		c.Close()
		t.Fatalf("port %d accepted a connection, want it closed", port)
	}
}

func requireLoopbackV6(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	ln.Close()
}

type stubListener struct{}

func (stubListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (stubListener) Close() error              { return nil }
func (stubListener) Addr() net.Addr            { return &net.TCPAddr{} }

func dialTCPFrame(t *testing.T, from, to *peerEdge, port int, src string) *tls.Conn {
	t.Helper()
	tc, err := dialPeerTLS(t, from.srv.peers.clientTLS(to.pin()), to.peerAddr())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	sendFrame(t, tc, peerFrameTCP, uint16(port), src, nil)
	return tc
}

func TestAcceptForwardedUnknownPortRefused(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()
	bound, _, err := fx.mgr.bind(fx.as, 20001, "example.com", nil, false)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	client, server := realConnPair(t)
	defer client.Close()
	defer server.Close()

	if fwd, ok := fx.mgr.acceptForwarded(20005, server); ok {
		fwd.abort()
		t.Fatal("a port with no tunnel was accepted")
	}
	fwd, ok := fx.mgr.acceptForwarded(bound, server)
	if !ok {
		t.Fatal("a bound port was refused")
	}
	fwd.abort()
}

func TestAcceptForwardedAllowCIDRUsesProxySource(t *testing.T) {
	pc := newPeerCluster(t)
	a, _ := pc.tcpEdge(t, "edge-a", "127.0.0.1")
	b, rec := pc.tcpEdge(t, "edge-b", "127.0.0.1")
	registerPeers(t, a, b)
	port, _, err := rec.fx.mgr.bind(rec.fx.as, 0, "example.com", []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, false)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	refused := metricDelta(metricTCPRejectedForbiddenCIDR)

	allowed := dialTCPFrame(t, a, b, port, "203.0.113.9:4000")
	mustPeerStatus(t, allowed, peerStatusAccept)
	pingEcho(t, allowed)
	pre := rec.pre.Load()
	if pre == nil || pre.ClientAddr != "203.0.113.9:4000" {
		t.Fatalf("agent preamble = %+v, want client 203.0.113.9:4000", pre)
	}

	denied := dialTCPFrame(t, a, b, port, "198.51.100.7:4000")
	mustPeerStatus(t, denied, peerStatusAccept)
	expectClosed(t, denied)
	if rec.hits.Load() != 1 || refused() != 1 {
		t.Fatalf("agent hits = %d, cidr refusals = %d, want 1 and 1", rec.hits.Load(), refused())
	}
}

func TestAcceptForwardedNeverReforwards(t *testing.T) {
	pc := newPeerCluster(t)
	a, _ := pc.tcpEdge(t, "edge-a", "127.0.0.1")
	b, _ := pc.tcpEdge(t, "edge-b", "127.0.0.1")
	registerPeers(t, a, b)
	third := freeTCPAddr(t)
	dials := countDials(t, third)
	snapshot := map[int][]storage.EdgePeer{20004: {{EdgeID: "edge-c", PeerAddr: third, SPKISHA256: "unused"}}}
	b.srv.peers.tcpOwners.Store(&snapshot)
	forwarded := metricDelta(metricPeerTCPForwarded)

	tc := dialTCPFrame(t, a, b, 20004, "203.0.113.9:4000")
	mustPeerStatus(t, tc, peerStatusNotOwner)
	expectClosed(t, tc)
	time.Sleep(100 * time.Millisecond)
	if dials.Load() != 0 || forwarded() != 0 {
		t.Fatalf("dials = %d, forwarded = %d, want both zero", dials.Load(), forwarded())
	}
}

func TestPeerTCPPortOutOfRangeRefused(t *testing.T) {
	pc := newPeerCluster(t)
	a, _ := pc.tcpEdge(t, "edge-a", "127.0.0.1")
	b, rec := pc.tcpEdge(t, "edge-b", "127.0.0.1")
	registerPeers(t, a, b)
	mgr := rec.fx.mgr

	outside := []int{mgr.lo - 1, mgr.hi + 1}
	for _, port := range outside {
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("listen %d: %v", port, err)
		}
		mgr.mu.Lock()
		tt := mgr.registerTunnelLocked(rec.fx.as, port, "example.com", ln, nil)
		mgr.mu.Unlock()
		go mgr.acceptLoop(tt)
	}
	inside, _, err := mgr.bind(rec.fx.as, 0, "example.com", nil, false)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	ok := dialTCPFrame(t, a, b, inside, "203.0.113.9:4000")
	mustPeerStatus(t, ok, peerStatusAccept)
	for _, port := range outside {
		tc := dialTCPFrame(t, a, b, port, "203.0.113.9:4000")
		mustPeerStatus(t, tc, peerStatusNotOwner)
		expectClosed(t, tc)
	}
}

func TestReconcileRemoteOpensAndCloses(t *testing.T) {
	tm := newTCPManager(1, 65535, "127.0.0.1", nil)
	got := make(chan int, 8)
	accept := func(port int, c net.Conn) {
		c.Close()
		got <- port
	}
	t.Cleanup(func() { tm.reconcileRemote(nil, accept) })
	ports := freePorts(t, 2)

	expectAccepted := func(port int) {
		t.Helper()
		c := dialPort(t, port)
		c.Close()
		select {
		case p := <-got:
			if p != port {
				t.Fatalf("accept callback saw port %d, want %d", p, port)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("port %d did not reach the accept callback", port)
		}
	}

	tm.reconcileRemote(map[int]struct{}{ports[0]: {}, ports[1]: {}}, accept)
	expectAccepted(ports[0])
	expectAccepted(ports[1])
	if metricPeerTCPListeners.Value() != 2 {
		t.Fatalf("listener gauge = %d, want 2", metricPeerTCPListeners.Value())
	}

	tm.reconcileRemote(map[int]struct{}{ports[1]: {}}, accept)
	expectPortRefused(t, ports[0])
	expectAccepted(ports[1])
	if metricPeerTCPListeners.Value() != 1 {
		t.Fatalf("listener gauge = %d, want 1", metricPeerTCPListeners.Value())
	}

	tm.reconcileRemote(nil, accept)
	expectPortRefused(t, ports[1])
	if metricPeerTCPListeners.Value() != 0 {
		t.Fatalf("listener gauge = %d, want 0", metricPeerTCPListeners.Value())
	}
}

func TestReconcileRemoteBackoffAfterBindFailure(t *testing.T) {
	tm := newTCPManager(1, 65535, "127.0.0.1", nil)
	accept := func(int, net.Conn) {}
	t.Cleanup(func() { tm.reconcileRemote(nil, accept) })
	port := freePorts(t, 1)[0]
	squatter, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	failed := metricDelta(metricPeerTCPBindFailed)
	want := map[int]struct{}{port: {}}

	tm.reconcileRemote(want, accept)
	if failed() != 1 || len(tm.remote) != 0 {
		t.Fatalf("bind failures = %d, listeners = %d, want 1 and 0", failed(), len(tm.remote))
	}
	squatter.Close()
	tm.reconcileRemote(want, accept)
	if len(tm.remote) != 0 {
		t.Fatal("a failed port was retried inside the backoff window")
	}
	tm.mu.Lock()
	tm.remoteFailed[port] = time.Now().Add(-remoteBindRetry - time.Second)
	tm.mu.Unlock()
	tm.reconcileRemote(want, accept)
	if len(tm.remote) != 1 {
		t.Fatal("a failed port was not retried after the backoff window")
	}
}

func TestReconcileRemoteCapAndAllocated(t *testing.T) {
	accept := func(int, net.Conn) {}

	t.Run("cap", func(t *testing.T) {
		tm := newTCPManager(1, 65535, "127.0.0.1", nil)
		want := make(map[int]struct{}, maxRemoteTCPListeners+1)
		for i := 0; i < maxRemoteTCPListeners; i++ {
			port := 1000 + i
			tm.remote[port] = stubListener{}
			want[port] = struct{}{}
		}
		extra := freePorts(t, 1)[0]
		want[extra] = struct{}{}
		t.Cleanup(func() { tm.reconcileRemote(nil, accept) })

		tm.reconcileRemote(want, accept)
		if len(tm.remote) != maxRemoteTCPListeners {
			t.Fatalf("listeners = %d, want the cap of %d", len(tm.remote), maxRemoteTCPListeners)
		}
		if _, ok := tm.remote[extra]; ok {
			t.Fatal("a listener was opened past the cap")
		}
		expectPortRefused(t, extra)
	})

	t.Run("outside the manager range", func(t *testing.T) {
		tm := newTCPManager(1, 2, "127.0.0.1", nil)
		port := freePorts(t, 1)[0]
		t.Cleanup(func() { tm.reconcileRemote(nil, accept) })

		tm.reconcileRemote(map[int]struct{}{port: {}}, accept)
		if len(tm.remote) != 0 {
			t.Fatalf("listeners = %d, want 0 for a port outside the range", len(tm.remote))
		}
		expectPortRefused(t, port)
	})

	t.Run("allocated", func(t *testing.T) {
		tm := newTCPManager(1, 65535, "127.0.0.1", nil)
		ports := freePorts(t, 2)
		tm.allocated[ports[0]] = struct{}{}
		t.Cleanup(func() { tm.reconcileRemote(nil, accept) })

		tm.reconcileRemote(map[int]struct{}{ports[0]: {}, ports[1]: {}}, accept)
		if _, ok := tm.remote[ports[0]]; ok {
			t.Fatal("a port this edge owns got a proxy listener")
		}
		if _, ok := tm.remote[ports[1]]; !ok {
			t.Fatal("a free wanted port got no proxy listener")
		}
		expectPortRefused(t, ports[0])
	})
}

func TestRequestedBindYieldsRemoteListener(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()
	proxied := make(chan int, 1)
	accept := func(port int, c net.Conn) {
		c.Close()
		proxied <- port
	}
	t.Cleanup(func() { fx.mgr.reconcileRemote(nil, accept) })

	fx.mgr.reconcileRemote(map[int]struct{}{20007: {}}, accept)
	if _, ok := fx.mgr.remote[20007]; !ok {
		t.Fatal("remote listener did not open")
	}
	port, _, err := fx.mgr.bind(fx.as, 20007, "example.com", nil, false)
	if err != nil || port != 20007 {
		t.Fatalf("bind = %d, %v; want the requested port", port, err)
	}
	if _, ok := fx.mgr.remote[20007]; ok {
		t.Fatal("remote listener survived a local bind on the same port")
	}

	c := dialPort(t, 20007)
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	select {
	case p := <-proxied:
		t.Fatalf("connection to a locally bound port was proxied (%d)", p)
	default:
	}
}

func TestAutoAllocSkipsRemote(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()
	fx.mgr.mu.Lock()
	for p := fx.mgr.lo; p < fx.mgr.hi; p++ {
		fx.mgr.remote[p] = stubListener{}
	}
	fx.mgr.mu.Unlock()
	t.Cleanup(func() {
		fx.mgr.mu.Lock()
		clear(fx.mgr.remote)
		fx.mgr.mu.Unlock()
	})

	port, _, err := fx.mgr.bind(fx.as, 0, "example.com", nil, false)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if port != fx.mgr.hi {
		t.Fatalf("auto-allocated port %d, want %d (every lower port is proxied)", port, fx.mgr.hi)
	}
}

func TestWatchTCPFailsClosedAfterTTL(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured time.Duration
		want       time.Duration
	}{
		{"default lease ttl", 0, storage.DefaultLeaseTTL},
		{"configured shorter lease ttl", 10 * time.Second, 10 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc := newPeerCluster(t)
			a, _ := pc.tcpEdge(t, "edge-a", "127.0.0.1")
			b, _ := pc.tcpEdge(t, "edge-b", "127.0.0.1")
			registerPeers(t, a, b)
			a.srv.cfg.LeaseTTL = tc.configured
			port := freePorts(t, 1)[0]
			a.srv.tcpMgr.lo, a.srv.tcpMgr.hi = port, port
			b.leaseTCP(t, port)
			ctx := context.Background()
			t.Cleanup(func() { a.srv.tcpMgr.reconcileRemote(nil, a.srv.peers.forwardTCP) })

			t0 := time.Now()
			a.srv.peers.pollTCP(ctx, t0)
			if _, ok := a.srv.tcpMgr.remote[port]; !ok {
				t.Fatal("remote port did not open while storage was healthy")
			}
			if owners := *a.srv.peers.tcpOwners.Load(); len(owners[port]) != 1 {
				t.Fatalf("owners = %+v, want one for port %d", owners, port)
			}

			a.store.Close()
			a.srv.peers.pollTCP(ctx, t0.Add(tc.want-time.Second))
			if _, ok := a.srv.tcpMgr.remote[port]; !ok {
				t.Fatal("remote port closed before the lease TTL elapsed")
			}
			a.srv.peers.pollTCP(ctx, t0.Add(tc.want+time.Second))
			if _, ok := a.srv.tcpMgr.remote[port]; ok {
				t.Fatal("remote port stayed open after the lease TTL elapsed without a fresh read")
			}
			if owners := *a.srv.peers.tcpOwners.Load(); len(owners) != 0 {
				t.Fatalf("owner snapshot = %+v, want empty", owners)
			}
			expectPortRefused(t, port)
		})
	}
}

type mappedRemoteConn struct {
	net.Conn
	remote net.Addr
}

func (c mappedRemoteConn) RemoteAddr() net.Addr { return c.remote }

func TestForwardTCPKeysLimiterByPlainIPv4(t *testing.T) {
	pc := newPeerCluster(t)
	a, _ := pc.tcpEdge(t, "edge-a", "127.0.0.1")
	a.srv.perIPLimiter = newPerIPLimiter(1, 1, 16)
	client, server := realConnPair(t)
	defer client.Close()
	defer server.Close()

	a.srv.peers.forwardTCP(20001, mappedRemoteConn{Conn: server, remote: &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 4242}})

	keys := a.srv.perIPLimiter.limiters.Keys()
	if len(keys) != 1 || keys[0] != "203.0.113.7" {
		t.Fatalf("limiter keys = %v, want [203.0.113.7]", keys)
	}
}

func TestTCPForwardInertWithoutPeers(t *testing.T) {
	t.Run("no peer address", func(t *testing.T) {
		pc := newPeerCluster(t)
		b := pc.edge(t, "edge-b")
		registerPeers(t, b)
		port := freePorts(t, 1)[0]
		b.leaseTCP(t, port)
		store, err := storage.Open(storage.Config{DSN: pc.dsn, EdgeID: "edge-a"})
		if err != nil {
			t.Fatalf("open storage: %v", err)
		}
		t.Cleanup(func() { store.Close() })
		s, err := New(Config{
			ControlAddr:  freeTCPAddr(t),
			PublicAddr:   freeTCPAddr(t),
			Domain:       "example.com",
			TokenSHA256:  sumToken("tok"),
			PublicScheme: "http",
			Insecure:     true,
			Storage:      store,
			TCPPortRange: fmt.Sprintf("%d-%d", port, port),
			TCPBindAddr:  "127.0.0.1",
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		runServer(t, s)
		if s.peers != nil {
			t.Fatal("peers configured without a peer address")
		}
		time.Sleep(300 * time.Millisecond)
		s.tcpMgr.mu.Lock()
		n := len(s.tcpMgr.remote)
		s.tcpMgr.mu.Unlock()
		if n != 0 {
			t.Fatalf("remote listeners = %d, want 0", n)
		}
		expectPortRefused(t, port)
	})

	t.Run("no tcp range", func(t *testing.T) {
		store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db"), EdgeID: "edge-a"})
		if err != nil {
			t.Fatalf("open storage: %v", err)
		}
		t.Cleanup(func() { store.Close() })
		cert, _ := passthroughTestCert(t, peerTestHost)
		listen := freeTCPAddr(t)
		s, err := New(Config{
			ControlAddr:     freeTCPAddr(t),
			PublicAddr:      freeTCPAddr(t),
			Domain:          "example.com",
			TokenSHA256:     sumToken("tok"),
			PublicScheme:    "https",
			Storage:         store,
			PeerAddr:        freeTCPAddr(t),
			PeerListen:      listen,
			PublicTLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		runServer(t, s)
		if s.tcpMgr != nil {
			t.Fatal("tcp manager configured without a port range")
		}
		time.Sleep(300 * time.Millisecond)
		c, err := net.DialTimeout("tcp", listen, 2*time.Second)
		if err != nil {
			t.Fatalf("peer listener is not accepting: %v", err)
		}
		c.Close()
	})
}

func TestForwardTCPSplicesToOwner(t *testing.T) {
	requireLoopbackV6(t)
	pc := newPeerCluster(t)
	a, _ := pc.tcpEdge(t, "edge-a", "::1")
	b, rec := pc.tcpEdge(t, "edge-b", "127.0.0.1")
	registerPeers(t, a, b)
	port, _, err := rec.fx.mgr.bind(rec.fx.as, 0, "example.com", nil, false)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	b.leaseTCP(t, port)
	t.Cleanup(func() { a.srv.tcpMgr.reconcileRemote(nil, a.srv.peers.forwardTCP) })
	forwarded := metricDelta(metricPeerTCPForwarded)

	a.srv.peers.pollTCP(context.Background(), time.Now())
	c, err := net.DialTimeout("tcp", net.JoinHostPort("::1", strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial the proxy listener: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	pre := rec.pre.Load()
	if pre == nil || pre.ClientAddr != c.LocalAddr().String() {
		t.Fatalf("agent preamble = %+v, want client %s", pre, c.LocalAddr())
	}
	if forwarded() != 1 {
		t.Fatalf("forwarded = %d, want 1", forwarded())
	}
	c.Close()
	peerEventually(t, "forward gauge to drain", func() bool { return metricActivePeerForwards.Value() == 0 })
}
