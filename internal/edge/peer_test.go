package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"expvar"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/storage"
)

const peerTestHost = "app.example.com"

type peerCluster struct {
	dsn  string
	cert tls.Certificate
	pool *x509.CertPool
}

func newPeerCluster(t *testing.T) *peerCluster {
	t.Helper()
	cert, pool := passthroughTestCert(t, peerTestHost)
	return &peerCluster{dsn: filepath.Join(t.TempDir(), "control.db"), cert: cert, pool: pool}
}

type peerEdge struct {
	id       string
	srv      *Server
	store    *storage.Store
	sni      *sniListener
	addr     string
	fx       *tcpFixture
	agentHit atomic.Int64
	accepts  atomic.Int64
	lastPre  atomic.Pointer[proto.StreamOpen]
}

type countingListener struct {
	net.Listener
	n *atomic.Int64
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

func countDials(t *testing.T, addr string) *atomic.Int64 {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("relisten on %s: %v", addr, err)
	}
	var n atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			c.Close()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
	})
	return &n
}

func (pc *peerCluster) edge(t *testing.T, edgeID string) *peerEdge {
	t.Helper()
	return pc.edgeWith(t, edgeID, nil)
}

func (pc *peerCluster) edgeWith(t *testing.T, edgeID string, mgr *tcpManager) *peerEdge {
	t.Helper()
	store, err := storage.Open(storage.Config{DSN: pc.dsn, EdgeID: edgeID})
	if err != nil {
		t.Fatalf("open storage %s: %v", edgeID, err)
	}
	t.Cleanup(func() { store.Close() })

	e := &peerEdge{id: edgeID, store: store, srv: newTestServer("tok")}
	e.srv.storage = store
	e.srv.tcpMgr = mgr
	e.srv.cfg.PeerAddr = "127.0.0.1:1"
	p, err := newPeerForwarder(e.srv)
	if err != nil {
		t.Fatalf("newPeerForwarder: %v", err)
	}
	e.srv.peers = p

	e.fx = newTCPFixture(t, func(conn net.Conn, pre proto.StreamOpen) {
		defer conn.Close()
		e.lastPre.Store(&pre)
		e.agentHit.Add(1)
		tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{pc.cert}})
		if err := tc.Handshake(); err != nil {
			return
		}
		io.Copy(tc, tc)
	})
	t.Cleanup(e.fx.cleanup)

	peerLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("peer listen: %v", err)
	}
	p.ln = countingListener{Listener: peerLn, n: &e.accepts}
	p.addr = peerLn.Addr().String()

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("public listen: %v", err)
	}
	e.sni = e.srv.newSNIListener(raw)
	e.addr = raw.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.acceptLoop(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		peerLn.Close()
		<-done
		e.sni.Close()
	})
	return e
}

func (e *peerEdge) pin() string      { return e.srv.peers.id.pin }
func (e *peerEdge) peerAddr() string { return e.srv.peers.addr }

func (e *peerEdge) record() storage.EdgePeer {
	return storage.EdgePeer{EdgeID: e.id, PeerAddr: e.peerAddr(), SPKISHA256: e.pin()}
}

func (e *peerEdge) bindTLS(t *testing.T, host string) {
	t.Helper()
	if _, _, err := e.srv.registry.BindWithOptions(BindOptions{Host: host, Session: e.fx.as, TLS: true}); err != nil {
		t.Fatalf("bind tls %s: %v", host, err)
	}
	e.lease(t, host)
}

func (e *peerEdge) lease(t *testing.T, host string) {
	t.Helper()
	e.acquire(t, host, false)
}

func (e *peerEdge) bindTLSMulti(t *testing.T, host string) {
	t.Helper()
	if _, _, err := e.srv.registry.BindWithOptions(BindOptions{Host: host, Session: e.fx.as, TLS: true}); err != nil {
		t.Fatalf("bind tls %s: %v", host, err)
	}
	e.acquire(t, host, true)
}

func (e *peerEdge) acquire(t *testing.T, host string, multi bool) {
	t.Helper()
	req := storage.LeaseRequest{
		Hostname:   host,
		Kind:       "tls",
		EdgeID:     e.id,
		OwnerID:    "owner",
		InstanceID: "inst-" + e.id,
		SessionID:  "sess-" + e.id + "-" + host,
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	if multi {
		req.MultiConnector = true
		req.ConnectorTokenDigest = testConnectorTokenDigest
	}
	if _, err := e.store.AcquireLease(context.Background(), req); err != nil {
		t.Fatalf("acquire lease %s on %s: %v", host, e.id, err)
	}
}

func registerPeers(t *testing.T, edges ...*peerEdge) {
	t.Helper()
	now := time.Now()
	for _, e := range edges {
		peer := e.record()
		peer.ExpiresAt = now.Add(time.Hour)
		if err := e.store.UpsertEdgePeer(context.Background(), peer); err != nil {
			t.Fatalf("register peer %s: %v", e.id, err)
		}
	}
	for _, e := range edges {
		e.srv.peers.lastRefresh.Store(0)
		e.srv.peers.refreshPins()
	}
}

func peerEventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func helloFor(t *testing.T, host string) []byte {
	t.Helper()
	return captureClientHello(t, &tls.Config{ServerName: host, InsecureSkipVerify: true})
}

func dialPeerTLS(t *testing.T, cfg *tls.Config, addr string) (*tls.Conn, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial peer: %v", err)
	}
	t.Cleanup(func() { raw.Close() })
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	tc := tls.Client(raw, cfg)
	return tc, tc.Handshake()
}

func peerRejected(t *testing.T, cfg *tls.Config, addr string) error {
	t.Helper()
	tc, err := dialPeerTLS(t, cfg, addr)
	if err != nil {
		return err
	}
	_ = tc.SetReadDeadline(time.Now().Add(time.Second))
	_, err = tc.Read(make([]byte, 1))
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return nil
	}
	return err
}

func sendForwarded(t *testing.T, c net.Conn, src string, hello []byte) {
	t.Helper()
	tc, ok := c.(*tls.Conn)
	if !ok {
		t.Fatalf("sendForwarded needs a TLS connection, got %T", c)
	}
	frame := peerFrame{kind: peerFrameSNI, src: netip.MustParseAddrPort(src), payload: hello}
	payload, ok := frame.encode(tc.ConnectionState().NegotiatedProtocol)
	if !ok {
		t.Fatalf("frame cannot be encoded for %q", tc.ConnectionState().NegotiatedProtocol)
	}
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write forwarded payload: %v", err)
	}
}

func readPeerStatus(c net.Conn) (byte, error) {
	var b [1]byte
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := io.ReadFull(c, b[:])
	return b[0], err
}

func mustPeerStatus(t *testing.T, c net.Conn, want byte) {
	t.Helper()
	got, err := readPeerStatus(c)
	if err != nil || got != want {
		t.Fatalf("status = %d, %v; want %d", got, err, want)
	}
}

func dialIngress(t *testing.T, e *peerEdge, host string, pool *x509.CertPool) (*tls.Conn, error) {
	t.Helper()
	return dialTLSClient(t, e.addr, nil, &tls.Config{ServerName: host, RootCAs: pool})
}

func pingEcho(t *testing.T, tc *tls.Conn) {
	t.Helper()
	if _, err := tc.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(tc, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
}

func sendRawHello(t *testing.T, addr string, hello []byte) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if _, err := c.Write(hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	return c
}

func acceptOne(t *testing.T, ln *sniListener) net.Conn {
	t.Helper()
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("accept: %v", r.err)
		}
		t.Cleanup(func() { r.c.Close() })
		return r.c
	case <-time.After(3 * time.Second):
		t.Fatal("connection was not delivered locally")
		return nil
	}
}

func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.Read(make([]byte, 1))
	if n != 0 || err == nil {
		t.Fatalf("read = %d, %v; want a closed connection", n, err)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("connection stayed open")
	}
}

func metricDelta(v *expvar.Int) func() int64 {
	before := v.Value()
	return func() int64 { return v.Value() - before }
}

func TestPeerTLSAcceptsKnownPin(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)

	tc, err := dialPeerTLS(t, a.srv.peers.clientTLS(b.pin()), b.peerAddr())
	if err != nil {
		t.Fatalf("handshake with a registered peer: %v", err)
	}
	sendForwarded(t, tc, "203.0.113.7:5000", []byte("GET / HTTP/1.1\r\n\r\n"))
	mustPeerStatus(t, tc, peerStatusNotOwner)
}

func TestPeerTLSRejectsWrongServerPin(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	other, err := newPeerIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	_, err = dialPeerTLS(t, a.srv.peers.clientTLS(other.pin), b.peerAddr())
	if !errors.Is(err, errPeerPinChanged) {
		t.Fatalf("handshake err = %v, want %v", err, errPeerPinChanged)
	}
}

func TestPeerTLSRejectsUnknownClientPin(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	stranger, err := newPeerIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	cfg := a.srv.peers.clientTLS(b.pin())
	cfg.Certificates = []tls.Certificate{stranger.cert}

	if err := peerRejected(t, cfg, b.peerAddr()); err == nil {
		t.Fatal("a client with an unregistered key was accepted")
	}
}

func TestPeerTLSRejectsMissingClientCert(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	cfg := a.srv.peers.clientTLS(b.pin())
	cfg.Certificates = nil

	if err := peerRejected(t, cfg, b.peerAddr()); err == nil {
		t.Fatal("a client without a certificate was accepted")
	}
}

func TestPeerTLSRejectsALPNMismatch(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)

	for name, protos := range map[string][]string{"other": {"h2"}, "none": nil} {
		t.Run(name, func(t *testing.T) {
			cfg := a.srv.peers.clientTLS(b.pin())
			cfg.VerifyConnection = nil
			cfg.NextProtos = protos
			if err := peerRejected(t, cfg, b.peerAddr()); err == nil {
				t.Fatal("a client with the wrong ALPN was accepted")
			}
		})
	}
}

func TestPeerTLSNeverResumes(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	if !b.srv.peers.serverTLS().SessionTicketsDisabled {
		t.Fatal("server config issues session tickets")
	}
	resumed := tls.ConnectionState{DidResume: true, NegotiatedProtocol: peerALPN2, PeerCertificates: []*x509.Certificate{b.srv.peers.id.cert.Leaf}}
	if err := b.srv.peers.serverTLS().VerifyConnection(resumed); !errors.Is(err, errPeerResumed) {
		t.Fatalf("server accepted a resumed session: %v", err)
	}
	if err := a.srv.peers.clientTLS(b.pin()).VerifyConnection(resumed); !errors.Is(err, errPeerResumed) {
		t.Fatalf("client accepted a resumed session: %v", err)
	}

	cfg := a.srv.peers.clientTLS(b.pin())
	cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)

	for round := 1; round <= 3; round++ {
		tc, err := dialPeerTLS(t, cfg, b.peerAddr())
		if err != nil {
			t.Fatalf("round %d handshake: %v", round, err)
		}
		if tc.ConnectionState().DidResume {
			t.Fatalf("round %d resumed a session", round)
		}
		sendForwarded(t, tc, "203.0.113.7:5000", []byte("GET / HTTP/1.1\r\n\r\n"))
		mustPeerStatus(t, tc, peerStatusNotOwner)
	}
}

func TestPeerPinRefreshIsRateLimited(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	newcomer, err := newPeerIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	cfg := a.srv.peers.clientTLS(b.pin())
	cfg.Certificates = []tls.Certificate{newcomer.cert}

	if err := peerRejected(t, cfg, b.peerAddr()); err == nil {
		t.Fatal("unregistered newcomer accepted")
	}
	now := time.Now()
	row := storage.EdgePeer{EdgeID: "edge-x", PeerAddr: "127.0.0.1:9", SPKISHA256: newcomer.pin, ExpiresAt: now.Add(time.Hour)}
	if err := a.store.UpsertEdgePeer(context.Background(), row); err != nil {
		t.Fatalf("register newcomer: %v", err)
	}
	if err := peerRejected(t, cfg, b.peerAddr()); err == nil {
		t.Fatal("pins were refreshed again inside the rate-limit window")
	}
	time.Sleep(peerPinRefreshInterval + 150*time.Millisecond)
	if err := peerRejected(t, cfg, b.peerAddr()); err != nil {
		t.Fatalf("newcomer still rejected after the window: %v", err)
	}
}

func TestNewRejectsInvalidPeerConfig(t *testing.T) {
	store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db"), EdgeID: "edge-a"})
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	base := func(mod func(*Config)) Config {
		cfg := Config{Domain: "example.com", TokenSHA256: sumToken("tok"), PublicScheme: "https", Storage: store, PeerAddr: "127.0.0.1:7443"}
		mod(&cfg)
		return cfg
	}
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"no storage", base(func(c *Config) { c.Storage = nil }), "durable storage"},
		{"insecure", base(func(c *Config) { c.Insecure = true; c.PublicScheme = "http" }), "insecure"},
		{"hostname", base(func(c *Config) { c.PeerAddr = "localhost:7443" }), "invalid peer address"},
		{"no port", base(func(c *Config) { c.PeerAddr = "127.0.0.1" }), "invalid peer address"},
		{"unspecified v4", base(func(c *Config) { c.PeerAddr = "0.0.0.0:7443" }), "specific address"},
		{"unspecified v6", base(func(c *Config) { c.PeerAddr = "[::]:7443" }), "specific address"},
		{"port zero", base(func(c *Config) { c.PeerAddr = "127.0.0.1:0" }), "specific address"},
		{"public tls with insecure", base(func(c *Config) {
			c.PeerAddr = ""
			c.Insecure = true
			c.PublicScheme = "http"
			c.PublicTLSConfig = &tls.Config{}
		}), "insecure"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(tc.cfg)
			if err == nil {
				t.Fatalf("New accepted the config: %+v", s.cfg)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestNewValidatesPeerAddrBeforeOpeningStorage(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "control.db")
	s, err := New(Config{
		Domain:        "example.com",
		TokenSHA256:   sumToken("tok"),
		PublicScheme:  "https",
		StorageDriver: "sqlite",
		StorageDSN:    dsn,
		EdgeID:        "edge-a",
		PeerAddr:      "localhost:4043",
	})
	if err == nil {
		t.Fatalf("New accepted a hostname as the peer address: %+v", s.cfg)
	}
	if !strings.Contains(err.Error(), "invalid peer address") {
		t.Fatalf("err = %v, want it to mention an invalid peer address", err)
	}
	if _, statErr := os.Stat(dsn); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("database file %s exists after a rejected peer address (stat err = %v)", dsn, statErr)
	}
}

func TestPeersNilWhenPeerAddrUnset(t *testing.T) {
	store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db"), EdgeID: "edge-a"})
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()
	s, err := New(Config{Domain: "example.com", TokenSHA256: sumToken("tok"), PublicScheme: "http", Insecure: true, Storage: store})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.peers != nil {
		t.Fatal("peers configured without a peer address")
	}
	s.peers.stop()
	s.peers.waitSplices(context.Background())
}

func TestPeerHeartbeatRegistersAndStopDeletes(t *testing.T) {
	pc := newPeerCluster(t)
	a := pc.edge(t, "edge-a")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.srv.peers.heartbeat(ctx) }()

	live := func() []storage.EdgePeer {
		peers, err := a.store.LiveEdgePeers(context.Background(), time.Now())
		if err != nil {
			t.Fatalf("live peers: %v", err)
		}
		return peers
	}
	peerEventually(t, "heartbeat registration", func() bool { return len(live()) == 1 })
	got := live()[0]
	if got.EdgeID != "edge-a" || got.PeerAddr != a.peerAddr() || got.SPKISHA256 != a.pin() {
		t.Fatalf("registered row = %+v", got)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("heartbeat returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("heartbeat did not stop")
	}
	a.srv.peers.stop()
	if n := len(live()); n != 0 {
		t.Fatalf("%d peer rows left after stop", n)
	}
	if c, err := net.DialTimeout("tcp", a.peerAddr(), time.Second); err == nil {
		c.Close()
		t.Fatal("peer listener still accepts connections after stop")
	}
}

func TestPeerAcceptRoutesForwardedTLSToAgent(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)

	tc, err := dialPeerTLS(t, a.srv.peers.clientTLS(b.pin()), b.peerAddr())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	sendForwarded(t, tc, "203.0.113.9:4000", helloFor(t, peerTestHost))
	mustPeerStatus(t, tc, peerStatusAccept)

	peerEventually(t, "agent stream", func() bool { return b.lastPre.Load() != nil })
	pre := b.lastPre.Load()
	if pre.Kind != proto.KindTLS || pre.Host != peerTestHost || pre.ClientAddr != "203.0.113.9:4000" {
		t.Fatalf("agent preamble = %+v", *pre)
	}
}

func TestPeerAcceptRejectsMissingProxyHeader(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)

	tc, err := dialPeerTLS(t, a.srv.peers.clientTLS(b.pin()), b.peerAddr())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := tc.Write(append([]byte{peerFrameSNI}, helloFor(t, peerTestHost)...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectClosed(t, tc)
	if b.agentHit.Load() != 0 {
		t.Fatal("a connection without a PROXY header reached the agent")
	}
}

func TestPeerAcceptRouteMissWritesNotOwner(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)

	tc, err := dialPeerTLS(t, a.srv.peers.clientTLS(b.pin()), b.peerAddr())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	sendForwarded(t, tc, "203.0.113.9:4000", helloFor(t, "ghost.example.com"))
	mustPeerStatus(t, tc, peerStatusNotOwner)
	expectClosed(t, tc)
}

func TestForwardedConnNeverForwardsAgain(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	forwarded := metricDelta(metricPeerForwardedConns)
	lookups := metricDelta(metricPeerLookups)

	tc, err := dialPeerTLS(t, b.srv.peers.clientTLS(a.pin()), a.peerAddr())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	sendForwarded(t, tc, "203.0.113.9:4000", helloFor(t, peerTestHost))
	mustPeerStatus(t, tc, peerStatusNotOwner)
	expectClosed(t, tc)
	time.Sleep(100 * time.Millisecond)
	if forwarded() != 0 || lookups() != 0 || b.agentHit.Load() != 0 {
		t.Fatalf("forwarded=%d lookups=%d agentHit=%d, want all zero", forwarded(), lookups(), b.agentHit.Load())
	}
}

func TestPeerAcceptHandshakeCap(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	for i := 0; i < maxPeerHandshakes; i++ {
		if !b.srv.peers.handshakeSem.tryAcquire() {
			t.Fatalf("slot %d not free", i)
		}
	}
	if _, err := dialPeerTLS(t, a.srv.peers.clientTLS(b.pin()), b.peerAddr()); err == nil {
		t.Fatal("handshake succeeded with every slot taken")
	}
	b.srv.peers.handshakeSem.release()
	if _, err := dialPeerTLS(t, a.srv.peers.clientTLS(b.pin()), b.peerAddr()); err != nil {
		t.Fatalf("handshake after a slot was freed: %v", err)
	}
}

func TestPeerAcceptUnauthenticatedCannotReachClassify(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	accepted := metricDelta(metricPeerAcceptedConns)
	line, err := proxyProtoV1Line(netip.MustParseAddrPort("203.0.113.9:4000"))
	if err != nil {
		t.Fatalf("proxy line: %v", err)
	}
	payload := append([]byte(line), helloFor(t, peerTestHost)...)

	t.Run("plaintext", func(t *testing.T) {
		c := sendRawHello(t, b.peerAddr(), payload)
		expectClosed(t, c)
	})
	t.Run("unregistered key", func(t *testing.T) {
		stranger, err := newPeerIdentity()
		if err != nil {
			t.Fatalf("identity: %v", err)
		}
		cfg := a.srv.peers.clientTLS(b.pin())
		cfg.Certificates = []tls.Certificate{stranger.cert}
		tc, err := dialPeerTLS(t, cfg, b.peerAddr())
		if err == nil {
			_, _ = tc.Write(payload)
			expectClosed(t, tc)
		}
	})
	time.Sleep(100 * time.Millisecond)
	if accepted() != 0 || b.agentHit.Load() != 0 {
		t.Fatalf("accepted=%d agentHit=%d, want both zero", accepted(), b.agentHit.Load())
	}
}

func TestPeerForwardSplicesToOwner(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	forwarded := metricDelta(metricPeerForwardedConns)

	tc, err := dialIngress(t, a, peerTestHost, pc.pool)
	if err != nil {
		t.Fatalf("handshake through the ingress edge: %v", err)
	}
	seen := tc.ConnectionState().PeerCertificates
	if len(seen) == 0 || !seen[0].Equal(pc.cert.Leaf) {
		t.Fatal("client did not see the agent's own certificate")
	}
	pingEcho(t, tc)
	if b.agentHit.Load() != 1 || forwarded() != 1 {
		t.Fatalf("agentHit=%d forwarded=%d, want 1 and 1", b.agentHit.Load(), forwarded())
	}
	tc.Close()
	peerEventually(t, "forward gauge to drain", func() bool { return metricActivePeerForwards.Value() == 0 })
}

func TestPeerForwardSendsRealClientAddr(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)

	tc, err := dialIngress(t, a, peerTestHost, pc.pool)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	pingEcho(t, tc)
	pre := b.lastPre.Load()
	if pre == nil || pre.ClientAddr != tc.LocalAddr().String() {
		t.Fatalf("agent saw client %+v, want %s", pre, tc.LocalAddr())
	}
}

func TestPeerForwardRetriesOnceAfterNotOwner(t *testing.T) {
	pc := newPeerCluster(t)
	a, b, c := pc.edge(t, "edge-a"), pc.edge(t, "edge-b"), pc.edge(t, "edge-c")
	registerPeers(t, a, b, c)
	b.bindTLS(t, peerTestHost)
	a.srv.peers.owners.Add(peerTestHost, &ownerEntry{peers: []storage.EdgePeer{c.record()}, resolved: time.Now()})
	stale := metricDelta(metricPeerForwardStale)
	lookups := metricDelta(metricPeerLookups)

	tc, err := dialIngress(t, a, peerTestHost, pc.pool)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	pingEcho(t, tc)
	if stale() != 1 || lookups() != 1 || b.agentHit.Load() != 1 {
		t.Fatalf("stale=%d lookups=%d agentHit=%d, want 1, 1, 1", stale(), lookups(), b.agentHit.Load())
	}
	if c.accepts.Load() != 1 || b.accepts.Load() != 1 {
		t.Fatalf("dials: edge-c=%d edge-b=%d, want 1 and 1", c.accepts.Load(), b.accepts.Load())
	}
	if got, ok := a.srv.peers.owners.Get(peerTestHost); !ok || len(got.peers) != 1 || got.peers[0].EdgeID != "edge-b" {
		t.Fatalf("owner cache = %+v, %v; want edge-b", got, ok)
	}
}

func TestPeerForwardRequeriesAfterPinMismatch(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	rotated := b.record()
	rotated.SPKISHA256 = strings.Repeat("ab", 32)
	a.srv.peers.owners.Add(peerTestHost, &ownerEntry{peers: []storage.EdgePeer{rotated}, resolved: time.Now()})
	lookups := metricDelta(metricPeerLookups)
	failed := metricDelta(metricPeerForwardFailed)

	tc, err := dialIngress(t, a, peerTestHost, pc.pool)
	if err != nil {
		t.Fatalf("first handshake after the owner re-keyed: %v", err)
	}
	pingEcho(t, tc)
	if lookups() != 1 || b.accepts.Load() != 2 || b.agentHit.Load() != 1 || failed() != 0 {
		t.Fatalf("lookups=%d dials=%d agentHit=%d failed=%d, want 1, 2, 1, 0", lookups(), b.accepts.Load(), b.agentHit.Load(), failed())
	}
	if got, ok := a.srv.peers.owners.Get(peerTestHost); !ok || len(got.peers) != 1 || got.peers[0].SPKISHA256 != b.pin() {
		t.Fatalf("owner cache = %+v, %v; want the refreshed record for edge-b", got, ok)
	}
}

func TestPeerForwardDoesNotRetryIdenticalStaleOwner(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.lease(t, peerTestHost)
	a.srv.peers.owners.Add(peerTestHost, &ownerEntry{peers: []storage.EdgePeer{b.record()}, resolved: time.Now()})
	lookups := metricDelta(metricPeerLookups)
	failed := metricDelta(metricPeerForwardFailed)
	stale := metricDelta(metricPeerForwardStale)

	if _, err := dialIngress(t, a, peerTestHost, pc.pool); err == nil {
		t.Fatal("handshake succeeded although the owner refuses the host")
	}
	peerEventually(t, "forward failure to be counted", func() bool { return failed() == 1 })
	if lookups() != 1 || stale() != 1 || b.accepts.Load() != 1 {
		t.Fatalf("lookups=%d stale=%d dials=%d, want 1, 1, 1 (no second dial to the identical row)", lookups(), stale(), b.accepts.Load())
	}
}

func TestPeerForwardFallsBackLocallyWhenNoOwner(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	lookups := metricDelta(metricPeerLookups)
	hello := helloFor(t, "ghost.example.com")

	for i := 0; i < 2; i++ {
		sendRawHello(t, a.addr, hello)
		got := acceptOne(t, a.sni)
		buf := make([]byte, len(hello))
		_ = got.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(got, buf); err != nil || string(buf) != string(hello) {
			t.Fatalf("delivered conn replay = %v, matches=%v", err, string(buf) == string(hello))
		}
	}
	if lookups() != 1 {
		t.Fatalf("lookups = %d, want 1 (second miss served from the miss cache)", lookups())
	}
}

func TestPeerForwardClosesWhenOwnerUnreachable(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	b.srv.peers.ln.Close()
	failed := metricDelta(metricPeerForwardFailed)

	if _, err := dialIngress(t, a, peerTestHost, pc.pool); err == nil {
		t.Fatal("handshake succeeded with the owner unreachable")
	}
	peerEventually(t, "forward failure to be counted", func() bool { return failed() == 1 })
}

func TestPeerForwardSkipsApexAndCallbackHost(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	a.srv.visitor = &visitorLogin{callback: &url.URL{Scheme: "https", Host: "login.example.com", Path: "/cb"}}
	lookups := metricDelta(metricPeerLookups)

	for _, host := range []string{"example.com", "login.example.com"} {
		b.lease(t, host)
		sendRawHello(t, a.addr, helloFor(t, host))
		acceptOne(t, a.sni)
	}
	if lookups() != 0 {
		t.Fatalf("lookups = %d, want 0", lookups())
	}
}

func TestPeerForwardSkipsNonTunnelHosts(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)

	cases := map[string]bool{
		"app.example.com":   true,
		"APP.Example.COM":   true,
		"example.com":       false,
		"a.b.example.com":   false,
		"app.other.org":     false,
		"_x.example.com":    false,
		"1.2.3.4":           false,
		"":                  false,
		"notexample.com":    false,
		".example.com":      false,
		"app.example.com.":  false,
		"-bad-.example.com": false,
	}
	for host, want := range cases {
		if got := a.srv.peers.eligible(host); got != want {
			t.Errorf("eligible(%q) = %v, want %v", host, got, want)
		}
	}

	b.lease(t, "app.other.org")
	lookups := metricDelta(metricPeerLookups)
	sendRawHello(t, a.addr, helloFor(t, "app.other.org"))
	acceptOne(t, a.sni)
	if lookups() != 0 {
		t.Fatalf("lookups = %d for a host outside the edge domain", lookups())
	}
}

func TestPeerForwardClosesOnLookupCap(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	for i := 0; i < maxPeerLookups; i++ {
		if !a.srv.peers.lookupSem.tryAcquire() {
			t.Fatalf("lookup slot %d not free", i)
		}
	}
	capped := metricDelta(metricPeerRejectedLookupCap)
	lookups := metricDelta(metricPeerLookups)

	c := sendRawHello(t, a.addr, helloFor(t, "ghost.example.com"))
	expectClosed(t, c)
	if capped() != 1 || lookups() != 0 {
		t.Fatalf("capped=%d lookups=%d, want 1 and 0", capped(), lookups())
	}
	for i := 0; i < maxPeerLookups; i++ {
		a.srv.peers.lookupSem.release()
	}
}

func TestOwnerCacheSurvivesMissFlood(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	p := a.srv.peers
	p.owners.Add(peerTestHost, &ownerEntry{peers: []storage.EdgePeer{b.record()}, resolved: time.Now()})

	for i := 0; i < 50000; i++ {
		p.misses.Add(fmt.Sprintf("miss-%d.example.com", i), struct{}{})
	}
	if got, ok := p.owners.Get(peerTestHost); !ok || len(got.peers) != 1 || got.peers[0].EdgeID != "edge-b" {
		t.Fatalf("owner entry = %+v, %v after the flood", got, ok)
	}
	if n := p.misses.Len(); n > peerMissCacheSize {
		t.Fatalf("miss cache holds %d entries, cap is %d", n, peerMissCacheSize)
	}
}

func TestRouteMissStatus(t *testing.T) {
	pc := newPeerCluster(t)
	a := pc.edge(t, "edge-a")
	plain := newTestServer("tok")

	forwardedCtx := context.WithValue(context.Background(), peerForwardedKey{}, true)
	req := func(ctx context.Context, host, sni string) *http.Request {
		r := httptest.NewRequest("GET", "https://"+host+"/x", nil).WithContext(ctx)
		if sni != "" {
			r.TLS = &tls.ConnectionState{ServerName: sni}
		}
		return r
	}
	cases := []struct {
		name string
		srv  *Server
		r    *http.Request
		want int
	}{
		{"peers forwarded", a.srv, req(forwardedCtx, "ghost.example.com", ""), http.StatusMisdirectedRequest},
		{"peers sni mismatch", a.srv, req(context.Background(), "ghost.example.com", "other.example.com"), http.StatusMisdirectedRequest},
		{"peers sni mismatch case-insensitive match", a.srv, req(context.Background(), "ghost.example.com", "GHOST.example.com"), http.StatusNotFound},
		{"peers plain miss", a.srv, req(context.Background(), "ghost.example.com", ""), http.StatusNotFound},
		{"no peers forwarded", plain, req(forwardedCtx, "ghost.example.com", ""), http.StatusNotFound},
		{"no peers sni mismatch", plain, req(context.Background(), "ghost.example.com", "other.example.com"), http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.srv.routeMissStatus(tc.r, "ghost.example.com"); got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}

	agentCert, _ := passthroughTestCert(t, "secure.example.com")
	h := newSNIHarness(t, agentCert, nil)
	h.bindTLS(t, "secure.example.com", nil)
	if got := h.srv.routeMissStatus(req(context.Background(), "secure.example.com", ""), "secure.example.com"); got != http.StatusMisdirectedRequest {
		t.Fatalf("tls-bound host status = %d, want 421", got)
	}

	mis := metricDelta(metricPeerMisdirected)
	a.srv.routeMissStatus(req(forwardedCtx, "ghost.example.com", ""), "ghost.example.com")
	if mis() != 1 {
		t.Fatalf("misdirected counter delta = %d, want 1", mis())
	}
}

func TestForwardingInertWithoutPeerAddr(t *testing.T) {
	pc := newPeerCluster(t)
	b := pc.edge(t, "edge-b")
	registerPeers(t, b)
	b.bindTLS(t, peerTestHost)

	h := newSNIHarness(t, pc.cert, nil)
	store, err := storage.Open(storage.Config{DSN: pc.dsn, EdgeID: "edge-a"})
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()
	h.srv.storage = store
	if h.srv.peers != nil {
		t.Fatal("peers configured on a plain server")
	}
	forwarded := metricDelta(metricPeerForwardedConns)
	lookups := metricDelta(metricPeerLookups)
	accepted := metricDelta(metricPeerAcceptedConns)

	sendRawHello(t, h.addr, helloFor(t, peerTestHost))
	acceptOne(t, h.ln)
	if forwarded() != 0 || lookups() != 0 || accepted() != 0 || b.agentHit.Load() != 0 {
		t.Fatalf("forwarded=%d lookups=%d accepted=%d ownerHit=%d, want all zero", forwarded(), lookups(), accepted(), b.agentHit.Load())
	}
}

func holdFlight(p *peerForwarder, key string) (release func()) {
	started := make(chan struct{})
	gate := make(chan struct{})
	go func() {
		p.lookups.Do(key, func() (any, error) {
			close(started)
			<-gate
			return p.lookupOnce(key)
		})
	}()
	<-started
	return func() { close(gate) }
}

type resolved struct {
	entry *ownerEntry
	res   lookupResult
}

func resolveConcurrently(p *peerForwarder, key string, n int, release func()) []resolved {
	out := make([]resolved, n)
	var wg sync.WaitGroup
	for i := range out {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i].entry, out[i].res = p.resolve(key)
		}()
	}
	time.Sleep(300 * time.Millisecond)
	release()
	wg.Wait()
	return out
}

func TestPeerResolveCoalescesConcurrentLookups(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	lookups := metricDelta(metricPeerLookups)
	capped := metricDelta(metricPeerRejectedLookupCap)
	p := a.srv.peers

	results := resolveConcurrently(p, peerTestHost, 64, holdFlight(p, peerTestHost))
	for i, r := range results {
		if r.res != lookupFound || r.entry == nil || len(r.entry.peers) != 1 || r.entry.peers[0].EdgeID != "edge-b" {
			t.Fatalf("resolve %d = %+v, %v; want edge-b", i, r.entry, r.res)
		}
	}
	if lookups() != 1 || capped() != 0 {
		t.Fatalf("lookups=%d capped=%d, want one database query and no cap rejections", lookups(), capped())
	}
}

func TestPeerResolveRefusesWhenEveryLookupSlotIsBusy(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	p := a.srv.peers
	for i := 0; i < maxPeerLookups; i++ {
		if !p.lookupSem.tryAcquire() {
			t.Fatalf("lookup slot %d not free", i)
		}
	}
	capped := metricDelta(metricPeerRejectedLookupCap)
	lookups := metricDelta(metricPeerLookups)

	if entry, res := p.resolve("ninth.example.com"); res != lookupRefused || entry != nil {
		t.Fatalf("resolve with every slot busy = %+v, %v; want a refusal", entry, res)
	}
	if capped() != 1 {
		t.Fatalf("capped = %d, want 1", capped())
	}

	results := resolveConcurrently(p, peerTestHost, 16, holdFlight(p, peerTestHost))
	for i, r := range results {
		if r.res != lookupRefused {
			t.Fatalf("waiter %d = %+v, %v; want every waiter of the flight refused", i, r.entry, r.res)
		}
	}
	if capped() != 2 || lookups() != 0 {
		t.Fatalf("capped=%d lookups=%d, want 2 (once per flight) and 0", capped(), lookups())
	}
	for i := 0; i < maxPeerLookups; i++ {
		p.lookupSem.release()
	}
	if _, res := p.resolve(peerTestHost); res != lookupFound {
		t.Fatalf("resolve after the slots were freed = %v", res)
	}
}

func TestPeerForwardReachesSecondOwnerWhenFirstIsDown(t *testing.T) {
	pc := newPeerCluster(t)
	a, b, c := pc.edge(t, "edge-a"), pc.edge(t, "edge-b"), pc.edge(t, "edge-c")
	registerPeers(t, a, b, c)
	b.bindTLSMulti(t, peerTestHost)
	c.bindTLSMulti(t, peerTestHost)
	b.srv.peers.ln.Close()
	lookups := metricDelta(metricPeerLookups)
	failed := metricDelta(metricPeerForwardFailed)

	tc, err := dialIngress(t, a, peerTestHost, pc.pool)
	if err != nil {
		t.Fatalf("handshake with the first owner down: %v", err)
	}
	pingEcho(t, tc)
	if c.agentHit.Load() != 1 || b.agentHit.Load() != 0 || lookups() != 1 || failed() != 0 {
		t.Fatalf("edge-c hits=%d edge-b hits=%d lookups=%d failed=%d, want 1, 0, 1, 0", c.agentHit.Load(), b.agentHit.Load(), lookups(), failed())
	}

	redials := countDials(t, b.peerAddr())
	second, err := dialIngress(t, a, peerTestHost, pc.pool)
	if err != nil {
		t.Fatalf("second handshake: %v", err)
	}
	pingEcho(t, second)
	if redials.Load() != 0 || c.agentHit.Load() != 2 || lookups() != 1 {
		t.Fatalf("dials to the down owner=%d edge-c hits=%d lookups=%d, want 0, 2, 1", redials.Load(), c.agentHit.Load(), lookups())
	}
}

func TestPeerForwardDoesNotRequeryWhenOwnerIsDown(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	b.srv.peers.ln.Close()
	lookups := metricDelta(metricPeerLookups)
	failed := metricDelta(metricPeerForwardFailed)

	if _, err := dialIngress(t, a, peerTestHost, pc.pool); err == nil {
		t.Fatal("handshake succeeded with the only owner down")
	}
	peerEventually(t, "forward failure to be counted", func() bool { return failed() == 1 })
	if lookups() != 2 {
		t.Fatalf("lookups = %d, want 2 (the lookup, and one re-resolve because the entry predates the failure)", lookups())
	}

	redials := countDials(t, b.peerAddr())
	const connections = 20
	for i := 0; i < connections; i++ {
		if _, err := dialIngress(t, a, peerTestHost, pc.pool); err == nil {
			t.Fatal("handshake succeeded with the only owner down")
		}
	}
	peerEventually(t, "every forward failure to be counted", func() bool { return failed() == 1+connections })
	if redials.Load() != 0 || lookups() != 2 {
		t.Fatalf("dials inside the down window=%d lookups=%d, want 0 and 2", redials.Load(), lookups())
	}
}

func TestPeerForwardNeverMakesAThirdAttempt(t *testing.T) {
	pc := newPeerCluster(t)
	a, b, c, d := pc.edge(t, "edge-a"), pc.edge(t, "edge-b"), pc.edge(t, "edge-c"), pc.edge(t, "edge-d")
	registerPeers(t, a, b, c, d)
	for _, e := range []*peerEdge{b, c, d} {
		e.srv.peers.ln.Close()
	}
	a.srv.peers.owners.Add(peerTestHost, &ownerEntry{peers: []storage.EdgePeer{b.record(), c.record(), d.record()}, resolved: time.Now()})
	lookups := metricDelta(metricPeerLookups)
	failed := metricDelta(metricPeerForwardFailed)

	if _, err := dialIngress(t, a, peerTestHost, pc.pool); err == nil {
		t.Fatal("handshake succeeded with every owner down")
	}
	peerEventually(t, "forward failure to be counted", func() bool { return failed() == 1 })
	addrs := map[string]string{"edge-b": b.peerAddr(), "edge-c": c.peerAddr(), "edge-d": d.peerAddr()}
	for id, want := range map[string]bool{"edge-b": true, "edge-c": true, "edge-d": false} {
		if _, down := a.srv.peers.down.Get(addrs[id]); down != want {
			t.Fatalf("%s marked down = %v, want %v", id, down, want)
		}
	}
	if lookups() != 0 {
		t.Fatalf("lookups = %d, want 0", lookups())
	}
}

func TestPeerKnownPin(t *testing.T) {
	pc := newPeerCluster(t)
	b := pc.edge(t, "edge-b")
	p := b.srv.peers
	pin := strings.Repeat("cd", 32)

	t.Run("nil", func(t *testing.T) {
		p.pins.Store(nil)
		if p.knownPin(pin) {
			t.Fatal("a nil pin set accepted a pin")
		}
	})
	t.Run("empty", func(t *testing.T) {
		p.pins.Store(&map[string]time.Time{})
		if p.knownPin(pin) {
			t.Fatal("an empty pin set accepted a pin")
		}
	})
	t.Run("expired", func(t *testing.T) {
		p.pins.Store(&map[string]time.Time{pin: time.Now().Add(-time.Second)})
		if p.knownPin(pin) {
			t.Fatal("a pin past its expiry was accepted")
		}
	})
	t.Run("live", func(t *testing.T) {
		p.pins.Store(&map[string]time.Time{pin: time.Now().Add(time.Hour)})
		if !p.knownPin(pin) || p.knownPin(strings.Repeat("ef", 32)) {
			t.Fatal("a live pin must be accepted and an unlisted one rejected")
		}
	})
}

func TestPeerAcceptRejectsExpiredPinWhenRefreshCannotSucceed(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.store.Close()

	b.srv.peers.pins.Store(&map[string]time.Time{a.pin(): time.Now().Add(time.Hour)})
	if err := peerRejected(t, a.srv.peers.clientTLS(b.pin()), b.peerAddr()); err != nil {
		t.Fatalf("a pin inside its expiry was rejected: %v", err)
	}
	b.srv.peers.pins.Store(&map[string]time.Time{a.pin(): time.Now().Add(-time.Second)})
	b.srv.peers.lastRefresh.Store(0)
	if err := peerRejected(t, a.srv.peers.clientTLS(b.pin()), b.peerAddr()); err == nil {
		t.Fatal("a pin past its expiry was accepted while the pin refresh was failing")
	}
}

func TestPeerAcceptRejectsDeletedRowOnceCachedExpiryPasses(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	if err := a.store.DeleteEdgePeer(context.Background(), a.id); err != nil {
		t.Fatalf("delete row: %v", err)
	}
	if err := peerRejected(t, a.srv.peers.clientTLS(b.pin()), b.peerAddr()); err != nil {
		t.Fatalf("a deleted row was rejected before its cached expiry passed: %v", err)
	}
	b.srv.peers.pins.Store(&map[string]time.Time{a.pin(): time.Now().Add(-time.Second)})
	b.srv.peers.lastRefresh.Store(0)
	if err := peerRejected(t, a.srv.peers.clientTLS(b.pin()), b.peerAddr()); err == nil {
		t.Fatal("a deleted row was still accepted after its cached expiry passed")
	}
}

func serveRecovering(t *testing.T, p *peerForwarder) (net.Conn, <-chan any) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			c = nil
		}
		accepted <- c
	}()
	cli, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { cli.Close() })
	srv := <-accepted
	if srv == nil {
		t.Fatal("accept failed")
	}
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		p.serveConn(context.Background(), srv)
	}()
	return cli, done
}

func TestPeerAcceptClosesProxyHeaderWithoutClientAddress(t *testing.T) {
	v2Local := append(append([]byte{}, proxyProtoV2Signature...), 0x20, 0x00, 0x00, 0x00)
	for name, header := range map[string][]byte{
		"v1 unknown": []byte("PROXY UNKNOWN\r\n"),
		"v2 local":   v2Local,
	} {
		t.Run(name, func(t *testing.T) {
			pc := newPeerCluster(t)
			a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
			registerPeers(t, a, b)
			b.bindTLS(t, peerTestHost)
			accepted := metricDelta(metricPeerAcceptedConns)

			cli, done := serveRecovering(t, b.srv.peers)
			_ = cli.SetDeadline(time.Now().Add(5 * time.Second))
			tc := tls.Client(cli, a.srv.peers.clientTLS(b.pin()))
			if err := tc.Handshake(); err != nil {
				t.Fatalf("handshake: %v", err)
			}
			if _, err := tc.Write(append(append([]byte{peerFrameSNI}, header...), helloFor(t, peerTestHost)...)); err != nil {
				t.Fatalf("write: %v", err)
			}
			expectClosed(t, tc)
			select {
			case v := <-done:
				if v != nil {
					t.Fatalf("serveConn panicked: %v", v)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("serveConn did not return")
			}
			if accepted() != 0 || b.agentHit.Load() != 0 {
				t.Fatalf("accepted=%d agentHit=%d, want both zero", accepted(), b.agentHit.Load())
			}
		})
	}
}

func expectNotDelivered(t *testing.T, ln *sniListener) {
	t.Helper()
	got := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			got <- c
		}
	}()
	select {
	case c := <-got:
		c.Close()
		t.Fatal("a connection was delivered to the local path")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestPeerForwardClosesWhenLookupFails(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	a.store.Close()
	lookupErrors := metricDelta(metricPeerLookupErrors)

	c := sendRawHello(t, a.addr, helloFor(t, peerTestHost))
	expectClosed(t, c)
	expectNotDelivered(t, a.sni)
	if lookupErrors() != 1 {
		t.Fatalf("lookup errors = %d, want 1", lookupErrors())
	}
	if _, miss := a.srv.peers.misses.Get(peerTestHost); miss {
		t.Fatal("a failed lookup was cached as a miss")
	}
}

func TestPeerForwardKeepsPassingBytesPastTheStatusTimeout(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)

	tc, err := dialIngress(t, a, peerTestHost, pc.pool)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	pingEcho(t, tc)
	time.Sleep(peerStatusTimeout + time.Second)
	pingEcho(t, tc)
}

func TestPeerForwardRateLimitsBeforeLookup(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	a.srv.perIPLimiter = newPerIPLimiter(0, 0, 16)
	lookups := metricDelta(metricPeerLookups)
	limited := metricDelta(metricRejectedRateLimited)

	c := sendRawHello(t, a.addr, helloFor(t, peerTestHost))
	expectClosed(t, c)
	if lookups() != 0 || limited() != 1 {
		t.Fatalf("lookups=%d rate-limited=%d, want 0 and 1", lookups(), limited())
	}
}

func TestPeerForwardRateLimitsCachedOwner(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	a.srv.peers.owners.Add(peerTestHost, &ownerEntry{peers: []storage.EdgePeer{b.record()}, resolved: time.Now()})
	a.srv.perIPLimiter = newPerIPLimiter(0, 1, 16)
	limited := metricDelta(metricRejectedRateLimited)

	tc, err := dialIngress(t, a, peerTestHost, pc.pool)
	if err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	pingEcho(t, tc)
	c := sendRawHello(t, a.addr, helloFor(t, peerTestHost))
	expectClosed(t, c)
	if b.accepts.Load() != 1 || limited() != 1 {
		t.Fatalf("dials=%d rate-limited=%d, want 1 and 1", b.accepts.Load(), limited())
	}
}

func TestPeerAcceptRequiresTLS13(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	cfg := a.srv.peers.clientTLS(b.pin())
	cfg.MinVersion = tls.VersionTLS12
	cfg.MaxVersion = tls.VersionTLS12

	if err := peerRejected(t, cfg, b.peerAddr()); err == nil {
		t.Fatal("a TLS 1.2 client with a registered key was accepted")
	}
}

func TestPeerForwardAfterStopClosesInsteadOfSplicing(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	a.srv.peers.stop()
	forwarded := metricDelta(metricPeerForwardedConns)

	c := sendRawHello(t, a.addr, helloFor(t, peerTestHost))
	expectClosed(t, c)
	if forwarded() != 0 {
		t.Fatalf("forwarded = %d after stop, want 0", forwarded())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	a.srv.peers.waitSplices(ctx)
	if ctx.Err() != nil {
		t.Fatal("waitSplices did not return after stop")
	}
}

func dialPingOnce(addr, host string, pool *x509.CertPool) error {
	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	tc := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: pool})
	if err := tc.Handshake(); err != nil {
		return err
	}
	if _, err := tc.Write([]byte("ping")); err != nil {
		return err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(tc, buf); err != nil {
		return err
	}
	if string(buf) != "ping" {
		return fmt.Errorf("echo = %q", buf)
	}
	return nil
}

func pingConcurrently(addr, host string, pool *x509.CertPool, n int) []error {
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = dialPingOnce(addr, host, pool)
		}()
	}
	close(start)
	wg.Wait()
	return errs
}

func serveLocalHTTP(t *testing.T, e *peerEdge, cert tls.Certificate) {
	t.Helper()
	srv := &http.Server{Handler: http.HandlerFunc(e.srv.handlePublic), ConnContext: peerConnContext}
	ln := tls.NewListener(e.sni, &tls.Config{Certificates: []tls.Certificate{cert}})
	done := make(chan struct{})
	go func() {
		srv.Serve(ln)
		close(done)
	}()
	t.Cleanup(func() {
		srv.Close()
		<-done
	})
}

func getLocalStatus(t *testing.T, e *peerEdge, host string, pool *x509.CertPool) int {
	t.Helper()
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{RootCAs: pool},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, e.addr)
			},
		},
	}
	resp, err := client.Get("https://" + host + "/")
	if err != nil {
		t.Fatalf("GET %s: %v", host, err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func TestPeerForwardCoalescesStaleOwnerLookups(t *testing.T) {
	pc := newPeerCluster(t)
	a, b, c := pc.edge(t, "edge-a"), pc.edge(t, "edge-b"), pc.edge(t, "edge-c")
	registerPeers(t, a, b, c)
	b.bindTLS(t, peerTestHost)
	a.srv.perIP = nil
	b.srv.perIP = nil
	a.srv.peers.owners.Add(peerTestHost, &ownerEntry{peers: []storage.EdgePeer{c.record()}, resolved: time.Now()})
	lookups := metricDelta(metricPeerLookups)
	capped := metricDelta(metricPeerRejectedLookupCap)

	const clients = 40
	for i, err := range pingConcurrently(a.addr, peerTestHost, pc.pool, clients) {
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
	}
	if b.agentHit.Load() != clients {
		t.Fatalf("agent hits on edge-b = %d, want %d", b.agentHit.Load(), clients)
	}
	if lookups() != 1 || capped() != 0 {
		t.Fatalf("lookups=%d capped=%d, want exactly 1 lookup (every waiter of the flight shares one cached entry, and a flight re-checks the cache before it queries) and no cap rejections", lookups(), capped())
	}
}

func TestPeerForwardSiblingWaitersShareOneEntry(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	p := a.srv.peers
	lookups := metricDelta(metricPeerLookups)

	results := resolveConcurrently(p, peerTestHost, 2, holdFlight(p, peerTestHost))
	for i, r := range results {
		if r.res != lookupFound || r.entry == nil {
			t.Fatalf("resolve %d = %+v, %v; want a found entry", i, r.entry, r.res)
		}
	}
	if results[0].entry != results[1].entry {
		t.Fatal("two waiters of one lookup received different entries")
	}
	if cached, ok := p.owners.Peek(peerTestHost); !ok || cached != results[0].entry {
		t.Fatalf("cached entry = %p, %v; want the entry both waiters received", cached, ok)
	}
	if lookups() != 1 {
		t.Fatalf("lookups = %d, want 1", lookups())
	}

	p.owners.Remove(peerTestHost)
	v, err, _ := p.lookups.Do(peerTestHost, func() (any, error) { return p.lookupOnce(peerTestHost) })
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if cached, ok := p.owners.Peek(peerTestHost); !ok || cached != v {
		t.Fatalf("cached entry = %p, %v; the flight must cache the entry it returns", cached, ok)
	}
}

func TestPeerForwardFindsNewOwnerAfterOwnerStopped(t *testing.T) {
	pc := newPeerCluster(t)
	a, b, c := pc.edge(t, "edge-a"), pc.edge(t, "edge-b"), pc.edge(t, "edge-c")
	registerPeers(t, a, b, c)
	b.bindTLS(t, peerTestHost)

	first, err := dialIngress(t, a, peerTestHost, pc.pool)
	if err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	pingEcho(t, first)
	first.Close()
	cached, ok := a.srv.peers.owners.Get(peerTestHost)
	if !ok {
		t.Fatal("owner entry was not cached")
	}

	b.srv.registry.Unbind(peerTestHost, b.fx.as)
	b.srv.peers.stop()
	if err := b.store.ReleaseSession(context.Background(), "edge-b", "sess-edge-b-"+peerTestHost); err != nil {
		t.Fatalf("release lease: %v", err)
	}
	c.bindTLS(t, peerTestHost)
	a.srv.peers.owners.Add(peerTestHost, &ownerEntry{peers: cached.peers, resolved: time.Now().Add(-peerDownCacheTTL - time.Second)})
	lookups := metricDelta(metricPeerLookups)

	second, err := dialIngress(t, a, peerTestHost, pc.pool)
	if err != nil {
		t.Fatalf("handshake after the owner stopped: %v", err)
	}
	pingEcho(t, second)
	if lookups() != 1 || c.agentHit.Load() != 1 {
		t.Fatalf("lookups=%d edge-c hits=%d, want 1 and 1", lookups(), c.agentHit.Load())
	}
}

func TestPeerForwardRecoversWithFreshEntryAfterOwnerStopped(t *testing.T) {
	pc := newPeerCluster(t)
	a, b, c := pc.edge(t, "edge-a"), pc.edge(t, "edge-b"), pc.edge(t, "edge-c")
	registerPeers(t, a, b, c)
	b.bindTLS(t, peerTestHost)

	first, err := dialIngress(t, a, peerTestHost, pc.pool)
	if err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	pingEcho(t, first)
	first.Close()
	cached, ok := a.srv.peers.owners.Get(peerTestHost)
	if !ok || time.Since(cached.resolved) > peerDownCacheTTL {
		t.Fatal("expected a fresh cached owner entry")
	}

	b.srv.registry.Unbind(peerTestHost, b.fx.as)
	b.srv.peers.stop()
	if err := b.store.ReleaseSession(context.Background(), "edge-b", "sess-edge-b-"+peerTestHost); err != nil {
		t.Fatalf("release lease: %v", err)
	}
	c.bindTLS(t, peerTestHost)
	lookups := metricDelta(metricPeerLookups)

	second, err := dialIngress(t, a, peerTestHost, pc.pool)
	if err != nil {
		t.Fatalf("handshake after the owner stopped: %v", err)
	}
	pingEcho(t, second)
	second.Close()
	if lookups() != 1 || c.agentHit.Load() != 1 {
		t.Fatalf("lookups=%d edge-c hits=%d, want 1 and 1", lookups(), c.agentHit.Load())
	}

	third, err := dialIngress(t, a, peerTestHost, pc.pool)
	if err != nil {
		t.Fatalf("third handshake: %v", err)
	}
	pingEcho(t, third)
	if lookups() != 1 || c.agentHit.Load() != 2 {
		t.Fatalf("lookups=%d edge-c hits=%d, want the cached owner to be used with no query (1 and 2)", lookups(), c.agentHit.Load())
	}
}

func TestPeerForwardDialsReRegisteredEdgeAtNewAddress(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	oldAddr := ln.Addr().String()
	ln.Close()
	oldRecord := storage.EdgePeer{EdgeID: "edge-b", PeerAddr: oldAddr, SPKISHA256: b.pin()}
	p := a.srv.peers
	p.owners.Add(peerTestHost, &ownerEntry{peers: []storage.EdgePeer{oldRecord}, resolved: time.Now()})
	lookups := metricDelta(metricPeerLookups)

	tc, err := dialIngress(t, a, peerTestHost, pc.pool)
	if err != nil {
		t.Fatalf("handshake after the edge re-registered at a new address: %v", err)
	}
	pingEcho(t, tc)
	if _, down := p.down.Get(oldAddr); !down {
		t.Fatal("the address that failed to dial was not marked down")
	}
	if lookups() != 1 || b.agentHit.Load() != 1 {
		t.Fatalf("lookups=%d edge-b hits=%d, want 1 and 1", lookups(), b.agentHit.Load())
	}
}

func TestPeerLateDialFailuresDoNotRenewDownMark(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	b.srv.peers.ln.Close()
	p := a.srv.peers
	frame := peerFrame{kind: peerFrameSNI, src: netip.MustParseAddrPort("203.0.113.9:4000")}
	stale := &ownerEntry{peers: []storage.EdgePeer{b.record()}, resolved: time.Now().Add(-peerDownCacheTTL - time.Second)}
	lookups := metricDelta(metricPeerLookups)

	if upstream, noOwner := p.connect(peerTestHost, stale, frame); upstream != nil || noOwner {
		t.Fatalf("connect to an unreachable owner = %v, noOwner=%v; want a failure", upstream, noOwner)
	}
	if lookups() != 1 {
		t.Fatalf("lookups after the first failure = %d, want the one re-resolve", lookups())
	}
	marked, ok := p.down.Peek(b.peerAddr())
	if !ok {
		t.Fatal("the unreachable address was not marked down")
	}
	fresh, ok := p.owners.Peek(peerTestHost)
	if !ok || !fresh.resolved.After(marked) {
		t.Fatalf("re-resolved entry = %+v, %v; want one resolved after the down mark", fresh, ok)
	}
	time.Sleep(5 * time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if upstream, outcome := p.attempt(b.record(), frame); upstream != nil || outcome != peerDown {
				t.Errorf("late attempt = %v, %d; want nil, %d", upstream, outcome, peerDown)
			}
		}()
	}
	wg.Wait()

	if upstream, noOwner := p.connect(peerTestHost, fresh, frame); upstream != nil || noOwner {
		t.Fatalf("connect after the late failures = %v, noOwner=%v; want a failure", upstream, noOwner)
	}
	if lookups() != 1 {
		t.Fatalf("lookups = %d, want 1: late failures must not make the fresh entry look older than the down mark", lookups())
	}
	if again, _ := p.down.Peek(b.peerAddr()); !again.Equal(marked) {
		t.Fatalf("down mark moved from %v to %v, want the first mark kept", marked, again)
	}
}

func TestPeerForwardCapsRejectWithoutDialing(t *testing.T) {
	t.Run("forward slots exhausted", func(t *testing.T) {
		pc := newPeerCluster(t)
		a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
		registerPeers(t, a, b)
		b.bindTLS(t, peerTestHost)
		p := a.srv.peers
		p.owners.Add(peerTestHost, &ownerEntry{peers: []storage.EdgePeer{b.record()}, resolved: time.Now()})
		for i := 0; i < maxPeerForwards; i++ {
			if !p.forwardSem.tryAcquire() {
				t.Fatalf("forward slot %d not free", i)
			}
		}
		rejected := metricDelta(metricPeerRejectedForwardCap)
		tlsRejected := metricDelta(metricTLSRejectedGlobalCap)

		c := sendRawHello(t, a.addr, helloFor(t, peerTestHost))
		expectClosed(t, c)
		if rejected() != 1 || tlsRejected() != 0 || b.accepts.Load() != 0 {
			t.Fatalf("forward cap rejections=%d tls global cap rejections=%d dials=%d, want 1, 0 and 0", rejected(), tlsRejected(), b.accepts.Load())
		}
		for i := 0; i < maxPeerForwards; i++ {
			p.forwardSem.release()
		}
	})
	t.Run("client address slots exhausted", func(t *testing.T) {
		pc := newPeerCluster(t)
		a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
		registerPeers(t, a, b)
		b.bindTLS(t, peerTestHost)
		p := a.srv.peers
		p.owners.Add(peerTestHost, &ownerEntry{peers: []storage.EdgePeer{b.record()}, resolved: time.Now()})
		a.srv.perIP = newPerIPInflight(1)
		release, ok := a.srv.perIP.acquire("127.0.0.1")
		if !ok {
			t.Fatal("could not take the client address slot")
		}
		defer release()
		rejected := metricDelta(metricRejectedPerIPCap)

		c := sendRawHello(t, a.addr, helloFor(t, peerTestHost))
		expectClosed(t, c)
		if rejected() != 1 || b.accepts.Load() != 0 {
			t.Fatalf("per-address rejections=%d dials=%d, want 1 and 0", rejected(), b.accepts.Load())
		}
		for i := 0; i < maxPeerForwards; i++ {
			if !p.forwardSem.tryAcquire() {
				t.Fatalf("forward slot %d leaked after the per-address rejection", i)
			}
		}
		for i := 0; i < maxPeerForwards; i++ {
			p.forwardSem.release()
		}
	})
}

func TestPeerForwardStaleWithNoLiveOwnerServesLocally(t *testing.T) {
	pc := newPeerCluster(t)
	a, b, c := pc.edge(t, "edge-a"), pc.edge(t, "edge-b"), pc.edge(t, "edge-c")
	registerPeers(t, a, b, c)
	serveLocalHTTP(t, a, pc.cert)
	a.srv.peers.owners.Add(peerTestHost, &ownerEntry{peers: []storage.EdgePeer{c.record()}, resolved: time.Now()})
	lookups := metricDelta(metricPeerLookups)
	failed := metricDelta(metricPeerForwardFailed)

	if got := getLocalStatus(t, a, peerTestHost, pc.pool); got != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 from the local terminating path", got)
	}
	if lookups() != 1 || failed() != 0 || c.accepts.Load() != 1 {
		t.Fatalf("lookups=%d failed=%d dials to the stale owner=%d, want 1, 0, 1", lookups(), failed(), c.accepts.Load())
	}
	if _, miss := a.srv.peers.misses.Get(peerTestHost); !miss {
		t.Fatal("the hostname did not enter the miss cache")
	}
	if _, cached := a.srv.peers.owners.Get(peerTestHost); cached {
		t.Fatal("the stale owner entry was kept")
	}
}

func TestPeerAcceptForwardedWithoutSNIWritesNotOwner(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)

	tc, err := dialPeerTLS(t, a.srv.peers.clientTLS(b.pin()), b.peerAddr())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	sendForwarded(t, tc, "203.0.113.9:4000", captureClientHello(t, &tls.Config{InsecureSkipVerify: true}))
	mustPeerStatus(t, tc, peerStatusNotOwner)
	expectClosed(t, tc)
	if b.agentHit.Load() != 0 {
		t.Fatal("a forwarded connection without SNI reached the agent")
	}
}

func TestSpliceGraceEndsHalfOpenConnection(t *testing.T) {
	run := func(t *testing.T, grace time.Duration) (finished func() bool, closeAll func()) {
		t.Helper()
		clientFar, clientNear := realConnPair(t)
		upstreamNear, upstreamFar := realConnPair(t)
		done := make(chan struct{})
		go func() {
			splice(clientNear, upstreamNear, time.Minute, grace)
			close(done)
		}()
		upstreamFar.Close()
		_ = clientFar.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := clientFar.Read(make([]byte, 1)); n != 0 || err != io.EOF {
			t.Fatalf("client read = %d, %v; want EOF after the upstream closed", n, err)
		}
		closeAll = func() {
			clientFar.Close()
			clientNear.Close()
			upstreamNear.Close()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("splice did not return after every connection was closed")
			}
		}
		finished = func() bool {
			select {
			case <-done:
				return true
			case <-time.After(time.Second):
				return false
			}
		}
		return finished, closeAll
	}

	t.Run("grace ends the copy", func(t *testing.T) {
		finished, closeAll := run(t, 200*time.Millisecond)
		defer closeAll()
		if !finished() {
			t.Fatal("splice with a 200ms grace was still running after one second")
		}
	})
	t.Run("no grace keeps it open", func(t *testing.T) {
		finished, closeAll := run(t, 0)
		defer closeAll()
		if finished() {
			t.Fatal("splice without a grace returned while the client stayed open")
		}
	})
}

func TestSpliceGraceCapHoldsAgainstClientTraffic(t *testing.T) {
	clientFar, clientNear := realConnPair(t)
	upstreamNear, upstreamFar := realConnPair(t)
	done := make(chan struct{})
	go func() {
		splice(clientNear, upstreamNear, 400*time.Millisecond, 300*time.Millisecond)
		close(done)
	}()
	stop := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if _, err := clientFar.Write([]byte{1}); err != nil {
					return
				}
			}
		}
	}()
	defer func() {
		close(stop)
		clientFar.Close()
		clientNear.Close()
		upstreamNear.Close()
		upstreamFar.Close()
		<-writerDone
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("splice did not return after every connection was closed")
		}
	}()

	upstreamFar.(*net.TCPConn).CloseWrite()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("splice with a 300ms grace was still running after one second of client traffic")
	}
}

func TestValidatePeerListen(t *testing.T) {
	cases := []struct {
		name   string
		addr   string
		listen string
		want   string
	}{
		{"listen without peer address", "", ":7443", "requires a peer address"},
		{"hostname", "127.0.0.1:7443", "localhost:7443", "peer listen address"},
		{"no port", "127.0.0.1:7443", "127.0.0.1", "peer listen address"},
		{"port zero", "127.0.0.1:7443", ":0", "peer listen address"},
		{"port too large", "127.0.0.1:7443", ":65536", "peer listen address"},
		{"port not numeric", "127.0.0.1:7443", ":http", "peer listen address"},
		{"port only", "127.0.0.1:7443", ":7443", ""},
		{"unspecified v4", "127.0.0.1:7443", "0.0.0.0:7443", ""},
		{"unspecified v6", "127.0.0.1:7443", "[::]:7443", ""},
		{"loopback", "127.0.0.1:7443", "127.0.0.1:7443", ""},
		{"unspecified peer address", "0.0.0.0:7443", ":7443", "specific address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePeerAddr(Config{PeerAddr: tc.addr, PeerListen: tc.listen}, true)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("validatePeerAddr = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validatePeerAddr = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestPeerListenAdvertisesPeerAddr(t *testing.T) {
	store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db"), EdgeID: "edge-a"})
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	cert, _ := passthroughTestCert(t, peerTestHost)
	advertised := freeTCPAddr(t)
	listen := freeTCPAddr(t)
	s, err := New(Config{
		ControlAddr:     freeTCPAddr(t),
		PublicAddr:      freeTCPAddr(t),
		Domain:          "example.com",
		TokenSHA256:     sumToken("tok"),
		PublicScheme:    "https",
		Storage:         store,
		PeerAddr:        advertised,
		PeerListen:      listen,
		PublicTLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	runServer(t, s)

	c, err := net.DialTimeout("tcp", listen, 2*time.Second)
	if err != nil {
		t.Fatalf("peer listener is not accepting on %s: %v", listen, err)
	}
	c.Close()
	if c, err := net.DialTimeout("tcp", advertised, time.Second); err == nil {
		c.Close()
		t.Fatalf("something listens on the advertised address %s", advertised)
	}
	peerEventually(t, "peer registration", func() bool {
		peers, err := store.LiveEdgePeers(context.Background(), time.Now())
		return err == nil && len(peers) == 1 && peers[0].PeerAddr == advertised
	})
}

type fakePeerOwner struct {
	addr string
	pin  string
	got  chan []byte
}

func newFakePeer1Owner(t *testing.T) *fakePeerOwner {
	t.Helper()
	id, err := newPeerIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakePeerOwner{addr: ln.Addr().String(), pin: id.pin, got: make(chan []byte, 4)}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{id.cert},
		ClientAuth:   tls.RequireAnyClientCert,
		NextProtos:   []string{peerALPN1},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				tc := tls.Server(c, cfg)
				if tc.Handshake() != nil {
					return
				}
				buf := make([]byte, 4096)
				n, _ := tc.Read(buf)
				if n == 0 {
					return
				}
				got := append([]byte{}, buf[:n]...)
				_ = tc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				for {
					n, err := tc.Read(buf)
					got = append(got, buf[:n]...)
					if err != nil {
						break
					}
				}
				f.got <- got
				_, _ = tc.Write([]byte{peerStatusAccept})
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
	})
	return f
}

func (f *fakePeerOwner) peer() storage.EdgePeer {
	return storage.EdgePeer{EdgeID: "fake-owner", PeerAddr: f.addr, SPKISHA256: f.pin}
}

func sendFrame(t *testing.T, c *tls.Conn, kind byte, port uint16, src string, payload []byte) {
	t.Helper()
	frame := peerFrame{kind: kind, port: port, src: netip.MustParseAddrPort(src), payload: payload}
	b, ok := frame.encode(peerALPN2)
	if !ok {
		t.Fatalf("frame kind %#x cannot be encoded", kind)
	}
	if _, err := c.Write(b); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

func TestPeerServerPrefersPeer2(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)

	tc, err := dialPeerTLS(t, a.srv.peers.clientTLS(b.pin()), b.peerAddr())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if got := tc.ConnectionState().NegotiatedProtocol; got != peerALPN2 {
		t.Fatalf("negotiated %q, want %q", got, peerALPN2)
	}
}

func TestPeerServerServesPeer1Client(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	cfg := a.srv.peers.clientTLS(b.pin())
	cfg.NextProtos = []string{peerALPN1}

	tc, err := dialPeerTLS(t, cfg, b.peerAddr())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if got := tc.ConnectionState().NegotiatedProtocol; got != peerALPN1 {
		t.Fatalf("negotiated %q, want %q", got, peerALPN1)
	}
	sendForwarded(t, tc, "203.0.113.9:4000", helloFor(t, peerTestHost))
	mustPeerStatus(t, tc, peerStatusAccept)
	peerEventually(t, "agent stream", func() bool { return b.lastPre.Load() != nil })
	pre := b.lastPre.Load()
	if pre.Kind != proto.KindTLS || pre.Host != peerTestHost || pre.ClientAddr != "203.0.113.9:4000" {
		t.Fatalf("agent preamble = %+v", *pre)
	}
}

func TestPeerClientNeverSendsTypedFrameToPeer1Owner(t *testing.T) {
	pc := newPeerCluster(t)
	a := pc.edge(t, "edge-a")
	owner := newFakePeer1Owner(t)
	hello := helloFor(t, peerTestHost)
	frame := peerFrame{kind: peerFrameSNI, src: netip.MustParseAddrPort("203.0.113.9:4000"), payload: hello}

	tc, outcome := a.srv.peers.attempt(owner.peer(), frame)
	if outcome != peerOK || tc == nil {
		t.Fatalf("attempt outcome = %d, want %d", outcome, peerOK)
	}
	tc.Close()
	select {
	case got := <-owner.got:
		if len(got) == 0 || got[0] != 'P' {
			t.Fatalf("first byte sent to a peer-1 owner = %#x, want 'P' of PROXY", got[:min(len(got), 1)])
		}
		if !strings.HasPrefix(string(got), "PROXY TCP4 203.0.113.9 203.0.113.9 4000 4000\r\n") || !strings.HasSuffix(string(got), string(hello)) {
			t.Fatalf("legacy bytes = %d bytes, want the PROXY line and the %d byte ClientHello", len(got), len(hello))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the peer-1 owner received nothing")
	}
}

func TestPeerFrameEncode(t *testing.T) {
	src := netip.MustParseAddrPort("203.0.113.9:4000")
	const line = "PROXY TCP4 203.0.113.9 203.0.113.9 4000 4000\r\n"
	cases := []struct {
		name   string
		frame  peerFrame
		alpn   string
		want   string
		wantOK bool
	}{
		{"sni peer-2", peerFrame{kind: peerFrameSNI, src: src, payload: []byte("HELLO")}, peerALPN2, "\x01" + line + "HELLO", true},
		{"sni peer-1", peerFrame{kind: peerFrameSNI, src: src, payload: []byte("HELLO")}, peerALPN1, line + "HELLO", true},
		{"tcp peer-2", peerFrame{kind: peerFrameTCP, port: 8080, src: src}, peerALPN2, "\x02\x1f\x90" + line, true},
		{"tcp peer-2 high port", peerFrame{kind: peerFrameTCP, port: 65535, src: src}, peerALPN2, "\x02\xff\xff" + line, true},
		{"control peer-2", peerFrame{kind: peerFrameControl, src: src, payload: []byte("abc")}, peerALPN2, "\x03" + line + "abc", true},
		{"tcp peer-1", peerFrame{kind: peerFrameTCP, port: 8080, src: src}, peerALPN1, "", false},
		{"control peer-1", peerFrame{kind: peerFrameControl, src: src, payload: []byte("abc")}, peerALPN1, "", false},
		{"unknown protocol", peerFrame{kind: peerFrameSNI, src: src}, "ngstone-peer-9", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.frame.encode(tc.alpn)
			if ok != tc.wantOK || string(got) != tc.want {
				t.Fatalf("encode = %q, %v; want %q, %v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestPeerServerRejectsUnknownFrameType(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	accepted := metricDelta(metricPeerAcceptedConns)

	tc, err := dialPeerTLS(t, a.srv.peers.clientTLS(b.pin()), b.peerAddr())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	sendFrame(t, tc, 0x7f, 0, "203.0.113.9:4000", helloFor(t, peerTestHost))
	expectClosed(t, tc)
	time.Sleep(100 * time.Millisecond)
	if accepted() != 0 || b.agentHit.Load() != 0 {
		t.Fatalf("accepted=%d agentHit=%d, want both zero", accepted(), b.agentHit.Load())
	}
}

func TestPeerServerDispatchesOnNegotiatedALPN(t *testing.T) {
	cases := []struct {
		name  string
		alpns []string
		send  func(t *testing.T) []byte
	}{
		{
			name:  "peer-2 negotiated, legacy bytes sent",
			alpns: []string{peerALPN2},
			send: func(t *testing.T) []byte {
				frame := peerFrame{kind: peerFrameSNI, src: netip.MustParseAddrPort("203.0.113.9:4000"), payload: helloFor(t, peerTestHost)}
				b, ok := frame.encode(peerALPN1)
				if !ok {
					t.Fatal("legacy frame cannot be encoded")
				}
				return b
			},
		},
		{
			name:  "peer-1 negotiated, typed frame sent",
			alpns: []string{peerALPN1},
			send: func(t *testing.T) []byte {
				frame := peerFrame{kind: peerFrameSNI, src: netip.MustParseAddrPort("203.0.113.9:4000"), payload: helloFor(t, peerTestHost)}
				b, ok := frame.encode(peerALPN2)
				if !ok {
					t.Fatal("typed frame cannot be encoded")
				}
				return b
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc := newPeerCluster(t)
			a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
			registerPeers(t, a, b)
			b.bindTLS(t, peerTestHost)
			accepted := metricDelta(metricPeerAcceptedConns)
			cfg := a.srv.peers.clientTLS(b.pin())
			cfg.NextProtos = tc.alpns

			conn, err := dialPeerTLS(t, cfg, b.peerAddr())
			if err != nil {
				t.Fatalf("handshake: %v", err)
			}
			if got := conn.ConnectionState().NegotiatedProtocol; got != tc.alpns[0] {
				t.Fatalf("negotiated %q, want %q", got, tc.alpns[0])
			}
			if _, err := conn.Write(tc.send(t)); err != nil {
				t.Fatalf("write: %v", err)
			}
			expectClosed(t, conn)
			time.Sleep(100 * time.Millisecond)
			if accepted() != 0 || b.agentHit.Load() != 0 {
				t.Fatalf("accepted=%d agentHit=%d, want both zero", accepted(), b.agentHit.Load())
			}
		})
	}
}

func TestPeerServerRefusesTCPWithoutManagerAndControlWhileDraining(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	accepted := metricDelta(metricPeerAcceptedConns)

	cases := []struct {
		name    string
		kind    byte
		port    uint16
		payload []byte
	}{
		{"tcp", peerFrameTCP, 8080, nil},
		{"control", peerFrameControl, 0, []byte("GET / HTTP/1.1\r\n\r\n")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.kind == peerFrameControl {
				b.srv.controlMu.Lock()
				b.srv.controlDraining = true
				b.srv.controlMu.Unlock()
			}
			conn, err := dialPeerTLS(t, a.srv.peers.clientTLS(b.pin()), b.peerAddr())
			if err != nil {
				t.Fatalf("handshake: %v", err)
			}
			sendFrame(t, conn, tc.kind, tc.port, "203.0.113.9:4000", tc.payload)
			mustPeerStatus(t, conn, peerStatusNotOwner)
			expectClosed(t, conn)
		})
	}
	time.Sleep(100 * time.Millisecond)
	if accepted() != 0 || b.agentHit.Load() != 0 {
		t.Fatalf("accepted=%d agentHit=%d, want both zero", accepted(), b.agentHit.Load())
	}
}

func TestPeerServerRejectsUnknownALPN(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)

	cfg := a.srv.peers.clientTLS(b.pin())
	cfg.VerifyConnection = nil
	cfg.NextProtos = []string{"ngstone-peer-9"}
	if err := peerRejected(t, cfg, b.peerAddr()); err == nil {
		t.Fatal("a client offering only an unknown protocol was accepted")
	}

	state := tls.ConnectionState{NegotiatedProtocol: "ngstone-peer-9", PeerCertificates: []*x509.Certificate{a.srv.peers.id.cert.Leaf}}
	if err := b.srv.peers.serverTLS().VerifyConnection(state); !errors.Is(err, errPeerALPN) {
		t.Fatalf("server VerifyConnection = %v, want %v", err, errPeerALPN)
	}
	state.PeerCertificates = []*x509.Certificate{b.srv.peers.id.cert.Leaf}
	if err := a.srv.peers.clientTLS(b.pin()).VerifyConnection(state); !errors.Is(err, errPeerALPN) {
		t.Fatalf("client VerifyConnection = %v, want %v", err, errPeerALPN)
	}
}

func TestPeerSkewDoesNotMarkOwnerDown(t *testing.T) {
	pc := newPeerCluster(t)
	a := pc.edge(t, "edge-a")
	owner := newFakePeer1Owner(t)
	skew := metricDelta(metricPeerVersionSkew)
	frame := peerFrame{kind: peerFrameTCP, port: 8080, src: netip.MustParseAddrPort("203.0.113.9:4000")}

	tc, outcome := a.srv.peers.attempt(owner.peer(), frame)
	if tc != nil || outcome != peerSkew {
		t.Fatalf("attempt = %v, %d; want nil, %d", tc, outcome, peerSkew)
	}
	if _, down := a.srv.peers.down.Get(owner.peer().PeerAddr); down {
		t.Fatal("a version skew marked the owner down")
	}
	if skew() != 1 {
		t.Fatalf("skew counter moved by %d, want 1", skew())
	}
	select {
	case got := <-owner.got:
		t.Fatalf("the peer-1 owner received %q", got)
	case <-time.After(100 * time.Millisecond):
	}
}
