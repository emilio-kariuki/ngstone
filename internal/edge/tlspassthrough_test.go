package edge

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"golang.org/x/net/websocket"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

func passthroughTestCert(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: names[0]},
		DNSNames:              names,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func captureClientHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	clientSide, captureSide := net.Pipe()
	go func() {
		_ = tls.Client(clientSide, cfg).Handshake()
	}()
	defer captureSide.Close()
	defer clientSide.Close()
	_ = captureSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	header := make([]byte, 5)
	if _, err := io.ReadFull(captureSide, header); err != nil {
		t.Fatalf("read ClientHello record header: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint16(header[3:5]))
	if _, err := io.ReadFull(captureSide, body); err != nil {
		t.Fatalf("read ClientHello record body: %v", err)
	}
	return append(header, body...)
}

func fragmentClientHello(record []byte, sizes ...int) []byte {
	version := record[1:3]
	msg := record[5:]
	var out []byte
	for len(msg) > 0 {
		n := len(msg)
		if len(sizes) > 0 {
			n = min(sizes[0], len(msg))
			sizes = sizes[1:]
		}
		out = append(out, 0x16, version[0], version[1], byte(n>>8), byte(n))
		out = append(out, msg[:n]...)
		msg = msg[n:]
	}
	return out
}

func TestPeekClientHelloReadsSNIAndKeepsBytes(t *testing.T) {
	hello := captureClientHello(t, &tls.Config{ServerName: "Secure.Example.COM", InsecureSkipVerify: true})
	input := append(append([]byte{}, hello...), []byte("application-data")...)

	name, peeked, err := peekClientHello(bytes.NewReader(input), maxClientHelloBytes)
	if err != nil {
		t.Fatalf("peekClientHello: %v", err)
	}
	if name != "secure.example.com" {
		t.Fatalf("server name = %q, want secure.example.com", name)
	}
	if !bytes.HasPrefix(input, peeked) || len(peeked) < len(hello) {
		t.Fatalf("peeked %d bytes that are not a prefix of the input covering the ClientHello (%d bytes)", len(peeked), len(hello))
	}
}

func TestPeekClientHelloFragmentedAcrossRecordsAndReads(t *testing.T) {
	hello := captureClientHello(t, &tls.Config{ServerName: "frag.example.com", InsecureSkipVerify: true})
	fragmented := fragmentClientHello(hello, 7, 40, 100)
	if bytes.Equal(fragmented, hello) {
		t.Fatal("fragmenting did not change the record layout")
	}

	name, peeked, err := peekClientHello(iotest.OneByteReader(bytes.NewReader(fragmented)), maxClientHelloBytes)
	if err != nil {
		t.Fatalf("peekClientHello: %v", err)
	}
	if name != "frag.example.com" {
		t.Fatalf("server name = %q, want frag.example.com", name)
	}
	if !bytes.Equal(peeked, fragmented) {
		t.Fatalf("peeked %d bytes, want exactly the %d fragmented bytes", len(peeked), len(fragmented))
	}
}

func TestPeekClientHelloWithoutSNI(t *testing.T) {
	hello := captureClientHello(t, &tls.Config{InsecureSkipVerify: true})

	name, peeked, err := peekClientHello(bytes.NewReader(hello), maxClientHelloBytes)
	if err != nil {
		t.Fatalf("peekClientHello: %v", err)
	}
	if name != "" {
		t.Fatalf("server name = %q, want empty", name)
	}
	if !bytes.Equal(peeked, hello) {
		t.Fatal("peeked bytes differ from the ClientHello")
	}
}

func TestPeekClientHelloOversizedStopsAtLimit(t *testing.T) {
	declared := 20000
	msg := make([]byte, 4+declared)
	msg[0] = 0x01
	msg[1], msg[2], msg[3] = byte(declared>>16), byte(declared>>8), byte(declared)
	record := append([]byte{0x16, 0x03, 0x01, 0, 0}, msg...)
	input := fragmentClientHello(record, 16384, 16384)

	limit := 4096
	_, peeked, err := peekClientHello(bytes.NewReader(input), limit)
	if !errors.Is(err, errClientHelloTooLarge) {
		t.Fatalf("err = %v, want errClientHelloTooLarge", err)
	}
	if len(peeked) != limit {
		t.Fatalf("peeked %d bytes, want exactly the %d byte limit", len(peeked), limit)
	}
	if !bytes.HasPrefix(input, peeked) {
		t.Fatal("peeked bytes are not a prefix of the input")
	}
}

func TestPeekClientHelloNotTLS(t *testing.T) {
	input := []byte("GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
	_, peeked, err := peekClientHello(bytes.NewReader(input), maxClientHelloBytes)
	if !errors.Is(err, errNotClientHello) {
		t.Fatalf("err = %v, want errNotClientHello", err)
	}
	if !bytes.HasPrefix(input, peeked) || len(peeked) == 0 {
		t.Fatalf("peeked %q is not a non-empty prefix of the request", peeked)
	}
}

func TestPeekClientHelloTruncatedReportsReadError(t *testing.T) {
	hello := captureClientHello(t, &tls.Config{ServerName: "short.example.com", InsecureSkipVerify: true})
	_, _, err := peekClientHello(bytes.NewReader(hello[:len(hello)/2]), maxClientHelloBytes)
	if err == nil || errors.Is(err, errNotClientHello) || errors.Is(err, errClientHelloTooLarge) {
		t.Fatalf("err = %v, want the underlying read error", err)
	}
}

func TestReplayConnReplaysPeekedBytesFirst(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	rc := &replayConn{Conn: a, buf: []byte("peeked-")}
	go func() {
		b.Write([]byte("rest"))
		b.Close()
	}()
	got, err := io.ReadAll(rc)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "peeked-rest" {
		t.Fatalf("read %q, want peeked-rest", got)
	}
}

func TestTLSTunnelURL(t *testing.T) {
	cases := map[string]string{
		"":                "tls://app.example.com",
		":443":            "tls://app.example.com",
		"0.0.0.0:443":     "tls://app.example.com",
		"127.0.0.1:18443": "tls://app.example.com:18443",
	}
	for addr, want := range cases {
		if got := tlsTunnelURL("app.example.com", addr); got != want {
			t.Errorf("tlsTunnelURL(%q) = %q, want %q", addr, got, want)
		}
	}
}

type sniHarness struct {
	srv      *Server
	ln       *sniListener
	addr     string
	fx       *tcpFixture
	agentHit atomic.Int64
	lastPre  atomic.Pointer[proto.StreamOpen]
}

func newSNIHarness(t *testing.T, agentCert tls.Certificate, wrap func(net.Listener) net.Listener) *sniHarness {
	t.Helper()
	h := &sniHarness{srv: newTestServer("tok")}
	h.fx = newTCPFixture(t, func(conn net.Conn, pre proto.StreamOpen) {
		defer conn.Close()
		h.agentHit.Add(1)
		h.lastPre.Store(&pre)
		tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{agentCert}})
		if err := tc.Handshake(); err != nil {
			return
		}
		io.Copy(tc, tc)
	})
	t.Cleanup(h.fx.cleanup)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	inner := net.Listener(raw)
	if wrap != nil {
		inner = wrap(raw)
	}
	h.ln = h.srv.newSNIListener(inner)
	h.addr = raw.Addr().String()
	t.Cleanup(func() { h.ln.Close() })
	return h
}

func (h *sniHarness) bindTLS(t *testing.T, host string, ac *accessControl) {
	t.Helper()
	if _, _, err := h.srv.registry.BindWithOptions(BindOptions{Host: host, Session: h.fx.as, Access: ac, TLS: true}); err != nil {
		t.Fatalf("bind tls %s: %v", host, err)
	}
}

func dialTLSClient(t *testing.T, addr string, prefix []byte, cfg *tls.Config) (*tls.Conn, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { raw.Close() })
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	if len(prefix) > 0 {
		if _, err := raw.Write(prefix); err != nil {
			t.Fatalf("write prefix: %v", err)
		}
	}
	tc := tls.Client(raw, cfg)
	return tc, tc.Handshake()
}

func TestSNIListenerRoutesTLSBindingToAgentCertificate(t *testing.T) {
	agentCert, agentPool := passthroughTestCert(t, "secure.example.com")
	h := newSNIHarness(t, agentCert, nil)
	h.bindTLS(t, "secure.example.com", nil)

	tc, err := dialTLSClient(t, h.addr, nil, &tls.Config{ServerName: "secure.example.com", RootCAs: agentPool})
	if err != nil {
		t.Fatalf("client handshake through passthrough: %v", err)
	}
	peer := tc.ConnectionState().PeerCertificates
	if len(peer) == 0 || !bytes.Equal(peer[0].Raw, agentCert.Leaf.Raw) {
		t.Fatal("client did not see the agent's own certificate")
	}
	if _, err := tc.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(tc, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	pre := h.lastPre.Load()
	if pre == nil || pre.Kind != proto.KindTLS || pre.Host != "secure.example.com" {
		t.Fatalf("stream preamble = %+v, want kind tls for secure.example.com", pre)
	}
	if !strings.HasPrefix(pre.ClientAddr, "127.0.0.1:") {
		t.Fatalf("preamble client addr = %q, want the loopback client", pre.ClientAddr)
	}
}

func TestSNIListenerFallsThroughForOtherHostnames(t *testing.T) {
	agentCert, _ := passthroughTestCert(t, "secure.example.com")
	edgeCert, edgePool := passthroughTestCert(t, "*.example.com", "example.com")
	h := newSNIHarness(t, agentCert, nil)
	h.bindTLS(t, "secure.example.com", nil)

	accepted := make(chan error, 1)
	go func() {
		c, err := h.ln.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer c.Close()
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{edgeCert}})
		accepted <- tc.Handshake()
	}()

	tc, err := dialTLSClient(t, h.addr, nil, &tls.Config{ServerName: "app.example.com", RootCAs: edgePool})
	if err != nil {
		t.Fatalf("client handshake against the terminating path: %v", err)
	}
	if err := <-accepted; err != nil {
		t.Fatalf("terminating handshake: %v", err)
	}
	if peer := tc.ConnectionState().PeerCertificates; len(peer) == 0 || !bytes.Equal(peer[0].Raw, edgeCert.Leaf.Raw) {
		t.Fatal("client did not see the edge certificate on fallthrough")
	}
	if h.agentHit.Load() != 0 {
		t.Fatal("agent received a stream for a hostname that is not a tls binding")
	}
}

func TestSNIListenerFallsThroughForHTTPBindingAndPlainHTTP(t *testing.T) {
	agentCert, _ := passthroughTestCert(t, "secure.example.com")
	h := newSNIHarness(t, agentCert, nil)
	if _, _, err := h.srv.registry.BindWithOptions(BindOptions{Host: "web.example.com", Session: h.fx.as}); err != nil {
		t.Fatalf("bind http: %v", err)
	}

	request := "GET / HTTP/1.1\r\nHost: web.example.com\r\n\r\n"
	raw, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	if _, err := io.WriteString(raw, request); err != nil {
		t.Fatalf("write: %v", err)
	}

	c, err := h.ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(request))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read replayed request: %v", err)
	}
	if string(got) != request {
		t.Fatalf("replayed %q, want %q", got, request)
	}
	if h.agentHit.Load() != 0 {
		t.Fatal("plain HTTP must not open a tls stream")
	}
}

func TestSNIListenerAllowCIDRRejectsOutsideClient(t *testing.T) {
	agentCert, agentPool := passthroughTestCert(t, "secure.example.com")
	h := newSNIHarness(t, agentCert, nil)
	ac, err := buildAccessControl(proto.Bind{AllowCIDRs: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatalf("access control: %v", err)
	}
	h.bindTLS(t, "secure.example.com", ac)

	if _, err := dialTLSClient(t, h.addr, nil, &tls.Config{ServerName: "secure.example.com", RootCAs: agentPool}); err == nil {
		t.Fatal("handshake succeeded from a client outside allow_cidr")
	}
	if h.agentHit.Load() != 0 {
		t.Fatal("agent received a stream from a client outside allow_cidr")
	}
}

func TestSNIListenerUsesProxyProtocolSourceForAllowCIDR(t *testing.T) {
	agentCert, agentPool := passthroughTestCert(t, "secure.example.com")
	h := newSNIHarness(t, agentCert, func(ln net.Listener) net.Listener {
		return newProxyProtoListener(ln, time.Second, nil)
	})
	ac, err := buildAccessControl(proto.Bind{AllowCIDRs: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatalf("access control: %v", err)
	}
	h.bindTLS(t, "secure.example.com", ac)

	header := []byte("PROXY TCP4 10.1.2.3 10.0.0.1 40000 443\r\n")
	tc, err := dialTLSClient(t, h.addr, header, &tls.Config{ServerName: "secure.example.com", RootCAs: agentPool})
	if err != nil {
		t.Fatalf("handshake behind PROXY protocol: %v", err)
	}
	if peer := tc.ConnectionState().PeerCertificates; len(peer) == 0 || !bytes.Equal(peer[0].Raw, agentCert.Leaf.Raw) {
		t.Fatal("client did not see the agent certificate")
	}
	pre := h.lastPre.Load()
	if pre == nil || !strings.HasPrefix(pre.ClientAddr, "10.1.2.3:") {
		t.Fatalf("preamble client addr = %+v, want the PROXY protocol source", pre)
	}
}

func TestSNIListenerClosesWhenNoHealthyConnector(t *testing.T) {
	agentCert, agentPool := passthroughTestCert(t, "secure.example.com")
	h := newSNIHarness(t, agentCert, nil)
	h.bindTLS(t, "secure.example.com", nil)
	h.fx.as.streamSem = newGlobalSemaphore(1)
	if !h.fx.as.tryAcquireStream() {
		t.Fatal("could not take the only stream slot")
	}
	defer h.fx.as.releaseStream()

	if _, err := dialTLSClient(t, h.addr, nil, &tls.Config{ServerName: "secure.example.com", RootCAs: agentPool}); err == nil {
		t.Fatal("handshake succeeded with the session stream cap exhausted")
	}
	if h.agentHit.Load() != 0 {
		t.Fatal("agent received a stream beyond the session cap")
	}
}

func TestSNIListenerCloseUnblocksAccept(t *testing.T) {
	h := newSNIHarness(t, tls.Certificate{}, nil)
	done := make(chan error, 1)
	go func() {
		_, err := h.ln.Accept()
		done <- err
	}()
	h.ln.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("accept err = %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
}

func TestRegistryTLSBindingsAreSeparateFromHTTPRouting(t *testing.T) {
	r := NewRegistry()
	as, cleanup := newTestAgentSession(t, "inst-a")
	defer cleanup()

	if _, _, err := r.BindWithOptions(BindOptions{Host: "secure.example.com", Session: as, TLS: true}); err != nil {
		t.Fatalf("bind tls: %v", err)
	}
	if _, ok := r.Route("secure.example.com"); ok {
		t.Fatal("HTTP Route must not return a tls binding")
	}
	if _, ok := r.RouteTLS("SECURE.example.com"); !ok {
		t.Fatal("RouteTLS did not find the tls binding")
	}

	_, _, err := r.BindWithOptions(BindOptions{Host: "secure.example.com", Session: as})
	if !errors.Is(err, ErrKindConflict) {
		t.Fatalf("http bind over live tls binding err = %v, want ErrKindConflict", err)
	}
	if !errors.Is(err, ErrSubdomainTaken) {
		t.Fatal("ErrKindConflict must also read as ErrSubdomainTaken so random-name retries skip it")
	}

	if _, _, err := r.BindWithOptions(BindOptions{Host: "web.example.com", Session: as}); err != nil {
		t.Fatalf("bind http: %v", err)
	}
	if _, _, err := r.BindWithOptions(BindOptions{Host: "web.example.com", Session: as, TLS: true}); !errors.Is(err, ErrKindConflict) {
		t.Fatalf("tls bind over live http binding err = %v, want ErrKindConflict", err)
	}
	if _, ok := r.RouteTLS("web.example.com"); ok {
		t.Fatal("RouteTLS must not return an http binding")
	}

	if _, _, err := r.BindWithOptions(BindOptions{Host: "x.example.com", Session: as, TLS: true, HTTP2: true}); !errors.Is(err, ErrConnectorConfigMismatch) {
		t.Fatalf("tls bind with HTTP/2 err = %v, want ErrConnectorConfigMismatch", err)
	}

	info := r.dashboardSnapshot()
	tlsSeen := false
	for _, b := range info {
		if b.Hostname == "secure.example.com" {
			tlsSeen = b.TLS
		}
	}
	if !tlsSeen {
		t.Fatal("dashboard snapshot does not flag the tls binding")
	}
}

func TestRegistryTLSKindChangeAfterSessionDies(t *testing.T) {
	r := NewRegistry()
	old, oldCleanup := newTestAgentSession(t, "inst-old")
	if _, _, err := r.BindWithOptions(BindOptions{Host: "swap.example.com", Session: old}); err != nil {
		t.Fatalf("bind http: %v", err)
	}
	oldCleanup()
	select {
	case <-old.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("old session did not close")
	}

	fresh, freshCleanup := newTestAgentSession(t, "inst-new")
	defer freshCleanup()
	_, evicted, err := r.BindWithOptions(BindOptions{Host: "swap.example.com", Session: fresh, TLS: true})
	if err != nil {
		t.Fatalf("tls bind over dead http binding: %v", err)
	}
	if evicted != old {
		t.Fatal("dead http holder was not reported as evicted")
	}
	if _, ok := r.RouteTLS("swap.example.com"); !ok {
		t.Fatal("tls binding missing after replacing a dead http binding")
	}
}

func bindOverWire(t *testing.T, s *Server, as *AgentSession, client, server tunnel.Session, bind proto.Bind) proto.Msg {
	t.Helper()
	go func() {
		client.Control().Write(proto.TypeBind, 1, bind)
	}()
	msg, err := server.Control().Read()
	if err != nil {
		t.Fatalf("server read bind: %v", err)
	}
	decoded, err := proto.Decode[proto.Bind](msg)
	if err != nil {
		t.Fatalf("decode bind: %v", err)
	}
	s.handleBind(context.Background(), as, server.Control(), msg.ID, decoded)
	reply, err := client.Control().Read()
	if err != nil {
		t.Fatalf("read bind reply: %v", err)
	}
	return reply
}

func TestHandleBindTLSOverControlPlane(t *testing.T) {
	client, server, cleanup := newRawSessionPair(t)
	defer cleanup()
	s := newTestServer("tok")
	s.cfg.PublicAddr = ":443"
	as := &AgentSession{ID: "tls-sess", InstanceID: "tls-inst", Sess: server, IDGen: proto.NewEdgeIDGen(), NegotiatedVersion: proto.ProtoVersion}

	reply := bindOverWire(t, s, as, client, server, proto.Bind{Kind: proto.KindTLS, Subdomain: "secure", Takeover: true, AllowCIDRs: []string{"127.0.0.0/8"}})
	if reply.Type != proto.TypeBindOK {
		t.Fatalf("reply = %+v, want bind_ok", reply)
	}
	ok, _ := proto.Decode[proto.BindOK](reply)
	if ok.Hostname != "secure.example.com" || ok.URL != "tls://secure.example.com" {
		t.Fatalf("bind ok = %+v", ok)
	}
	b, found := s.registry.RouteTLS("secure.example.com")
	if !found || len(b.snapshot.Load().access.prefixes()) != 1 {
		t.Fatal("tls binding missing or allow_cidr not applied")
	}

	reply = bindOverWire(t, s, as, client, server, proto.Bind{Kind: proto.KindHTTP, Subdomain: "secure"})
	if reply.Type != proto.TypeBindErr {
		t.Fatalf("http bind over tls name reply = %+v, want bind_err", reply)
	}
	e, _ := proto.Decode[proto.BindErr](reply)
	if e.Code != proto.CodeKindConflict || !strings.Contains(e.Message, "tls") {
		t.Fatalf("http bind over tls name err = %+v, want kind_conflict naming tls", e)
	}

	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "web.example.com", Session: as}); err != nil {
		t.Fatalf("bind http: %v", err)
	}
	reply = bindOverWire(t, s, as, client, server, proto.Bind{Kind: proto.KindTLS, Subdomain: "web"})
	e, _ = proto.Decode[proto.BindErr](reply)
	if reply.Type != proto.TypeBindErr || e.Code != proto.CodeKindConflict || !strings.Contains(e.Message, "http") {
		t.Fatalf("tls bind over http name reply = %+v %+v, want kind_conflict naming http", reply, e)
	}

	for _, bad := range []proto.Bind{
		{Kind: proto.KindTLS, Subdomain: "a", HTTP2: true},
		{Kind: proto.KindTLS, Subdomain: "b", BasicAuthSHA256: []string{strings.Repeat("a", 64)}},
		{Kind: proto.KindTLS, Subdomain: "c", RemotePort: 9000},
	} {
		reply = bindOverWire(t, s, as, client, server, bad)
		e, _ = proto.Decode[proto.BindErr](reply)
		if reply.Type != proto.TypeBindErr || e.Code != proto.CodeInvalidAccess {
			t.Fatalf("bind %+v reply = %+v %+v, want invalid_access", bad, reply, e)
		}
	}
}

func TestHandleBindTLSRandomNameSkipsHTTPHostname(t *testing.T) {
	client, server, cleanup := newRawSessionPair(t)
	defer cleanup()
	s := newTestServer("tok")
	names := []string{"taken", "open"}
	i := 0
	s.randomName = func() string {
		n := names[i]
		if i < len(names)-1 {
			i++
		}
		return n
	}
	as := &AgentSession{ID: "tls-sess", InstanceID: "tls-inst", Sess: server, IDGen: proto.NewEdgeIDGen(), NegotiatedVersion: proto.ProtoVersion}
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "taken.example.com", Session: as}); err != nil {
		t.Fatalf("bind http: %v", err)
	}

	reply := bindOverWire(t, s, as, client, server, proto.Bind{Kind: proto.KindTLS})
	ok, _ := proto.Decode[proto.BindOK](reply)
	if reply.Type != proto.TypeBindOK || ok.Hostname != "open.example.com" {
		t.Fatalf("reply = %+v %+v, want bind_ok on open.example.com", reply, ok)
	}
}

func TestSNIListenerKeepsWebSocketControlFallbackOverTLS(t *testing.T) {
	agentCert, agentPool := passthroughTestCert(t, "secure.example.com")
	edgeCert, edgePool := passthroughTestCert(t, "example.com", "*.example.com")
	h := newSNIHarness(t, agentCert, nil)
	h.bindTLS(t, "secure.example.com", nil)
	h.srv.unauthSem = newGlobalSemaphore(2)

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.srv.handlePublicListener(r.Context(), w, r)
	}))
	ts.Listener.Close()
	ts.Listener = h.ln
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{edgeCert}}
	ts.StartTLS()
	defer ts.Close()

	wsConfig, err := websocket.NewConfig("wss://"+h.addr+controlWebSocketPath, "https://"+h.addr)
	if err != nil {
		t.Fatalf("websocket config: %v", err)
	}
	wsConfig.Protocol = []string{controlWebSocketSubprotocol}
	wsConfig.TlsConfig = &tls.Config{ServerName: "example.com", RootCAs: edgePool}
	ws, err := websocket.DialConfig(wsConfig)
	if err != nil {
		t.Fatalf("websocket control dial through the SNI listener: %v", err)
	}
	sess, err := tunnel.Client(ws)
	if err != nil {
		t.Fatalf("tunnel client: %v", err)
	}
	defer sess.Close("test done")
	if err := sess.Control().Write(proto.TypeAuth, 1, proto.Auth{Token: "tok", InstanceID: "ws-fallback", ProtoVersions: proto.SupportedVersions}); err != nil {
		t.Fatalf("auth write: %v", err)
	}
	reply, err := sess.Control().Read()
	if err != nil {
		t.Fatalf("auth reply: %v", err)
	}
	if reply.Type != proto.TypeAuthOK {
		t.Fatalf("auth reply = %q, want auth_ok", reply.Type)
	}

	tc, err := dialTLSClient(t, h.addr, nil, &tls.Config{ServerName: "secure.example.com", RootCAs: agentPool})
	if err != nil {
		t.Fatalf("passthrough handshake alongside the control fallback: %v", err)
	}
	if peer := tc.ConnectionState().PeerCertificates; len(peer) == 0 || !bytes.Equal(peer[0].Raw, agentCert.Leaf.Raw) {
		t.Fatal("passthrough client did not see the agent certificate")
	}
}
