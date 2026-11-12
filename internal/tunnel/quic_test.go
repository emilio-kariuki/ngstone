package tunnel

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"ngstone/internal/proto"
)

func allowAllWindows(*quic.Conn, uint64) bool { return true }

func quicTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "quic-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func quicTestClientTLS() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{QUICALPN},
	}
}

func newQUICTestListener(t *testing.T, laddr string) (*quic.Listener, int) {
	t.Helper()
	udpAddr, err := net.ResolveUDPAddr("udp", laddr)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("udp listen %s: %v", laddr, err)
	}
	tr := &quic.Transport{Conn: pc}
	ln, err := tr.Listen(&tls.Config{
		Certificates: []tls.Certificate{quicTestCert(t)},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{QUICALPN},
	}, QUICServerConfig(allowAllWindows))
	if err != nil {
		pc.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ln.Close()
		tr.Close()
		pc.Close()
	})
	return ln, pc.LocalAddr().(*net.UDPAddr).Port
}

func quicTestAddr(port int) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func quicDialLoopback(t *testing.T, ctx context.Context, port int, tlsConf *tls.Config, early bool) (*quic.Conn, error) {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", quicTestAddr(port))
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { pc.Close() })
	if early {
		return quic.DialEarly(ctx, pc, raddr, tlsConf, quicClientConfig())
	}
	return quic.Dial(ctx, pc, raddr, tlsConf, quicClientConfig())
}

type quicPeers struct {
	client net.Conn
	server net.Conn
	qc     *quic.Conn
}

func newQUICPeers(t *testing.T) quicPeers {
	t.Helper()
	ln, port := newQUICTestListener(t, "127.0.0.1:0")
	type result struct {
		nc  net.Conn
		qc  *quic.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		qc, err := ln.Accept(ctx)
		if err != nil {
			ch <- result{err: err}
			return
		}
		nc, err := AcceptQUIC(ctx, qc)
		ch <- result{nc: nc, qc: qc, err: err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cc, err := DialQUIC(ctx, quicTestAddr(port), quicTestClientTLS())
	if err != nil {
		t.Fatalf("DialQUIC: %v", err)
	}
	if _, err := cc.Write([]byte{0}); err != nil {
		t.Fatalf("client first write: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	one := make([]byte, 1)
	if _, err := io.ReadFull(r.nc, one); err != nil {
		t.Fatalf("server first read: %v", err)
	}
	t.Cleanup(func() {
		r.qc.CloseWithError(0, "")
		r.nc.Close()
		cc.Close()
	})
	return quicPeers{client: cc, server: r.nc, qc: r.qc}
}

func newQUICSessionPair(t *testing.T) (Session, Session) {
	t.Helper()
	ln, port := newQUICTestListener(t, "127.0.0.1:0")
	type result struct {
		sess Session
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		qc, err := ln.Accept(ctx)
		if err != nil {
			ch <- result{err: err}
			return
		}
		nc, err := AcceptQUIC(ctx, qc)
		if err != nil {
			ch <- result{err: err}
			return
		}
		s, err := Server(nc)
		ch <- result{sess: s, err: err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nc, err := DialQUIC(ctx, quicTestAddr(port), quicTestClientTLS())
	if err != nil {
		t.Fatalf("DialQUIC: %v", err)
	}
	cs, err := Client(nc)
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("server session: %v", r.err)
	}
	return cs, r.sess
}

func TestQUICSessionRoundTrip(t *testing.T) {
	client, server := newQUICSessionPair(t)
	defer server.Close("test done")
	defer client.Close("test done")

	go client.Control().Write(proto.TypeAuth, 1, proto.Auth{Token: "tok", InstanceID: "abc"})
	msg, err := server.Control().Read()
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if msg.Type != proto.TypeAuth {
		t.Fatalf("got type %q", msg.Type)
	}
	if err := server.Control().Write(proto.TypeAuthOK, msg.ID, proto.AuthOK{ProtoVersion: 1}); err != nil {
		t.Fatalf("server write: %v", err)
	}
	reply, err := client.Control().Read()
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if reply.Type != proto.TypeAuthOK || reply.ID != msg.ID {
		t.Fatalf("reply mismatch: %+v", reply)
	}

	pre := proto.StreamOpen{Kind: proto.KindHTTP, Host: "x.example.com", ReqID: "r1", ClientAddr: "1.2.3.4:5"}
	openErr := make(chan error, 1)
	var cc net.Conn
	go func() {
		var err error
		cc, err = client.OpenStream(context.Background(), pre)
		openErr <- err
	}()
	sc, err := server.AcceptRaw(context.Background())
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer sc.Close()
	got, err := readPreamble(sc)
	if err != nil {
		t.Fatalf("readPreamble: %v", err)
	}
	if got != pre {
		t.Fatalf("preamble mismatch: %+v", got)
	}
	if err := <-openErr; err != nil {
		t.Fatalf("open: %v", err)
	}
	defer cc.Close()
	go io.Copy(sc, sc)
	go cc.Write([]byte("echo me"))
	buf := make([]byte, 7)
	if _, err := io.ReadFull(cc, buf); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(buf) != "echo me" {
		t.Fatalf("echo mismatch: %q", buf)
	}
}

func TestQUICCoreSessionTests(t *testing.T) {
	prev := sessionPairFactory
	sessionPairFactory = newQUICSessionPair
	t.Cleanup(func() { sessionPairFactory = prev })
	for _, tc := range []struct {
		name string
		fn   func(*testing.T)
	}{
		{"SessionControlRoundTrip", TestSessionControlRoundTrip},
		{"OpenAcceptStreamPreambleRoundTrip", TestOpenAcceptStreamPreambleRoundTrip},
		{"OpenStreamCancelledContext", TestOpenStreamCancelledContextReturnsPromptlyAndDoesNotLeak},
		{"ListenerRemoteAddrFromPreamble", TestListenerRemoteAddrFromPreamble},
		{"ListenerSilentStreamDoesNotBlockOthers", TestListenerSilentStreamDoesNotBlockOthers},
		{"ListenerClosesSilentStreamAfterPreambleDeadline", TestListenerClosesSilentStreamAfterPreambleDeadline},
	} {
		t.Run(tc.name, tc.fn)
	}
}

func TestQUICSessionHalfClose(t *testing.T) {
	client, server := newQUICSessionPair(t)
	defer server.Close("test done")
	defer client.Close("test done")

	pre := proto.StreamOpen{Kind: proto.KindHTTP, Host: "x.example.com"}
	openErr := make(chan error, 1)
	var cc net.Conn
	go func() {
		var err error
		cc, err = client.OpenStream(context.Background(), pre)
		openErr <- err
	}()
	sc, err := server.AcceptRaw(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	if _, err := readPreamble(sc); err != nil {
		t.Fatal(err)
	}
	if err := <-openErr; err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	if _, err := cc.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := cc.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(sc)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(got) != "request" {
		t.Fatalf("got %q", got)
	}
	if _, err := sc.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	sc.Close()
	resp, err := io.ReadAll(cc)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(resp) != "response" {
		t.Fatalf("got %q", resp)
	}
}

func TestQUICSessionLargeTransfer(t *testing.T) {
	client, server := newQUICSessionPair(t)
	defer server.Close("test done")
	defer client.Close("test done")

	pre := proto.StreamOpen{Kind: proto.KindHTTP, Host: "x.example.com"}
	openErr := make(chan error, 1)
	var cc net.Conn
	go func() {
		var err error
		cc, err = client.OpenStream(context.Background(), pre)
		openErr <- err
	}()
	sc, err := server.AcceptRaw(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	if _, err := readPreamble(sc); err != nil {
		t.Fatal(err)
	}
	if err := <-openErr; err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	const size = 8 << 20
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	go func() {
		cc.Write(payload)
		cc.Close()
	}()
	sc.SetReadDeadline(time.Now().Add(30 * time.Second))
	got, err := io.ReadAll(sc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes", len(got))
	}
}

func TestQUICConfigBounds(t *testing.T) {
	gate := func(*quic.Conn, uint64) bool { return true }
	for _, server := range []bool{true, false} {
		var g func(*quic.Conn, uint64) bool
		if server {
			g = gate
		}
		cfg := quicClientConfig()
		wantHandshake := 5 * time.Second
		if server {
			cfg = QUICServerConfig(g)
			wantHandshake = 2500 * time.Millisecond
		}
		if cfg.HandshakeIdleTimeout != wantHandshake {
			t.Errorf("server=%v HandshakeIdleTimeout = %v, want %v", server, cfg.HandshakeIdleTimeout, wantHandshake)
		}
		if cfg.MaxIdleTimeout != 15*time.Second {
			t.Errorf("server=%v MaxIdleTimeout = %v", server, cfg.MaxIdleTimeout)
		}
		if cfg.KeepAlivePeriod != 5*time.Second {
			t.Errorf("server=%v KeepAlivePeriod = %v", server, cfg.KeepAlivePeriod)
		}
		if cfg.InitialStreamReceiveWindow != 64<<10 || cfg.InitialConnectionReceiveWindow != 64<<10 {
			t.Errorf("server=%v initial windows = %d/%d", server, cfg.InitialStreamReceiveWindow, cfg.InitialConnectionReceiveWindow)
		}
		if cfg.MaxStreamReceiveWindow != 1<<20 || cfg.MaxConnectionReceiveWindow != 1<<20 {
			t.Errorf("server=%v max windows = %d/%d", server, cfg.MaxStreamReceiveWindow, cfg.MaxConnectionReceiveWindow)
		}
		wantStreams := int64(-1)
		if server {
			wantStreams = 1
		}
		if cfg.MaxIncomingStreams != wantStreams {
			t.Errorf("server=%v MaxIncomingStreams = %d, want %d", server, cfg.MaxIncomingStreams, wantStreams)
		}
		if cfg.MaxIncomingUniStreams != -1 {
			t.Errorf("server=%v MaxIncomingUniStreams = %d", server, cfg.MaxIncomingUniStreams)
		}
		if cfg.Allow0RTT {
			t.Errorf("server=%v Allow0RTT is set", server)
		}
		if cfg.EnableDatagrams {
			t.Errorf("server=%v EnableDatagrams is set", server)
		}
		if server != (cfg.AllowConnectionWindowIncrease != nil) {
			t.Errorf("server=%v AllowConnectionWindowIncrease set = %v", server, cfg.AllowConnectionWindowIncrease != nil)
		}
	}
	denied := QUICServerConfig(func(*quic.Conn, uint64) bool { return false })
	if denied.AllowConnectionWindowIncrease(nil, 1) {
		t.Error("QUICServerConfig did not install the gate")
	}
}

func TestQUICServerRefusesSecondStream(t *testing.T) {
	p := newQUICPeers(t)
	cc := p.client.(*quicConn)
	_, err := cc.conn.OpenStream()
	if err == nil {
		t.Fatal("second client stream was allowed")
	}
	var limit *quic.StreamLimitReachedError
	if !errors.As(err, &limit) {
		t.Fatalf("second stream error = %v, want StreamLimitReachedError", err)
	}
}

func TestQUICServerCannotOpenStreams(t *testing.T) {
	p := newQUICPeers(t)
	_, err := p.qc.OpenStream()
	if err == nil {
		t.Fatal("server opened a stream to the client")
	}
	var limit *quic.StreamLimitReachedError
	if !errors.As(err, &limit) {
		t.Fatalf("server open error = %v, want StreamLimitReachedError", err)
	}
	if _, err := p.qc.OpenUniStream(); err == nil {
		t.Fatal("server opened a unidirectional stream to the client")
	}
	if _, err := p.client.(*quicConn).conn.OpenUniStream(); err == nil {
		t.Fatal("client opened a unidirectional stream to the server")
	}
}

func TestQUICRejectsWrongALPN(t *testing.T) {
	_, port := newQUICTestListener(t, "127.0.0.1:0")
	tlsConf := quicTestClientTLS()
	tlsConf.NextProtos = []string{"h3"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nc, err := DialQUIC(ctx, quicTestAddr(port), tlsConf)
	if err == nil {
		nc.Close()
		t.Fatal("dial with the wrong ALPN succeeded")
	}
}

func TestQUICNever0RTT(t *testing.T) {
	ln, port := newQUICTestListener(t, "127.0.0.1:0")
	go func() {
		for {
			qc, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if st, err := qc.AcceptStream(ctx); err == nil {
					io.Copy(io.Discard, st)
				}
				qc.CloseWithError(0, "")
			}()
		}
	}()
	tlsConf := quicTestClientTLS()
	tlsConf.ServerName = "localhost"
	tlsConf.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		qc, err := quicDialLoopback(t, ctx, port, tlsConf, true)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		select {
		case <-qc.HandshakeComplete():
		case <-time.After(5 * time.Second):
			t.Fatalf("dial %d: handshake did not complete", i)
		}
		st, err := qc.OpenStreamSync(ctx)
		if err != nil {
			t.Fatalf("dial %d: open stream: %v", i, err)
		}
		st.Write([]byte{0})
		time.Sleep(200 * time.Millisecond)
		state := qc.ConnectionState()
		if state.Used0RTT {
			t.Fatalf("connection %d used 0-RTT", i)
		}
		if i == 1 && !state.TLS.DidResume {
			t.Logf("second connection did not resume the session")
		}
		qc.CloseWithError(0, "")
		cancel()
	}
}

func TestQUICCloseDeliversQueuedData(t *testing.T) {
	p := newQUICPeers(t)
	const size = 256 << 10
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	writeErr := make(chan error, 1)
	go func() {
		_, err := p.server.Write(payload)
		p.server.Close()
		writeErr <- err
	}()
	p.client.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(p.client)
	if err != nil {
		t.Fatalf("client read after %d bytes: %v", len(got), err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %d bytes, want %d", len(got), size)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("server write: %v", err)
	}
}

func TestQUICDialerCloseBlocksUntilConnClosed(t *testing.T) {
	p := newQUICPeers(t)
	go func() {
		io.Copy(io.Discard, p.server)
		time.Sleep(400 * time.Millisecond)
		p.server.Close()
	}()
	cc := p.client.(*quicConn)
	start := time.Now()
	cc.Close()
	select {
	case <-cc.conn.Context().Done():
	default:
		t.Fatalf("dialer Close returned after %v with the connection still open", time.Since(start))
	}
	if d := time.Since(start); d > quicCloseLinger+time.Second {
		t.Fatalf("dialer Close took %v", d)
	}
}

func TestQUICAcceptorCloseReturnsPromptly(t *testing.T) {
	p := newQUICPeers(t)
	start := time.Now()
	p.server.Close()
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("acceptor Close took %v", d)
	}
	select {
	case <-p.qc.Context().Done():
	case <-time.After(4 * time.Second):
		t.Fatal("connection still open 4s after the acceptor closed")
	}
}

func TestQUICCloseUnblocksBlockedWrite(t *testing.T) {
	p := newQUICPeers(t)
	writeDone := make(chan error, 1)
	go func() {
		_, err := p.server.Write(make([]byte, 4<<20))
		writeDone <- err
	}()
	time.Sleep(300 * time.Millisecond)
	select {
	case err := <-writeDone:
		t.Fatalf("write finished before close: %v", err)
	default:
	}
	closeDone := make(chan struct{})
	go func() {
		p.server.Close()
		close(closeDone)
	}()
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("blocked write returned nil after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked write was not released by Close")
	}
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return")
	}
}

func TestQUICCloseUnblocksPendingRead(t *testing.T) {
	p := newQUICPeers(t)
	readDone := make(chan error, 1)
	go func() {
		_, err := p.server.Read(make([]byte, 16))
		readDone <- err
	}()
	time.Sleep(200 * time.Millisecond)
	p.server.Close()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("pending read returned nil after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending read was not released by Close")
	}
}

func TestQUICRemoteAddrUnmapsIPv4(t *testing.T) {
	ln, port := newQUICTestListener(t, "[::]:0")
	type result struct {
		nc  net.Conn
		qc  *quic.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		qc, err := ln.Accept(ctx)
		if err != nil {
			ch <- result{err: err}
			return
		}
		nc, err := AcceptQUIC(ctx, qc)
		ch <- result{nc: nc, qc: qc, err: err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cc, err := DialQUIC(ctx, quicTestAddr(port), quicTestClientTLS())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()
	cc.Write([]byte{0})
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	defer r.nc.Close()
	defer r.qc.CloseWithError(0, "")
	ua, ok := r.nc.RemoteAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("RemoteAddr is %T", r.nc.RemoteAddr())
	}
	if got := ua.String(); len(got) < 10 || got[:10] != "127.0.0.1:" {
		t.Fatalf("RemoteAddr = %q", got)
	}
	if ua.AddrPort().Addr().Is4In6() {
		t.Fatalf("RemoteAddr %v is still an IPv4-mapped IPv6 address", ua)
	}
}

func TestAcceptQUICClosesConnWithoutStream(t *testing.T) {
	ln, port := newQUICTestListener(t, "127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cqc, err := quicDialLoopback(t, ctx, port, quicTestClientTLS(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer cqc.CloseWithError(0, "")
	sqc, err := ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	short, cancelShort := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancelShort()
	if _, err := AcceptQUIC(short, sqc); err == nil {
		t.Fatal("AcceptQUIC succeeded without a stream")
	}
	select {
	case <-sqc.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("connection left open after AcceptQUIC failed")
	}
}

func TestOrderQUICCandidatesPutsIPv4First(t *testing.T) {
	in := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("::ffff:192.0.2.1"),
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("192.0.2.2"),
	}
	want := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
	}
	got := orderQUICCandidates(in)
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if len(orderQUICCandidates(nil)) != 0 {
		t.Fatal("no addresses must yield no candidates")
	}
}

func TestDialQUICBindsRouteSourceAddress(t *testing.T) {
	ln, port := newQUICTestListener(t, "127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		qc, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		qc.CloseWithError(0, "")
	}()
	nc, err := DialQUIC(ctx, quicTestAddr(port), quicTestClientTLS())
	if err != nil {
		t.Fatalf("DialQUIC: %v", err)
	}
	defer nc.Close()
	la, ok := nc.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("LocalAddr type = %T, want *net.UDPAddr", nc.LocalAddr())
	}
	if !la.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("LocalAddr = %v, want 127.0.0.1", la)
	}
}
