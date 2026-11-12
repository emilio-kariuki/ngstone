package edge

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

func quicTestServer(slots int64) *Server {
	return &Server{
		handshakeSem: newGlobalSemaphore(slots),
		unauthSem:    newGlobalSemaphore(slots),
	}
}

func quicTestClientTLS() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{tunnel.QUICALPN},
	}
}

func quicSlotFree(sem *globalSemaphore) bool {
	if !sem.tryAcquire() {
		return false
	}
	sem.release()
	return true
}

func waitQUICSlotFree(t *testing.T, name string, sem *globalSemaphore) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if quicSlotFree(sem) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s slot was never released", name)
}

func verifiedClient() *quic.ClientInfo {
	return &quic.ClientInfo{RemoteAddr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1}, AddrVerified: true}
}

func TestQUICAdmissionRequiresVerifiedAddress(t *testing.T) {
	s := quicTestServer(1)
	info := verifiedClient()
	info.AddrVerified = false
	if _, err := s.admitQUIC(context.Background(), info); err == nil {
		t.Fatal("admitQUIC accepted an unverified source address")
	}
	if !quicSlotFree(s.handshakeSem) || !quicSlotFree(s.unauthSem) {
		t.Fatal("a refused connection held a slot")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := s.admitQUIC(ctx, verifiedClient()); err != nil {
		t.Fatalf("admitQUIC refused a verified address: %v", err)
	}
	if quicSlotFree(s.handshakeSem) || quicSlotFree(s.unauthSem) {
		t.Fatal("an admitted connection did not take both slots")
	}
}

func TestQUICAdmissionCapsUnauthenticatedSessions(t *testing.T) {
	s := &Server{handshakeSem: newGlobalSemaphore(3), unauthSem: newGlobalSemaphore(1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := s.admitQUIC(ctx, verifiedClient()); err != nil {
		t.Fatalf("first admission: %v", err)
	}
	if _, err := s.admitQUIC(ctx, verifiedClient()); err == nil {
		t.Fatal("second unauthenticated connection was admitted past the cap")
	}
	for i := 0; i < 2; i++ {
		if !s.handshakeSem.tryAcquire() {
			t.Fatalf("handshake slot %d leaked by the refused admission", i)
		}
	}
	if s.handshakeSem.tryAcquire() {
		t.Fatal("handshake semaphore has more free slots than configured")
	}
}

func TestQUICAdmissionHandshakeRefusalDoesNotLeakUnauth(t *testing.T) {
	s := &Server{handshakeSem: newGlobalSemaphore(1), unauthSem: newGlobalSemaphore(2)}
	if !s.handshakeSem.tryAcquire() {
		t.Fatal("could not exhaust the handshake semaphore")
	}
	if _, err := s.admitQUIC(context.Background(), verifiedClient()); err == nil {
		t.Fatal("admitQUIC succeeded with no handshake slot")
	}
	for i := 0; i < 2; i++ {
		if !s.unauthSem.tryAcquire() {
			t.Fatalf("unauthenticated slot %d leaked by a handshake refusal", i)
		}
	}
}

func TestQUICAdmissionReleasesOnFailedHandshake(t *testing.T) {
	s := quicTestServer(1)
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := s.admitQUIC(ctx, verifiedClient()); err != nil {
		t.Fatalf("admitQUIC: %v", err)
	}
	cancel()
	waitQUICSlotFree(t, "handshake", s.handshakeSem)
	waitQUICSlotFree(t, "unauthenticated", s.unauthSem)
}

func TestQUICAdmissionReleasesOnAuth(t *testing.T) {
	s := quicTestServer(1)
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	admitted, err := s.admitQUIC(ctx1, verifiedClient())
	if err != nil {
		t.Fatalf("admitQUIC: %v", err)
	}
	adm := quicAdmissionFrom(admitted)
	adm.releaseHandshake()
	if !quicSlotFree(s.handshakeSem) {
		t.Fatal("handshake slot not released")
	}
	if quicSlotFree(s.unauthSem) {
		t.Fatal("unauthenticated slot released before authentication")
	}
	adm.authenticated()
	if !quicSlotFree(s.unauthSem) {
		t.Fatal("unauthenticated slot not released by authentication")
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	if _, err := s.admitQUIC(ctx2, verifiedClient()); err != nil {
		t.Fatalf("second admission after authentication: %v", err)
	}
	adm.authenticated()
	cancel1()
	time.Sleep(100 * time.Millisecond)
	if quicSlotFree(s.unauthSem) {
		t.Fatal("releasing the first connection twice freed the second connection's slot")
	}
}

func startQUICServeForTest(t *testing.T, s *Server, withAdmission bool) string {
	t.Helper()
	tlsConf, err := s.quicTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	if withAdmission {
		tr.VerifySourceAddress = func(net.Addr) bool { return true }
		tr.ConnContext = s.admitQUIC
	}
	ln, err := tr.Listen(tlsConf, s.quicConfig())
	if err != nil {
		pc.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.serveQUIC(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		ln.Close()
		tr.Close()
		pc.Close()
		<-done
	})
	return pc.LocalAddr().String()
}

func dialQUICRaw(t *testing.T, addr string) (*quic.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { pc.Close() })
	qc, err := quic.Dial(ctx, pc, raddr, quicTestClientTLS(), &quic.Config{HandshakeIdleTimeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { qc.CloseWithError(0, "") })
	return qc, nil
}

func TestQUICAcceptFailsClosedWithoutAdmission(t *testing.T) {
	s := &Server{}
	addr := startQUICServeForTest(t, s, false)
	qc, err := dialQUICRaw(t, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case <-qc.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("a connection with no admission record was not closed")
	}
}

func TestQUICWindowAllowedRequiresAuth(t *testing.T) {
	if quicWindowAllowed(context.Background()) {
		t.Fatal("window growth allowed with no admission record")
	}
	s := quicTestServer(1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	admitted, err := s.admitQUIC(ctx, verifiedClient())
	if err != nil {
		t.Fatal(err)
	}
	if quicWindowAllowed(admitted) {
		t.Fatal("window growth allowed before authentication")
	}
	quicAdmissionFrom(admitted).authenticated()
	if !quicWindowAllowed(admitted) {
		t.Fatal("window growth refused after authentication")
	}
}

func TestNewRejectsQUICWithPublicTLSConfig(t *testing.T) {
	_, err := New(Config{Domain: "example.com", QUIC: true, PublicTLSConfig: &tls.Config{}})
	if err == nil || !strings.Contains(err.Error(), "QUIC") {
		t.Fatalf("New with QUIC and a public TLS config: err = %v, want a QUIC error", err)
	}
	if _, err := New(Config{Domain: "example.com", QUIC: true, Insecure: true}); err != nil {
		t.Fatalf("New with QUIC and insecure mode: %v", err)
	}
	if _, err := New(Config{Domain: "example.com", QUIC: true}); err != nil {
		t.Fatalf("New with QUIC and managed certificates: %v", err)
	}
}

func startQUICEdgeForTest(t *testing.T, limits LimitsConfig) (*Server, string, string) {
	t.Helper()
	controlAddr := freeTCPAddr(t)
	publicAddr := freeTCPAddr(t)
	s, err := New(Config{
		ControlAddr:  controlAddr,
		PublicAddr:   publicAddr,
		Domain:       "example.com",
		TokenSHA256:  sumToken("tok"),
		PublicScheme: "http",
		Insecure:     true,
		QUIC:         true,
		Limits:       limits,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-runErr:
		case <-time.After(20 * time.Second):
			t.Error("edge did not stop")
		}
	})
	waitTCPUpOrRunErr(t, publicAddr, runErr)
	return s, controlAddr, publicAddr
}

func dialQUICSession(t *testing.T, addr string) tunnel.Session {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err := tunnel.DialQUIC(ctx, addr, quicTestClientTLS())
		cancel()
		if err == nil {
			sess, err := tunnel.Client(conn)
			if err != nil {
				conn.Close()
				t.Fatalf("tunnel client: %v", err)
			}
			return sess
		}
		if time.Now().After(deadline) {
			t.Fatalf("quic dial %s: %v", addr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func quicAuth(sess tunnel.Session, token, instance string) (string, error) {
	ctrl := sess.Control()
	if err := ctrl.Write(proto.TypeAuth, 1, proto.Auth{Token: token, InstanceID: instance, ProtoVersions: proto.SupportedVersions}); err != nil {
		return "", err
	}
	ctrl.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply, err := ctrl.Read()
	if err != nil {
		return "", err
	}
	return reply.Type, nil
}

func TestQUICAuthFailuresHitAuthLimiter(t *testing.T) {
	s, controlAddr, _ := startQUICEdgeForTest(t, LimitsConfig{})
	for i := 0; i < maxAuthFailuresPerMinute; i++ {
		sess := dialQUICSession(t, controlAddr)
		typ, err := quicAuth(sess, "wrong", fmt.Sprintf("bad-%d", i))
		if err != nil || typ != proto.TypeAuthErr {
			t.Fatalf("attempt %d: reply = %q, %v; want %q", i, typ, err, proto.TypeAuthErr)
		}
		sess.Close("done")
	}
	if s.authLimiter.allowed("127.0.0.1") {
		t.Fatal("QUIC auth failures were not counted against 127.0.0.1")
	}
	sess := dialQUICSession(t, controlAddr)
	defer sess.Close("done")
	if typ, err := quicAuth(sess, "tok", "good"); err == nil && typ == proto.TypeAuthOK {
		t.Fatal("a rate-limited address authenticated over QUIC")
	}
}

func TestQUICAgentSessionBindsAndServes(t *testing.T) {
	_, controlAddr, publicAddr := startQUICEdgeForTest(t, LimitsConfig{UnauthSessions: 1})

	sessA := dialQUICSession(t, controlAddr)
	defer sessA.Close("done")
	if typ, err := quicAuth(sessA, "tok", "agent-a"); err != nil || typ != proto.TypeAuthOK {
		t.Fatalf("auth A: %q, %v", typ, err)
	}
	ln, err := tunnel.NewListener(sessA)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, "over-quic\n")
	})}
	go srv.Serve(ln)
	defer srv.Close()

	ctrl := sessA.Control()
	if err := ctrl.Write(proto.TypeBind, 2, proto.Bind{Kind: proto.KindHTTP, Subdomain: "demo"}); err != nil {
		t.Fatal(err)
	}
	ctrl.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		m, err := ctrl.Read()
		if err != nil {
			t.Fatalf("bind reply: %v", err)
		}
		if m.Type == proto.TypeBindOK {
			break
		}
		if m.Type == proto.TypeBindErr {
			t.Fatalf("bind refused: %+v", m)
		}
	}

	req, _ := http.NewRequest(http.MethodGet, "http://"+publicAddr+"/", nil)
	req.Host = "demo.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("public request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "over-quic\n" {
		t.Fatalf("public response = %q", body)
	}

	sessB := dialQUICSession(t, controlAddr)
	defer sessB.Close("done")
	if typ, err := quicAuth(sessB, "tok", "agent-b"); err != nil || typ != proto.TypeAuthOK {
		t.Fatalf("second agent could not authenticate after the first released its slot: %q, %v", typ, err)
	}
}

func quicBind(t *testing.T, sess tunnel.Session, subdomain string) {
	t.Helper()
	ctrl := sess.Control()
	if err := ctrl.Write(proto.TypeBind, 2, proto.Bind{Kind: proto.KindHTTP, Subdomain: subdomain}); err != nil {
		t.Fatalf("bind write: %v", err)
	}
	ctrl.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		m, err := ctrl.Read()
		if err != nil {
			t.Fatalf("bind reply: %v", err)
		}
		if m.Type == proto.TypeBindOK {
			return
		}
		if m.Type == proto.TypeBindErr {
			t.Fatalf("bind refused: %+v", m)
		}
	}
}

func TestQUICAuthenticatedSessionSurvivesHardStop(t *testing.T) {
	shortenAuthDeadline(t, time.Second)
	_, controlAddr, _ := startQUICEdgeForTest(t, LimitsConfig{UnauthSessions: 1})
	start := time.Now()
	sess := dialQUICSession(t, controlAddr)
	defer sess.Close("done")
	if typ, err := quicAuth(sess, "tok", "agent-hard-stop"); err != nil || typ != proto.TypeAuthOK {
		t.Fatalf("auth: %q, %v", typ, err)
	}
	time.Sleep(time.Until(start.Add(authDeadline + 500*time.Millisecond)))
	quicBind(t, sess, "hardstop")
}

func TestQUICDrainRefusesNewConnections(t *testing.T) {
	s := quicTestServer(2)
	s.controlDraining = true
	addr := startQUICServeForTest(t, s, true)
	qc, err := dialQUICRaw(t, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case <-qc.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("a connection during drain was not closed")
	}
	var appErr *quic.ApplicationError
	if !errors.As(context.Cause(qc.Context()), &appErr) || appErr.ErrorMessage != "draining" {
		t.Fatalf("close cause = %v, want an application error with message draining", context.Cause(qc.Context()))
	}
	waitQUICSlotFree(t, "handshake", s.handshakeSem)
	waitQUICSlotFree(t, "unauthenticated", s.unauthSem)
}

func TestQUICWindowGateOnRealConn(t *testing.T) {
	s := quicTestServer(1)
	tr, ln, err := s.listenQUIC(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listenQUIC: %v", err)
	}
	t.Cleanup(func() {
		ln.Close()
		tr.Close()
		tr.Conn.Close()
	})
	if _, err := dialQUICRaw(t, tr.Conn.LocalAddr().String()); err != nil {
		t.Fatalf("dial: %v", err)
	}
	actx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qc, err := ln.Accept(actx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	adm := quicAdmissionFrom(qc.Context())
	if adm == nil {
		t.Fatal("listener-accepted connection carries no admission record")
	}
	gate := s.quicConfig().AllowConnectionWindowIncrease
	if gate == nil {
		t.Fatal("listener config has no window gate installed")
	}
	if quicWindowGate(qc, 1<<20) || gate(qc, 1<<20) {
		t.Fatal("window gate open before authentication")
	}
	adm.authenticated()
	if !quicWindowGate(qc, 1<<20) || !gate(qc, 1<<20) {
		t.Fatal("window gate closed after authentication")
	}
}

func TestQUICHandshakeBudgetIsHalfTheAuthDeadline(t *testing.T) {
	s := quicTestServer(1)
	if got, want := s.quicConfig().HandshakeIdleTimeout, authDeadline/2; got != want {
		t.Fatalf("HandshakeIdleTimeout = %v, want %v", got, want)
	}
}

func TestQUICListenerConsultsWindowGate(t *testing.T) {
	var allowed, refused atomic.Int64
	orig := quicWindowGate
	quicWindowGate = func(qc *quic.Conn, delta uint64) bool {
		ok := orig(qc, delta)
		if ok {
			allowed.Add(1)
		} else {
			refused.Add(1)
		}
		return ok
	}
	t.Cleanup(func() { quicWindowGate = orig })

	_, controlAddr, publicAddr := startQUICEdgeForTest(t, LimitsConfig{UnauthSessions: 1})
	sess := dialQUICSession(t, controlAddr)
	defer sess.Close("done")
	if typ, err := quicAuth(sess, "tok", "agent-gate"); err != nil || typ != proto.TypeAuthOK {
		t.Fatalf("auth: %q, %v", typ, err)
	}
	ln, err := tunnel.NewListener(sess)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{'x'}, 8<<20)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	})}
	go srv.Serve(ln)
	defer srv.Close()
	quicBind(t, sess, "gate")

	req, _ := http.NewRequest(http.MethodGet, "http://"+publicAddr+"/", nil)
	req.Host = "gate.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("public request: %v", err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err != nil || n != int64(len(payload)) {
		t.Fatalf("public response: %d bytes, %v; want %d", n, err, len(payload))
	}
	if allowed.Load() == 0 {
		t.Fatalf("window gate allowed no increase after authentication (allowed=%d refused=%d)", allowed.Load(), refused.Load())
	}
	t.Logf("window gate calls: allowed=%d refused=%d", allowed.Load(), refused.Load())
}

func TestQUICHandshakeSlotReleasedAfterAccept(t *testing.T) {
	_, controlAddr, _ := startQUICEdgeForTest(t, LimitsConfig{HandshakeConcurrency: 1})
	for i := 0; i < 2; i++ {
		sess := dialQUICSession(t, controlAddr)
		defer sess.Close("done")
		if typ, err := quicAuth(sess, "tok", fmt.Sprintf("agent-%d", i)); err != nil || typ != proto.TypeAuthOK {
			t.Fatalf("auth %d with another authenticated session open: %q, %v", i, typ, err)
		}
	}
}

func shortenAuthDeadline(t *testing.T, d time.Duration) {
	t.Helper()
	orig := authDeadline
	authDeadline = d
	t.Cleanup(func() { authDeadline = orig })
}

func requireUnauthSlotHeldThenFreedWithin(t *testing.T, s *Server, start time.Time, bound time.Duration) {
	t.Helper()
	if quicSlotFree(s.unauthSem) {
		t.Fatal("unauthenticated slot was free while the connection had not authenticated")
	}
	for !quicSlotFree(s.unauthSem) {
		if elapsed := time.Since(start); elapsed > bound {
			t.Fatalf("unauthenticated slot still held %v after admission, want release within %v", elapsed, bound)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestQUICUnauthLifetimeBoundedWithoutStream(t *testing.T) {
	shortenAuthDeadline(t, time.Second)
	s, controlAddr, _ := startQUICEdgeForTest(t, LimitsConfig{UnauthSessions: 1})
	start := time.Now()
	if _, err := dialQUICRaw(t, controlAddr); err != nil {
		t.Fatalf("dial: %v", err)
	}
	requireUnauthSlotHeldThenFreedWithin(t, s, start, authDeadline+300*time.Millisecond)
}

func TestQUICUnauthLifetimeBoundedAfterLateSilentStream(t *testing.T) {
	shortenAuthDeadline(t, time.Second)
	s, controlAddr, _ := startQUICEdgeForTest(t, LimitsConfig{UnauthSessions: 1})
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tunnel.DialQUIC(ctx, controlAddr, quicTestClientTLS())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { go conn.Close() }()
	time.Sleep(600 * time.Millisecond)
	if _, err := conn.Write([]byte{0}); err != nil {
		t.Fatalf("partial hello: %v", err)
	}
	requireUnauthSlotHeldThenFreedWithin(t, s, start, authDeadline+300*time.Millisecond)
}

func TestQUICFailedAuthHoldsSlotUntilConnectionCloses(t *testing.T) {
	shortenAuthDeadline(t, time.Second)
	s, controlAddr, _ := startQUICEdgeForTest(t, LimitsConfig{UnauthSessions: 1})
	start := time.Now()
	qc, err := dialQUICRaw(t, controlAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := qc.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if _, err := st.Write(bytes.Repeat([]byte{0xff}, 64)); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	st.SetReadDeadline(start.Add(authDeadline))
	if _, err := io.Copy(io.Discard, st); err != nil {
		t.Fatalf("edge did not finish the failed control stream before the deadline: %v", err)
	}
	select {
	case <-qc.Context().Done():
		t.Fatal("connection was already closed when the second dial was attempted")
	default:
	}
	if quicSlotFree(s.unauthSem) {
		t.Fatal("unauthenticated slot released while the failed connection was still open")
	}
	if _, err := dialQUICRaw(t, controlAddr); err == nil {
		t.Fatal("second connection was admitted while the failed one was still open")
	}
	select {
	case <-qc.Context().Done():
	case <-time.After(time.Until(start.Add(authDeadline + 500*time.Millisecond))):
		t.Fatalf("edge left a failed-auth connection open past %v", authDeadline+500*time.Millisecond)
	}
	waitQUICSlotFree(t, "unauthenticated", s.unauthSem)
}

func TestQUICTLSConfigClonesManagedConfig(t *testing.T) {
	mgr, err := NewTLSManager(TLSConfig{
		Domain:      "quic-config.invalid",
		DNSProvider: fakeDNSProvider{},
		ACMEEmail:   "ops@quic-config.invalid",
		StoragePath: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewTLSManager: %v", err)
	}
	apex := mgr.ApexTLSConfig()
	before := append([]string(nil), apex.NextProtos...)
	s := &Server{tlsMgr: mgr}
	cfg, err := s.quicTLSConfig()
	if err != nil {
		t.Fatalf("quicTLSConfig: %v", err)
	}
	if cfg == apex {
		t.Fatal("quicTLSConfig returned the shared apex config instead of a clone")
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != tunnel.QUICALPN {
		t.Fatalf("NextProtos = %v, want [%s]", cfg.NextProtos, tunnel.QUICALPN)
	}
	if strings.Join(apex.NextProtos, ",") != strings.Join(before, ",") {
		t.Fatalf("apex NextProtos changed from %v to %v", before, apex.NextProtos)
	}
}
