package edge

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

func realConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type res struct {
		c   net.Conn
		err error
	}
	accepted := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- res{c, err}
	}()

	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	ar := <-accepted
	if ar.err != nil {
		t.Fatalf("accept: %v", ar.err)
	}
	return dialed, ar.c
}

type tcpFixture struct {
	as      *AgentSession
	mgr     *tcpManager
	agent   tunnel.Session
	server  tunnel.Session
	cleanup func()
}

func newTCPFixture(t *testing.T, handler func(net.Conn, proto.StreamOpen)) *tcpFixture {
	t.Helper()
	agentCarrier, serverCarrier := realConnPair(t)

	type res struct {
		sess tunnel.Session
		err  error
	}
	agentCh := make(chan res, 1)
	serverCh := make(chan res, 1)
	go func() {
		s, err := tunnel.Client(agentCarrier)
		agentCh <- res{s, err}
	}()
	go func() {
		s, err := tunnel.Server(serverCarrier)
		serverCh <- res{s, err}
	}()

	ar := <-agentCh
	if ar.err != nil {
		t.Fatalf("agent session: %v", ar.err)
	}
	sr := <-serverCh
	if sr.err != nil {
		t.Fatalf("server session: %v", sr.err)
	}

	as := &AgentSession{
		ID:         randomHex(4),
		InstanceID: "tcp-inst",
		Sess:       sr.sess,
		IDGen:      proto.NewEdgeIDGen(),
		streamSem:  newGlobalSemaphore(64),
	}

	agentDone := make(chan struct{})
	go func() {
		defer close(agentDone)
		for {
			conn, err := ar.sess.AcceptRaw(context.Background())
			if err != nil {
				return
			}
			pre, err := readAgentPreamble(conn)
			if err != nil {
				conn.Close()
				continue
			}
			go handler(conn, pre)
		}
	}()

	mgr := newTCPManager(20000, 20009, "127.0.0.1", nil)

	cleanup := func() {
		mgr.releaseSession(as)
		ar.sess.Close("test done")
		sr.sess.Close("test done")
		<-agentDone
	}

	return &tcpFixture{as: as, mgr: mgr, agent: ar.sess, server: sr.sess, cleanup: cleanup}
}

func readAgentPreamble(conn net.Conn) (proto.StreamOpen, error) {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	m, err := proto.ReadMsg(conn)
	if err != nil {
		return proto.StreamOpen{}, err
	}
	pre, err := proto.Decode[proto.StreamOpen](m)
	if err != nil {
		return proto.StreamOpen{}, err
	}
	conn.SetReadDeadline(time.Time{})
	return pre, nil
}

func echoHandler(conn net.Conn, _ proto.StreamOpen) {
	io.Copy(conn, conn)
	conn.Close()
}

func dialPort(t *testing.T, port int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial port %d: %v", port, err)
	}
	return c
}

func TestTCPAllocateFreeReuse(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()

	p1, err := fx.mgr.bind(fx.as, 0, "example.com")
	if err != nil {
		t.Fatalf("first bind: %v", err)
	}
	if p1 < 20000 || p1 > 20009 {
		t.Fatalf("allocated port %d out of range", p1)
	}

	fx.mgr.mu.Lock()
	_, taken := fx.mgr.allocated[p1]
	fx.mgr.mu.Unlock()
	if !taken {
		t.Fatalf("port %d should be marked allocated after bind", p1)
	}

	fx.mgr.releaseSession(fx.as)

	fx.mgr.mu.Lock()
	_, stillTaken := fx.mgr.allocated[p1]
	nSess := len(fx.mgr.bySession)
	fx.mgr.mu.Unlock()
	if stillTaken {
		t.Fatalf("port %d should be free after release", p1)
	}
	if nSess != 0 {
		t.Fatalf("bySession should be empty after release, has %d", nSess)
	}

	p2, err := fx.mgr.bind(fx.as, p1, "example.com")
	if err != nil {
		t.Fatalf("re-bind freed port %d: %v", p1, err)
	}
	if p2 != p1 {
		t.Fatalf("expected to reuse freed port %d, got %d", p1, p2)
	}
}

func TestTCPExhaustionReturnsError(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()

	total := fx.mgr.hi - fx.mgr.lo + 1
	for i := 0; i < total; i++ {
		if _, err := fx.mgr.bind(fx.as, 0, "example.com"); err != nil {
			t.Fatalf("bind %d/%d failed early: %v", i+1, total, err)
		}
	}
	if _, err := fx.mgr.bind(fx.as, 0, "example.com"); err != errPortUnavailable {
		t.Fatalf("expected errPortUnavailable at exhaustion, got %v", err)
	}
}

func TestTCPSpecificPortHonoredAndRejectedWhenTaken(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()

	want := 20005
	got, err := fx.mgr.bind(fx.as, want, "example.com")
	if err != nil {
		t.Fatalf("specific bind: %v", err)
	}
	if got != want {
		t.Fatalf("specific port not honored: want %d got %d", want, got)
	}

	if _, err := fx.mgr.bind(fx.as, want, "example.com"); err != errPortUnavailable {
		t.Fatalf("second request for taken port should be errPortUnavailable, got %v", err)
	}

	if _, err := fx.mgr.bind(fx.as, 30000, "example.com"); err != errPortUnavailable {
		t.Fatalf("out-of-range port should be errPortUnavailable, got %v", err)
	}
}

func TestTCPConcurrentBindsNeverDoubleAllocate(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()

	total := fx.mgr.hi - fx.mgr.lo + 1
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := make(map[int]int)
	var okCount int

	for i := 0; i < total*2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := fx.mgr.bind(fx.as, 0, "example.com")
			if err != nil {
				return
			}
			mu.Lock()
			seen[p]++
			okCount++
			mu.Unlock()
		}()
	}
	wg.Wait()

	if okCount != total {
		t.Fatalf("expected exactly %d successful binds, got %d", total, okCount)
	}
	for p, c := range seen {
		if c != 1 {
			t.Fatalf("port %d allocated %d times (double allocation)", p, c)
		}
	}
}

func TestTCPEndToEndEchoSequential(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()

	port, err := fx.mgr.bind(fx.as, 0, "example.com")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	for i := 0; i < 5; i++ {
		func() {
			c := dialPort(t, port)
			defer c.Close()
			payload := []byte(fmt.Sprintf("hello-%d", i))
			c.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := c.Write(payload); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, len(payload))
			if _, err := io.ReadFull(c, buf); err != nil {
				t.Fatalf("read echo: %v", err)
			}
			if !bytes.Equal(buf, payload) {
				t.Fatalf("echo mismatch: got %q want %q", buf, payload)
			}
		}()
	}
}

func TestTCPEndToEndEchoConcurrent(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()

	port, err := fx.mgr.bind(fx.as, 0, "example.com")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	const n = 16
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
			if err != nil {
				errCh <- err
				return
			}
			defer c.Close()
			payload := []byte(fmt.Sprintf("conn-%02d-payload", i))
			c.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := c.Write(payload); err != nil {
				errCh <- err
				return
			}
			buf := make([]byte, len(payload))
			if _, err := io.ReadFull(c, buf); err != nil {
				errCh <- err
				return
			}
			if !bytes.Equal(buf, payload) {
				errCh <- fmt.Errorf("mismatch %q != %q", buf, payload)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent echo error: %v", err)
	}
}

func TestTCPHalfClosePropagation(t *testing.T) {
	agentReady := make(chan net.Conn, 1)
	handler := func(conn net.Conn, _ proto.StreamOpen) {
		agentReady <- conn
	}
	fx := newTCPFixture(t, handler)
	defer fx.cleanup()

	port, err := fx.mgr.bind(fx.as, 0, "example.com")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	client := dialPort(t, port)
	defer client.Close()

	client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write([]byte("BANNER")); err != nil {
		t.Fatalf("client write banner: %v", err)
	}

	var agentConn net.Conn
	select {
	case agentConn = <-agentReady:
	case <-time.After(5 * time.Second):
		t.Fatalf("agent side never received the stream")
	}
	defer agentConn.Close()
	agentConn.SetDeadline(time.Now().Add(5 * time.Second))

	banner := make([]byte, len("BANNER"))
	if _, err := io.ReadFull(agentConn, banner); err != nil {
		t.Fatalf("agent read banner: %v", err)
	}
	if string(banner) != "BANNER" {
		t.Fatalf("banner mismatch: %q", banner)
	}

	tcpClient, ok := client.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("client conn does not support CloseWrite; test would not exercise half-close")
	}
	if err := tcpClient.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}

	if _, err := io.ReadAll(agentConn); err != nil {
		t.Fatalf("agent read after client half-close should hit clean EOF, got: %v", err)
	}

	reply := []byte("SERVER-STILL-TALKING")
	if _, err := agentConn.Write(reply); err != nil {
		t.Fatalf("agent write after client half-close (receive direction must stay open): %v", err)
	}
	if cw, ok := agentConn.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		agentConn.Close()
	}

	got := make([]byte, len(reply))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("client read reply after its own half-close: %v", err)
	}
	if !bytes.Equal(got, reply) {
		t.Fatalf("reply mismatch: got %q want %q", got, reply)
	}
}

func TestTCPHalfCloseAgentSideClientKeepsSending(t *testing.T) {
	type agentResult struct {
		got []byte
		err error
	}
	resultCh := make(chan agentResult, 1)
	handler := func(conn net.Conn, _ proto.StreamOpen) {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte("AGENTBANNER")); err != nil {
			resultCh <- agentResult{nil, fmt.Errorf("agent write banner: %w", err)}
			return
		}
		conn.Close()
		got, err := io.ReadAll(conn)
		resultCh <- agentResult{got, err}
	}

	fx := newTCPFixture(t, handler)
	defer fx.cleanup()

	port, err := fx.mgr.bind(fx.as, 0, "example.com")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	client := dialPort(t, port)
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))

	banner := make([]byte, len("AGENTBANNER"))
	if _, err := io.ReadFull(client, banner); err != nil {
		t.Fatalf("client read banner: %v", err)
	}
	if string(banner) != "AGENTBANNER" {
		t.Fatalf("banner mismatch: %q", banner)
	}

	if _, err := io.ReadAll(client); err != nil {
		t.Fatalf("client read side should hit a clean EOF after agent half-close, got: %v", err)
	}

	after := []byte("CLIENT-STILL-SENDING")
	if _, err := client.Write(after); err != nil {
		t.Fatalf("client write after agent half-close (send direction must survive; full-close would kill it): %v", err)
	}
	if cw, ok := client.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}

	select {
	case r := <-resultCh:
		if r.err != nil {
			t.Fatalf("agent read after half-close: %v", r.err)
		}
		if !bytes.Equal(r.got, after) {
			t.Fatalf("agent did not receive client's post-half-close data: got %q want %q (the client->agent direction was torn down by a full close instead of a write half-close)", r.got, after)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("agent never returned the client's post-half-close data; the client->agent direction was likely closed by a full close")
	}
}

func TestTCPReleaseClosesListenersAndRefusesConnect(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()

	port, err := fx.mgr.bind(fx.as, 0, "example.com")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	c := dialPort(t, port)
	c.Close()

	fx.mgr.releaseSession(fx.as)

	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
		if err != nil {
			break
		}
		conn.Close()
		if time.Now().After(deadline) {
			t.Fatalf("port %d still accepting connections after release", port)
		}
		time.Sleep(20 * time.Millisecond)
	}

	fx.mgr.mu.Lock()
	_, taken := fx.mgr.allocated[port]
	fx.mgr.mu.Unlock()
	if taken {
		t.Fatalf("port %d still marked allocated after release", port)
	}
}

func TestTCPReleaseIsIdempotent(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()

	port, err := fx.mgr.bind(fx.as, 0, "example.com")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	fx.mgr.releaseSession(fx.as)
	fx.mgr.releaseSession(fx.as)

	p2, err := fx.mgr.bind(fx.as, port, "example.com")
	if err != nil {
		t.Fatalf("re-bind after double release: %v", err)
	}
	if p2 != port {
		t.Fatalf("expected reuse of %d, got %d", port, p2)
	}
}

func TestTCPPortInUseRollsBackAllocation(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()

	occupied := 20007
	blocker, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(occupied)))
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer blocker.Close()

	if _, err := fx.mgr.bind(fx.as, occupied, "example.com"); err == nil {
		t.Fatalf("bind on externally-occupied port should fail")
	}

	fx.mgr.mu.Lock()
	_, taken := fx.mgr.allocated[occupied]
	fx.mgr.mu.Unlock()
	if taken {
		t.Fatalf("port %d must not stay in the free-list after a failed listen", occupied)
	}

	blocker.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		p, err := fx.mgr.bind(fx.as, occupied, "example.com")
		if err == nil {
			if p != occupied {
				t.Fatalf("expected to rebind %d, got %d", occupied, p)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("could not rebind %d after blocker released: %v", occupied, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTCPBackpressureClosesWhenStreamSemFull(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()
	fx.as.streamSem = newGlobalSemaphore(0)

	port, err := fx.mgr.bind(fx.as, 0, "example.com")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	c := dialPort(t, port)
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	_, err = c.Read(buf)
	if err == nil {
		t.Fatalf("expected connection to be closed under backpressure, read succeeded")
	}
}

func TestTCPReleasesStreamSlot(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()
	fx.as.streamSem = newGlobalSemaphore(1)

	port, err := fx.mgr.bind(fx.as, 0, "example.com")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	attempt := func(tag string) error {
		c := dialPort(t, port)
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		payload := []byte(tag)
		if _, err := c.Write(payload); err != nil {
			return err
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(c, buf); err != nil {
			return err
		}
		return nil
	}

	roundTrip := func(tag string) {
		deadline := time.Now().Add(3 * time.Second)
		for {
			if err := attempt(tag); err == nil {
				return
			} else if time.Now().After(deadline) {
				t.Fatalf("%s round trip never succeeded within deadline; the single stream slot is not being released after a conn finishes: %v", tag, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	roundTrip("first")
	roundTrip("second")
	roundTrip("third")
}

func TestTCPInflightDrainsAfterRelease(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()

	port, err := fx.mgr.bind(fx.as, 0, "example.com")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	c := dialPort(t, port)
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("drain")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	c.Close()

	fx.mgr.releaseSession(fx.as)

	done := make(chan struct{})
	go func() {
		fx.as.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("inflight never drained to zero after conn teardown (inflight.Done not called per conn)")
	}
}

func TestTCPNoGoroutineLeak(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()

	runtime.GC()
	before := runtime.NumGoroutine()

	for round := 0; round < 5; round++ {
		port, err := fx.mgr.bind(fx.as, 0, "example.com")
		if err != nil {
			t.Fatalf("bind: %v", err)
		}
		for i := 0; i < 4; i++ {
			c := dialPort(t, port)
			c.SetDeadline(time.Now().Add(3 * time.Second))
			payload := []byte("leakcheck")
			if _, err := c.Write(payload); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, len(payload))
			if _, err := io.ReadFull(c, buf); err != nil {
				t.Fatalf("read: %v", err)
			}
			c.Close()
		}
		fx.mgr.releaseSession(fx.as)
	}

	deadline := time.Now().Add(3 * time.Second)
	var after int
	for {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
		after = runtime.NumGoroutine()
		if after <= before+5 || time.Now().After(deadline) {
			break
		}
	}
	if after > before+5 {
		t.Fatalf("goroutine leak: before=%d after=%d", before, after)
	}
}

func TestParseTCPPortRange(t *testing.T) {
	cases := []struct {
		in      string
		lo, hi  int
		wantErr bool
	}{
		{"10000-10999", 10000, 10999, false},
		{" 10000 - 10999 ", 10000, 10999, false},
		{"10000", 0, 0, true},
		{"10999-10000", 0, 0, true},
		{"0-100", 0, 0, true},
		{"1-70000", 0, 0, true},
		{"abc-def", 0, 0, true},
		{"", 0, 0, true},
	}
	for _, c := range cases {
		lo, hi, err := parseTCPPortRange(c.in)
		if c.wantErr {
			if err == nil {
				t.Fatalf("parseTCPPortRange(%q) expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseTCPPortRange(%q): %v", c.in, err)
		}
		if lo != c.lo || hi != c.hi {
			t.Fatalf("parseTCPPortRange(%q) = %d,%d want %d,%d", c.in, lo, hi, c.lo, c.hi)
		}
	}
}

func TestTCPBindDisabledWhenRangeEmpty(t *testing.T) {
	s, err := New(Config{
		Domain:       "example.com",
		TokenSHA256:  sumToken("tok"),
		PublicScheme: "https",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.tcpMgr != nil {
		t.Fatalf("tcpMgr must be nil when TCPPortRange is empty")
	}

	client, server, cleanup := newRawSessionPair(t)
	defer cleanup()

	as := &AgentSession{ID: "x", InstanceID: "i", Sess: server, IDGen: proto.NewEdgeIDGen()}

	go func() {
		client.Control().Write(proto.TypeBind, 1, proto.Bind{Kind: proto.KindTCP})
	}()
	msg, err := server.Control().Read()
	if err != nil {
		t.Fatalf("read bind: %v", err)
	}
	bind, err := proto.Decode[proto.Bind](msg)
	if err != nil {
		t.Fatalf("decode bind: %v", err)
	}
	s.handleBind(as, server.Control(), msg.ID, bind)

	reply, err := client.Control().Read()
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply.Type != proto.TypeBindErr {
		t.Fatalf("reply type = %q, want %q", reply.Type, proto.TypeBindErr)
	}
	e, err := proto.Decode[proto.BindErr](reply)
	if err != nil {
		t.Fatalf("decode bind err: %v", err)
	}
	if e.Code != proto.CodeKindUnsupported {
		t.Fatalf("code = %q, want %q", e.Code, proto.CodeKindUnsupported)
	}
}

func TestNewInvalidTCPRangeIsStartupError(t *testing.T) {
	_, err := New(Config{
		Domain:       "example.com",
		TokenSHA256:  sumToken("tok"),
		PublicScheme: "https",
		TCPPortRange: "not-a-range-9",
	})
	if err == nil {
		t.Fatalf("expected startup error for invalid TCP port range")
	}
}

func TestTCPBindEndToEndOverControlPlane(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()

	s := newTestServer("tok")
	s.tcpMgr = fx.mgr

	ctrl := fx.as.Sess.Control()
	handled := make(chan struct{})
	go func() {
		s.handleBindTCP(fx.as, ctrl, 42, proto.Bind{Kind: proto.KindTCP})
		close(handled)
	}()

	reply, err := fx.agent.Control().Read()
	if err != nil {
		t.Fatalf("agent read bind reply: %v", err)
	}
	<-handled
	if reply.Type != proto.TypeBindOK || reply.ID != 42 {
		t.Fatalf("reply = %+v, want bind_ok id=42", reply)
	}
	ok, err := proto.Decode[proto.BindOK](reply)
	if err != nil {
		t.Fatalf("decode bind ok: %v", err)
	}
	if ok.Port < 20000 || ok.Port > 20009 {
		t.Fatalf("bind ok port %d out of range", ok.Port)
	}
	if ok.Hostname != "example.com" {
		t.Fatalf("hostname = %q, want example.com", ok.Hostname)
	}
	wantURL := "tcp://example.com:" + strconv.Itoa(ok.Port)
	if ok.URL != wantURL {
		t.Fatalf("url = %q, want %q", ok.URL, wantURL)
	}

	c := dialPort(t, ok.Port)
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo mismatch: %q", buf)
	}
}
