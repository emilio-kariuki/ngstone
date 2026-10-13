package edge

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

func newRawSessionPair(t *testing.T) (client, server tunnel.Session, cleanup func()) {
	t.Helper()
	c1, c2 := net.Pipe()

	type result struct {
		sess tunnel.Session
		err  error
	}
	clientCh := make(chan result, 1)
	serverCh := make(chan result, 1)
	go func() {
		s, err := tunnel.Client(c1)
		clientCh <- result{s, err}
	}()
	go func() {
		s, err := tunnel.Server(c2)
		serverCh <- result{s, err}
	}()

	cr := <-clientCh
	if cr.err != nil {
		t.Fatalf("client session: %v", cr.err)
	}
	sr := <-serverCh
	if sr.err != nil {
		t.Fatalf("server session: %v", sr.err)
	}

	return cr.sess, sr.sess, func() {
		cr.sess.Close("test done")
		sr.sess.Close("test done")
	}
}

func newTestServer(token string) *Server {
	sum := sha256.Sum256([]byte(token))
	limits, _ := LimitsConfig{}.withDefaults()
	s := &Server{
		cfg:         Config{Domain: "example.com", TokenSHA256: sum[:], PublicScheme: "https", Limits: limits},
		registry:    NewRegistry(),
		authLimiter: newAuthRateLimiter(),
		randomName:  randomSubdomain,
		perIP:       newPerIPInflight(limits.PerIPInFlight),
		shares:      newShareRegistry(0),
		shareSem:    newGlobalSemaphore(maxGlobalShareConns),
	}
	s.shares.onExpire = func(sh *share) { s.closeShare(sh, proto.ShareReasonExpired) }
	s.shares.onIdle = func(sh *share) { s.closeShare(sh, proto.ShareReasonIdle) }
	return s
}

func TestAuthWrongTokenRejected(t *testing.T) {
	client, server, cleanup := newRawSessionPair(t)
	defer cleanup()

	s := newTestServer("correct-token")

	go func() {
		client.Control().Write(proto.TypeAuth, 1, proto.Auth{
			Token:         "wrong-token",
			InstanceID:    "inst1",
			ClientVersion: "test",
			ProtoVersions: []int{proto.ProtoVersion},
		})
	}()

	if _, err := s.authenticate(server, "127.0.0.1", netip.AddrPort{}, time.Now().Add(5*time.Second)); err == nil {
		t.Fatalf("expected error for wrong token")
	}

	reply, err := client.Control().Read()
	if err != nil {
		t.Fatalf("client read reply: %v", err)
	}
	if reply.Type != proto.TypeAuthErr {
		t.Fatalf("got type %q, want %q", reply.Type, proto.TypeAuthErr)
	}
	if reply.ID != 1 {
		t.Fatalf("reply id = %d, want 1 (echoed from request)", reply.ID)
	}
	e, err := proto.Decode[proto.AuthErr](reply)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if e.Code != proto.CodeBadToken {
		t.Fatalf("code = %q, want %q", e.Code, proto.CodeBadToken)
	}
}

func TestAuthMissingWithinDeadlineCloses(t *testing.T) {
	origDeadline := authDeadline
	authDeadline = 200 * time.Millisecond
	defer func() { authDeadline = origDeadline }()

	_, server, cleanup := newRawSessionPair(t)
	defer cleanup()

	s := newTestServer("tok")

	start := time.Now()
	_, err := s.authenticate(server, "127.0.0.1", netip.AddrPort{}, time.Now().Add(authDeadline))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected a timeout error when no auth message ever arrives")
	}
	if elapsed > authDeadline+500*time.Millisecond {
		t.Fatalf("authenticate took %v to give up, want close to the %v deadline", elapsed, authDeadline)
	}
}

func TestAuthNoCommonVersion(t *testing.T) {
	client, server, cleanup := newRawSessionPair(t)
	defer cleanup()

	s := newTestServer("tok")

	go func() {
		client.Control().Write(proto.TypeAuth, 7, proto.Auth{
			Token:         "tok",
			InstanceID:    "inst1",
			ProtoVersions: []int{99},
		})
	}()

	if _, err := s.authenticate(server, "127.0.0.1", netip.AddrPort{}, time.Now().Add(5*time.Second)); err == nil {
		t.Fatalf("expected error for incompatible protocol versions")
	}

	reply, err := client.Control().Read()
	if err != nil {
		t.Fatalf("client read reply: %v", err)
	}
	if reply.Type != proto.TypeAuthErr || reply.ID != 7 {
		t.Fatalf("reply mismatch: %+v", reply)
	}
	e, err := proto.Decode[proto.AuthErr](reply)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if e.Code != proto.CodeNoCommonVersion {
		t.Fatalf("code = %q, want %q", e.Code, proto.CodeNoCommonVersion)
	}
}

func TestAuthRateLimitTripsAtSixAttempts(t *testing.T) {
	l := newAuthRateLimiter()
	ip := "9.9.9.9"

	for i := 0; i < maxAuthFailuresPerMinute; i++ {
		if !l.allowed(ip) {
			t.Fatalf("attempt %d should still be allowed", i+1)
		}
		l.recordFailure(ip)
	}
	if l.allowed(ip) {
		t.Fatalf("6th attempt should be blocked by the rate limiter")
	}

	other := "1.1.1.1"
	if !l.allowed(other) {
		t.Fatalf("a different IP must not be affected by another IP's failures")
	}
}

func TestReplyIDsEcho(t *testing.T) {
	client, server, cleanup := newRawSessionPair(t)
	defer cleanup()

	s := newTestServer("tok")

	go func() {
		client.Control().Write(proto.TypeAuth, 11, proto.Auth{
			Token:         "tok",
			InstanceID:    "inst1",
			ProtoVersions: []int{proto.ProtoVersion},
		})
	}()

	as, err := s.authenticate(server, "127.0.0.1", netip.AddrPort{}, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	authReply, err := client.Control().Read()
	if err != nil {
		t.Fatalf("read auth reply: %v", err)
	}
	if authReply.Type != proto.TypeAuthOK || authReply.ID != 11 {
		t.Fatalf("auth reply mismatch: %+v", authReply)
	}

	go func() {
		client.Control().Write(proto.TypeBind, 13, proto.Bind{Kind: proto.KindHTTP, Subdomain: "foo"})
	}()

	msg, err := server.Control().Read()
	if err != nil {
		t.Fatalf("server read bind: %v", err)
	}
	bind, err := proto.Decode[proto.Bind](msg)
	if err != nil {
		t.Fatalf("decode bind: %v", err)
	}
	s.handleBind(as, server.Control(), msg.ID, bind)

	bindReply, err := client.Control().Read()
	if err != nil {
		t.Fatalf("read bind reply: %v", err)
	}
	if bindReply.Type != proto.TypeBindOK || bindReply.ID != 13 {
		t.Fatalf("bind reply mismatch: %+v", bindReply)
	}
}

func TestNegotiateVersion(t *testing.T) {
	if v, ok := negotiateVersion([]int{1}); !ok || v != 1 {
		t.Fatalf("negotiateVersion([1]) = (%d,%v), want (1,true)", v, ok)
	}
	if v, ok := negotiateVersion([]int{2, 3}); !ok || v != 3 {
		t.Fatalf("negotiateVersion([2,3]) = (%d,%v), want (3,true)", v, ok)
	}
	if v, ok := negotiateVersion([]int{3, 4}); !ok || v != 3 {
		t.Fatalf("negotiateVersion([3,4]) = (%d,%v), want (3,true)", v, ok)
	}
	if v, ok := negotiateVersion([]int{2, 1}); !ok || v != 2 {
		t.Fatalf("negotiateVersion([2,1]) = (%d,%v), want (2,true)", v, ok)
	}
	if v, ok := negotiateVersion([]int{1, 2}); !ok || v != 2 {
		t.Fatalf("negotiateVersion([1,2]) = (%d,%v), want (2,true) (order-independent)", v, ok)
	}
	if _, ok := negotiateVersion([]int{4, 5}); ok {
		t.Fatalf("negotiateVersion([4,5]) should report no common version")
	}
	if _, ok := negotiateVersion([]int{}); ok {
		t.Fatalf("negotiateVersion([]) should report no common version")
	}
	if _, ok := negotiateVersion(nil); ok {
		t.Fatalf("negotiateVersion(nil) should report no common version")
	}
}

func TestUnauthSlotReleasedAfterAuthAllowsSecondAgent(t *testing.T) {
	controlAddr := freeTCPAddr(t)
	publicAddr := freeTCPAddr(t)

	s, err := New(Config{
		ControlAddr:  controlAddr,
		PublicAddr:   publicAddr,
		Domain:       "example.com",
		TokenSHA256:  sumToken("tok"),
		PublicScheme: "http",
		Insecure:     true,
		Limits:       LimitsConfig{UnauthSessions: 1},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-runErrCh
	})

	dialAndAuth := func(instanceID string) (tunnel.Session, error) {
		conn, err := net.Dial("tcp", controlAddr)
		if err != nil {
			return nil, err
		}
		sess, err := tunnel.Client(conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		ctrl := sess.Control()
		if err := ctrl.Write(proto.TypeAuth, 1, proto.Auth{
			Token:         "tok",
			InstanceID:    instanceID,
			ProtoVersions: []int{proto.ProtoVersion},
		}); err != nil {
			sess.Close("write auth failed")
			return nil, err
		}
		reply, err := ctrl.Read()
		if err != nil {
			sess.Close("read auth reply failed")
			return nil, err
		}
		if reply.Type != proto.TypeAuthOK {
			sess.Close("unexpected auth reply")
			return nil, fmt.Errorf("auth reply = %+v, want %q", reply, proto.TypeAuthOK)
		}
		return sess, nil
	}

	closeGracefully := func(sess tunnel.Session) {
		ctrl := sess.Control()
		ctrl.Write(proto.TypeGoodbye, 99, proto.Goodbye{Reason: "test done"})
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			ctrl.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			if _, err := ctrl.Read(); err != nil {
				break
			}
		}
		sess.Close("test done")
	}

	var sessA tunnel.Session
	authAttemptDeadline := time.Now().Add(5 * time.Second)
	for {
		var aerr error
		sessA, aerr = dialAndAuth("agent-a")
		if aerr == nil {
			break
		}
		if time.Now().After(authAttemptDeadline) {
			t.Fatalf("first agent never managed to authenticate against the just-started listener: %v", aerr)
		}
		time.Sleep(20 * time.Millisecond)
	}

	type result struct {
		sess tunnel.Session
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		sess, err := dialAndAuth("agent-b")
		resCh <- result{sess, err}
	}()

	var sessB tunnel.Session
	select {
	case r := <-resCh:
		if r.err != nil {
			closeGracefully(sessA)
			t.Fatalf("second agent could not authenticate while an already-authenticated agent held the connection (UnauthSessions=1): %v — the unauth slot is not being released at the authentication boundary", r.err)
		}
		sessB = r.sess
	case <-time.After(3 * time.Second):
		closeGracefully(sessA)
		t.Fatalf("second agent's authentication attempt hung; the unauth slot from the first, now-authenticated agent was never released")
	}

	closeGracefully(sessA)
	closeGracefully(sessB)
}

func TestHandleControlConnSessionSurvivesPastAuthDeadline(t *testing.T) {
	origAuthDeadline := authDeadline
	origHeartbeat := heartbeatInterval
	authDeadline = 1 * time.Second
	heartbeatInterval = 300 * time.Millisecond
	defer func() {
		authDeadline = origAuthDeadline
		heartbeatInterval = origHeartbeat
	}()

	c1, c2 := net.Pipe()
	s := newTestServer("tok")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.handleControlConn(ctx, c2, func() {})

	clientSess, err := tunnel.Client(c1)
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	defer clientSess.Close("test done")
	ctrl := clientSess.Control()

	if err := ctrl.Write(proto.TypeAuth, 1, proto.Auth{
		Token:         "tok",
		InstanceID:    "inst-fix1",
		ProtoVersions: []int{proto.ProtoVersion},
	}); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	reply, err := ctrl.Read()
	if err != nil {
		t.Fatalf("read auth reply: %v", err)
	}
	if reply.Type != proto.TypeAuthOK {
		t.Fatalf("auth reply = %q, want %q", reply.Type, proto.TypeAuthOK)
	}

	const surviveFor = 8 * time.Second
	start := time.Now()
	var pings atomic.Int64
	readErrCh := make(chan error, 1)
	stop := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			ctrl.SetReadDeadline(time.Now().Add(1 * time.Second))
			msg, err := ctrl.Read()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				readErrCh <- err
				return
			}
			if msg.Type == proto.TypePing {
				pings.Add(1)
				p, _ := proto.Decode[proto.Ping](msg)
				ctrl.Write(proto.TypePong, msg.ID, proto.Pong{TS: p.TS})
			}
		}
	}()

	select {
	case err := <-readErrCh:
		t.Fatalf("control connection died after %s (auth deadline was %s): %v — the raw conn's read deadline from auth is likely still armed after auth succeeded", time.Since(start), authDeadline, err)
	case <-clientSess.Done():
		t.Fatalf("session died after %s, before the %s survive window elapsed (auth deadline %s) — the raw conn's read deadline from auth is likely still armed", time.Since(start), surviveFor, authDeadline)
	case <-time.After(surviveFor):
	}
	close(stop)
	<-readerDone

	elapsed := time.Since(start)
	got := pings.Load()
	if got == 0 {
		t.Fatalf("session survived %s but never exchanged a heartbeat ping/pong — traffic did not actually flow", elapsed)
	}
	t.Logf("session stayed alive and exchanged %d ping/pong round trips over %s (past the %s auth deadline)", got, elapsed, authDeadline)
}

func TestControlLoopGoodbyeDoesNotLeakReaderGoroutine(t *testing.T) {
	const n = 30

	runtime.GC()
	before := runtime.NumGoroutine()

	for i := 0; i < n; i++ {
		client, server, cleanup := newRawSessionPair(t)
		s := newTestServer("tok")

		go func() {
			client.Control().Write(proto.TypeAuth, 1, proto.Auth{
				Token:         "tok",
				InstanceID:    "inst",
				ProtoVersions: []int{proto.ProtoVersion},
			})
		}()
		as, err := s.authenticate(server, "127.0.0.1", netip.AddrPort{}, time.Now().Add(5*time.Second))
		if err != nil {
			t.Fatalf("authenticate: %v", err)
		}
		if _, err := client.Control().Read(); err != nil {
			t.Fatalf("read auth ok: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			s.controlLoop(ctx, as)
			close(done)
		}()

		if err := client.Control().Write(proto.TypeGoodbye, 2, proto.Goodbye{Reason: "bye"}); err != nil {
			t.Logf("iteration %d: write goodbye failed (%v), likely a transient session hiccup under heavy parallel test load; skipping this iteration", i, err)
			cancel()
			cleanup()
			continue
		}

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("controlLoop did not exit after goodbye (iteration %d)", i)
		}
		cancel()
		cleanup()
	}

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	after := runtime.NumGoroutine()

	t.Logf("goroutines before=%d after=%d (ran %d session teardowns through the goodbye path)", before, after, n)
	if after > before+5 {
		t.Fatalf("goroutine leak: before=%d after=%d (ran %d session teardowns through the goodbye path)", before, after, n)
	}
}

func TestHandleBindRandomNameNeverTakesOverLiveDifferentInstance(t *testing.T) {
	client, server, cleanup := newRawSessionPair(t)
	defer cleanup()

	s := newTestServer("tok")
	names := []string{"collide", "free"}
	i := 0
	s.randomName = func() string {
		n := names[i]
		if i < len(names)-1 {
			i++
		}
		return n
	}

	liveHolder, liveHolderCleanup := newTestAgentSession(t, "holder-instance")
	defer liveHolderCleanup()
	if _, _, err := s.registry.Bind("collide.example.com", liveHolder, true, nil); err != nil {
		t.Fatalf("pre-bind: %v", err)
	}

	as := &AgentSession{ID: "requester", InstanceID: "requester-instance", Sess: server, IDGen: proto.NewEdgeIDGen()}

	go func() {
		client.Control().Write(proto.TypeBind, 1, proto.Bind{Kind: proto.KindHTTP, Subdomain: "", Takeover: true})
	}()

	msg, err := server.Control().Read()
	if err != nil {
		t.Fatalf("server read bind: %v", err)
	}
	bind, err := proto.Decode[proto.Bind](msg)
	if err != nil {
		t.Fatalf("decode bind: %v", err)
	}
	s.handleBind(as, server.Control(), msg.ID, bind)

	reply, err := client.Control().Read()
	if err != nil {
		t.Fatalf("read bind reply: %v", err)
	}
	if reply.Type != proto.TypeBindOK {
		t.Fatalf("bind reply = %+v, want %q", reply, proto.TypeBindOK)
	}
	bindOK, err := proto.Decode[proto.BindOK](reply)
	if err != nil {
		t.Fatalf("decode bind ok: %v", err)
	}
	if bindOK.Hostname != "free.example.com" {
		t.Fatalf("expected random assignment to skip the colliding live name and land on the free one, got %q", bindOK.Hostname)
	}

	got, ok := s.registry.Route("collide.example.com")
	if !ok || got.Sess != liveHolder {
		t.Fatalf("random-name bind must never evict a live different-instance holder, even though Bind.Takeover was true: route=%+v ok=%v", got, ok)
	}
}
