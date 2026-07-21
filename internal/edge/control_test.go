package edge

import (
	"crypto/sha256"
	"net"
	"net/netip"
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
	return &Server{
		cfg:         Config{Domain: "example.com", TokenSHA256: sum[:]},
		registry:    NewRegistry(),
		authLimiter: newAuthRateLimiter(),
	}
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
	if v, ok := negotiateVersion([]int{1}); !ok || v != proto.ProtoVersion {
		t.Fatalf("negotiateVersion([1]) = (%d,%v), want (%d,true)", v, ok, proto.ProtoVersion)
	}
	if _, ok := negotiateVersion([]int{2, 3}); ok {
		t.Fatalf("negotiateVersion([2,3]) should report no common version")
	}
	if _, ok := negotiateVersion(nil); ok {
		t.Fatalf("negotiateVersion(nil) should report no common version")
	}
}
