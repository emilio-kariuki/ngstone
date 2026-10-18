package edge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

func testShareReq(secret string, ttl time.Duration) proto.Share {
	sum := sha256.Sum256([]byte(secret))
	return proto.Share{
		Kind:         proto.KindTCP,
		SecretSHA256: hex.EncodeToString(sum[:]),
		Label:        "staging replica",
		Targets:      []proto.ShareTarget{{ID: "t1", Preset: "postgres", DefaultPort: 5432}},
		ExpiresAtMS:  time.Now().Add(ttl).UnixMilli(),
	}
}

// connectFor admits and joins as under name, the way handleConnect does
// for a share without approval.
func connectFor(r *shareRegistry, sh *share, as *AgentSession, name string) (string, error) {
	id, err := r.admit(sh, as, proto.Connect{Name: name}, nil)
	if err != nil {
		return "", err
	}
	if err := r.join(sh, as, id); err != nil {
		return "", err
	}
	return id, nil
}

func testSession(instanceID string, remote string) *AgentSession {
	as := &AgentSession{
		ID:         randomHex(4),
		InstanceID: instanceID,
		IDGen:      proto.NewEdgeIDGen(),
		Scope:      proto.ScopeOperator,
	}
	if remote != "" {
		as.Remote = netip.MustParseAddrPort(remote)
	}
	return as
}

func TestShareValidateRejectsBadRequests(t *testing.T) {
	r := newShareRegistry(time.Hour)
	now := time.Now()
	good := testShareReq("s", 10*time.Minute)

	cases := map[string]func(req *proto.Share){
		"http kind":          func(req *proto.Share) { req.Kind = proto.KindHTTP },
		"short hash":         func(req *proto.Share) { req.SecretSHA256 = "abcd" },
		"non-hex hash":       func(req *proto.Share) { req.SecretSHA256 = "zz" + req.SecretSHA256[2:] },
		"past expiry":        func(req *proto.Share) { req.ExpiresAtMS = now.Add(-time.Second).UnixMilli() },
		"zero expiry":        func(req *proto.Share) { req.ExpiresAtMS = 0 },
		"bad preset":         func(req *proto.Share) { req.Targets[0].Preset = "mongo" },
		"no targets":         func(req *proto.Share) { req.Targets = nil },
		"bad target id":      func(req *proto.Share) { req.Targets[0].ID = "T 1" },
		"short idle":         func(req *proto.Share) { req.IdleTimeoutMS = 1000 },
		"bad pass hash":      func(req *proto.Share) { req.PassphraseSHA256 = "zz" },
		"control char label": func(req *proto.Share) { req.Label = "a\x00b" },
		"huge max_conns":     func(req *proto.Share) { req.MaxConns = maxShareMaxConns + 1 },
		"bad cidr":           func(req *proto.Share) { req.AllowCIDRs = []string{"not-a-cidr"} },
		"port out of range":  func(req *proto.Share) { req.Targets[0].DefaultPort = 70000 },
	}
	for name, mutate := range cases {
		req := good
		req.Targets = append([]proto.ShareTarget(nil), good.Targets...)
		mutate(&req)
		if _, err := r.validateShare(req, now); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}

	if _, err := r.validateShare(testShareReq("s", 2*time.Hour), now); !errors.Is(err, errShareTTLTooLong) {
		t.Fatalf("ttl beyond max: err = %v, want errShareTTLTooLong", err)
	}

	sh, err := r.validateShare(good, now)
	if err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	if sh.policy.maxConns != defaultShareMaxConns || sh.policy.maxConnectors != defaultShareMaxConnectors {
		t.Fatalf("defaults not applied: %+v", sh.policy)
	}
}

func TestShareRegisterLimitsAndTakeover(t *testing.T) {
	r := newShareRegistry(time.Hour)
	owner := testSession("inst-a", "")

	for i := 0; i < maxSharesPerSession; i++ {
		sh, err := r.validateShare(testShareReq("secret-"+string(rune('a'+i)), time.Minute), time.Now())
		if err != nil {
			t.Fatalf("validate %d: %v", i, err)
		}
		if _, err := r.register(owner, sh); err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
	}
	extra, _ := r.validateShare(testShareReq("one-too-many", time.Minute), time.Now())
	if _, err := r.register(owner, extra); !errors.Is(err, errTooManyShares) {
		t.Fatalf("9th share: err = %v, want errTooManyShares", err)
	}
	if r.count() != maxSharesPerSession {
		t.Fatalf("count = %d, want %d", r.count(), maxSharesPerSession)
	}

	// Same secret from a different instance is refused.
	other := testSession("inst-b", "")
	dup, _ := r.validateShare(testShareReq("secret-a", time.Minute), time.Now())
	if _, err := r.register(other, dup); !errors.Is(err, errShareTaken) {
		t.Fatalf("different instance: err = %v, want errShareTaken", err)
	}

	// Same secret from the same instance (reconnect) replaces the old share.
	reconnected := testSession("inst-a", "")
	again, _ := r.validateShare(testShareReq("secret-a", time.Minute), time.Now())
	replaced, err := r.register(reconnected, again)
	if err != nil {
		t.Fatalf("same instance re-register: %v", err)
	}
	if replaced == nil {
		t.Fatalf("expected the old share to be returned for closing")
	}
	if got, ok := r.lookup("secret-a"); !ok || got != again {
		t.Fatalf("lookup after re-register returned %v, %v; want the new share", got, ok)
	}
	if r.count() != maxSharesPerSession {
		t.Fatalf("count after replace = %d, want %d", r.count(), maxSharesPerSession)
	}
}

func TestShareLookupIgnoresClosedAndExpired(t *testing.T) {
	r := newShareRegistry(time.Hour)
	owner := testSession("inst-a", "")
	sh, _ := r.validateShare(testShareReq("s", time.Minute), time.Now())
	if _, err := r.register(owner, sh); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.lookup("s"); !ok {
		t.Fatalf("live share not found")
	}
	if _, ok := r.lookup("wrong"); ok {
		t.Fatalf("unknown secret found")
	}

	r.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if _, ok := r.lookup("s"); ok {
		t.Fatalf("expired share should not be found")
	}
	r.now = time.Now

	if _, _, _, ok := r.close(sh, proto.ShareReasonRevoked); !ok {
		t.Fatalf("first close should report ok")
	}
	if _, _, _, ok := r.close(sh, proto.ShareReasonRevoked); ok {
		t.Fatalf("second close must be a no-op")
	}
	if _, ok := r.lookup("s"); ok {
		t.Fatalf("closed share should not be found")
	}
	if r.count() != 0 {
		t.Fatalf("count after close = %d, want 0", r.count())
	}
}

func TestShareConnectPolicy(t *testing.T) {
	r := newShareRegistry(time.Hour)
	owner := testSession("inst-a", "")
	req := testShareReq("s", time.Minute)
	req.AllowCIDRs = []string{"203.0.113.0/24"}
	req.MaxConnectors = 1
	req.SingleUse = true
	sh, err := r.validateShare(req, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.register(owner, sh); err != nil {
		t.Fatal(err)
	}

	outside := testSession("c-out", "198.51.100.7:1000")
	if _, err := connectFor(r, sh, outside, ""); !errors.Is(err, errShareForbidden) {
		t.Fatalf("outside allow list: err = %v, want errShareForbidden", err)
	}

	first := testSession("c-1", "203.0.113.9:1000")
	id, err := connectFor(r, sh, first, "")
	if err != nil || id != "c1" {
		t.Fatalf("first connector: id=%q err=%v", id, err)
	}
	if again, err := connectFor(r, sh, first, ""); err != nil || again != id {
		t.Fatalf("repeat connect must be idempotent: id=%q err=%v", again, err)
	}

	second := testSession("c-2", "203.0.113.10:1000")
	if _, err := connectFor(r, sh, second, ""); !errors.Is(err, errShareLocked) {
		t.Fatalf("single-use lock: err = %v, want errShareLocked", err)
	}

	// Same instance reconnecting on a new session is still the locked holder;
	// with max_connectors=1 it is the connector count that refuses it until
	// the old session leaves.
	firstAgain := testSession("c-1", "203.0.113.9:2000")
	if _, err := connectFor(r, sh, firstAgain, ""); !errors.Is(err, errShareFull) {
		t.Fatalf("second session of the locked instance while the first is live: err = %v, want errShareFull", err)
	}
	if _, ok := r.disconnect(sh, first); !ok {
		t.Fatalf("disconnect should find the member")
	}
	if _, err := connectFor(r, sh, firstAgain, ""); err != nil {
		t.Fatalf("locked instance after the old session left: %v", err)
	}
}

func TestShareNamesPassphraseAndUses(t *testing.T) {
	r := newShareRegistry(time.Hour)
	owner := testSession("inst-a", "")
	req := testShareReq("s", time.Minute)
	req.MaxUses = 2
	req.MaxConnectors = 4
	req.PassphraseSHA256 = proto.PassphraseDigest(req.SecretSHA256, "open sesame")
	sh, err := r.validateShare(req, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.register(owner, sh); err != nil {
		t.Fatal(err)
	}

	a := testSession("a", "203.0.113.1:1")
	if _, err := r.admit(sh, a, proto.Connect{Name: "alice"}, nil); !errors.Is(err, errBadPassphrase) {
		t.Fatalf("missing passphrase: err = %v, want errBadPassphrase", err)
	}
	if _, err := r.admit(sh, a, proto.Connect{Name: "alice", Passphrase: "wrong"}, nil); !errors.Is(err, errBadPassphrase) {
		t.Fatalf("wrong passphrase: err = %v, want errBadPassphrase", err)
	}
	id, err := r.admit(sh, a, proto.Connect{Name: "alice", Passphrase: "open sesame"}, nil)
	if err != nil || id != "alice" {
		t.Fatalf("named connector: id=%q err=%v", id, err)
	}
	if err := r.join(sh, a, id); err != nil {
		t.Fatal(err)
	}

	b := testSession("b", "203.0.113.2:1")
	id2, err := r.admit(sh, b, proto.Connect{Name: "alice", Passphrase: "open sesame"}, nil)
	if err != nil || id2 != "alice-2" {
		t.Fatalf("duplicate name should be suffixed: id=%q err=%v", id2, err)
	}
	if err := r.join(sh, b, id2); err != nil {
		t.Fatal(err)
	}

	c := testSession("c", "203.0.113.3:1")
	if _, err := r.admit(sh, c, proto.Connect{Name: "bad name!", Passphrase: "open sesame"}, nil); !errors.Is(err, errUsesExhausted) {
		t.Fatalf("third use: err = %v, want errUsesExhausted", err)
	}
	if got := r.list(owner); len(got) != 1 || got[0].Uses != 2 || len(got[0].Connectors) != 2 || !got[0].Passphrase || !got[0].Mine {
		t.Fatalf("list = %+v", got)
	}
	if got := r.list(a); got[0].Mine {
		t.Fatalf("list from a non-owner must not claim the share")
	}
}

func TestShareAdmitReservesPendingNames(t *testing.T) {
	r := newShareRegistry(time.Hour)
	owner := testSession("inst-a", "")
	req := testShareReq("s", time.Minute)
	req.Approve = true
	sh, err := r.validateShare(req, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.register(owner, sh); err != nil {
		t.Fatal(err)
	}
	p1 := &pendingConnect{session: testSession("a", "203.0.113.1:1"), answer: make(chan bool, 1)}
	id1, err := r.admit(sh, p1.session, proto.Connect{Name: "alice"}, p1)
	if err != nil || id1 != "alice" || p1.id != "alice" {
		t.Fatalf("first pending: id=%q p.id=%q err=%v", id1, p1.id, err)
	}
	p2 := &pendingConnect{session: testSession("b", "203.0.113.2:1"), answer: make(chan bool, 1)}
	id2, err := r.admit(sh, p2.session, proto.Connect{Name: "alice"}, p2)
	if err != nil || id2 != "alice-2" {
		t.Fatalf("second pending with the same name: id=%q err=%v", id2, err)
	}
	if !r.resolvePending(sh, "alice", true) {
		t.Fatalf("pending alice should resolve")
	}
	if r.resolvePending(sh, "alice", true) {
		t.Fatalf("resolving twice should find nothing")
	}
	if got := <-p1.answer; !got {
		t.Fatalf("approval not delivered")
	}
	if err := r.join(sh, p1.session, "alice"); err != nil {
		t.Fatal(err)
	}
	if !r.idleNow(sh) {
		t.Fatalf("share with no relayed connection should be idle")
	}
}

func TestShareExtendAndIdle(t *testing.T) {
	r := newShareRegistry(time.Hour)
	idled := make(chan *share, 1)
	r.onIdle = func(sh *share) { idled <- sh }
	owner := testSession("inst-a", "")
	req := testShareReq("s", time.Minute)
	req.IdleTimeoutMS = minShareIdleTimeout.Milliseconds()
	sh, err := r.validateShare(req, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Shorten the idle timer under test; validation already enforced the
	// floor on the request.
	sh.policy.idleTimeout = 100 * time.Millisecond
	if _, err := r.register(owner, sh); err != nil {
		t.Fatal(err)
	}

	if _, err := r.extend(sh, time.Now().Add(2*time.Hour)); !errors.Is(err, errShareTTLTooLong) {
		t.Fatalf("extend beyond max ttl: err = %v", err)
	}
	if _, err := r.extend(sh, time.Now().Add(-time.Second)); err == nil {
		t.Fatalf("extend into the past should fail")
	}
	later := time.Now().Add(30 * time.Minute)
	if _, err := r.extend(sh, later); err != nil {
		t.Fatalf("extend: %v", err)
	}
	if !sh.expiresAt.Equal(later) {
		t.Fatalf("expiresAt = %v, want %v", sh.expiresAt, later)
	}

	select {
	case got := <-idled:
		if got != sh {
			t.Fatalf("idle callback got a different share")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("idle callback did not fire for a share with no connections")
	}
}

func TestShareExpiryCallbackFires(t *testing.T) {
	r := newShareRegistry(time.Hour)
	fired := make(chan *share, 1)
	r.onExpire = func(sh *share) { fired <- sh }
	owner := testSession("inst-a", "")
	sh, _ := r.validateShare(testShareReq("s", 150*time.Millisecond), time.Now())
	if _, err := r.register(owner, sh); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-fired:
		if got != sh {
			t.Fatalf("callback got a different share")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("expiry callback did not fire")
	}
}

// authAs runs the edge-side auth for a client that sends auth on its own.
func authAs(t *testing.T, s *Server, client, server tunnel.Session, auth proto.Auth, remote string) *AgentSession {
	t.Helper()
	go func() {
		client.Control().Write(proto.TypeAuth, 1, auth)
	}()
	rp := netip.AddrPort{}
	if remote != "" {
		rp = netip.MustParseAddrPort(remote)
	}
	as, err := s.authenticate(context.Background(), server, rp.Addr().String(), rp, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	reply, err := client.Control().Read()
	if err != nil {
		t.Fatalf("read auth reply: %v", err)
	}
	if reply.Type != proto.TypeAuthOK {
		t.Fatalf("auth reply = %+v, want auth_ok", reply)
	}
	return as
}

func readType(t *testing.T, c *proto.Conn, want string) proto.Msg {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	m, err := c.Read()
	if err != nil {
		t.Fatalf("read %s: %v", want, err)
	}
	if m.Type != want {
		t.Fatalf("got %s (%s), want %s", m.Type, string(m.Data), want)
	}
	return m
}

func readEvent(t *testing.T, c *proto.Conn, want string) proto.ShareEvent {
	t.Helper()
	m := readType(t, c, proto.TypeShareEvent)
	ev, err := proto.Decode[proto.ShareEvent](m)
	if err != nil {
		t.Fatalf("decode share event: %v", err)
	}
	if ev.Event != want {
		t.Fatalf("event = %q (%+v), want %q", ev.Event, ev, want)
	}
	return ev
}

// TestShareRelayEndToEnd drives a sharer session and a connector session
// through the real control loops and relays bytes between them in-process.
func TestShareRelayEndToEnd(t *testing.T) {
	s := newTestServer("tok")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Sharer.
	sharerClient, sharerServer, cleanupSharer := newRawSessionPair(t)
	defer cleanupSharer()
	sharerAS := authAs(t, s, sharerClient, sharerServer, proto.Auth{
		Token: "tok", InstanceID: "sharer", ProtoVersions: proto.SupportedVersions,
	}, "")
	if sharerAS.Scope != proto.ScopeOperator {
		t.Fatalf("sharer scope = %q", sharerAS.Scope)
	}
	sharerDone := make(chan struct{})
	go func() { s.controlLoop(ctx, sharerAS); close(sharerDone) }()

	// The sharer's data side: echo every stream the edge opens, like the
	// agent's tcpServer would against a local database.
	sharerLn, err := tunnel.NewListener(sharerClient)
	if err != nil {
		t.Fatal(err)
	}
	defer sharerLn.Close()
	gotPreamble := make(chan proto.StreamOpen, 4)
	go func() {
		for {
			c, err := sharerLn.Accept()
			if err != nil {
				return
			}
			gotPreamble <- c.(interface{ Preamble() proto.StreamOpen }).Preamble()
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	const secret = "the-link-secret"
	req := testShareReq(secret, time.Minute)
	if err := sharerClient.Control().Write(proto.TypeShare, 3, req); err != nil {
		t.Fatal(err)
	}
	shareOKMsg := readType(t, sharerClient.Control(), proto.TypeShareOK)
	if shareOKMsg.ID != 3 {
		t.Fatalf("share_ok id = %d, want 3", shareOKMsg.ID)
	}
	shareOK, _ := proto.Decode[proto.ShareOK](shareOKMsg)
	if shareOK.ShareID == "" || shareOK.ExpiresAtMS != req.ExpiresAtMS {
		t.Fatalf("share_ok = %+v", shareOK)
	}

	// Bad secret is a rate-limited auth failure.
	badClient, badServer, cleanupBad := newRawSessionPair(t)
	go func() {
		badClient.Control().Write(proto.TypeAuth, 1, proto.Auth{ShareSecret: "nope", InstanceID: "x", ProtoVersions: proto.SupportedVersions})
	}()
	if _, err := s.authenticate(context.Background(), badServer, "203.0.113.5", netip.MustParseAddrPort("203.0.113.5:1"), time.Now().Add(5*time.Second)); err == nil {
		t.Fatalf("bad share secret must fail auth")
	}
	badReply := readType(t, badClient.Control(), proto.TypeAuthErr)
	if e, _ := proto.Decode[proto.AuthErr](badReply); e.Code != proto.CodeBadShare {
		t.Fatalf("bad secret code = %q, want %q", e.Code, proto.CodeBadShare)
	}
	if s.authLimiter.allowed("203.0.113.5") != true {
		t.Fatalf("one failure must not trip the limiter")
	}
	cleanupBad()

	// Connector.
	connClient, connServer, cleanupConn := newRawSessionPair(t)
	defer cleanupConn()
	connAS := authAs(t, s, connClient, connServer, proto.Auth{
		ShareSecret: secret, InstanceID: "conn", ProtoVersions: proto.SupportedVersions,
	}, "203.0.113.9:40000")
	if connAS.Scope != proto.ScopeConnector {
		t.Fatalf("connector scope = %q", connAS.Scope)
	}
	connDone := make(chan struct{})
	go func() { s.controlLoop(ctx, connAS); close(connDone) }()

	// A stream before connect is dropped: the connector is not a member yet.
	early, err := connClient.OpenStream(ctx, proto.StreamOpen{Kind: proto.KindShare, Host: shareOK.ShareID, ShareID: shareOK.ShareID})
	if err != nil {
		t.Fatal(err)
	}
	early.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := early.Read(make([]byte, 1)); err == nil {
		t.Fatalf("stream before connect should be closed by the edge")
	}

	if err := connClient.Control().Write(proto.TypeConnect, 5, proto.Connect{}); err != nil {
		t.Fatal(err)
	}
	connOKMsg := readType(t, connClient.Control(), proto.TypeConnectOK)
	connOK, _ := proto.Decode[proto.ConnectOK](connOKMsg)
	if connOK.ShareID != shareOK.ShareID || connOK.Label != "staging replica" || len(connOK.Targets) != 1 || connOK.Targets[0].Preset != "postgres" || connOK.Targets[0].DefaultPort != 5432 || connOK.ConnectorID != "c1" {
		t.Fatalf("connect_ok = %+v", connOK)
	}
	joined := readEvent(t, sharerClient.Control(), proto.ShareEventConnectorJoined)
	if joined.ConnectorID != "c1" || joined.ClientAddr != "203.0.113.9:40000" {
		t.Fatalf("joined event = %+v", joined)
	}

	// Relay bytes.
	stream, err := connClient.OpenStream(ctx, proto.StreamOpen{Kind: proto.KindShare, Host: shareOK.ShareID, ShareID: shareOK.ShareID, ReqID: "r1"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case pre := <-gotPreamble:
		if pre.Kind != proto.KindTCP || pre.ShareID != shareOK.ShareID || pre.ClientAddr != "203.0.113.9:40000" || pre.ReqID != "r1" || pre.Target != "t1" {
			t.Fatalf("sharer preamble = %+v", pre)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("sharer never received the relayed stream")
	}
	open := readEvent(t, sharerClient.Control(), proto.ShareEventConnOpen)
	if open.ConnID != 1 || open.ConnectorID != "c1" {
		t.Fatalf("open event = %+v", open)
	}
	msg := []byte("select 1\n")
	if _, err := stream.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(stream, buf); err != nil || string(buf) != string(msg) {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	stream.Close()
	closed := readEvent(t, sharerClient.Control(), proto.ShareEventConnClose)
	if closed.ConnID != 1 || closed.BytesUp != int64(len(msg)) || closed.BytesDown != int64(len(msg)) {
		t.Fatalf("close event = %+v", closed)
	}

	// A connector may not bind; the session is closed.
	if err := connClient.Control().Write(proto.TypeBind, 7, proto.Bind{Kind: proto.KindHTTP}); err != nil {
		t.Fatal(err)
	}
	forbidden := readType(t, connClient.Control(), proto.TypeError)
	if e, _ := proto.Decode[proto.Error](forbidden); e.Code != proto.CodeForbidden {
		t.Fatalf("bind on connector session: code = %q, want forbidden", e.Code)
	}
	select {
	case <-connDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("connector control loop should exit after a forbidden message")
	}
	left := readEvent(t, sharerClient.Control(), proto.ShareEventConnectorLeft)
	if left.ConnectorID != "c1" {
		t.Fatalf("left event = %+v", left)
	}

	// Unshare revokes: a fresh connector is told, and its session closes.
	conn2Client, conn2Server, cleanupConn2 := newRawSessionPair(t)
	defer cleanupConn2()
	conn2AS := authAs(t, s, conn2Client, conn2Server, proto.Auth{
		ShareSecret: secret, InstanceID: "conn2", ProtoVersions: proto.SupportedVersions,
	}, "203.0.113.10:40000")
	conn2Done := make(chan struct{})
	go func() { s.controlLoop(ctx, conn2AS); close(conn2Done) }()
	conn2Client.Control().Write(proto.TypeConnect, 9, proto.Connect{})
	readType(t, conn2Client.Control(), proto.TypeConnectOK)
	readEvent(t, sharerClient.Control(), proto.ShareEventConnectorJoined)

	if err := sharerClient.Control().Write(proto.TypeUnshare, 11, proto.Unshare{ShareID: shareOK.ShareID}); err != nil {
		t.Fatal(err)
	}
	// The sharer gets the closed event and then unshare_ok.
	readEvent(t, sharerClient.Control(), proto.ShareEventClosed)
	readType(t, sharerClient.Control(), proto.TypeUnshareOK)
	closedMsg := readType(t, conn2Client.Control(), proto.TypeShareClosed)
	if sc, _ := proto.Decode[proto.ShareClosed](closedMsg); sc.Reason != proto.ShareReasonRevoked {
		t.Fatalf("share_closed reason = %q, want revoked", sc.Reason)
	}
	select {
	case <-conn2Done:
	case <-time.After(5 * time.Second):
		t.Fatalf("connector session should be closed after revocation")
	}
	if _, ok := s.shares.lookup(secret); ok {
		t.Fatalf("share still resolvable after unshare")
	}

	// Sharer goodbye after a re-register tears the new share down as revoked.
	if err := sharerClient.Control().Write(proto.TypeShare, 13, testShareReq("second", time.Minute)); err != nil {
		t.Fatal(err)
	}
	readType(t, sharerClient.Control(), proto.TypeShareOK)
	if _, ok := s.shares.lookup("second"); !ok {
		t.Fatalf("second share not registered")
	}
	sharerClient.Control().Write(proto.TypeGoodbye, 15, proto.Goodbye{Reason: "shutdown"})
	select {
	case <-sharerDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("sharer control loop should exit after goodbye")
	}
	if _, ok := s.shares.lookup("second"); ok {
		t.Fatalf("share survived the sharer's goodbye")
	}
	if s.shares.count() != 0 {
		t.Fatalf("registry not empty after teardown: %d", s.shares.count())
	}
}

func TestOperatorSessionCannotConnectAndStreamsAreRejected(t *testing.T) {
	s := newTestServer("tok")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, server, cleanup := newRawSessionPair(t)
	defer cleanup()
	as := authAs(t, s, client, server, proto.Auth{Token: "tok", InstanceID: "op", ProtoVersions: proto.SupportedVersions}, "")
	done := make(chan struct{})
	go func() { s.controlLoop(ctx, as); close(done) }()

	// A stream pushed into the edge by an operator is closed, and the
	// session stays up.
	st, err := client.OpenStream(ctx, proto.StreamOpen{Kind: proto.KindShare, Host: "x", ShareID: "x"})
	if err != nil {
		t.Fatal(err)
	}
	st.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := st.Read(make([]byte, 1)); err == nil {
		t.Fatalf("operator stream should be closed")
	}
	if _, err := io.WriteString(st, "x"); err == nil {
		// Writes may succeed briefly before the RST lands; that is fine.
		_ = err
	}

	client.Control().Write(proto.TypeConnect, 3, proto.Connect{})
	m := readType(t, client.Control(), proto.TypeError)
	if e, _ := proto.Decode[proto.Error](m); e.Code != proto.CodeForbidden {
		t.Fatalf("connect on operator session: code = %q, want forbidden", e.Code)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("control loop should exit after a forbidden connect")
	}
}

func TestShareRelayRespectsMaxConns(t *testing.T) {
	s := newTestServer("tok")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var controlLoops sync.WaitGroup
	t.Cleanup(func() {
		done := make(chan struct{})
		go func() {
			controlLoops.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("share control loops did not stop during cleanup")
		}
	})

	sharerClient, sharerServer, cleanupSharer := newRawSessionPair(t)
	defer cleanupSharer()
	sharerAS := authAs(t, s, sharerClient, sharerServer, proto.Auth{Token: "tok", InstanceID: "sharer", ProtoVersions: proto.SupportedVersions}, "")
	controlLoops.Add(1)
	go func() {
		defer controlLoops.Done()
		s.controlLoop(ctx, sharerAS)
	}()
	sharerLn, _ := tunnel.NewListener(sharerClient)
	defer sharerLn.Close()
	hold := make(chan struct{})
	defer close(hold)
	go func() {
		for {
			c, err := sharerLn.Accept()
			if err != nil {
				return
			}
			go func() { <-hold; c.Close() }()
		}
	}()

	req := testShareReq("s", time.Minute)
	req.MaxConns = 1
	sharerClient.Control().Write(proto.TypeShare, 3, req)
	okMsg := readType(t, sharerClient.Control(), proto.TypeShareOK)
	shareOK, _ := proto.Decode[proto.ShareOK](okMsg)

	connClient, connServer, cleanupConn := newRawSessionPair(t)
	defer cleanupConn()
	connAS := authAs(t, s, connClient, connServer, proto.Auth{ShareSecret: "s", InstanceID: "c", ProtoVersions: proto.SupportedVersions}, "203.0.113.9:1")
	controlLoops.Add(1)
	go func() {
		defer controlLoops.Done()
		s.controlLoop(ctx, connAS)
	}()
	connClient.Control().Write(proto.TypeConnect, 5, proto.Connect{})
	readType(t, connClient.Control(), proto.TypeConnectOK)
	readEvent(t, sharerClient.Control(), proto.ShareEventConnectorJoined)

	first, err := connClient.OpenStream(ctx, proto.StreamOpen{Kind: proto.KindShare, Host: shareOK.ShareID, ShareID: shareOK.ShareID})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	readEvent(t, sharerClient.Control(), proto.ShareEventConnOpen)

	second, err := connClient.OpenStream(ctx, proto.StreamOpen{Kind: proto.KindShare, Host: shareOK.ShareID, ShareID: shareOK.ShareID})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	rejected := readEvent(t, sharerClient.Control(), proto.ShareEventConnRejected)
	if rejected.Reason != "max_conns" {
		t.Fatalf("rejected reason = %q, want max_conns", rejected.Reason)
	}
	second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatalf("second stream should have been closed")
	}
}

var _ net.Conn = (*inflightConn)(nil)
