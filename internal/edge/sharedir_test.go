package edge

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ngstone/internal/credentials"
	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

type shareCluster struct {
	pc      *peerCluster
	a, b, c *peerEdge
}

func newShareCluster(t *testing.T) *shareCluster {
	t.Helper()
	pc := newPeerCluster(t)
	a, b, c := pc.edge(t, "edge-a"), pc.edge(t, "edge-b"), pc.edge(t, "edge-c")
	registerPeers(t, a, b, c)
	return &shareCluster{pc: pc, a: a, b: b, c: c}
}

func serveControlOn(t *testing.T, e *peerEdge) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.srv.serveControl(ctx, ln)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		ln.Close()
		<-done
	})
	return ln.Addr().String()
}

func shareReply(t *testing.T, c *proto.Conn) proto.Msg {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	m, err := c.Read()
	if err != nil {
		t.Fatalf("read share reply: %v", err)
	}
	return m
}

func startShareRaw(t *testing.T, e *peerEdge, secret string, mod func(*proto.Share)) (tunnel.Session, proto.Msg) {
	t.Helper()
	client, server, cleanup := newRawSessionPair(t)
	t.Cleanup(cleanup)
	as := authAs(t, e.srv, client, server, proto.Auth{Token: "tok", InstanceID: "sharer-" + e.id + "-" + secret, ProtoVersions: proto.SupportedVersions}, "")
	go e.srv.controlLoop(context.Background(), as)
	ln, err := tunnel.NewListener(client)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	req := testShareReq(secret, 10*time.Minute)
	if mod != nil {
		mod(&req)
	}
	if err := client.Control().Write(proto.TypeShare, 3, req); err != nil {
		t.Fatal(err)
	}
	for {
		m := shareReply(t, client.Control())
		if m.Type != proto.TypeShareEvent {
			return client, m
		}
	}
}

func startShare(t *testing.T, e *peerEdge, secret string, mod func(*proto.Share)) (tunnel.Session, string) {
	t.Helper()
	client, m := startShareRaw(t, e, secret, mod)
	if m.Type != proto.TypeShareOK {
		t.Fatalf("share reply = %s %s, want share_ok", m.Type, m.Data)
	}
	ok, err := proto.Decode[proto.ShareOK](m)
	if err != nil {
		t.Fatal(err)
	}
	return client, ok.ShareID
}

type connectorDial struct {
	sess  tunnel.Session
	reply proto.Msg
	local string
}

func dialConnector(t *testing.T, addr, secret string) connectorDial {
	t.Helper()
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	sess, err := tunnel.Client(nc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close("test done") })
	if err := sess.Control().Write(proto.TypeAuth, 1, proto.Auth{ShareSecret: secret, InstanceID: "conn-" + secret, ProtoVersions: proto.SupportedVersions}); err != nil {
		t.Fatal(err)
	}
	sess.Control().SetReadDeadline(time.Now().Add(5 * time.Second))
	m, _ := sess.Control().Read()
	sess.Control().SetReadDeadline(time.Time{})
	return connectorDial{sess: sess, reply: m, local: nc.LocalAddr().String()}
}

func peerControlSession(t *testing.T, from, to *peerEdge, src string) tunnel.Session {
	t.Helper()
	conn, err := dialPeerTLS(t, from.srv.peers.clientTLS(to.pin()), to.peerAddr())
	if err != nil {
		t.Fatalf("peer handshake: %v", err)
	}
	sendFrame(t, conn, peerFrameControl, 0, src, nil)
	mustPeerStatus(t, conn, peerStatusAccept)
	conn.SetDeadline(time.Time{})
	sess, err := tunnel.Client(conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close("test done") })
	return sess
}

func readSession(t *testing.T, sess tunnel.Session) proto.Msg {
	t.Helper()
	sess.Control().SetReadDeadline(time.Now().Add(5 * time.Second))
	defer sess.Control().SetReadDeadline(time.Time{})
	m, err := sess.Control().Read()
	if err != nil {
		t.Fatalf("read control: %v", err)
	}
	return m
}

func shareDirHas(t *testing.T, from *peerEdge, secret string) bool {
	t.Helper()
	key := shareDirKey(shareSecretHashBytes(secret))
	_, ok, err := from.store.LookupShareEdge(context.Background(), key, from.id, time.Now())
	if err != nil {
		t.Fatalf("lookup share edge: %v", err)
	}
	return ok
}

func shareSecretHashBytes(secret string) []byte {
	h := shareSecretHash(secret)
	return h[:]
}

func TestShareDirKeyNotRegistryDigest(t *testing.T) {
	h := shareSecretHash("the-link-secret")
	key := shareDirKey(h[:])
	if len(key) != 64 {
		t.Fatalf("key length = %d, want 64 hex chars", len(key))
	}
	if key == hexOf(h[:]) {
		t.Fatal("directory key equals the registry digest")
	}
	if key != shareDirKey(h[:]) {
		t.Fatal("directory key is not deterministic")
	}
	domain := sha256.Sum256(append([]byte("ngstone-share-directory\x00"), h[:]...))
	if key != hexOf(domain[:]) {
		t.Fatalf("key = %s, want sha256(domain || digest) = %s", key, hexOf(domain[:]))
	}
	plain := sha256.Sum256(h[:])
	if key == hexOf(plain[:]) {
		t.Fatal("directory key is a bare hash of the registry digest")
	}
	other := shareSecretHash("another-secret")
	if key == shareDirKey(other[:]) {
		t.Fatal("different secrets share a directory key")
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

func TestControlForwardReachesSharerEdge(t *testing.T) {
	cl := newShareCluster(t)
	sharer, shareID := startShare(t, cl.b, "the-link-secret", nil)
	forwarded := metricDelta(metricPeerControlForwarded)
	addr := serveControlOn(t, cl.a)

	d := dialConnector(t, addr, "the-link-secret")
	if d.reply.Type != proto.TypeAuthOK {
		t.Fatalf("auth reply = %s %s, want auth_ok", d.reply.Type, d.reply.Data)
	}
	if err := d.sess.Control().Write(proto.TypeConnect, 5, proto.Connect{}); err != nil {
		t.Fatal(err)
	}
	if m := readSession(t, d.sess); m.Type != proto.TypeConnectOK {
		t.Fatalf("connect reply = %s %s", m.Type, m.Data)
	}
	if ev := readEvent(t, sharer.Control(), proto.ShareEventConnectorJoined); ev.ClientAddr != d.local {
		t.Fatalf("sharer saw connector %q, want the real client address %q", ev.ClientAddr, d.local)
	}

	stream, err := d.sess.OpenStream(context.Background(), proto.StreamOpen{Kind: proto.KindShare, Host: shareID, ShareID: shareID, ReqID: "r1"})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	msg := []byte("select 1\n")
	if _, err := stream.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(stream, buf); err != nil || string(buf) != string(msg) {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	if cl.a.srv.shares.count() != 0 || cl.b.srv.shares.count() != 1 {
		t.Fatalf("shares: edge-a %d, edge-b %d", cl.a.srv.shares.count(), cl.b.srv.shares.count())
	}
	if forwarded() != 1 {
		t.Fatalf("forwarded = %d, want 1", forwarded())
	}
}

func TestControlForwardChargesBeforeLookup(t *testing.T) {
	cl := newShareCluster(t)
	startShare(t, cl.b, "the-link-secret", nil)
	addr := serveControlOn(t, cl.a)

	t.Run("per-ip rate limiter", func(t *testing.T) {
		cl.a.srv.perIPLimiter = newPerIPLimiter(0, 0, 16)
		lookups, forwarded := metricDelta(metricPeerLookups), metricDelta(metricPeerControlForwarded)
		d := dialConnector(t, addr, "the-link-secret")
		if d.reply.Type == proto.TypeAuthOK {
			t.Fatal("a connector over the per-IP rate was forwarded")
		}
		if lookups() != 0 || forwarded() != 0 {
			t.Fatalf("lookups = %d forwarded = %d, want 0 before the rate check passes", lookups(), forwarded())
		}
		cl.a.srv.perIPLimiter = nil
	})

	t.Run("auth failure limiter", func(t *testing.T) {
		for i := 0; i < maxAuthFailuresPerMinute; i++ {
			cl.a.srv.authLimiter.recordFailure("127.0.0.1")
		}
		lookups, forwarded := metricDelta(metricPeerLookups), metricDelta(metricPeerControlForwarded)
		d := dialConnector(t, addr, "the-link-secret")
		if d.reply.Type == proto.TypeAuthOK {
			t.Fatal("a rate-limited address was forwarded")
		}
		if lookups() != 0 || forwarded() != 0 {
			t.Fatalf("lookups = %d forwarded = %d, want 0 for a limited address", lookups(), forwarded())
		}
	})
}

func TestControlForwardNegativeCache(t *testing.T) {
	cl := newShareCluster(t)
	addr := serveControlOn(t, cl.a)
	lookups := metricDelta(metricPeerLookups)

	for i := 0; i < 2; i++ {
		d := dialConnector(t, addr, "nobody-holds-this")
		if d.reply.Type != proto.TypeAuthErr {
			t.Fatalf("attempt %d reply = %s, want auth_err", i, d.reply.Type)
		}
		if e, _ := proto.Decode[proto.AuthErr](d.reply); e.Code != proto.CodeBadShare {
			t.Fatalf("attempt %d code = %q, want %q", i, e.Code, proto.CodeBadShare)
		}
	}
	if lookups() != 1 {
		t.Fatalf("lookups = %d, want 1: the miss must be cached", lookups())
	}
}

func TestControlForwardLookupSemFullTakesLocalPath(t *testing.T) {
	cl := newShareCluster(t)
	startShare(t, cl.b, "the-link-secret", nil)
	addr := serveControlOn(t, cl.a)

	for i := 0; i < maxPeerLookups; i++ {
		if !cl.a.srv.peers.lookupSem.tryAcquire() {
			t.Fatal("lookup semaphore smaller than expected")
		}
	}
	capped := metricDelta(metricPeerRejectedLookupCap)
	if d := dialConnector(t, addr, "the-link-secret"); d.reply.Type == proto.TypeAuthOK {
		t.Fatal("forwarded while the lookup semaphore was full")
	}
	if capped() != 1 {
		t.Fatalf("lookup cap rejections = %d, want 1", capped())
	}
	for i := 0; i < maxPeerLookups; i++ {
		cl.a.srv.peers.lookupSem.release()
	}
	if d := dialConnector(t, addr, "the-link-secret"); d.reply.Type != proto.TypeAuthOK {
		t.Fatalf("after the semaphore freed, reply = %s %s; a full semaphore must not poison the miss cache", d.reply.Type, d.reply.Data)
	}
}

func TestControlForwardStoreErrorFailsClosed(t *testing.T) {
	cl := newShareCluster(t)
	startShare(t, cl.b, "the-link-secret", nil)
	addr := serveControlOn(t, cl.a)
	cl.a.store.Close()
	errs, forwarded := metricDelta(metricPeerLookupErrors), metricDelta(metricPeerControlForwarded)

	d := dialConnector(t, addr, "the-link-secret")
	if d.reply.Type != proto.TypeAuthErr {
		t.Fatalf("reply = %s %s, want the local bad_share answer", d.reply.Type, d.reply.Data)
	}
	if errs() != 1 || forwarded() != 0 {
		t.Fatalf("lookup errors = %d forwarded = %d, want 1 and 0", errs(), forwarded())
	}
	if _, cached := cl.a.srv.peers.misses.Get("share:" + shareDirKey(shareSecretHashBytes("the-link-secret"))); cached {
		t.Fatal("a storage error was cached as a miss")
	}
}

func TestControlForwardAfterHandshakeCap(t *testing.T) {
	cl := newShareCluster(t)
	startShare(t, cl.b, "the-link-secret", nil)
	cl.a.srv.tlsMgr = &TLSManager{apexTLSConfig: &tls.Config{Certificates: []tls.Certificate{cl.pc.cert}}}
	cl.a.srv.handshakeSem = newGlobalSemaphore(1)
	addr := serveControlOn(t, cl.a)

	dialTLS := func() (tunnel.Session, proto.Msg, error) {
		nc, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { nc.Close() })
		tc := tls.Client(nc, &tls.Config{ServerName: peerTestHost, RootCAs: cl.pc.pool})
		nc.SetDeadline(time.Now().Add(5 * time.Second))
		if err := tc.Handshake(); err != nil {
			return nil, proto.Msg{}, err
		}
		sess, err := tunnel.Client(tc)
		if err != nil {
			return nil, proto.Msg{}, err
		}
		t.Cleanup(func() { sess.Close("test done") })
		if err := sess.Control().Write(proto.TypeAuth, 1, proto.Auth{ShareSecret: "the-link-secret", InstanceID: "tls-conn", ProtoVersions: proto.SupportedVersions}); err != nil {
			return nil, proto.Msg{}, err
		}
		m, err := sess.Control().Read()
		return sess, m, err
	}

	if !cl.a.srv.handshakeSem.tryAcquire() {
		t.Fatal("handshake semaphore unexpectedly busy")
	}
	lookups := metricDelta(metricPeerLookups)
	if _, _, err := dialTLS(); err == nil {
		t.Fatal("handshake succeeded with the handshake semaphore full")
	}
	if lookups() != 0 {
		t.Fatalf("lookups = %d, want 0: no sniffing before the handshake slot is held", lookups())
	}
	cl.a.srv.handshakeSem.release()

	_, m, err := dialTLS()
	if err != nil || m.Type != proto.TypeAuthOK {
		t.Fatalf("TLS connector = %s %s, %v; want auth_ok through the forward", m.Type, m.Data, err)
	}
	if cl.b.srv.shares.count() != 1 || lookups() != 1 {
		t.Fatalf("lookups = %d, want 1 once the handshake completed", lookups())
	}
}

func TestControlForwardSkipsLocalShare(t *testing.T) {
	cl := newShareCluster(t)
	startShare(t, cl.a, "the-link-secret", nil)
	exp := time.Now().Add(time.Hour)
	if err := cl.b.store.PublishShare(context.Background(), shareDirKey(shareSecretHashBytes("the-link-secret")), "sh_elsewhere", "edge-b", "legacy", exp); err != nil {
		t.Fatal(err)
	}
	addr := serveControlOn(t, cl.a)
	lookups, forwarded := metricDelta(metricPeerLookups), metricDelta(metricPeerControlForwarded)

	d := dialConnector(t, addr, "the-link-secret")
	if d.reply.Type != proto.TypeAuthOK {
		t.Fatalf("reply = %s %s, want the local share to answer", d.reply.Type, d.reply.Data)
	}
	if lookups() != 0 || forwarded() != 0 {
		t.Fatalf("lookups = %d forwarded = %d, want 0: a locally held share is never looked up", lookups(), forwarded())
	}
}

func TestControlForwardAgentAuthUntouched(t *testing.T) {
	cl := newShareCluster(t)
	addr := serveControlOn(t, cl.a)
	lookups, forwarded := metricDelta(metricPeerLookups), metricDelta(metricPeerControlForwarded)

	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	sess, err := tunnel.Client(nc)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close("test done")
	if err := sess.Control().Write(proto.TypeAuth, 1, proto.Auth{Token: "tok", InstanceID: "agent", ProtoVersions: proto.SupportedVersions}); err != nil {
		t.Fatal(err)
	}
	if m := readSession(t, sess); m.Type != proto.TypeAuthOK {
		t.Fatalf("agent auth = %s %s, want auth_ok", m.Type, m.Data)
	}
	if lookups() != 0 || forwarded() != 0 {
		t.Fatalf("lookups = %d forwarded = %d, want 0 for a token auth", lookups(), forwarded())
	}
}

func TestForwardedControlRejectsTokenAuth(t *testing.T) {
	cl := newShareCluster(t)
	sess := peerControlSession(t, cl.a, cl.b, "203.0.113.9:4000")
	if err := sess.Control().Write(proto.TypeAuth, 1, proto.Auth{Token: "tok", InstanceID: "agent", ProtoVersions: proto.SupportedVersions}); err != nil {
		t.Fatal(err)
	}
	m := readSession(t, sess)
	if m.Type != proto.TypeError {
		t.Fatalf("forwarded token auth = %s %s, want an error", m.Type, m.Data)
	}
	if e, _ := proto.Decode[proto.Error](m); e.Code != proto.CodeMalformed {
		t.Fatalf("code = %q, want %q", e.Code, proto.CodeMalformed)
	}
	for i := 1; i < maxAuthFailuresPerMinute; i++ {
		s := peerControlSession(t, cl.a, cl.b, "203.0.113.9:4000")
		s.Control().Write(proto.TypeAuth, 1, proto.Auth{Token: "tok", InstanceID: "agent", ProtoVersions: proto.SupportedVersions})
		readSession(t, s)
	}
	if cl.b.srv.authLimiter.allowed("203.0.113.9") {
		t.Fatal("forwarded token auth failures were not charged to the client address")
	}
}

func TestForwardedControlNotReforwarded(t *testing.T) {
	cl := newShareCluster(t)
	startShare(t, cl.c, "the-link-secret", nil)
	lookups := metricDelta(metricPeerLookups)

	sess := peerControlSession(t, cl.a, cl.b, "203.0.113.9:4000")
	if err := sess.Control().Write(proto.TypeAuth, 1, proto.Auth{ShareSecret: "the-link-secret", InstanceID: "conn", ProtoVersions: proto.SupportedVersions}); err != nil {
		t.Fatal(err)
	}
	m := readSession(t, sess)
	if m.Type != proto.TypeAuthErr {
		t.Fatalf("reply = %s %s, want the owner's bad_share, not a second hop", m.Type, m.Data)
	}
	if lookups() != 0 || cl.c.srv.shares.count() != 1 {
		t.Fatalf("lookups = %d, want 0", lookups())
	}
}

func TestAdmitForwardedControlUsesUnauthCap(t *testing.T) {
	cl := newShareCluster(t)
	cl.b.srv.unauthSem = newGlobalSemaphore(1)
	if !cl.b.srv.unauthSem.tryAcquire() {
		t.Fatal("semaphore busy")
	}
	conn, err := dialPeerTLS(t, cl.a.srv.peers.clientTLS(cl.b.pin()), cl.b.peerAddr())
	if err != nil {
		t.Fatal(err)
	}
	sendFrame(t, conn, peerFrameControl, 0, "203.0.113.9:4000", nil)
	mustPeerStatus(t, conn, peerStatusNotOwner)
	expectClosed(t, conn)
	cl.b.srv.unauthSem.release()

	startShare(t, cl.b, "the-link-secret", nil)
	sess := peerControlSession(t, cl.a, cl.b, "203.0.113.9:4000")
	sess.Control().Write(proto.TypeAuth, 1, proto.Auth{ShareSecret: "the-link-secret", InstanceID: "conn", ProtoVersions: proto.SupportedVersions})
	if m := readSession(t, sess); m.Type != proto.TypeAuthOK {
		t.Fatalf("reply = %s %s, want auth_ok once a slot is free", m.Type, m.Data)
	}
	peerEventually(t, "unauth slot released after auth", func() bool {
		if cl.b.srv.unauthSem.tryAcquire() {
			cl.b.srv.unauthSem.release()
			return true
		}
		return false
	})
}

func TestAdmitForwardedControlRefusesWhileDraining(t *testing.T) {
	cl := newShareCluster(t)
	cl.b.srv.unauthSem = newGlobalSemaphore(1)
	cl.b.srv.controlMu.Lock()
	cl.b.srv.controlDraining = true
	cl.b.srv.controlMu.Unlock()

	conn, err := dialPeerTLS(t, cl.a.srv.peers.clientTLS(cl.b.pin()), cl.b.peerAddr())
	if err != nil {
		t.Fatal(err)
	}
	sendFrame(t, conn, peerFrameControl, 0, "203.0.113.9:4000", nil)
	mustPeerStatus(t, conn, peerStatusNotOwner)
	expectClosed(t, conn)
	if !cl.b.srv.unauthSem.tryAcquire() {
		t.Fatal("a refused forwarded control connection leaked its unauth slot")
	}
	cl.b.srv.unauthSem.release()
	done := make(chan struct{})
	go func() {
		cl.b.srv.controlConns.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a refused forwarded control connection leaked a control place")
	}
}

func TestIngressReleasesUnauthOnForward(t *testing.T) {
	cl := newShareCluster(t)
	startShare(t, cl.b, "the-link-secret", nil)
	cl.a.srv.unauthSem = newGlobalSemaphore(1)
	addr := serveControlOn(t, cl.a)

	d := dialConnector(t, addr, "the-link-secret")
	if d.reply.Type != proto.TypeAuthOK {
		t.Fatalf("reply = %s %s", d.reply.Type, d.reply.Data)
	}
	if !cl.a.srv.unauthSem.tryAcquire() {
		t.Fatal("the ingress edge kept its unauthenticated slot for the lifetime of a forwarded session")
	}
	cl.a.srv.unauthSem.release()
}

func TestShareAllowCIDRUsesProxySource(t *testing.T) {
	cl := newShareCluster(t)
	startShare(t, cl.b, "the-link-secret", func(s *proto.Share) { s.AllowCIDRs = []string{"203.0.113.0/24"} })

	connect := func(src string) proto.Msg {
		sess := peerControlSession(t, cl.a, cl.b, src)
		sess.Control().Write(proto.TypeAuth, 1, proto.Auth{ShareSecret: "the-link-secret", InstanceID: "conn-" + src, ProtoVersions: proto.SupportedVersions})
		if m := readSession(t, sess); m.Type != proto.TypeAuthOK {
			t.Fatalf("auth = %s %s", m.Type, m.Data)
		}
		sess.Control().Write(proto.TypeConnect, 5, proto.Connect{})
		return readSession(t, sess)
	}
	if m := connect("203.0.113.9:4000"); m.Type != proto.TypeConnectOK {
		t.Fatalf("allowed client address = %s %s, want connect_ok", m.Type, m.Data)
	}
	m := connect("198.51.100.7:4000")
	if m.Type != proto.TypeConnectErr {
		t.Fatalf("outside client address = %s %s, want connect_err", m.Type, m.Data)
	}
	if e, _ := proto.Decode[proto.ConnectErr](m); e.Code != proto.CodeForbiddenCIDR {
		t.Fatalf("code = %q, want %q", e.Code, proto.CodeForbiddenCIDR)
	}
}

func TestSharePublishFailureRejectsShare(t *testing.T) {
	cl := newShareCluster(t)
	cl.b.store.Close()

	_, m := startShareRaw(t, cl.b, "the-link-secret", nil)
	if m.Type != proto.TypeShareErr {
		t.Fatalf("reply = %s %s, want share_err", m.Type, m.Data)
	}
	e, _ := proto.Decode[proto.ShareErr](m)
	if e.Code != proto.CodeInternal || e.Message != "could not publish share to the edge group" {
		t.Fatalf("share_err = %+v", e)
	}
	if _, ok := cl.b.srv.shares.lookup("the-link-secret"); ok || cl.b.srv.shares.count() != 0 {
		t.Fatal("an unpublished share stayed registered")
	}
}

func TestReplaceSameDigestKeepsDirectoryRow(t *testing.T) {
	cl := newShareCluster(t)
	startShare(t, cl.b, "the-link-secret", nil)
	old, ok := cl.b.srv.shares.lookup("the-link-secret")
	if !ok {
		t.Fatal("share not registered")
	}
	replacement := *old
	replacement.closed = false
	replacement.connectors = nil
	replacement.pending = nil
	replacement.conns = nil
	if _, err := cl.b.srv.shares.register(old.owner, &replacement); err != nil {
		t.Fatal(err)
	}
	cl.b.srv.closeShare(old, proto.ShareReasonSharerGone)
	time.Sleep(300 * time.Millisecond)
	if !shareDirHas(t, cl.a, "the-link-secret") {
		t.Fatal("replacing a share with the same digest withdrew its directory row")
	}
}

func TestReplaceDifferentDigestWithdrawsOldRow(t *testing.T) {
	cl := newShareCluster(t)
	sharer, _ := startShare(t, cl.b, "first-secret", nil)
	_ = sharer
	startShare(t, cl.b, "second-secret", nil)
	old, ok := cl.b.srv.shares.lookup("first-secret")
	if !ok {
		t.Fatal("first share not registered")
	}
	cl.b.srv.closeShare(old, proto.ShareReasonRevoked)
	peerEventually(t, "old directory row withdrawn", func() bool { return !shareDirHas(t, cl.a, "first-secret") })
	if !shareDirHas(t, cl.a, "second-secret") {
		t.Fatal("withdrawing one share removed another's row")
	}
}

func TestRemoteUnshareRevokes(t *testing.T) {
	cl := newShareCluster(t)
	sharer, shareID := startShare(t, cl.b, "the-link-secret", nil)

	op, server, cleanup := newRawSessionPair(t)
	t.Cleanup(cleanup)
	as := authAs(t, cl.a.srv, op, server, proto.Auth{Token: "tok", InstanceID: "operator", ProtoVersions: proto.SupportedVersions}, "")
	go cl.a.srv.controlLoop(context.Background(), as)

	op.Control().Write(proto.TypeUnshare, 11, proto.Unshare{ShareID: "sh_nonexistent"})
	m := readSession(t, op)
	if m.Type != proto.TypeError {
		t.Fatalf("unknown share = %s %s, want an error", m.Type, m.Data)
	}
	if e, _ := proto.Decode[proto.Error](m); e.Code != proto.CodeShareNotFound {
		t.Fatalf("code = %q, want %q", e.Code, proto.CodeShareNotFound)
	}

	op.Control().Write(proto.TypeUnshare, 12, proto.Unshare{ShareID: shareID})
	if m := readSession(t, op); m.Type != proto.TypeUnshareOK {
		t.Fatalf("remote unshare = %s %s, want unshare_ok", m.Type, m.Data)
	}
	if _, ok := cl.b.srv.shares.lookup("the-link-secret"); !ok {
		t.Fatal("the holding edge closed the share before its next sync")
	}
	cl.b.srv.peers.syncShares(context.Background(), time.Now())
	if _, ok := cl.b.srv.shares.lookup("the-link-secret"); ok {
		t.Fatal("the holding edge kept a revoked share")
	}
	ev := readEvent(t, sharer.Control(), proto.ShareEventClosed)
	if ev.Reason != proto.ShareReasonRevoked {
		t.Fatalf("closed reason = %q, want revoked", ev.Reason)
	}
	if shareDirHas(t, cl.a, "the-link-secret") {
		t.Fatal("a revoked share is still in the directory")
	}
}

func TestHeartbeatPurgesOwnDirectoryRowsAtStart(t *testing.T) {
	cl := newShareCluster(t)
	exp := time.Now().Add(time.Hour)
	if err := cl.b.store.PublishShare(context.Background(), shareDirKey([]byte("stale")), "sh_stale", "edge-b", "legacy", exp); err != nil {
		t.Fatal(err)
	}
	if err := cl.c.store.PublishShare(context.Background(), shareDirKey([]byte("peer")), "sh_peer", "edge-c", "legacy", exp); err != nil {
		t.Fatal(err)
	}
	has := func(from *peerEdge, digest string) bool {
		_, ok, err := from.store.LookupShareEdge(context.Background(), shareDirKey([]byte(digest)), from.id, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !has(cl.a, "stale") {
		t.Fatal("seed row missing")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		cl.b.srv.peers.heartbeat(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	peerEventually(t, "stale rows purged", func() bool { return !has(cl.a, "stale") })
	if !has(cl.a, "peer") {
		t.Fatal("startup purge removed another edge's row")
	}
}

func TestShareForwardInertWithoutPeers(t *testing.T) {
	s := newTestServer("tok")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.serveControl(ctx, ln)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		ln.Close()
		<-done
	})

	d := dialConnector(t, ln.Addr().String(), "nobody-holds-this")
	if d.reply.Type != proto.TypeAuthErr {
		t.Fatalf("reply = %s %s, want the local bad_share answer", d.reply.Type, d.reply.Data)
	}

	client, server, cleanup := newRawSessionPair(t)
	t.Cleanup(cleanup)
	as := authAs(t, s, client, server, proto.Auth{Token: "tok", InstanceID: "sharer", ProtoVersions: proto.SupportedVersions}, "")
	go s.controlLoop(ctx, as)
	if err := client.Control().Write(proto.TypeShare, 3, testShareReq("local-secret", time.Minute)); err != nil {
		t.Fatal(err)
	}
	if m := shareReply(t, client.Control()); m.Type != proto.TypeShareOK {
		t.Fatalf("share without peers = %s %s", m.Type, m.Data)
	}
	client.Control().Write(proto.TypeListShares, 4, proto.ListShares{})
	m := shareReply(t, client.Control())
	ok, err := proto.Decode[proto.SharesOK](m)
	if err != nil || ok.Edge != "" || len(ok.Shares) != 1 {
		t.Fatalf("list = %+v, %v; want one share and no edge id", ok, err)
	}
}

func useShareCredentials(cl *shareCluster) {
	for _, e := range []*peerEdge{cl.a, cl.b, cl.c} {
		e.srv.cfg.TokenSHA256 = nil
		e.srv.credentialStore = e.store
	}
}

func issueShareToken(t *testing.T, e *peerEdge, owner string) string {
	t.Helper()
	issued, err := e.store.Issue(credentials.Spec{Kind: credentials.KindShare, OwnerID: owner}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return issued.Token
}

func startCredentialOperator(t *testing.T, e *peerEdge, token, instance string) tunnel.Session {
	t.Helper()
	client, server, cleanup := newRawSessionPair(t)
	t.Cleanup(cleanup)
	as := authAs(t, e.srv, client, server, proto.Auth{Token: token, InstanceID: instance, ProtoVersions: proto.SupportedVersions}, "")
	go e.srv.controlLoop(context.Background(), as)
	return client
}

func credentialShare(t *testing.T, e *peerEdge, token, instance, secret string) (tunnel.Session, proto.Msg) {
	t.Helper()
	client := startCredentialOperator(t, e, token, instance)
	if err := client.Control().Write(proto.TypeShare, 3, testShareReq(secret, 10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	for {
		m := shareReply(t, client.Control())
		if m.Type != proto.TypeShareEvent {
			return client, m
		}
	}
}

func TestRemoteUnshareRequiresOwner(t *testing.T) {
	cl := newShareCluster(t)
	useShareCredentials(cl)
	tokenA, tokenB := issueShareToken(t, cl.a, "owner-a"), issueShareToken(t, cl.a, "owner-b")

	sharer, m := credentialShare(t, cl.b, tokenA, "sharer", "the-link-secret")
	if m.Type != proto.TypeShareOK {
		t.Fatalf("share reply = %s %s, want share_ok", m.Type, m.Data)
	}
	ok, err := proto.Decode[proto.ShareOK](m)
	if err != nil {
		t.Fatal(err)
	}

	other := startCredentialOperator(t, cl.a, tokenB, "operator-b")
	other.Control().Write(proto.TypeUnshare, 11, proto.Unshare{ShareID: ok.ShareID})
	m = readSession(t, other)
	if e, _ := proto.Decode[proto.Error](m); m.Type != proto.TypeError || e.Code != proto.CodeShareNotFound {
		t.Fatalf("other owner's unshare = %s %s, want share_not_found", m.Type, m.Data)
	}
	cl.b.srv.peers.syncShares(context.Background(), time.Now())
	if _, live := cl.b.srv.shares.lookup("the-link-secret"); !live {
		t.Fatal("another owner's unshare revoked the share")
	}

	owner := startCredentialOperator(t, cl.a, tokenA, "operator-a")
	owner.Control().Write(proto.TypeUnshare, 12, proto.Unshare{ShareID: ok.ShareID})
	if m := readSession(t, owner); m.Type != proto.TypeUnshareOK {
		t.Fatalf("owner's remote unshare = %s %s, want unshare_ok", m.Type, m.Data)
	}
	cl.b.srv.peers.syncShares(context.Background(), time.Now())
	if _, live := cl.b.srv.shares.lookup("the-link-secret"); live {
		t.Fatal("the holding edge kept a share its owner revoked")
	}
	if ev := readEvent(t, sharer.Control(), proto.ShareEventClosed); ev.Reason != proto.ShareReasonRevoked {
		t.Fatalf("closed reason = %q, want revoked", ev.Reason)
	}
}

func TestCrossEdgeSameSecretOtherOwnerRejected(t *testing.T) {
	cl := newShareCluster(t)
	useShareCredentials(cl)
	tokenA, tokenB := issueShareToken(t, cl.a, "owner-a"), issueShareToken(t, cl.a, "owner-b")

	if _, m := credentialShare(t, cl.b, tokenA, "sharer-a", "the-link-secret"); m.Type != proto.TypeShareOK {
		t.Fatalf("owner-a share reply = %s %s, want share_ok", m.Type, m.Data)
	}
	_, m := credentialShare(t, cl.c, tokenB, "sharer-b", "the-link-secret")
	e, _ := proto.Decode[proto.ShareErr](m)
	if m.Type != proto.TypeShareErr || e.Code != proto.CodeShareTaken || e.Message != "this share secret is registered by another agent" {
		t.Fatalf("owner-b share reply = %s %s, want share_taken", m.Type, m.Data)
	}
	if _, live := cl.c.srv.shares.lookup("the-link-secret"); live || cl.c.srv.shares.count() != 0 {
		t.Fatal("the refused share stayed registered on the second edge")
	}
	peer, found, err := cl.a.store.LookupShareEdge(context.Background(), shareDirKey(shareSecretHashBytes("the-link-secret")), cl.a.id, time.Now())
	if err != nil || !found || peer.EdgeID != cl.b.id {
		t.Fatalf("directory lookup = %+v, %v, %v, want edge %s", peer, found, err, cl.b.id)
	}
}

func blockPublish(t *testing.T, e *peerEdge) (started <-chan struct{}, release func()) {
	t.Helper()
	in, out := make(chan struct{}), make(chan struct{})
	var startOnce, releaseOnce sync.Once
	e.srv.peers.beforePublish = func() error {
		startOnce.Do(func() { close(in) })
		<-out
		return nil
	}
	release = func() { releaseOnce.Do(func() { close(out) }) }
	t.Cleanup(release)
	return in, release
}

func awaitSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestSharePendingUntilPublished(t *testing.T) {
	cl := newShareCluster(t)
	started, release := blockPublish(t, cl.b)
	res := make(chan proto.Msg, 1)
	go func() {
		_, m := startShareRaw(t, cl.b, "the-link-secret", nil)
		res <- m
	}()
	awaitSignal(t, started, "the publish to start")

	hash := shareSecretHash("the-link-secret")
	if _, ok := cl.b.srv.shares.lookup("the-link-secret"); ok {
		t.Fatal("an unpublished share is visible to connector lookups")
	}
	if cl.b.srv.shares.holds(hash) {
		t.Fatal("an unpublished share is reported as held")
	}
	if len(cl.b.srv.shares.live()) != 0 {
		t.Fatal("an unpublished share is listed as live")
	}
	if shareDirHas(t, cl.a, "the-link-secret") {
		t.Fatal("the directory row exists before the publish finished")
	}
	select {
	case m := <-res:
		t.Fatalf("sharer got %s before the publish finished", m.Type)
	case <-time.After(300 * time.Millisecond):
	}

	release()
	select {
	case m := <-res:
		if m.Type != proto.TypeShareOK {
			t.Fatalf("share reply = %s %s, want share_ok", m.Type, m.Data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no share reply after the publish finished")
	}
	if _, ok := cl.b.srv.shares.lookup("the-link-secret"); !ok {
		t.Fatal("the share is not usable after the publish")
	}
	if !cl.b.srv.shares.holds(hash) || !shareDirHas(t, cl.a, "the-link-secret") {
		t.Fatal("the published share is not held and listed")
	}
}

func TestCrossOwnerSameSecretNeverAdmitsConnector(t *testing.T) {
	cl := newShareCluster(t)
	useShareCredentials(cl)
	tokenA, tokenB := issueShareToken(t, cl.a, "owner-a"), issueShareToken(t, cl.a, "owner-b")
	if _, m := credentialShare(t, cl.b, tokenA, "sharer-a", "the-link-secret"); m.Type != proto.TypeShareOK {
		t.Fatalf("owner-a share reply = %s %s, want share_ok", m.Type, m.Data)
	}

	started, release := blockPublish(t, cl.c)
	res := make(chan proto.Msg, 1)
	go func() {
		_, m := credentialShare(t, cl.c, tokenB, "sharer-b", "the-link-secret")
		res <- m
	}()
	awaitSignal(t, started, "the second publish to start")

	forwarded := metricDelta(metricPeerControlForwarded)
	d := dialConnector(t, serveControlOn(t, cl.c), "the-link-secret")
	if d.reply.Type != proto.TypeAuthOK {
		t.Fatalf("connector reply = %s %s, want auth_ok from the owner's edge", d.reply.Type, d.reply.Data)
	}
	if forwarded() != 1 {
		t.Fatalf("forwarded control sessions = %d, want 1: the pending share on the second edge answered", forwarded())
	}

	release()
	select {
	case m := <-res:
		e, _ := proto.Decode[proto.ShareErr](m)
		if m.Type != proto.TypeShareErr || e.Code != proto.CodeShareTaken {
			t.Fatalf("owner-b share reply = %s %s, want share_taken", m.Type, m.Data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no share reply after the publish finished")
	}
	if cl.c.srv.shares.count() != 0 {
		t.Fatal("the refused share stayed registered on the second edge")
	}
}

func waitWithin(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		f()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not finish within %s", what, d)
	}
}

func TestForwardedControlSpliceEndsAtShutdown(t *testing.T) {
	for _, trigger := range []string{"context", "stop"} {
		t.Run(trigger, func(t *testing.T) {
			cl := newShareCluster(t)
			startShare(t, cl.b, "the-link-secret", nil)
			ctx, cancel := context.WithCancel(context.Background())
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			served := make(chan struct{})
			go func() {
				cl.a.srv.serveControl(ctx, ln)
				close(served)
			}()
			t.Cleanup(func() {
				cancel()
				ln.Close()
				<-served
			})

			d := dialConnector(t, ln.Addr().String(), "the-link-secret")
			if d.reply.Type != proto.TypeAuthOK {
				t.Fatalf("reply = %s %s", d.reply.Type, d.reply.Data)
			}
			waitWithin(t, time.Second, "control wait during a live splice", cl.a.srv.controlConns.Wait)

			if trigger == "context" {
				cancel()
			} else {
				cl.a.srv.peers.stop()
			}
			waitWithin(t, time.Second, "waitSplices", func() { cl.a.srv.peers.waitSplices(context.Background()) })
			waitWithin(t, time.Second, "control wait", cl.a.srv.controlConns.Wait)

			d.sess.Control().SetReadDeadline(time.Now().Add(time.Second))
			if _, err := d.sess.Control().Read(); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("connector side of the splice stayed open: %v", err)
			}
			waitWithin(t, time.Second, "owner edge control wait", cl.b.srv.controlConns.Wait)
		})
	}
}

func shareDirCarries(t *testing.T, from, holder *peerEdge, secret string, at time.Time) bool {
	t.Helper()
	peer := holder.record()
	peer.ExpiresAt = time.Now().Add(time.Hour)
	if err := holder.store.UpsertEdgePeer(context.Background(), peer); err != nil {
		t.Fatal(err)
	}
	key := shareDirKey(shareSecretHashBytes(secret))
	_, ok, err := from.store.LookupShareEdge(context.Background(), key, from.id, at)
	if err != nil {
		t.Fatalf("lookup share edge: %v", err)
	}
	return ok
}

func TestHeartbeatRepairsMissingDirectoryRow(t *testing.T) {
	cl := newShareCluster(t)
	_, id := startShare(t, cl.b, "repair-secret", nil)
	key := shareDirKey(shareSecretHashBytes("repair-secret"))
	if err := cl.b.store.WithdrawShare(context.Background(), key, "edge-b", id); err != nil {
		t.Fatal(err)
	}
	if shareDirHas(t, cl.a, "repair-secret") {
		t.Fatal("the row survived the withdraw")
	}
	cl.b.srv.peers.beat(context.Background(), cl.b.srv.peers.leaseTTL())
	if !shareDirHas(t, cl.a, "repair-secret") {
		t.Fatal("the heartbeat did not restore the directory row")
	}
}

func TestFailedExtendIsRepairedOnNextBeat(t *testing.T) {
	cl := newShareCluster(t)
	sess, id := startShare(t, cl.b, "extend-secret", nil)
	var fail atomic.Bool
	fail.Store(true)
	cl.b.srv.peers.beforePublish = func() error {
		if fail.Load() {
			return errors.New("store unavailable")
		}
		return nil
	}
	newExp := time.Now().Add(20 * time.Minute)
	if err := sess.Control().Write(proto.TypeShareUpdate, 9, proto.ShareUpdate{ShareID: id, ExpiresAtMS: newExp.UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	for {
		m := readSession(t, sess)
		if m.Type == proto.TypeShareOK {
			break
		}
		if m.Type == proto.TypeShareErr {
			t.Fatalf("update refused: %s", m.Data)
		}
	}
	probe := time.Now().Add(15 * time.Minute)
	if shareDirCarries(t, cl.a, cl.b, "extend-secret", probe) {
		t.Fatal("the directory carries the new expiry although the write failed")
	}
	fail.Store(false)
	cl.b.srv.peers.beat(context.Background(), cl.b.srv.peers.leaseTTL())
	if !shareDirCarries(t, cl.a, cl.b, "extend-secret", probe) {
		t.Fatal("the next heartbeat did not carry the new expiry to the directory")
	}
}

func TestQuickReRegisterKeepsDirectoryRow(t *testing.T) {
	cl := newShareCluster(t)
	gate := make(chan struct{})
	cl.b.srv.peers.beforeWithdraw = func() { <-gate }
	_, id := startShare(t, cl.b, "quick-secret", nil)
	for i := 0; i < 30; i++ {
		old, ok := cl.b.srv.shares.byShareID(id)
		if !ok {
			t.Fatalf("round %d: share %s is not live", i, id)
		}
		cl.b.srv.closeShare(old, "unshared")
		_, id = startShare(t, cl.b, "quick-secret", nil)
		gate <- struct{}{}
		cl.b.srv.peers.withdraws.Wait()
		if !shareDirHas(t, cl.a, "quick-secret") {
			t.Fatalf("round %d: the old registration's withdraw removed the new row", i)
		}
	}
}
