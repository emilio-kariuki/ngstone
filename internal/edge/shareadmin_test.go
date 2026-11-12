package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"ngstone/internal/credentials"
	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

const operatorAddr = "203.0.113.7:4000"

func startRemoteOperator(t *testing.T, e *peerEdge, token, instance string) tunnel.Session {
	t.Helper()
	client, server, cleanup := newRawSessionPair(t)
	t.Cleanup(cleanup)
	as := authAs(t, e.srv, client, server, proto.Auth{Token: token, InstanceID: instance, ProtoVersions: proto.SupportedVersions}, operatorAddr)
	go e.srv.controlLoop(context.Background(), as)
	return client
}

func fakeHolder(t *testing.T, e *peerEdge, nextProtos []string, serve func(net.Conn)) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := e.srv.peers.serverTLS()
	if nextProtos != nil {
		cfg.NextProtos = nextProtos
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer raw.Close()
				tc := tls.Server(raw, cfg)
				if tc.Handshake() != nil {
					return
				}
				serve(tc)
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		wg.Wait()
	})
	rec := e.record()
	rec.PeerAddr = ln.Addr().String()
	rec.ExpiresAt = time.Now().Add(time.Hour)
	if err := e.store.UpsertEdgePeer(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
}

func shareIDOf(t *testing.T, m proto.Msg) string {
	t.Helper()
	if m.Type != proto.TypeShareOK {
		t.Fatalf("share reply = %s %s, want share_ok", m.Type, m.Data)
	}
	ok, err := proto.Decode[proto.ShareOK](m)
	if err != nil {
		t.Fatal(err)
	}
	return ok.ShareID
}

func listFrom(t *testing.T, op tunnel.Session, id uint64) proto.SharesOK {
	t.Helper()
	if err := op.Control().Write(proto.TypeListShares, id, nil); err != nil {
		t.Fatal(err)
	}
	m := readSession(t, op)
	ok, err := proto.Decode[proto.SharesOK](m)
	if m.Type != proto.TypeSharesOK || m.ID != id || err != nil {
		t.Fatalf("list reply = %s %s, %v", m.Type, m.Data, err)
	}
	return ok
}

func connectTo(t *testing.T, sharer tunnel.Session, e *peerEdge, secret string) (connectorDial, string) {
	t.Helper()
	d := dialConnector(t, serveControlOn(t, e), secret)
	if d.reply.Type != proto.TypeAuthOK {
		t.Fatalf("connector auth = %s %s", d.reply.Type, d.reply.Data)
	}
	if err := d.sess.Control().Write(proto.TypeConnect, 5, proto.Connect{}); err != nil {
		t.Fatal(err)
	}
	if m := readSession(t, d.sess); m.Type != proto.TypeConnectOK {
		t.Fatalf("connect reply = %s %s", m.Type, m.Data)
	}
	ev := readEvent(t, sharer.Control(), proto.ShareEventConnectorJoined)
	return d, ev.ConnectorID
}

func registryExpiryMS(r *shareRegistry, sh *share) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return sh.expiresAt.UnixMilli()
}

func TestRemoteExtendAndKick(t *testing.T) {
	cl := newShareCluster(t)
	useShareCredentials(cl)
	token := issueShareToken(t, cl.a, "owner-o")
	sharer, m := credentialShare(t, cl.b, token, "sharer", "link-secret")
	shareID := shareIDOf(t, m)
	d, connectorID := connectTo(t, sharer, cl.b, "link-secret")

	op := startRemoteOperator(t, cl.a, token, "operator")
	accepted := metricDelta(metricPeerAcceptedConns)
	newExpiry := time.Now().Add(20 * time.Minute).UnixMilli()
	if err := op.Control().Write(proto.TypeShareUpdate, 21, proto.ShareUpdate{ShareID: shareID, ExpiresAtMS: newExpiry}); err != nil {
		t.Fatal(err)
	}
	m = readSession(t, op)
	ok, err := proto.Decode[proto.ShareOK](m)
	if m.Type != proto.TypeShareOK || m.ID != 21 || err != nil || ok.ShareID != shareID || ok.ExpiresAtMS != newExpiry {
		t.Fatalf("remote extend = %s id=%d %s, %v", m.Type, m.ID, m.Data, err)
	}
	sh, live := cl.b.srv.shares.byShareID(shareID)
	if !live || registryExpiryMS(cl.b.srv.shares, sh) != newExpiry {
		t.Fatal("the holding edge did not apply the new expiry")
	}
	if _, onA := cl.a.srv.shares.byShareID(shareID); onA {
		t.Fatal("the ingress edge acted on the share locally")
	}
	upd, err := proto.Decode[proto.ShareUpdated](readType(t, d.sess.Control(), proto.TypeShareUpdated))
	if err != nil || upd.ShareID != shareID || upd.ExpiresAtMS != newExpiry {
		t.Fatalf("connector update = %+v, %v", upd, err)
	}
	if ev := readEvent(t, sharer.Control(), proto.ShareEventExtended); ev.ExpiresAtMS != newExpiry {
		t.Fatalf("sharer saw expiry %d, want %d", ev.ExpiresAtMS, newExpiry)
	}

	if err := op.Control().Write(proto.TypeKick, 22, proto.Kick{ShareID: shareID, ConnectorID: connectorID}); err != nil {
		t.Fatal(err)
	}
	m = readSession(t, op)
	kicked, err := proto.Decode[proto.KickOK](m)
	if m.Type != proto.TypeKickOK || m.ID != 22 || err != nil || kicked.ConnectorID != connectorID || kicked.ShareID != shareID {
		t.Fatalf("remote kick = %s id=%d %s, %v", m.Type, m.ID, m.Data, err)
	}
	closed, err := proto.Decode[proto.ShareClosed](readType(t, d.sess.Control(), proto.TypeShareClosed))
	if err != nil || closed.Reason != proto.ShareReasonKicked {
		t.Fatalf("connector close = %+v, %v, want kicked", closed, err)
	}
	if got := accepted(); got != 2 {
		t.Fatalf("admin connections accepted by the holder = %d, want 2", got)
	}
}

func TestRemoteExtendOtherOwner(t *testing.T) {
	cl := newShareCluster(t)
	useShareCredentials(cl)
	tokenO, tokenP := issueShareToken(t, cl.a, "owner-o"), issueShareToken(t, cl.a, "owner-p")
	sharer, m := credentialShare(t, cl.b, tokenO, "sharer", "link-secret")
	shareID := shareIDOf(t, m)
	_, connectorID := connectTo(t, sharer, cl.b, "link-secret")
	before := cl.b.accepts.Load()
	accepted := metricDelta(metricPeerAcceptedConns)

	op := startRemoteOperator(t, cl.a, tokenP, "operator-p")
	op.Control().Write(proto.TypeShareUpdate, 31, proto.ShareUpdate{ShareID: shareID, ExpiresAtMS: time.Now().Add(20 * time.Minute).UnixMilli()})
	m = readSession(t, op)
	if e, _ := proto.Decode[proto.ShareErr](m); m.Type != proto.TypeShareErr || e.Code != proto.CodeShareNotFound {
		t.Fatalf("other owner's extend = %s %s, want share_not_found", m.Type, m.Data)
	}
	op.Control().Write(proto.TypeKick, 32, proto.Kick{ShareID: shareID, ConnectorID: connectorID})
	m = readSession(t, op)
	if e, _ := proto.Decode[proto.Error](m); m.Type != proto.TypeError || e.Code != proto.CodeShareNotFound {
		t.Fatalf("other owner's kick = %s %s, want share_not_found", m.Type, m.Data)
	}
	if ok := listFrom(t, op, 33); len(ok.Shares) != 0 || len(ok.Unreached) != 0 {
		t.Fatalf("other owner's list = %+v, want nothing", ok)
	}
	if accepted() != 0 || cl.b.accepts.Load() != before {
		t.Fatalf("the holder was contacted for a share its operator cannot see (accepted %d)", accepted())
	}
	sh, _ := cl.b.srv.shares.byShareID(shareID)
	if _, _, live := cl.b.srv.shares.connectorByID(sh, connectorID); !live {
		t.Fatal("another owner's kick removed the connector")
	}
}

func TestRemoteKickRevokedCredential(t *testing.T) {
	cl := newShareCluster(t)
	useShareCredentials(cl)
	issued, err := cl.a.store.Issue(credentials.Spec{Kind: credentials.KindShare, OwnerID: "owner-o"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sharer, m := credentialShare(t, cl.b, issued.Token, "sharer", "link-secret")
	shareID := shareIDOf(t, m)
	d, connectorID := connectTo(t, sharer, cl.b, "link-secret")
	op := startRemoteOperator(t, cl.a, issued.Token, "operator")
	if err := cl.a.store.Revoke(issued.Credential.ID); err != nil {
		t.Fatal(err)
	}
	failures := authFailures(cl.b.srv, "203.0.113.7")

	op.Control().Write(proto.TypeKick, 41, proto.Kick{ShareID: shareID, ConnectorID: connectorID})
	m = readSession(t, op)
	e, _ := proto.Decode[proto.Error](m)
	if m.Type != proto.TypeError || e.Code != proto.CodeShareNotFound || !strings.Contains(e.Message, "rejected") {
		t.Fatalf("kick with a revoked credential = %s %s, want share_not_found naming the rejection", m.Type, m.Data)
	}
	sh, _ := cl.b.srv.shares.byShareID(shareID)
	if _, _, live := cl.b.srv.shares.connectorByID(sh, connectorID); !live {
		t.Fatal("a revoked credential kicked a connector")
	}
	if got := authFailures(cl.b.srv, "203.0.113.7"); got != failures+1 {
		t.Fatalf("holder auth failures for the operator address = %d, want %d", got, failures+1)
	}
	if authFailures(cl.b.srv, "127.0.0.1") != 0 {
		t.Fatal("the failure was counted against the forwarding edge")
	}
	_ = d
}

func TestRemoteAdminSkewReported(t *testing.T) {
	cl := newShareCluster(t)
	useShareCredentials(cl)
	token := issueShareToken(t, cl.a, "owner-o")
	_, m := credentialShare(t, cl.b, token, "sharer", "link-secret")
	shareID := shareIDOf(t, m)
	fakeHolder(t, cl.b, []string{peerALPN2, peerALPN1}, func(net.Conn) {})
	skew := metricDelta(metricPeerVersionSkew)

	op := startRemoteOperator(t, cl.a, token, "operator")
	op.Control().Write(proto.TypeShareUpdate, 51, proto.ShareUpdate{ShareID: shareID, ExpiresAtMS: time.Now().Add(20 * time.Minute).UnixMilli()})
	m = readSession(t, op)
	e, _ := proto.Decode[proto.ShareErr](m)
	if m.Type != proto.TypeShareErr || e.Code != proto.CodeShareNotFound || !strings.Contains(e.Message, "older ngstoned") || !strings.Contains(e.Message, cl.b.id) {
		t.Fatalf("extend against an older holder = %s %s, want share_not_found naming an older ngstoned", m.Type, m.Data)
	}
	if skew() != 1 {
		t.Fatalf("version skew counter moved by %d, want 1", skew())
	}

	op.Control().Write(proto.TypeKick, 52, proto.Kick{ShareID: shareID, ConnectorID: "c1"})
	m = readSession(t, op)
	if k, _ := proto.Decode[proto.Error](m); m.Type != proto.TypeError || !strings.Contains(k.Message, "older ngstoned") {
		t.Fatalf("kick against an older holder = %s %s", m.Type, m.Data)
	}
}

func TestGroupListShares(t *testing.T) {
	cl := newShareCluster(t)
	useShareCredentials(cl)
	tokenO, tokenP := issueShareToken(t, cl.a, "owner-o"), issueShareToken(t, cl.a, "owner-p")
	_, m := credentialShare(t, cl.a, tokenO, "sharer-a", "secret-a")
	idA := shareIDOf(t, m)
	_, m = credentialShare(t, cl.b, tokenO, "sharer-b", "secret-b")
	idB := shareIDOf(t, m)
	_, m = credentialShare(t, cl.c, tokenO, "sharer-c", "secret-c")
	shareIDOf(t, m)
	_, m = credentialShare(t, cl.b, tokenP, "sharer-p", "secret-p")
	shareIDOf(t, m)
	cl.c.srv.peers.ln.Close()

	op := startRemoteOperator(t, cl.a, tokenO, "operator")
	start := time.Now()
	ok := listFrom(t, op, 61)
	if elapsed := time.Since(start); elapsed > 3500*time.Millisecond {
		t.Fatalf("list took %s", elapsed)
	}
	if !ok.Group || len(ok.Unreached) != 1 || ok.Unreached[0] != cl.c.id {
		t.Fatalf("group=%v unreached=%v, want true [%s]", ok.Group, ok.Unreached, cl.c.id)
	}
	if len(ok.Shares) != 2 || ok.Shares[0].ShareID != idA || ok.Shares[0].Edge != cl.a.id || ok.Shares[1].ShareID != idB || ok.Shares[1].Edge != cl.b.id {
		t.Fatalf("shares = %+v, want [%s on %s, %s on %s]", ok.Shares, idA, cl.a.id, idB, cl.b.id)
	}
	if !ok.Shares[0].Mine && ok.Shares[0].Edge == cl.a.id && ok.Shares[1].Mine {
		t.Fatal("a remote row claims to belong to the asking session")
	}
}

func TestGroupListHolderStallBounded(t *testing.T) {
	cl := newShareCluster(t)
	useShareCredentials(cl)
	token := issueShareToken(t, cl.a, "owner-o")
	_, m := credentialShare(t, cl.a, token, "sharer-a", "secret-a")
	idA := shareIDOf(t, m)
	_, m = credentialShare(t, cl.b, token, "sharer-b", "secret-b")
	shareIDOf(t, m)
	closed := make(chan struct{})
	fakeHolder(t, cl.b, nil, func(tc net.Conn) {
		br := bufio.NewReader(tc)
		if _, err := br.ReadByte(); err != nil {
			return
		}
		if _, err := br.ReadString('\n'); err != nil {
			return
		}
		tc.Write([]byte{peerStatusAccept})
		io.Copy(io.Discard, br)
		close(closed)
	})

	op := startRemoteOperator(t, cl.a, token, "operator")
	start := time.Now()
	ok := listFrom(t, op, 71)
	if elapsed := time.Since(start); elapsed > 3500*time.Millisecond {
		t.Fatalf("list against a stalled holder took %s", elapsed)
	}
	if len(ok.Unreached) != 1 || ok.Unreached[0] != cl.b.id || len(ok.Shares) != 1 || ok.Shares[0].ShareID != idA {
		t.Fatalf("shares=%+v unreached=%v", ok.Shares, ok.Unreached)
	}
	awaitSignal(t, closed, "the ingress to drop the stalled admin connection")
}

func TestAdminSessionNoRecursion(t *testing.T) {
	cl := newShareCluster(t)
	useShareCredentials(cl)
	token := issueShareToken(t, cl.a, "owner-o")
	_, m := credentialShare(t, cl.b, token, "sharer-b", "secret-b")
	idB := shareIDOf(t, m)
	_, m = credentialShare(t, cl.c, token, "sharer-c", "secret-c")
	idC := shareIDOf(t, m)
	before := cl.c.accepts.Load()

	sess := peerAdminSession(t, cl.a, cl.b, "203.0.113.9:4000")
	if m := peerAdminAuth(t, sess, proto.Auth{Token: token}); m.Type != proto.TypeAuthOK {
		t.Fatalf("admin auth = %s %s", m.Type, m.Data)
	}
	ok := listFrom(t, sess, 81)
	if ok.Group || len(ok.Unreached) != 0 || len(ok.Shares) != 1 || ok.Shares[0].ShareID != idB {
		t.Fatalf("admin list = %+v, want only edge-b's share and no group flag", ok)
	}
	sess.Control().Write(proto.TypeShareUpdate, 82, proto.ShareUpdate{ShareID: idC, ExpiresAtMS: time.Now().Add(20 * time.Minute).UnixMilli()})
	m = readSession(t, sess)
	if e, _ := proto.Decode[proto.ShareErr](m); m.Type != proto.TypeShareErr || e.Code != proto.CodeShareNotFound || strings.Contains(e.Message, "did not answer") {
		t.Fatalf("admin extend of another edge's share = %s %s, want a plain share_not_found", m.Type, m.Data)
	}
	if cl.c.accepts.Load() != before {
		t.Fatal("an admin session fanned out to a third edge")
	}
}

func TestRelayTokenRetention(t *testing.T) {
	cl := newShareCluster(t)
	useShareCredentials(cl)
	issue := func(spec credentials.Spec) string {
		issued, err := cl.a.store.Issue(spec, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return issued.Token
	}
	shareToken := issue(credentials.Spec{Kind: credentials.KindShare, OwnerID: "owner-o"})
	httpToken := issue(credentials.Spec{Kind: credentials.KindHTTP, Subdomain: "scoped", OwnerID: "owner-o"})

	auth := func(e *peerEdge, token, instance string) *AgentSession {
		client, server, cleanup := newRawSessionPair(t)
		t.Cleanup(cleanup)
		return authAs(t, e.srv, client, server, proto.Auth{Token: token, InstanceID: instance, ProtoVersions: proto.SupportedVersions}, operatorAddr)
	}
	if as := auth(cl.a, shareToken, "relay-share"); as.relayToken != shareToken {
		t.Fatal("a share credential's token is not retained for relay")
	}
	if as := auth(cl.a, httpToken, "relay-http"); as.relayToken != "" {
		t.Fatal("a tunnel credential's token is retained")
	}

	cl.a.srv.credentialStore = nil
	cl.a.srv.cfg.TokenSHA256 = sumToken("tok")
	if as := auth(cl.a, "tok", "relay-legacy"); as.relayToken != "tok" {
		t.Fatal("a legacy operator token is not retained for relay")
	}

	solo := newTestServer("tok")
	client, server, cleanup := newRawSessionPair(t)
	t.Cleanup(cleanup)
	if as := authAs(t, solo, client, server, proto.Auth{Token: "tok", InstanceID: "solo", ProtoVersions: proto.SupportedVersions}, operatorAddr); as.relayToken != "" {
		t.Fatal("a standalone edge retains operator tokens")
	}
}

func TestGroupListCaches(t *testing.T) {
	cl := newShareCluster(t)
	useShareCredentials(cl)
	token := issueShareToken(t, cl.a, "owner-o")
	_, m := credentialShare(t, cl.b, token, "sharer", "link-secret")
	shareID := shareIDOf(t, m)
	op := startRemoteOperator(t, cl.a, token, "operator")
	accepted := metricDelta(metricPeerAcceptedConns)

	first := listFrom(t, op, 91)
	if accepted() != 1 || len(first.Shares) != 1 {
		t.Fatalf("first list accepted=%d shares=%d, want 1 and 1", accepted(), len(first.Shares))
	}
	listFrom(t, op, 92)
	if accepted() != 1 {
		t.Fatalf("a repeat list within the cache window dialed the holder again (%d)", accepted())
	}

	newExpiry := time.Now().Add(25 * time.Minute).UnixMilli()
	op.Control().Write(proto.TypeShareUpdate, 93, proto.ShareUpdate{ShareID: shareID, ExpiresAtMS: newExpiry})
	if m := readSession(t, op); m.Type != proto.TypeShareOK {
		t.Fatalf("extend = %s %s", m.Type, m.Data)
	}
	after := listFrom(t, op, 94)
	if len(after.Shares) != 1 || after.Shares[0].ExpiresAtMS != newExpiry {
		t.Fatalf("list after an extend shows %+v, want expiry %d", after.Shares, newExpiry)
	}
}

func TestRemoteAdminNeverLogsToken(t *testing.T) {
	cl := newShareCluster(t)
	useShareCredentials(cl)
	logs := &lockedBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	issued, err := cl.a.store.Issue(credentials.Spec{Kind: credentials.KindShare, OwnerID: "owner-o"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := cl.a.store.Issue(credentials.Spec{Kind: credentials.KindShare, OwnerID: "owner-o"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sharer, m := credentialShare(t, cl.b, issued.Token, "sharer", "link-secret")
	shareID := shareIDOf(t, m)
	_, connectorID := connectTo(t, sharer, cl.b, "link-secret")

	op := startRemoteOperator(t, cl.a, issued.Token, "operator")
	listFrom(t, op, 101)
	op.Control().Write(proto.TypeShareUpdate, 102, proto.ShareUpdate{ShareID: shareID, ExpiresAtMS: time.Now().Add(20 * time.Minute).UnixMilli()})
	readSession(t, op)
	op.Control().Write(proto.TypeKick, 103, proto.Kick{ShareID: shareID, ConnectorID: connectorID})
	readSession(t, op)

	bad := startRemoteOperator(t, cl.a, revoked.Token, "operator-revoked")
	if err := cl.a.store.Revoke(revoked.Credential.ID); err != nil {
		t.Fatal(err)
	}
	bad.Control().Write(proto.TypeKick, 104, proto.Kick{ShareID: shareID, ConnectorID: connectorID})
	readSession(t, bad)

	out := logs.String()
	if !strings.Contains(out, "edge: remote share admin") {
		t.Fatal("the forwarding edge logged no remote share admin line")
	}
	for _, secret := range []string{issued.Token, revoked.Token} {
		if strings.Contains(out, secret) {
			t.Fatal("an operator token appeared in the logs")
		}
	}
}
