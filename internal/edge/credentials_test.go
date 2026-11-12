package edge

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"ngstone/internal/credentials"
	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

func TestScopedCredentialAuthAndBindScope(t *testing.T) {
	store, err := credentials.Open(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	issued, err := store.Issue(credentials.Spec{Subdomain: "demo"}, time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	client, server, cleanup := newRawSessionPair(t)
	defer cleanup()
	s := newTestServer("")
	s.cfg.TokenSHA256 = nil
	s.credentialStore = store

	go func() {
		_ = client.Control().Write(proto.TypeAuth, 1, proto.Auth{
			Token:         issued.Token,
			InstanceID:    "scoped-agent",
			ProtoVersions: []int{proto.ProtoVersion},
		})
	}()
	as, err := s.authenticate(context.Background(), server, "127.0.0.1", netip.AddrPort{}, time.Now().Add(5*time.Second), authDirect)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if as.Credential == nil || as.Credential.ID != issued.Credential.ID {
		t.Fatalf("session credential = %+v, want %s", as.Credential, issued.Credential.ID)
	}
	if _, err := client.Control().Read(); err != nil {
		t.Fatalf("read auth reply: %v", err)
	}

	if err := writeAndHandleBind(t, s, client, server, as, proto.Bind{Kind: proto.KindHTTP, Subdomain: "other"}); err != nil {
		t.Fatalf("mismatched bind: %v", err)
	}
	reply, err := client.Control().Read()
	if err != nil {
		t.Fatalf("read mismatched bind reply: %v", err)
	}
	if reply.Type != proto.TypeBindErr {
		t.Fatalf("mismatched bind reply type = %q, want %q", reply.Type, proto.TypeBindErr)
	}
	bindErr, err := proto.Decode[proto.BindErr](reply)
	if err != nil {
		t.Fatalf("decode bind error: %v", err)
	}
	if bindErr.Code != proto.CodeCredentialScope {
		t.Fatalf("mismatched bind code = %q, want %q", bindErr.Code, proto.CodeCredentialScope)
	}

	if err := writeAndHandleBind(t, s, client, server, as, proto.Bind{Kind: proto.KindHTTP, Subdomain: "DEMO"}); err != nil {
		t.Fatalf("matching bind: %v", err)
	}
	reply, err = client.Control().Read()
	if err != nil {
		t.Fatalf("read matching bind reply: %v", err)
	}
	if reply.Type != proto.TypeBindOK {
		t.Fatalf("matching bind reply type = %q, want %q", reply.Type, proto.TypeBindOK)
	}
}

func TestScopedCredentialRevocationClosesLiveSession(t *testing.T) {
	originalHeartbeat := heartbeatInterval
	heartbeatInterval = 20 * time.Millisecond
	defer func() { heartbeatInterval = originalHeartbeat }()

	store, err := credentials.Open(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	issued, err := store.Issue(credentials.Spec{Subdomain: "demo"}, time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	client, server, cleanup := newRawSessionPair(t)
	defer cleanup()
	s := newTestServer("")
	s.cfg.TokenSHA256 = nil
	s.credentialStore = store

	go func() {
		_ = client.Control().Write(proto.TypeAuth, 1, proto.Auth{
			Token:         issued.Token,
			InstanceID:    "revocation-agent",
			ProtoVersions: []int{proto.ProtoVersion},
		})
	}()
	as, err := s.authenticate(context.Background(), server, "127.0.0.1", netip.AddrPort{}, time.Now().Add(5*time.Second), authDirect)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if _, err := client.Control().Read(); err != nil {
		t.Fatalf("read auth reply: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		s.controlLoop(ctx, as)
		close(done)
	}()

	if err := store.Revoke(issued.Credential.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	gotGoodbye := false
	for time.Now().Before(deadline) {
		_ = client.Control().SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		msg, err := client.Control().Read()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				continue
			}
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				continue
			}
			break
		}
		if msg.Type == proto.TypePing {
			_ = client.Control().Write(proto.TypePong, msg.ID, proto.Pong{})
		}
		if msg.Type == proto.TypeGoodbye {
			gotGoodbye = true
			break
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("control loop did not close after credential revocation")
	}
	if !gotGoodbye {
		t.Fatal("revocation did not produce a goodbye message")
	}
}

func TestScopedTCPCredentialRequiresExactPort(t *testing.T) {
	store, err := credentials.Open(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	issued, err := store.Issue(credentials.Spec{Kind: credentials.KindTCP, RemotePort: 15432}, time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	s := newTestServer("")
	s.cfg.TokenSHA256 = nil
	s.credentialStore = store
	as := &AgentSession{Credential: &issued.Credential}
	if err := s.validateCredentialBind(context.Background(), as, proto.Bind{Kind: proto.KindTCP, RemotePort: 5432}); err == nil {
		t.Fatal("wrong TCP port accepted")
	}
	if err := s.validateCredentialBind(context.Background(), as, proto.Bind{Kind: proto.KindTCP, RemotePort: 15432}); err != nil {
		t.Fatalf("matching TCP port rejected: %v", err)
	}
}

func TestScopedCredentialControlLoopRejectsShareCommands(t *testing.T) {
	store, err := credentials.Open(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := store.Issue(credentials.Spec{Subdomain: "demo"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{
		proto.TypeShare, proto.TypeUnshare, proto.TypeShareUpdate, proto.TypeKick,
		proto.TypeApprove, proto.TypeListShares, proto.TypeWatchShares, proto.TypeConnect,
	} {
		t.Run(typ, func(t *testing.T) {
			s := newTestServer("legacy-token")
			s.credentialStore = store
			client, server, cleanup := newRawSessionPair(t)
			defer cleanup()
			as := authAs(t, s, client, server, proto.Auth{
				Token: issued.Token, InstanceID: "scoped", ProtoVersions: proto.SupportedVersions,
			}, "127.0.0.1:1234")
			if as.Credential == nil || as.Credential.ID != issued.Credential.ID {
				t.Fatal("scoped credential was not attached to the authenticated session")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			metricActiveSessions.Add(1)
			go func() {
				defer close(done)
				s.controlLoop(ctx, as)
			}()
			t.Cleanup(func() {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("scoped control session did not close")
				}
			})
			ctrl := client.Control()
			if err := ctrl.Write(proto.TypeBind, 3, proto.Bind{Kind: proto.KindHTTP, Subdomain: "demo"}); err != nil {
				t.Fatal(err)
			}
			readType(t, ctrl, proto.TypeBindOK)
			if _, ok := s.registry.Route("demo.example.com"); !ok {
				t.Fatal("scoped tunnel was not bound")
			}
			if err := ctrl.Write(proto.TypePing, 5, proto.Ping{TS: 123}); err != nil {
				t.Fatal(err)
			}
			pong, err := proto.Decode[proto.Pong](readType(t, ctrl, proto.TypePong))
			if err != nil || pong.TS != 123 {
				t.Fatalf("scoped ping reply = %+v, %v", pong, err)
			}
			if err := ctrl.Write(proto.TypeUnbind, 7, proto.Unbind{Hostname: "demo.example.com"}); err != nil {
				t.Fatal(err)
			}
			readType(t, ctrl, proto.TypeUnbindOK)
			if _, ok := s.registry.Route("demo.example.com"); ok {
				t.Fatal("scoped tunnel was not unbound")
			}
			if err := ctrl.Write(typ, 9, struct{}{}); err != nil {
				t.Fatal(err)
			}
			reply, err := proto.Decode[proto.Error](readType(t, ctrl, proto.TypeError))
			if err != nil || reply.Code != proto.CodeForbidden {
				t.Fatalf("scoped %s reply = %+v, %v; want forbidden", typ, reply, err)
			}
		})
	}
}

func TestScopedCredentialAuthenticationModesRemainSeparate(t *testing.T) {
	store, err := credentials.Open(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := store.Issue(credentials.Spec{Subdomain: "demo"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		auth proto.Auth
		typ  string
		code string
	}{
		{"legacy token", proto.Auth{Token: "legacy-token"}, proto.TypeAuthErr, proto.CodeBadToken},
		{"mixed token and share secret", proto.Auth{Token: issued.Token, ShareSecret: "share-secret"}, proto.TypeError, proto.CodeMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer("legacy-token")
			s.credentialStore = store
			client, server, cleanup := newRawSessionPair(t)
			defer cleanup()
			auth := tc.auth
			auth.ProtoVersions = proto.SupportedVersions
			if err := client.Control().Write(proto.TypeAuth, 1, auth); err != nil {
				t.Fatal(err)
			}
			if _, err := s.authenticate(context.Background(), server, "127.0.0.1", netip.AddrPort{}, time.Now().Add(5*time.Second), authDirect); err == nil {
				t.Fatal("authentication unexpectedly succeeded")
			}
			reply, err := proto.Decode[proto.Error](readType(t, client.Control(), tc.typ))
			if err != nil || reply.Code != tc.code {
				t.Fatalf("authentication reply = %+v, %v; want %s", reply, err, tc.code)
			}
		})
	}
}

func writeAndHandleBind(t *testing.T, s *Server, client, server tunnel.Session, as *AgentSession, bind proto.Bind) error {
	t.Helper()
	if err := client.Control().Write(proto.TypeBind, 2, bind); err != nil {
		return err
	}
	msg, err := server.Control().Read()
	if err != nil {
		return err
	}
	decoded, err := proto.Decode[proto.Bind](msg)
	if err != nil {
		return err
	}
	s.handleBind(context.Background(), as, server.Control(), msg.ID, decoded)
	return nil
}

func newShareCredentialServer(t *testing.T) (*Server, *credentials.Store) {
	t.Helper()
	store, err := credentials.Open(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer("")
	s.cfg.TokenSHA256 = nil
	s.credentialStore = store
	return s, store
}

func startCredentialSession(t *testing.T, s *Server, token, instance string) tunnel.Session {
	t.Helper()
	client, server, cleanup := newRawSessionPair(t)
	t.Cleanup(cleanup)
	as := authAs(t, s, client, server, proto.Auth{Token: token, InstanceID: instance, ProtoVersions: proto.SupportedVersions}, "127.0.0.1:1234")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.controlLoop(ctx, as)
	}()
	t.Cleanup(func() {
		cancel()
		client.Close("test done")
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("credential control session did not close")
		}
	})
	return client
}

func exchange(t *testing.T, ctrl *proto.Conn, typ string, id uint64, payload any) proto.Msg {
	t.Helper()
	if err := ctrl.Write(typ, id, payload); err != nil {
		t.Fatal(err)
	}
	for {
		m := shareReply(t, ctrl)
		if m.Type == proto.TypeShareEvent || m.Type == proto.TypePing {
			continue
		}
		return m
	}
}

func TestNonShareCredentialsCannotShare(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec credentials.Spec
	}{
		{"preview", credentials.Spec{Kind: credentials.KindPreview}},
		{"tcp", credentials.Spec{Kind: credentials.KindTCP, RemotePort: 15432}},
		{"tls", credentials.Spec{Kind: credentials.KindTLS, Subdomain: "secure"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, store := newShareCredentialServer(t)
			issued, err := store.Issue(tc.spec, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			ctrl := startCredentialSession(t, s, issued.Token, "scoped-"+tc.name).Control()
			m := exchange(t, ctrl, proto.TypeShare, 9, testShareReq("secret-"+tc.name, 10*time.Minute))
			reply, err := proto.Decode[proto.Error](m)
			if m.Type != proto.TypeError || err != nil || reply.Code != proto.CodeForbidden {
				t.Fatalf("share reply = %s %s, want forbidden error", m.Type, m.Data)
			}
			if s.shares.count() != 0 {
				t.Fatal("a non-share credential registered a share")
			}
		})
	}
}

func TestShareCredentialControlLoop(t *testing.T) {
	s, store := newShareCredentialServer(t)
	issued, err := store.Issue(credentials.Spec{Kind: credentials.KindShare, OwnerID: "owner-a"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ctrl := startCredentialSession(t, s, issued.Token, "sharer").Control()
	if m := exchange(t, ctrl, proto.TypeShare, 3, testShareReq("secret", 10*time.Minute)); m.Type != proto.TypeShareOK {
		t.Fatalf("share reply = %s %s, want share_ok", m.Type, m.Data)
	}
	if s.shares.count() != 1 {
		t.Fatal("the share was not registered")
	}
	for i, tc := range []struct {
		typ     string
		payload any
	}{
		{proto.TypeBind, proto.Bind{Kind: proto.KindHTTP, Subdomain: "demo"}},
		{proto.TypeUnbind, proto.Unbind{Hostname: "demo.example.com"}},
		{proto.TypeConnect, proto.Connect{}},
	} {
		forbidden := startCredentialSession(t, s, issued.Token, fmt.Sprintf("forbidden-%d", i)).Control()
		m := exchange(t, forbidden, tc.typ, uint64(20+i), tc.payload)
		reply, err := proto.Decode[proto.Error](m)
		if m.Type != proto.TypeError || err != nil || reply.Code != proto.CodeForbidden {
			t.Fatalf("%s reply = %s %s, want forbidden error", tc.typ, m.Type, m.Data)
		}
	}
	if _, ok := s.registry.Route("demo.example.com"); ok {
		t.Fatal("a share credential bound a tunnel")
	}
}

func TestShareCredentialCannotBind(t *testing.T) {
	s, store := newShareCredentialServer(t)
	issued, err := store.Issue(credentials.Spec{Kind: credentials.KindShare}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	as := &AgentSession{Credential: &issued.Credential}
	for name, bind := range map[string]proto.Bind{
		"http": {Kind: proto.KindHTTP, Subdomain: "demo"},
		"tcp":  {Kind: proto.KindTCP, RemotePort: 0},
		"tls":  {Kind: proto.KindTLS, Subdomain: "secure"},
	} {
		err := s.validateCredentialBind(context.Background(), as, bind)
		if err == nil || err.Error() != "share credentials cannot bind tunnels" {
			t.Fatalf("%s bind error = %v, want the share credential refusal", name, err)
		}
	}
}

func TestShareOwnerScoping(t *testing.T) {
	s, store := newShareCredentialServer(t)
	issue := func(owner string) string {
		issued, err := store.Issue(credentials.Spec{Kind: credentials.KindShare, OwnerID: owner}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return issued.Token
	}
	a1 := startCredentialSession(t, s, issue("owner-a"), "a1").Control()
	a2 := startCredentialSession(t, s, issue("owner-a"), "a2").Control()
	b := startCredentialSession(t, s, issue("owner-b"), "b").Control()

	m := exchange(t, a1, proto.TypeShare, 3, testShareReq("secret-a", 10*time.Minute))
	if m.Type != proto.TypeShareOK {
		t.Fatalf("share reply = %s %s, want share_ok", m.Type, m.Data)
	}
	ok, err := proto.Decode[proto.ShareOK](m)
	if err != nil {
		t.Fatal(err)
	}

	list := func(c *proto.Conn) []proto.ShareInfo {
		m := exchange(t, c, proto.TypeListShares, 4, struct{}{})
		if m.Type != proto.TypeSharesOK {
			t.Fatalf("list reply = %s %s", m.Type, m.Data)
		}
		out, err := proto.Decode[proto.SharesOK](m)
		if err != nil {
			t.Fatal(err)
		}
		return out.Shares
	}
	if got := list(b); len(got) != 0 {
		t.Fatalf("owner-b sees %d shares, want 0", len(got))
	}
	if got := list(a2); len(got) != 1 || got[0].ShareID != ok.ShareID {
		t.Fatalf("second owner-a credential sees %+v, want the share", got)
	}

	verbs := []struct {
		name    string
		typ     string
		payload func(id string) any
	}{
		{"unshare", proto.TypeUnshare, func(id string) any { return proto.Unshare{ShareID: id} }},
		{"update", proto.TypeShareUpdate, func(id string) any {
			return proto.ShareUpdate{ShareID: id, ExpiresAtMS: time.Now().Add(20 * time.Minute).UnixMilli()}
		}},
		{"kick", proto.TypeKick, func(id string) any { return proto.Kick{ShareID: id, ConnectorID: "c1"} }},
		{"approve", proto.TypeApprove, func(id string) any { return proto.Approve{ShareID: id, ConnectorID: "c1", Allow: true} }},
	}
	for _, v := range verbs {
		unknown := exchange(t, b, v.typ, 5, v.payload("sh_unknown"))
		other := exchange(t, b, v.typ, 6, v.payload(ok.ShareID))
		if unknown.Type == proto.TypeUnshareOK || unknown.Type == proto.TypeShareOK || unknown.Type == proto.TypeKickOK || unknown.Type == proto.TypeApproveOK {
			t.Fatalf("%s on an unknown id succeeded: %s", v.name, unknown.Data)
		}
		if other.Type != unknown.Type || string(other.Data) != string(unknown.Data) {
			t.Fatalf("%s on another owner's share = %s %s, want exactly the unknown-id reply %s %s", v.name, other.Type, other.Data, unknown.Type, unknown.Data)
		}
		if _, live := s.shares.byShareID(ok.ShareID); !live {
			t.Fatalf("%s by another owner removed the share", v.name)
		}
	}
	if m := exchange(t, a2, proto.TypeUnshare, 7, proto.Unshare{ShareID: ok.ShareID}); m.Type != proto.TypeUnshareOK {
		t.Fatalf("same-owner unshare = %s %s, want unshare_ok", m.Type, m.Data)
	}
	if _, live := s.shares.byShareID(ok.ShareID); live {
		t.Fatal("same-owner unshare left the share registered")
	}
}

func TestShareWatchersScopedToOwner(t *testing.T) {
	s, store := newShareCredentialServer(t)
	issue := func(owner string) string {
		issued, err := store.Issue(credentials.Spec{Kind: credentials.KindShare, OwnerID: owner}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return issued.Token
	}
	sharer := startCredentialSession(t, s, issue("owner-a"), "sharer").Control()
	watchA := startCredentialSession(t, s, issue("owner-a"), "watch-a").Control()
	watchB := startCredentialSession(t, s, issue("owner-b"), "watch-b").Control()
	for _, w := range []*proto.Conn{watchA, watchB} {
		if m := exchange(t, w, proto.TypeWatchShares, 2, struct{}{}); m.Type != proto.TypeWatchOK {
			t.Fatalf("watch reply = %s %s", m.Type, m.Data)
		}
	}
	silent := func(c *proto.Conn) {
		t.Helper()
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		defer c.SetReadDeadline(time.Time{})
		for {
			m, err := c.Read()
			if err != nil {
				return
			}
			if m.Type == proto.TypeShareEvent {
				t.Fatalf("owner-b watcher received a share event: %s", m.Data)
			}
		}
	}
	m := exchange(t, sharer, proto.TypeShare, 3, testShareReq("secret-a", 10*time.Minute))
	ok, err := proto.Decode[proto.ShareOK](m)
	if m.Type != proto.TypeShareOK || err != nil {
		t.Fatalf("share reply = %s %s", m.Type, m.Data)
	}
	readEvent(t, watchA, proto.ShareEventRegistered)
	silent(watchB)
	if m := exchange(t, sharer, proto.TypeUnshare, 4, proto.Unshare{ShareID: ok.ShareID}); m.Type != proto.TypeUnshareOK {
		t.Fatalf("unshare reply = %s %s", m.Type, m.Data)
	}
	readEvent(t, watchA, proto.ShareEventClosed)
	silent(watchB)
}

func TestShareTakeoverRequiresSameOwner(t *testing.T) {
	s, store := newShareCredentialServer(t)
	issue := func(owner string) string {
		issued, err := store.Issue(credentials.Spec{Kind: credentials.KindShare, OwnerID: owner}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return issued.Token
	}
	a := startCredentialSession(t, s, issue("owner-a"), "same-instance").Control()
	b := startCredentialSession(t, s, issue("owner-b"), "same-instance").Control()
	if m := exchange(t, a, proto.TypeShare, 3, testShareReq("secret-a", 10*time.Minute)); m.Type != proto.TypeShareOK {
		t.Fatalf("share reply = %s %s", m.Type, m.Data)
	}
	m := exchange(t, b, proto.TypeShare, 4, testShareReq("secret-a", 10*time.Minute))
	reply, err := proto.Decode[proto.ShareErr](m)
	if m.Type != proto.TypeShareErr || err != nil || reply.Code != proto.CodeShareTaken {
		t.Fatalf("takeover reply = %s %s, want share_taken", m.Type, m.Data)
	}
	if sh, live := s.shares.lookup("secret-a"); !live || sh.ownerID != "owner-a" {
		t.Fatal("the original share was displaced")
	}
}
