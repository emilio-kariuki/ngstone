package edge

import (
	"context"
	"errors"
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
	as, err := s.authenticate(context.Background(), server, "127.0.0.1", netip.AddrPort{}, time.Now().Add(5*time.Second))
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
	as, err := s.authenticate(context.Background(), server, "127.0.0.1", netip.AddrPort{}, time.Now().Add(5*time.Second))
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
			if _, err := s.authenticate(context.Background(), server, "127.0.0.1", netip.AddrPort{}, time.Now().Add(5*time.Second)); err == nil {
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
