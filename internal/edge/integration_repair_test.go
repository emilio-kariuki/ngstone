package edge

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ngstone/internal/credentials"
	"ngstone/internal/oidc"
	"ngstone/internal/proto"
	"ngstone/internal/storage"
)

func TestUploadTimeoutOverridesUpstreamSuccess(t *testing.T) {
	s := newClientLimitsServer(t, LimitsConfig{PerIPInFlight: 1, ClientIdleTimeout: 30 * time.Millisecond})
	as := newEchoAgentSession(t, "upload-timeout")
	binding, _, err := s.registry.Bind("demo.example.com", as, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	binding.connectorForSession(as).proxy.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if _, err := io.ReadAll(r.Body); !errors.Is(err, errClientIdle) {
			return nil, errors.New("request did not reach its upload deadline")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), ContentLength: 2, Request: r}, nil
	})
	runServer(t, s)
	conn, err := net.Dial("tcp", s.cfg.PublicAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: demo.example.com\r\nContent-Length: 100\r\n\r\nx"); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusRequestTimeout || !response.Close {
		t.Fatalf("stalled upload got %d, close=%v", response.StatusCode, response.Close)
	}
	if n := s.perIP.inUse("127.0.0.1"); n != 0 {
		t.Fatalf("timed-out upload retained %d slots", n)
	}
}

func TestAdminDrainChecksSessionOwner(t *testing.T) {
	for _, tc := range []struct {
		name, subject, role, owner string
		want                       int
	}{
		{"owner", "alice", oidc.RoleOperator, "alice", http.StatusAccepted},
		{"other owner", "bob", oidc.RoleOperator, "alice", http.StatusNotFound},
		{"unowned", "alice", oidc.RoleOperator, "", http.StatusNotFound},
		{"global admin", "bob", oidc.RoleAdmin, "alice", http.StatusAccepted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server, cleanup := newRawSessionPair(t)
			defer cleanup()
			s := newTestServer("")
			as := &AgentSession{ID: "session", InstanceID: "instance", Sess: server, IDGen: proto.NewEdgeIDGen(), Credential: &credentials.Credential{OwnerID: tc.owner}}
			if _, _, err := s.registry.Bind("demo.example.com", as, false, nil); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "/api/v1/tunnels/demo/drain", nil)
			r = r.WithContext(withAdminAuth(r.Context(), adminAuth{Principal: oidc.Principal{Subject: tc.subject, Role: tc.role}}))
			w := httptest.NewRecorder()
			s.handleAdminDrain(w, r, "demo")
			if w.Code != tc.want {
				t.Fatalf("drain status = %d, want %d", w.Code, tc.want)
			}
			if tc.want == http.StatusNotFound {
				if binding, ok := s.registry.Route("demo.example.com"); !ok || binding.Sess != as {
					t.Fatal("denied drain changed the tunnel")
				}
				return
			}
			if err := client.Control().SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			message, err := client.Control().Read()
			if err != nil || message.Type != proto.TypeGoodbye {
				t.Fatalf("authorized drain = %v, %v", message, err)
			}
		})
	}
}

func TestDurableTunnelBelongsToCredentialOwner(t *testing.T) {
	store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	issued, err := store.Issue(credentials.Spec{Subdomain: "demo", OwnerID: "alice"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer("")
	s.storage = store
	as := &AgentSession{ID: "session", InstanceID: "instance", Credential: &issued.Credential}
	lease, err := s.acquireDurableLease(as, proto.Bind{Kind: proto.KindHTTP, Subdomain: "demo"}, "demo.example.com", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateCustomDomain(t.Context(), storage.CustomDomainSpec{Domain: "demo.example.org", TunnelID: lease.TunnelID, OwnerID: "alice"}); err != nil {
		t.Fatalf("associate owner's tunnel: %v", err)
	}
	if lease.OwnerID != "alice" {
		t.Fatalf("lease owner = %q, want alice", lease.OwnerID)
	}
}

func TestDurablePoolAcceptsReorderedAccessLists(t *testing.T) {
	store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s := newTestServer("")
	s.storage = store
	bind := proto.Bind{Kind: proto.KindHTTP, Subdomain: "demo", MultiConnector: true, ConnectorTokenSHA256: testConnectorTokenDigest, AllowCIDRs: []string{"127.0.0.0/8", "10.0.0.0/8"}}
	a := &AgentSession{ID: "session-a", InstanceID: "instance-a"}
	b := &AgentSession{ID: "session-b", InstanceID: "instance-b"}
	first, err := s.acquireDurableLease(a, bind, "demo.example.com", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	bind.AllowCIDRs = []string{"10.0.0.0/8", "127.0.0.0/8"}
	second, err := s.acquireDurableLease(b, bind, "demo.example.com", 0, nil)
	if err != nil {
		t.Fatalf("equivalent connector configuration rejected: %v", err)
	}
	if second.TunnelID != first.TunnelID {
		t.Fatal("equivalent connector did not join the existing tunnel")
	}
	bind.AllowCIDRs = []string{"192.0.2.0/24"}
	if _, err := s.acquireDurableLease(&AgentSession{ID: "session-c", InstanceID: "instance-c"}, bind, "demo.example.com", 0, nil); err == nil {
		t.Fatal("different access configuration joined the pool")
	}
	if tunnels, err := store.ListTunnels(context.Background()); err != nil || len(tunnels) != 1 || len(tunnels[0].Connectors) != 2 {
		t.Fatalf("pool after rejected connector = %v, %v", tunnels, err)
	}
}

func TestPreviewCredentialUsesOneAssignedHostname(t *testing.T) {
	store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	issued, err := store.Issue(credentials.Spec{Kind: credentials.KindPreview, OwnerID: "alice"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer("")
	s.storage, s.credentialStore = store, store
	client, server, cleanup := newRawSessionPair(t)
	defer cleanup()
	as := &AgentSession{ID: "preview-session", InstanceID: "preview-instance", Sess: server, Credential: &issued.Credential, NegotiatedVersion: 2, IDGen: proto.NewEdgeIDGen()}
	for _, bad := range []proto.Bind{
		{Kind: proto.KindHTTP, Subdomain: "chosen"},
		{Kind: proto.KindTCP, RemotePort: 5432},
		{Kind: proto.KindHTTP, MultiConnector: true},
	} {
		if err := s.validateCredentialBind(t.Context(), as, bad); err == nil {
			t.Fatalf("preview credential accepted %v", bad)
		}
	}
	for i := range 2 {
		s.handleBind(t.Context(), as, server.Control(), uint64(i+1), proto.Bind{Kind: proto.KindHTTP, Takeover: true})
		message, err := client.Control().Read()
		if err != nil || message.Type != proto.TypeBindOK {
			t.Fatalf("preview bind = %v, %v", message, err)
		}
		bound, err := proto.Decode[proto.BindOK](message)
		if err != nil || bound.Hostname != "preview-"+issued.Credential.ID+".example.com" {
			t.Fatalf("assigned preview = %v, %v", bound, err)
		}
	}
	if tunnels, err := store.ListTunnels(t.Context()); err != nil || len(tunnels) != 1 {
		t.Fatalf("preview allocated multiple tunnels: %v, %v", tunnels, err)
	}
	if err := store.Revoke(issued.Credential.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.validateCredentialBind(t.Context(), as, proto.Bind{Kind: proto.KindHTTP}); err == nil {
		t.Fatal("revoked preview credential still binds")
	}
}

func TestRegistryReconnectRequiresSamePrincipal(t *testing.T) {
	s := newTestServer("")
	a, cleanupA := newTestAgentSession(t, "same-instance")
	defer cleanupA()
	b, cleanupB := newTestAgentSession(t, "same-instance")
	defer cleanupB()
	a.Credential = &credentials.Credential{ID: "first", OwnerID: "alice"}
	b.Credential = &credentials.Credential{ID: "second", OwnerID: "bob"}
	if _, _, err := s.registry.Bind("demo.example.com", a, false, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.registry.Bind("demo.example.com", b, false, nil); !errors.Is(err, ErrSubdomainTaken) {
		t.Fatalf("cross-owner reconnect = %v", err)
	}
	b.Credential.OwnerID = "alice"
	if _, evicted, err := s.registry.Bind("demo.example.com", b, false, nil); err != nil || evicted != a {
		t.Fatalf("same-owner credential rotation = %v, evicted %p", err, evicted)
	}
}
