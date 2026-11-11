package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"ngstone/internal/credentials"
	"ngstone/internal/proto"
	"ngstone/internal/storage"
)

type countingDomainStore struct {
	inner customDomainStore
	calls atomic.Int64
}

func (c *countingDomainStore) LookupCustomDomainTarget(ctx context.Context, domain string) (storage.CustomDomainTarget, bool, error) {
	c.calls.Add(1)
	return c.inner.LookupCustomDomainTarget(ctx, domain)
}

type flakyDomainStore struct {
	inner customDomainStore
	calls atomic.Int64
	fail  atomic.Bool
}

func (f *flakyDomainStore) LookupCustomDomainTarget(ctx context.Context, domain string) (storage.CustomDomainTarget, bool, error) {
	f.calls.Add(1)
	if f.fail.Load() {
		return storage.CustomDomainTarget{}, false, errors.New("storage unavailable")
	}
	return f.inner.LookupCustomDomainTarget(ctx, domain)
}

func openAliasStore(t *testing.T) *storage.Store {
	t.Helper()
	store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db"), EdgeID: "edge-test"})
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func newAliasServer(t *testing.T) *Server {
	t.Helper()
	s := newDomainTestServer(t)
	s.perIPLimiter = newPerIPLimiter(1000, 1000, 100)
	s.observability = newObservabilityRegistry()
	s.aliases = newAliasResolver(s.storage, s.customDomainReserved)
	return s
}

func registerActiveDomain(t *testing.T, store *storage.Store, domain, hostname, kind, owner string) string {
	t.Helper()
	lease, err := store.AcquireLease(t.Context(), storage.LeaseRequest{Hostname: hostname, Kind: kind, OwnerID: owner, InstanceID: hostname, SessionID: hostname})
	if err != nil {
		t.Fatalf("acquire lease %s: %v", hostname, err)
	}
	created, err := store.CreateCustomDomain(t.Context(), storage.CustomDomainSpec{Domain: domain, OwnerID: owner, TunnelID: lease.TunnelID})
	if err != nil {
		t.Fatalf("create domain %s: %v", domain, err)
	}
	if _, err := store.SetCustomDomainStatus(t.Context(), created.ID, "active"); err != nil {
		t.Fatalf("activate domain %s: %v", domain, err)
	}
	return lease.TunnelID
}

func ownedSession(t *testing.T, owner string, handler http.HandlerFunc) *AgentSession {
	t.Helper()
	as := newFakeAgentSession(t, "alias-"+owner, handler)
	as.Credential = &credentials.Credential{ID: "cred-" + owner, OwnerID: owner}
	return as
}

func aliasGet(s *Server, host string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/path", nil)
	req.RemoteAddr = "9.9.9.9:4000"
	rec := httptest.NewRecorder()
	s.handlePublic(rec, req)
	return rec
}

func TestAliasResolverBoundsLookups(t *testing.T) {
	store := openAliasStore(t)
	counting := &countingDomainStore{inner: store}
	reserved := func(name string) bool { return hostMatchesDomain(name, "example.com") }
	resolver := newAliasResolver(counting, reserved)

	for i := 0; i < 100; i++ {
		if _, ok := resolver.resolve("unknown.example.org", "1.1.1.1"); ok {
			t.Fatal("unknown name resolved")
		}
	}
	if got := counting.calls.Load(); got != 1 {
		t.Fatalf("lookups for one unknown name = %d, want 1", got)
	}

	before := counting.calls.Load()
	for i := 0; i < 100; i++ {
		resolver.resolve(fmt.Sprintf("random-%d.example.org", i), "2.2.2.2")
	}
	if got := counting.calls.Load() - before; got > aliasLimiterBurst {
		t.Fatalf("lookups for 100 random names from one ip = %d, want at most %d", got, aliasLimiterBurst)
	}

	before = counting.calls.Load()
	for i := 0; i < 100; i++ {
		resolver.resolve(fmt.Sprintf("n%d.example.com", i), "3.3.3.3")
		resolver.resolve("example.com", "3.3.3.3")
	}
	if got := counting.calls.Load() - before; got != 0 {
		t.Fatalf("lookups for names under the edge domain = %d, want 0", got)
	}
}

func TestAliasResolverDoesNotCacheStorageErrors(t *testing.T) {
	store := openAliasStore(t)
	registerActiveDomain(t, store, "app.example.org", "web.example.com", "http", "alice")
	flaky := &flakyDomainStore{inner: store}
	flaky.fail.Store(true)
	resolver := newAliasResolver(flaky, func(string) bool { return false })

	if _, ok := resolver.resolve("app.example.org", "1.1.1.1"); ok {
		t.Fatal("resolved while storage was failing")
	}
	flaky.fail.Store(false)
	target, ok := resolver.resolve("app.example.org", "1.1.1.1")
	if !ok || target.Hostname != "web.example.com" {
		t.Fatalf("resolve after recovery = %+v, %v", target, ok)
	}
	if got := flaky.calls.Load(); got != 2 {
		t.Fatalf("storage calls = %d, want 2", got)
	}
}

func TestLocalAliasRefusesOwnerMismatch(t *testing.T) {
	s := newAliasServer(t)
	registerActiveDomain(t, s.storage, "app.example.org", "web.example.com", "http", "alice")

	if _, b, state := s.localAlias("app.example.org", "1.1.1.1"); b != nil || state != aliasRemote {
		t.Fatalf("unbound state = %v binding=%v, want aliasRemote", state, b)
	}

	mallory := ownedSession(t, "mallory", nil)
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "web.example.com", Session: mallory}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if _, b, state := s.localAlias("app.example.org", "1.1.1.1"); b != nil || state != aliasRefused {
		t.Fatalf("mismatched owner state = %v binding=%v, want aliasRefused", state, b)
	}

	s.registry.Unbind("web.example.com", mallory)
	alice := ownedSession(t, "alice", nil)
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "web.example.com", Session: alice}); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	if _, b, state := s.localAlias("app.example.org", "1.1.1.1"); b == nil || state != aliasLocal {
		t.Fatalf("matching owner state = %v binding=%v, want aliasLocal", state, b)
	}
}

func TestHandlePublicRoutesActiveCustomDomain(t *testing.T) {
	s := newAliasServer(t)
	registerActiveDomain(t, s.storage, "app.example.org", "web.example.com", "http", "alice")
	var mu sync.Mutex
	var seenHost string
	as := ownedSession(t, "alice", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		mu.Lock()
		seenHost = r.Host
		mu.Unlock()
		io.WriteString(w, "origin-ok")
	})
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "web.example.com", Session: as}); err != nil {
		t.Fatalf("bind: %v", err)
	}

	rec := aliasGet(s, "App.Example.Org:8443")
	if rec.Code != http.StatusOK || rec.Body.String() != "origin-ok" {
		t.Fatalf("status = %d body = %q", rec.Code, rec.Body.String())
	}
	mu.Lock()
	got := seenHost
	mu.Unlock()
	if got != "App.Example.Org:8443" {
		t.Fatalf("agent saw Host %q", got)
	}
	found := false
	for _, delta := range s.observability.snapshot() {
		if delta.Hostname == "web.example.com" && delta.RequestCount == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("request not recorded under the canonical hostname: %+v", s.observability.snapshot())
	}
}

func TestHandlePublicPendingCustomDomain404(t *testing.T) {
	s := newAliasServer(t)
	store := s.storage
	lease, err := store.AcquireLease(t.Context(), storage.LeaseRequest{Hostname: "web.example.com", Kind: "http", OwnerID: "alice", InstanceID: "i", SessionID: "s"})
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if _, err := store.CreateCustomDomain(t.Context(), storage.CustomDomainSpec{Domain: "app.example.org", OwnerID: "alice", TunnelID: lease.TunnelID}); err != nil {
		t.Fatalf("create domain: %v", err)
	}
	hits := atomic.Int64{}
	as := ownedSession(t, "alice", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "origin-ok")
	})
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "web.example.com", Session: as}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if rec := aliasGet(s, "app.example.org"); rec.Code != http.StatusNotFound {
		t.Fatalf("pending domain status = %d, want 404", rec.Code)
	}
	if hits.Load() != 0 {
		t.Fatal("pending domain reached the agent")
	}
}

func TestHandlePublicCustomDomainTLSKind421(t *testing.T) {
	s := newAliasServer(t)
	registerActiveDomain(t, s.storage, "secure.example.org", "secure.example.com", "tls", "alice")
	as := ownedSession(t, "alice", nil)
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "secure.example.com", Session: as, TLS: true}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if rec := aliasGet(s, "secure.example.org"); rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("tls-kind custom domain status = %d, want 421", rec.Code)
	}
}

func TestHandlePublicCustomDomainLoginRule403(t *testing.T) {
	s := newAliasServer(t)
	registerActiveDomain(t, s.storage, "app.example.org", "login.example.com", "http", "alice")
	hits := atomic.Int64{}
	as := ownedSession(t, "alice", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "origin-ok")
	})
	ac, err := buildAccessControl(proto.Bind{OIDC: &proto.OIDCLogin{}})
	if err != nil {
		t.Fatalf("buildAccessControl: %v", err)
	}
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "login.example.com", Session: as, Access: ac}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	rec := aliasGet(s, "app.example.org")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("login-protected custom domain status = %d, want 403", rec.Code)
	}
	if hits.Load() != 0 {
		t.Fatal("login-protected custom domain reached the agent")
	}
}

func TestClassifyRoutesCustomDomainPassthrough(t *testing.T) {
	agentCert, agentPool := passthroughTestCert(t, "tls.example.org")
	s := newAliasServer(t)
	registerActiveDomain(t, s.storage, "tls.example.org", "tls-tun.example.com", "tls", "alice")

	var preamble atomic.Pointer[proto.StreamOpen]
	fx := newTCPFixture(t, func(conn net.Conn, pre proto.StreamOpen) {
		defer conn.Close()
		preamble.Store(&pre)
		tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{agentCert}})
		if err := tc.Handshake(); err != nil {
			return
		}
		io.Copy(tc, tc)
	})
	t.Cleanup(fx.cleanup)
	fx.as.Credential = &credentials.Credential{ID: "cred-alice", OwnerID: "alice"}
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "tls-tun.example.com", Session: fx.as, TLS: true}); err != nil {
		t.Fatalf("bind: %v", err)
	}

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := s.newSNIListener(raw)
	t.Cleanup(func() { ln.Close() })

	tc, err := dialTLSClient(t, raw.Addr().String(), nil, &tls.Config{ServerName: "tls.example.org", RootCAs: agentPool})
	if err != nil {
		t.Fatalf("handshake through custom domain passthrough: %v", err)
	}
	if _, err := tc.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(tc, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	pre := preamble.Load()
	if pre == nil || pre.Host != "tls-tun.example.com" || pre.Kind != "tls" {
		t.Fatalf("agent preamble = %+v, want canonical host and tls kind", pre)
	}
}
