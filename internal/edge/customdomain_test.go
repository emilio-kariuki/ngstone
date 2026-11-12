package edge

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ngstone/internal/credentials"
	"ngstone/internal/oidc"
	"ngstone/internal/proto"
	"ngstone/internal/storage"
)

type countingDomainStore struct {
	inner customDomainStore
	calls atomic.Int64
}

func (c *countingDomainStore) ActiveCustomDomains(ctx context.Context, limit int) ([]storage.ActiveCustomDomain, error) {
	c.calls.Add(1)
	return c.inner.ActiveCustomDomains(ctx, limit)
}

type flakyDomainStore struct {
	inner customDomainStore
	fail  atomic.Bool
}

func (f *flakyDomainStore) ActiveCustomDomains(ctx context.Context, limit int) ([]storage.ActiveCustomDomain, error) {
	if f.fail.Load() {
		return nil, errors.New("storage unavailable")
	}
	return f.inner.ActiveCustomDomains(ctx, limit)
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
	s.aliases = newAliasResolver(s.storage, s.customDomainReserved, s.leaseTTL)
	return s
}

func registerActiveDomain(t *testing.T, s *Server, domain, hostname, kind, owner string) string {
	t.Helper()
	store := s.storage
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
	s.aliases.refresh(t.Context())
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

func newTestResolver(store customDomainStore, reserved func(string) bool) *aliasResolver {
	return newAliasResolver(store, reserved, func() time.Duration { return 10 * time.Second })
}

func activateRow(t *testing.T, store *storage.Store, domain, hostname, owner string, activate bool) string {
	t.Helper()
	lease, err := store.AcquireLease(t.Context(), storage.LeaseRequest{Hostname: hostname, Kind: "http", OwnerID: owner, InstanceID: hostname, SessionID: hostname})
	if err != nil {
		t.Fatalf("acquire lease %s: %v", hostname, err)
	}
	created, err := store.CreateCustomDomain(t.Context(), storage.CustomDomainSpec{Domain: domain, OwnerID: owner, TunnelID: lease.TunnelID})
	if err != nil {
		t.Fatalf("create domain %s: %v", domain, err)
	}
	if activate {
		if _, err := store.SetCustomDomainStatus(t.Context(), created.ID, "active"); err != nil {
			t.Fatalf("activate domain %s: %v", domain, err)
		}
	}
	return created.ID
}

func TestAliasSnapshotRoutesOnlyActiveDomains(t *testing.T) {
	store := openAliasStore(t)
	activateRow(t, store, "live.example.org", "live.example.com", "alice", true)
	activateRow(t, store, "pending.example.org", "pending.example.com", "alice", false)
	disabledID := activateRow(t, store, "disabled.example.org", "disabled.example.com", "alice", true)
	if _, err := store.SetCustomDomainStatus(t.Context(), disabledID, "disabled"); err != nil {
		t.Fatal(err)
	}
	activateRow(t, store, "www.example.com", "reserved.example.net", "alice", true)
	resolver := newTestResolver(store, func(name string) bool { return hostMatchesDomain(name, "example.com") })
	resolver.refresh(t.Context())

	cases := []struct {
		host string
		want bool
	}{
		{"live.example.org", true},
		{"LIVE.Example.Org", true},
		{"pending.example.org", false},
		{"disabled.example.org", false},
		{"unknown.example.org", false},
		{"www.example.com", false},
	}
	for _, tc := range cases {
		target, ok := resolver.resolve(tc.host)
		if ok != tc.want {
			t.Fatalf("resolve(%q) = %+v, %v; want %v", tc.host, target, ok, tc.want)
		}
	}
	if target, _ := resolver.resolve("live.example.org"); target != (aliasTarget{Hostname: "live.example.com", Kind: "http", OwnerID: "alice"}) {
		t.Fatalf("live target = %+v", target)
	}
	if got := metricCustomDomainsActive.Value(); got != 2 {
		t.Fatalf("active gauge = %d, want 2 (live and the reserved name still in the snapshot)", got)
	}
}

func TestAliasResolveNeverQueriesStorage(t *testing.T) {
	store := openAliasStore(t)
	activateRow(t, store, "app.example.org", "web.example.com", "alice", true)
	counting := &countingDomainStore{inner: store}
	resolver := newTestResolver(counting, func(name string) bool { return hostMatchesDomain(name, "example.com") })
	resolver.refresh(t.Context())
	if got := counting.calls.Load(); got != 1 {
		t.Fatalf("calls after first load = %d, want 1", got)
	}
	for i := 0; i < 1000; i++ {
		resolver.resolve(fmt.Sprintf("random-%d.example.org", i))
		resolver.resolve("app.example.org")
		resolver.resolve(fmt.Sprintf("n%d.example.com", i))
	}
	if got := counting.calls.Load(); got != 1 {
		t.Fatalf("storage calls after 3000 resolves = %d, want 1", got)
	}
}

func TestAliasSnapshotFailsClosedAfterTTL(t *testing.T) {
	store := openAliasStore(t)
	activateRow(t, store, "app.example.org", "web.example.com", "alice", true)
	flaky := &flakyDomainStore{inner: store}
	resolver := newTestResolver(flaky, func(string) bool { return false })
	errs := metricDelta(metricCustomDomainLookupErrors)
	t0 := time.Now()

	resolver.load(t.Context(), t0)
	if _, ok := resolver.resolve("app.example.org"); !ok {
		t.Fatal("domain not routed after a successful load")
	}
	flaky.fail.Store(true)
	resolver.load(t.Context(), t0.Add(9*time.Second))
	if _, ok := resolver.resolve("app.example.org"); !ok {
		t.Fatal("snapshot dropped before the lease TTL elapsed")
	}
	resolver.load(t.Context(), t0.Add(11*time.Second))
	if _, ok := resolver.resolve("app.example.org"); ok {
		t.Fatal("stale snapshot still routes after the lease TTL")
	}
	if got := metricCustomDomainsActive.Value(); got != 0 {
		t.Fatalf("active gauge after expiry = %d, want 0", got)
	}
	if errs() != 2 {
		t.Fatalf("lookup errors = %d, want 2", errs())
	}
	flaky.fail.Store(false)
	resolver.load(t.Context(), t0.Add(12*time.Second))
	if _, ok := resolver.resolve("app.example.org"); !ok {
		t.Fatal("domain not routed after storage recovered")
	}
}

func captureAliasLogs(t *testing.T) *lockedBuffer {
	t.Helper()
	logs := &lockedBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return logs
}

func TestAliasSnapshotAtCapDropsNothing(t *testing.T) {
	store := openAliasStore(t)
	names := []string{"a.example.org", "b.example.org", "c.example.org"}
	for _, name := range names {
		activateRow(t, store, name, "host-"+name, "alice", true)
	}
	logs := captureAliasLogs(t)
	resolver := newTestResolver(store, func(string) bool { return false })
	resolver.limit = len(names)
	resolver.refresh(t.Context())
	for _, name := range names {
		if _, ok := resolver.resolve(name); !ok {
			t.Fatalf("resolve(%q) = false at exactly the cap", name)
		}
	}
	if strings.Contains(logs.String(), "routing cap") {
		t.Fatalf("cap message at exactly the cap: %s", logs.String())
	}
}

func TestAliasSnapshotCapDropsNewestActivation(t *testing.T) {
	store := openAliasStore(t)
	for _, name := range []string{"z.example.org", "m.example.org", "a.example.org"} {
		activateRow(t, store, name, "host-"+name, "alice", true)
	}
	logs := captureAliasLogs(t)
	resolver := newTestResolver(store, func(string) bool { return false })
	resolver.limit = 2
	resolver.refresh(t.Context())
	resolver.refresh(t.Context())

	for host, want := range map[string]bool{"z.example.org": true, "m.example.org": true, "a.example.org": false} {
		if _, ok := resolver.resolve(host); ok != want {
			t.Fatalf("resolve(%q) = %v, want %v", host, ok, want)
		}
	}
	if got := strings.Count(logs.String(), "exceed the routing cap"); got != 1 {
		t.Fatalf("over-cap warnings after two polls = %d, want 1: %s", got, logs.String())
	}

	resolver.limit = 3
	resolver.refresh(t.Context())
	resolver.refresh(t.Context())
	if _, ok := resolver.resolve("a.example.org"); !ok {
		t.Fatal("newest domain still unrouted after the cap cleared")
	}
	if got := strings.Count(logs.String(), "back within the routing cap"); got != 1 {
		t.Fatalf("cleared messages = %d, want 1: %s", got, logs.String())
	}
	if got := strings.Count(logs.String(), "exceed the routing cap"); got != 1 {
		t.Fatalf("over-cap warnings after clearing = %d, want 1: %s", got, logs.String())
	}
}

func TestAliasRefreshAfterStatusChange(t *testing.T) {
	s := newAliasServer(t)
	lease, err := s.storage.AcquireLease(t.Context(), storage.LeaseRequest{Hostname: "web.example.com", Kind: "http", OwnerID: "alice", InstanceID: "i1", SessionID: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	created := adminRequestAs(t, s, oidc.RoleOperator, "alice", http.MethodPost, "/api/v1/domains", []byte(`{"domain":"app.example.org","tunnel_id":"`+lease.TunnelID+`"}`))
	if created.Code != http.StatusCreated {
		t.Fatalf("create = %d; body=%s", created.Code, created.Body.String())
	}
	id := decodeDomain(t, created).ID
	path := "/api/v1/domains/" + id
	routed := func() bool {
		_, ok := s.aliases.resolve("app.example.org")
		return ok
	}
	if routed() {
		t.Fatal("pending domain routed")
	}
	if rec := adminRequestAs(t, s, oidc.RoleAdmin, "root", http.MethodPost, path+"/status", []byte(`{"status":"active"}`)); rec.Code != http.StatusOK {
		t.Fatalf("activate = %d; body=%s", rec.Code, rec.Body.String())
	}
	if !routed() {
		t.Fatal("activation did not take effect on the handling edge")
	}
	if rec := adminRequestAs(t, s, oidc.RoleAdmin, "root", http.MethodPost, path+"/status", []byte(`{"status":"disabled"}`)); rec.Code != http.StatusOK {
		t.Fatalf("disable = %d; body=%s", rec.Code, rec.Body.String())
	}
	if routed() {
		t.Fatal("disabling did not take effect on the handling edge")
	}
	if rec := adminRequestAs(t, s, oidc.RoleAdmin, "root", http.MethodPost, path+"/status", []byte(`{"status":"active"}`)); rec.Code != http.StatusOK || !routed() {
		t.Fatalf("reactivate = %d routed=%v", rec.Code, routed())
	}
	if rec := adminRequestAs(t, s, oidc.RoleOperator, "alice", http.MethodDelete, path, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d; body=%s", rec.Code, rec.Body.String())
	}
	if routed() {
		t.Fatal("deletion did not take effect on the handling edge")
	}
}

type cancelOnQueryStore struct {
	inner  customDomainStore
	cancel context.CancelFunc
}

func (c *cancelOnQueryStore) ActiveCustomDomains(ctx context.Context, limit int) ([]storage.ActiveCustomDomain, error) {
	c.cancel()
	return c.inner.ActiveCustomDomains(ctx, limit)
}

func TestAliasRefreshAfterAdminCallSurvivesClientDisconnect(t *testing.T) {
	s := newAliasServer(t)
	hook := &cancelOnQueryStore{inner: s.storage}
	s.aliases = newAliasResolver(hook, s.customDomainReserved, s.leaseTTL)
	lease, err := s.storage.AcquireLease(t.Context(), storage.LeaseRequest{Hostname: "web.example.com", Kind: "http", OwnerID: "alice", InstanceID: "i1", SessionID: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := s.storage.CreateCustomDomain(t.Context(), storage.CustomDomainSpec{Domain: "app.example.org", OwnerID: "alice", TunnelID: lease.TunnelID})
	if err != nil {
		t.Fatal(err)
	}
	routed := func() bool {
		_, ok := s.aliases.resolve("app.example.org")
		return ok
	}
	call := func(method, path string, body []byte) int {
		reqCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		hook.cancel = cancel
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:4041"
		auth := adminAuth{Principal: oidc.Principal{Subject: "root", Role: oidc.RoleAdmin}, AuthType: adminAuthTypeMTLS}
		req = req.WithContext(withAdminAuth(reqCtx, auth))
		rec := httptest.NewRecorder()
		s.handleAdminAPI(rec, req)
		return rec.Code
	}
	path := "/api/v1/domains/" + domain.ID
	if code := call(http.MethodPost, path+"/status", []byte(`{"status":"active"}`)); code != http.StatusOK {
		t.Fatalf("activate = %d", code)
	}
	if !routed() {
		t.Fatal("activation was not applied after the client disconnected")
	}
	if code := call(http.MethodDelete, path, nil); code != http.StatusNoContent {
		t.Fatalf("delete = %d", code)
	}
	if routed() {
		t.Fatal("deletion was not applied after the client disconnected")
	}
}

type gatedDomainStore struct {
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (g *gatedDomainStore) ActiveCustomDomains(context.Context, int) ([]storage.ActiveCustomDomain, error) {
	if g.calls.Add(1) == 1 {
		close(g.entered)
		<-g.release
		return []storage.ActiveCustomDomain{{Domain: "old.example.org", Hostname: "old.example.com", Kind: "http", OwnerID: "alice"}}, nil
	}
	return []storage.ActiveCustomDomain{{Domain: "new.example.org", Hostname: "new.example.com", Kind: "http", OwnerID: "alice"}}, nil
}

func TestAliasLoadNeverLetsOlderResultOverwriteNewer(t *testing.T) {
	store := &gatedDomainStore{entered: make(chan struct{}), release: make(chan struct{})}
	resolver := newTestResolver(store, func(string) bool { return false })
	now := time.Now()
	first := make(chan struct{})
	go func() {
		defer close(first)
		resolver.load(t.Context(), now)
	}()
	<-store.entered
	second := make(chan struct{})
	go func() {
		defer close(second)
		resolver.load(t.Context(), now)
	}()
	select {
	case <-second:
	case <-time.After(200 * time.Millisecond):
	}
	close(store.release)
	<-first
	<-second
	if _, ok := resolver.resolve("new.example.org"); !ok {
		t.Fatal("the newer load result was overwritten by an older one")
	}
	if _, ok := resolver.resolve("old.example.org"); ok {
		t.Fatal("the older load result replaced the newer snapshot")
	}
}

func TestRunLoadsCustomDomainsBeforeServing(t *testing.T) {
	store := openAliasStore(t)
	activateRow(t, store, "app.example.org", "web.example.com", "alice", true)
	controlAddr, publicAddr := freeTCPAddr(t), freeTCPAddr(t)
	s, err := New(Config{ControlAddr: controlAddr, PublicAddr: publicAddr, Domain: "example.com", TokenSHA256: sumToken("tok"), PublicScheme: "http", Insecure: true, Storage: store})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-runErr:
		case <-time.After(20 * time.Second):
			t.Error("edge did not stop")
		}
	})
	waitTCPUpOrRunErr(t, publicAddr, runErr)
	alice := ownedSession(t, "alice", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "routed") })
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "web.example.com", Session: alice}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://"+publicAddr+"/", nil)
	req.Host = "app.example.org"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "routed" {
		t.Fatalf("first request after start-up = %d %q, want 200 routed without waiting for a poll", resp.StatusCode, body)
	}
}

func TestRedirectToHTTPSForActiveCustomDomain(t *testing.T) {
	s := newAliasServer(t)
	registerActiveDomain(t, s, "app.example.org", "web.example.com", "http", "alice")
	activateRow(t, s.storage, "pending.example.org", "pending.example.com", "alice", false)
	s.aliases.refresh(t.Context())

	get := func(host string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/p?q=1", nil)
		req.RemoteAddr = "9.9.9.9:4000"
		rec := httptest.NewRecorder()
		s.redirectToHTTPS(rec, req)
		return rec
	}
	if rec := get("app.example.org"); rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "https://app.example.org/p?q=1" {
		t.Fatalf("active custom domain redirect = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := get("pending.example.org"); rec.Code != http.StatusNotFound {
		t.Fatalf("pending custom domain redirect = %d, want 404", rec.Code)
	}
	if rec := get("unknown.example.org"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown host redirect = %d, want 404", rec.Code)
	}
	if rec := get("anything.example.com"); rec.Code != http.StatusMovedPermanently {
		t.Fatalf("edge domain redirect = %d, want 301", rec.Code)
	}
}

func TestHandlePublicRefusesAliasOwnerMismatch(t *testing.T) {
	s := newAliasServer(t)
	registerActiveDomain(t, s, "app.example.org", "web.example.com", "http", "alice")
	hits := atomic.Int64{}
	mallory := ownedSession(t, "mallory", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "origin-ok")
	})
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "web.example.com", Session: mallory}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	mismatch := metricDelta(metricCustomDomainOwnerMismatch)
	if rec := aliasGet(s, "app.example.org"); rec.Code != http.StatusNotFound {
		t.Fatalf("owner mismatch status = %d, want 404", rec.Code)
	}
	if hits.Load() != 0 || mismatch() != 1 {
		t.Fatalf("agent hits = %d, mismatch = %d; want 0, 1", hits.Load(), mismatch())
	}
}

func TestClassifyRefusesAliasOwnerMismatch(t *testing.T) {
	agentCert, agentPool := passthroughTestCert(t, "tls.example.org")
	s := newAliasServer(t)
	registerActiveDomain(t, s, "tls.example.org", "tls-tun.example.com", "tls", "alice")
	var agentHits atomic.Int64
	fx := newTCPFixture(t, func(conn net.Conn, pre proto.StreamOpen) {
		defer conn.Close()
		agentHits.Add(1)
		tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{agentCert}})
		if err := tc.Handshake(); err != nil {
			return
		}
		io.Copy(tc, tc)
	})
	t.Cleanup(fx.cleanup)
	fx.as.Credential = &credentials.Credential{ID: "cred-mallory", OwnerID: "mallory"}
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "tls-tun.example.com", Session: fx.as, TLS: true}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := s.newSNIListener(raw)
	t.Cleanup(func() { ln.Close() })
	mismatch := metricDelta(metricCustomDomainOwnerMismatch)

	if _, err := dialTLSClient(t, raw.Addr().String(), nil, &tls.Config{ServerName: "tls.example.org", RootCAs: agentPool}); err == nil {
		t.Fatal("handshake succeeded through an owner-mismatched custom domain")
	}
	if agentHits.Load() != 0 || mismatch() != 1 {
		t.Fatalf("agent hits = %d, mismatch = %d; want 0, 1", agentHits.Load(), mismatch())
	}
}

func TestLocalAliasRefusesOwnerMismatch(t *testing.T) {
	s := newAliasServer(t)
	registerActiveDomain(t, s, "app.example.org", "web.example.com", "http", "alice")

	if _, b, state := s.localAlias("app.example.org"); b != nil || state != aliasRemote {
		t.Fatalf("unbound state = %v binding=%v, want aliasRemote", state, b)
	}

	mallory := ownedSession(t, "mallory", nil)
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "web.example.com", Session: mallory}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if _, b, state := s.localAlias("app.example.org"); b != nil || state != aliasRefused {
		t.Fatalf("mismatched owner state = %v binding=%v, want aliasRefused", state, b)
	}

	s.registry.Unbind("web.example.com", mallory)
	alice := ownedSession(t, "alice", nil)
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "web.example.com", Session: alice}); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	if _, b, state := s.localAlias("app.example.org"); b == nil || state != aliasLocal {
		t.Fatalf("matching owner state = %v binding=%v, want aliasLocal", state, b)
	}
}

func TestHandlePublicRoutesActiveCustomDomain(t *testing.T) {
	s := newAliasServer(t)
	registerActiveDomain(t, s, "app.example.org", "web.example.com", "http", "alice")
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
	registerActiveDomain(t, s, "secure.example.org", "secure.example.com", "tls", "alice")
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
	registerActiveDomain(t, s, "app.example.org", "login.example.com", "http", "alice")
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
	registerActiveDomain(t, s, "tls.example.org", "tls-tun.example.com", "tls", "alice")

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
