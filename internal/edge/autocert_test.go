package edge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"ngstone/internal/storage"
)

type countingStorage struct {
	certmagic.Storage
	calls   atomic.Int64
	locks   atomic.Int64
	unlocks atomic.Int64
}

func (s *countingStorage) Lock(ctx context.Context, name string) error {
	s.calls.Add(1)
	s.locks.Add(1)
	return s.Storage.Lock(ctx, name)
}

func (s *countingStorage) Unlock(ctx context.Context, name string) error {
	s.calls.Add(1)
	s.unlocks.Add(1)
	return s.Storage.Unlock(ctx, name)
}

func (s *countingStorage) Store(ctx context.Context, key string, value []byte) error {
	s.calls.Add(1)
	return s.Storage.Store(ctx, key, value)
}

func (s *countingStorage) Load(ctx context.Context, key string) ([]byte, error) {
	s.calls.Add(1)
	return s.Storage.Load(ctx, key)
}

func (s *countingStorage) Delete(ctx context.Context, key string) error {
	s.calls.Add(1)
	return s.Storage.Delete(ctx, key)
}

func (s *countingStorage) Exists(ctx context.Context, key string) bool {
	s.calls.Add(1)
	return s.Storage.Exists(ctx, key)
}

func (s *countingStorage) List(ctx context.Context, path string, recursive bool) ([]string, error) {
	s.calls.Add(1)
	return s.Storage.List(ctx, path, recursive)
}

func (s *countingStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	s.calls.Add(1)
	return s.Storage.Stat(ctx, key)
}

type fakeIssuer struct {
	calls    atomic.Int32
	err      atomic.Pointer[error]
	lifetime time.Duration
	caCert   *x509.Certificate
	caKey    *ecdsa.PrivateKey
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake test ca"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour * 365),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeIssuer{caCert: caCert, caKey: caKey}
}

func (f *fakeIssuer) setErr(err error) {
	if err == nil {
		f.err.Store(nil)
		return
	}
	f.err.Store(&err)
}

func (f *fakeIssuer) IssuerKey() string { return "fake" }

func (f *fakeIssuer) Issue(_ context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	f.calls.Add(1)
	if errp := f.err.Load(); errp != nil {
		return nil, *errp
	}
	notBefore, notAfter := time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)
	if f.lifetime > 0 {
		notBefore = time.Now().Add(-(f.lifetime - f.lifetime/6))
		notAfter = time.Now().Add(f.lifetime / 6)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: csr.DNSNames[0]},
		DNSNames:     csr.DNSNames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.caCert, csr.PublicKey, f.caKey)
	if err != nil {
		return nil, err
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.caCert.Raw})...)
	return &certmagic.IssuedCertificate{Certificate: chain}, nil
}

type allowList struct {
	names atomic.Pointer[map[string]bool]
	calls atomic.Int64
}

func newAllowList(names ...string) *allowList {
	a := &allowList{}
	a.set(names...)
	return a
}

func (a *allowList) set(names ...string) {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	a.names.Store(&m)
}

func (a *allowList) allowed(name string) bool {
	a.calls.Add(1)
	return (*a.names.Load())[name]
}

func newTestAutoManager(t *testing.T, allowed func(string) bool) (*TLSManager, *countingStorage, *fakeIssuer) {
	t.Helper()
	mgr, err := NewTLSManager(TLSConfig{
		Domain:              "example.com",
		DNSProvider:         fakeDNSProvider{},
		ACMEEmail:           "ops@example.com",
		StoragePath:         t.TempDir(),
		PublicAddr:          "127.0.0.1:8443",
		CustomDomainAllowed: allowed,
	})
	if err != nil {
		t.Fatalf("NewTLSManager: %v", err)
	}
	t.Cleanup(mgr.cache.Stop)
	cs := &countingStorage{Storage: mgr.magic.Storage}
	mgr.magic.Storage = cs
	mgr.custom.Storage = cs
	mgr.auto.Storage = cs
	fake := newFakeIssuer(t)
	mgr.auto.Issuers = []certmagic.Issuer{fake}
	return mgr, cs, fake
}

func handshake(t *testing.T, cfg *tls.Config, sni string, protos []string) (*x509.Certificate, error) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	serverErr := make(chan error, 1)
	go func() {
		err := tls.Server(serverConn, cfg).HandshakeContext(ctx)
		if err != nil {
			serverConn.Close()
		}
		serverErr <- err
	}()
	client := tls.Client(clientConn, &tls.Config{ServerName: sni, NextProtos: protos, InsecureSkipVerify: true})
	clientErr := client.HandshakeContext(ctx)
	if clientErr != nil {
		clientConn.Close()
	}
	serverResult := <-serverErr
	if clientErr != nil {
		return nil, clientErr
	}
	if serverResult != nil {
		return nil, serverResult
	}
	return client.ConnectionState().PeerCertificates[0], nil
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for !cond() {
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", what)
		case <-tick.C:
		}
	}
}

func waitForLocksReleased(t *testing.T, cs *countingStorage) {
	t.Helper()
	waitFor(t, "certificate storage locks to be released", func() bool {
		return cs.locks.Load() == cs.unlocks.Load()
	})
}

func advanceIssuanceClock(mgr *TLSManager, by time.Duration) {
	mgr.issuance.mu.Lock()
	defer mgr.issuance.mu.Unlock()
	mgr.issuance.now = func() time.Time { return time.Now().Add(by) }
}

func TestAutoCertInactiveNameTouchesNothing(t *testing.T) {
	allow := newAllowList()
	mgr, cs, fake := newTestAutoManager(t, allow.allowed)
	cfg := mgr.PublicTLSConfig()
	for _, protos := range [][]string{{"h2"}, {"acme-tls/1"}, {"h2", "http/1.1"}} {
		if _, err := handshake(t, cfg, "evil.example.net", protos); err == nil {
			t.Fatalf("handshake with protos %v for an inactive name succeeded", protos)
		}
	}
	if n := cs.calls.Load(); n != 0 {
		t.Fatalf("storage accessed %d times for an inactive name", n)
	}
	if n := fake.calls.Load(); n != 0 {
		t.Fatalf("issuer called %d times for an inactive name", n)
	}
}

func TestAutoCertEdgeDomainChallengeRefused(t *testing.T) {
	allow := newAllowList("x.example.com")
	mgr, cs, fake := newTestAutoManager(t, allow.allowed)
	if _, err := handshake(t, mgr.PublicTLSConfig(), "x.example.com", []string{"acme-tls/1"}); err == nil {
		t.Fatal("a challenge handshake for an edge-domain name succeeded")
	}
	if n := cs.calls.Load(); n != 0 {
		t.Fatalf("storage accessed %d times", n)
	}
	if n := allow.calls.Load(); n != 0 {
		t.Fatalf("allowed consulted %d times", n)
	}
	if n := fake.calls.Load(); n != 0 {
		t.Fatalf("issuer called %d times", n)
	}
}

func TestAutoCertEdgeDomainNeverConsultsDecision(t *testing.T) {
	allow := newAllowList("missing.example.com")
	mgr, cs, fake := newTestAutoManager(t, allow.allowed)
	if _, err := handshake(t, mgr.PublicTLSConfig(), "missing.example.com", []string{"h2"}); err == nil {
		t.Fatal("handshake for an uncached edge-domain name succeeded")
	}
	if n := allow.calls.Load(); n != 0 {
		t.Fatalf("allowed consulted %d times", n)
	}
	if n := cs.calls.Load(); n != 0 {
		t.Fatalf("storage accessed %d times", n)
	}
	if n := fake.calls.Load(); n != 0 {
		t.Fatalf("issuer called %d times", n)
	}
}

func TestAutoCertIssuesOnceForActiveName(t *testing.T) {
	allow := newAllowList("app.example.org")
	mgr, _, fake := newTestAutoManager(t, allow.allowed)
	for i := range 2 {
		leaf, err := handshake(t, mgr.PublicTLSConfig(), "app.example.org", []string{"h2"})
		if err != nil {
			t.Fatalf("handshake %d: %v", i, err)
		}
		if !slices.Equal(leaf.DNSNames, []string{"app.example.org"}) {
			t.Fatalf("handshake %d: leaf names = %v", i, leaf.DNSNames)
		}
	}
	if n := fake.calls.Load(); n != 1 {
		t.Fatalf("issuer called %d times, want 1", n)
	}
}

func TestAutoCertFailureCoolsDownWithoutStorage(t *testing.T) {
	allow := newAllowList("app.example.org")
	normalized := func(name string) bool {
		canonical, ok := storage.NormalizeCustomDomain(name)
		return ok && allow.allowed(canonical)
	}
	mgr, cs, fake := newTestAutoManager(t, normalized)
	fake.setErr(certmagic.ErrNoRetry{Err: errors.New("validation failed")})
	cfg := mgr.PublicTLSConfig()

	if _, err := handshake(t, cfg, "app.example.org", []string{"h2"}); err == nil {
		t.Fatal("first handshake succeeded with a failing issuer")
	}
	if n := fake.calls.Load(); n != 1 {
		t.Fatalf("issuer calls after first handshake = %d, want 1", n)
	}

	cs.calls.Store(0)
	if _, err := handshake(t, cfg, "app.example.org", []string{"h2"}); err == nil {
		t.Fatal("second handshake succeeded inside the cool-down")
	}
	if n := cs.calls.Load(); n != 0 {
		t.Fatalf("storage accessed %d times during the cool-down", n)
	}
	if n := fake.calls.Load(); n != 1 {
		t.Fatalf("issuer calls during the cool-down = %d, want 1", n)
	}

	for _, sni := range []string{"app.example.org ", "APP.example.org.", " app.example.org"} {
		cs.calls.Store(0)
		if _, err := handshake(t, cfg, sni, []string{"h2"}); err == nil {
			t.Fatalf("handshake with SNI %q succeeded inside the cool-down", sni)
		}
		if n := cs.calls.Load(); n != 0 {
			t.Fatalf("storage accessed %d times during the cool-down for SNI %q", n, sni)
		}
		if n := fake.calls.Load(); n != 1 {
			t.Fatalf("issuer calls during the cool-down for SNI %q = %d, want 1", sni, n)
		}
	}

	advanceIssuanceClock(mgr, autoCertNameInterval+time.Minute)
	if _, err := handshake(t, cfg, "app.example.org", []string{"h2"}); err == nil {
		t.Fatal("third handshake succeeded with a failing issuer")
	}
	if n := fake.calls.Load(); n != 2 {
		t.Fatalf("issuer calls after the cool-down = %d, want 2", n)
	}
}

func TestAutoCertNotServedAfterDisable(t *testing.T) {
	allow := newAllowList("app.example.org")
	mgr, _, fake := newTestAutoManager(t, allow.allowed)
	cfg := mgr.PublicTLSConfig()
	if _, err := handshake(t, cfg, "app.example.org", []string{"h2"}); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	allow.set()
	if _, err := handshake(t, cfg, "app.example.org", []string{"h2"}); err == nil {
		t.Fatal("a disabled name was served its cached certificate")
	}
	if n := fake.calls.Load(); n != 1 {
		t.Fatalf("issuer called %d times, want 1", n)
	}
}

func TestAutoCertNotRenewedAfterDisable(t *testing.T) {
	allow := newAllowList("app.example.org")
	mgr, _, fake := newTestAutoManager(t, allow.allowed)
	fake.lifetime = time.Hour
	if _, err := handshake(t, mgr.PublicTLSConfig(), "app.example.org", []string{"h2"}); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	allow.set()
	direct := &tls.Config{GetCertificate: mgr.auto.GetCertificate, NextProtos: []string{"h2"}}
	handshake(t, direct, "app.example.org", []string{"h2"})
	waitFor(t, "the certificate to be evicted from the cache", func() bool {
		return len(mgr.cache.AllMatchingCertificates("app.example.org")) == 0
	})
	if n := fake.calls.Load(); n != 1 {
		t.Fatalf("issuer called %d times, want 1", n)
	}
}

func TestAutoCertOperatorCertificateWins(t *testing.T) {
	allow := newAllowList("app.example.org")
	mgr, _, fake := newTestAutoManager(t, allow.allowed)

	dir := filepath.Join(t.TempDir(), "certs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeCustomPair(t, dir, "app", []string{"app.example.org"}, time.Now().Add(30*24*time.Hour))
	certs, err := loadCustomCertificates(dir, func(name string) bool { return hostMatchesDomain(name, "example.com") }, "example.com", time.Now())
	if err != nil {
		t.Fatalf("loadCustomCertificates: %v", err)
	}
	if err := mgr.AddCustomCertificates(t.Context(), certs); err != nil {
		t.Fatalf("AddCustomCertificates: %v", err)
	}
	operatorLeaf := certs[0].cert.Leaf.Raw

	cfg := mgr.PublicTLSConfig()
	for _, active := range []bool{true, false} {
		if active {
			allow.set("app.example.org")
		} else {
			allow.set()
		}
		leaf, err := handshake(t, cfg, "app.example.org", []string{"h2"})
		if err != nil {
			t.Fatalf("active=%v: handshake: %v", active, err)
		}
		if string(leaf.Raw) != string(operatorLeaf) {
			t.Fatalf("active=%v: served a certificate other than the operator's", active)
		}
	}
	if n := fake.calls.Load(); n != 0 {
		t.Fatalf("issuer called %d times despite an operator certificate", n)
	}
}

func TestIssuanceLimiterBoundsOrders(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIssuanceLimiter(func() time.Time { return now })
	obtaining := func(name string, renewal bool) error {
		return l.onEvent(t.Context(), "cert_obtaining", map[string]any{"identifier": name, "renewal": renewal})
	}
	isNoRetry := func(err error) bool {
		var nr certmagic.ErrNoRetry
		return errors.As(err, &nr)
	}

	if err := obtaining("a", false); err != nil {
		t.Fatalf("first order: %v", err)
	}
	if err := obtaining("a", false); !isNoRetry(err) {
		t.Fatalf("second order inside the interval: %v, want ErrNoRetry", err)
	}
	if err := obtaining("a", true); !isNoRetry(err) {
		t.Fatalf("renewal inside the interval: %v, want ErrNoRetry", err)
	}
	now = now.Add(autoCertNameInterval)
	if err := obtaining("a", false); err != nil {
		t.Fatalf("order after the interval: %v", err)
	}
	if err := l.onEvent(t.Context(), "cert_obtained", map[string]any{"identifier": "a"}); err != nil {
		t.Fatalf("unrelated event: %v", err)
	}
	if err := l.onEvent(t.Context(), "cert_obtaining", map[string]any{}); err != nil {
		t.Fatalf("empty identifier: %v", err)
	}

	now = time.Unix(1_700_000_000, 0)
	g := newIssuanceLimiter(func() time.Time { return now })
	for i := range autoCertBurst {
		name := string(rune('a'+i)) + ".example.org"
		if err := g.onEvent(t.Context(), "cert_obtaining", map[string]any{"identifier": name}); err != nil {
			t.Fatalf("order %d inside the burst: %v", i, err)
		}
	}
	if err := g.onEvent(t.Context(), "cert_obtaining", map[string]any{"identifier": "over.example.org"}); !isNoRetry(err) {
		t.Fatalf("order beyond the burst: %v, want ErrNoRetry", err)
	}
	if err := g.onEvent(t.Context(), "cert_obtaining", map[string]any{"identifier": "renew.example.org", "renewal": true}); err != nil {
		t.Fatalf("renewal beyond the burst: %v", err)
	}
}

func TestAutoCertFailedRenewalServesCachedWithoutStorage(t *testing.T) {
	allow := newAllowList("app.example.org")
	mgr, cs, fake := newTestAutoManager(t, allow.allowed)
	fake.lifetime = time.Hour
	cfg := mgr.PublicTLSConfig()

	first, err := handshake(t, cfg, "app.example.org", []string{"h2"})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	advanceIssuanceClock(mgr, autoCertNameInterval+time.Minute)
	fake.setErr(certmagic.ErrNoRetry{Err: errors.New("renewal failed")})
	if _, err := handshake(t, cfg, "app.example.org", []string{"h2"}); err != nil {
		t.Fatalf("handshake that triggers renewal: %v", err)
	}
	waitFor(t, "the failed renewal to be recorded", func() bool {
		return mgr.issuance.failedRecently("app.example.org")
	})
	waitForLocksReleased(t, cs)

	cs.calls.Store(0)
	leaf, err := handshake(t, cfg, "app.example.org", []string{"h2"})
	if err != nil {
		t.Fatalf("handshake after the failed renewal: %v", err)
	}
	if string(leaf.Raw) != string(first.Raw) {
		t.Fatal("the cached certificate was not served")
	}
	if n := cs.calls.Load(); n != 0 {
		t.Fatalf("storage accessed %d times serving a cached certificate", n)
	}
	if n := fake.calls.Load(); n != 2 {
		t.Fatalf("issuer called %d times, want 2", n)
	}
}

func TestAutoIssuerUsesOnlyTLSALPN(t *testing.T) {
	mgr, err := NewTLSManager(TLSConfig{
		Domain:              "example.com",
		DNSProvider:         fakeDNSProvider{},
		ACMEEmail:           "ops@example.com",
		StoragePath:         t.TempDir(),
		PublicAddr:          "127.0.0.1:8443",
		CustomDomainAllowed: func(string) bool { return false },
	})
	if err != nil {
		t.Fatalf("NewTLSManager: %v", err)
	}
	t.Cleanup(mgr.cache.Stop)
	if len(mgr.auto.Issuers) != 1 {
		t.Fatalf("auto has %d issuers, want 1", len(mgr.auto.Issuers))
	}
	iss, ok := mgr.auto.Issuers[0].(*certmagic.ACMEIssuer)
	if !ok {
		t.Fatalf("auto issuer is %T", mgr.auto.Issuers[0])
	}
	switch {
	case iss.DNS01Solver != nil:
		t.Error("DNS-01 solver inherited")
	case !iss.DisableHTTPChallenge:
		t.Error("HTTP-01 left enabled")
	case iss.DisableTLSALPNChallenge:
		t.Error("TLS-ALPN-01 disabled")
	case iss.DisableDistributedSolvers:
		t.Error("distributed solvers disabled")
	case iss.CA != certmagic.LetsEncryptStagingCA:
		t.Errorf("CA = %q", iss.CA)
	case iss.Email != "ops@example.com":
		t.Errorf("email = %q", iss.Email)
	case !iss.Agreed:
		t.Error("terms not agreed")
	case iss.ListenHost != "127.0.0.1":
		t.Errorf("listen host = %q", iss.ListenHost)
	case iss.AltTLSALPNPort != 8443:
		t.Errorf("alt TLS-ALPN port = %d", iss.AltTLSALPNPort)
	}
}

func TestNewTLSManagerRejectsPortlessPublicAddr(t *testing.T) {
	cfg := TLSConfig{
		Domain:      "example.com",
		DNSProvider: fakeDNSProvider{},
		ACMEEmail:   "ops@example.com",
		StoragePath: t.TempDir(),
		PublicAddr:  "127.0.0.1",
	}
	if _, err := NewTLSManager(cfg); err != nil {
		t.Fatalf("without CustomDomainAllowed: %v", err)
	}
	cfg.CustomDomainAllowed = func(string) bool { return true }
	if _, err := NewTLSManager(cfg); err == nil {
		t.Fatal("a public address without a port was accepted")
	}
	cfg.PublicAddr = "127.0.0.1:0"
	if _, err := NewTLSManager(cfg); err == nil {
		t.Fatal("a public address with port 0 was accepted")
	}
}

func TestPublicTLSConfigOffersACMEALPNOnlyWithAutoCerts(t *testing.T) {
	mgr, _, _ := newTestAutoManager(t, func(string) bool { return false })
	if got, want := mgr.PublicTLSConfig().NextProtos, []string{"h2", "http/1.1", "acme-tls/1"}; !slices.Equal(got, want) {
		t.Fatalf("with auto certificates NextProtos = %v, want %v", got, want)
	}
	apex := newTestApexManager(t, "example.com")
	if got, want := apex.PublicTLSConfig().NextProtos, []string{"h2", "http/1.1"}; !slices.Equal(got, want) {
		t.Fatalf("without auto certificates NextProtos = %v, want %v", got, want)
	}
}
