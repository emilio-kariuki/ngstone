package edge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

func TestApexStartupCheckFailsWithoutLoadableCert(t *testing.T) {
	mgr, err := NewTLSManager(TLSConfig{
		Domain:      "apex-check.invalid",
		DNSProvider: fakeDNSProvider{},
		ACMEEmail:   "ops@apex-check.invalid",
		StoragePath: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewTLSManager: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := mgr.CheckApexReady(ctx); err == nil {
		t.Fatalf("CheckApexReady() succeeded with no certificate ever obtained; it must refuse to let :4443 start")
	}
}

func TestNewTLSManagerRejectsUnknownACMECA(t *testing.T) {
	_, err := NewTLSManager(TLSConfig{
		Domain:      "bad-ca.invalid",
		DNSProvider: fakeDNSProvider{},
		ACMEEmail:   "ops@bad-ca.invalid",
		StoragePath: t.TempDir(),
		ACMECA:      "not-a-real-ca",
	})
	if err == nil {
		t.Fatalf("expected an error for an unrecognized -acme-ca value")
	}
}

func TestNewTLSManagerDefaultsToStaging(t *testing.T) {
	if ACMECAStaging == "" || ACMECAStaging == ACMECAProduction {
		t.Fatalf("sanity: staging/production constants must be distinct non-empty values")
	}
	_, err := NewTLSManager(TLSConfig{
		Domain:      "default-ca.invalid",
		DNSProvider: fakeDNSProvider{},
		ACMEEmail:   "ops@default-ca.invalid",
		StoragePath: t.TempDir(),
		ACMECA:      "",
	})
	if err != nil {
		t.Fatalf("NewTLSManager with empty ACMECA should default to staging, got error: %v", err)
	}
}

func TestNewTLSManagerResolvesCAURL(t *testing.T) {
	cases := []struct {
		name   string
		acmeCA string
		want   string
	}{
		{"empty defaults to staging", "", certmagic.LetsEncryptStagingCA},
		{"explicit staging", ACMECAStaging, certmagic.LetsEncryptStagingCA},
		{"explicit production", ACMECAProduction, certmagic.LetsEncryptProductionCA},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mgr, err := NewTLSManager(TLSConfig{
				Domain:      "ca-url.invalid",
				DNSProvider: fakeDNSProvider{},
				ACMEEmail:   "ops@ca-url.invalid",
				StoragePath: t.TempDir(),
				ACMECA:      c.acmeCA,
			})
			if err != nil {
				t.Fatalf("NewTLSManager(ACMECA=%q): %v", c.acmeCA, err)
			}
			if mgr.caURL != c.want {
				t.Fatalf("ACMECA=%q: caURL = %q, want %q", c.acmeCA, mgr.caURL, c.want)
			}
		})
	}
}

func newTestLeafCert(t *testing.T, domain string, notAfter time.Time) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newTestApexManager(t *testing.T, domain string) *TLSManager {
	t.Helper()
	mgr, err := NewTLSManager(TLSConfig{
		Domain:      domain,
		DNSProvider: fakeDNSProvider{},
		ACMEEmail:   "ops@" + domain,
		StoragePath: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewTLSManager: %v", err)
	}
	return mgr
}

func TestCheckApexReadyRejectsExpiredCert(t *testing.T) {
	mgr := newTestApexManager(t, "expired-apex.invalid")

	cert := newTestLeafCert(t, "expired-apex.invalid", time.Now().Add(-24*time.Hour))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := mgr.magic.CacheUnmanagedTLSCertificate(ctx, cert, nil); err != nil {
		t.Fatalf("cache expired cert: %v", err)
	}

	if err := mgr.CheckApexReady(ctx); err == nil {
		t.Fatalf("CheckApexReady() succeeded with an expired apex certificate; §4 requires a valid apex cert")
	}
}

func TestCheckApexReadyRejectsCertUnderOneDayRemaining(t *testing.T) {
	mgr := newTestApexManager(t, "soon-expiring-apex.invalid")

	cert := newTestLeafCert(t, "soon-expiring-apex.invalid", time.Now().Add(1*time.Hour))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := mgr.magic.CacheUnmanagedTLSCertificate(ctx, cert, nil); err != nil {
		t.Fatalf("cache soon-expiring cert: %v", err)
	}

	if err := mgr.CheckApexReady(ctx); err == nil {
		t.Fatalf("CheckApexReady() succeeded with under 24h of remaining certificate life; the failure must be loud before it becomes fatal")
	}
}

func TestCheckApexReadyAcceptsHealthyCert(t *testing.T) {
	mgr := newTestApexManager(t, "healthy-apex.invalid")

	cert := newTestLeafCert(t, "healthy-apex.invalid", time.Now().Add(90*24*time.Hour))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := mgr.magic.CacheUnmanagedTLSCertificate(ctx, cert, nil); err != nil {
		t.Fatalf("cache healthy cert: %v", err)
	}

	if err := mgr.CheckApexReady(ctx); err != nil {
		t.Fatalf("CheckApexReady() rejected a healthy apex certificate: %v", err)
	}
}
