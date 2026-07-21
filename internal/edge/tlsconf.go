package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

const (
	ACMECAStaging    = "staging"
	ACMECAProduction = "production"

	DefaultCertStoragePath = "/var/lib/private/ngstoned/certs"
)

type TLSConfig struct {
	Domain             string
	CloudflareAPIToken string
	ACMEEmail          string
	ACMECA             string
	StoragePath        string
}

type TLSManager struct {
	apexDomain     string
	wildcardDomain string
	magic          *certmagic.Config
	caURL          string
	apexTLSConfig  *tls.Config
}

func NewTLSManager(cfg TLSConfig) (*TLSManager, error) {
	if cfg.Domain == "" {
		return nil, errors.New("edge: tls: domain must not be empty")
	}
	if cfg.CloudflareAPIToken == "" {
		return nil, errors.New("edge: tls: cloudflare API token must not be empty")
	}
	if cfg.ACMEEmail == "" {
		return nil, errors.New("edge: tls: acme email must not be empty")
	}
	storagePath := cfg.StoragePath
	if storagePath == "" {
		storagePath = DefaultCertStoragePath
	}

	var caURL string
	switch cfg.ACMECA {
	case "", ACMECAStaging:
		caURL = certmagic.LetsEncryptStagingCA
	case ACMECAProduction:
		caURL = certmagic.LetsEncryptProductionCA
	default:
		return nil, fmt.Errorf("edge: tls: unknown -acme-ca %q, want %q or %q", cfg.ACMECA, ACMECAStaging, ACMECAProduction)
	}

	certmagic.Default.Storage = &certmagic.FileStorage{Path: storagePath}
	certmagic.DefaultACME.CA = caURL
	certmagic.DefaultACME.Email = cfg.ACMEEmail
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: &cloudflare.Provider{APIToken: cfg.CloudflareAPIToken},
		},
	}

	magic := certmagic.NewDefault()

	m := &TLSManager{
		apexDomain:     cfg.Domain,
		wildcardDomain: "*." + cfg.Domain,
		magic:          magic,
		caURL:          caURL,
	}
	m.apexTLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			forced := *hello
			forced.ServerName = m.apexDomain
			return m.magic.GetCertificate(&forced)
		},
	}
	return m, nil
}

func (m *TLSManager) ManageCerts(ctx context.Context) error {
	return m.magic.ManageSync(ctx, []string{m.wildcardDomain, m.apexDomain})
}

func (m *TLSManager) PublicTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.magic.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	}
}

func (m *TLSManager) ApexTLSConfig() *tls.Config {
	return m.apexTLSConfig
}

const minApexCertLifetime = 24 * time.Hour

func (m *TLSManager) CheckApexReady(ctx context.Context) error {
	leaf, err := m.loadLeaf(ctx, m.apexDomain)
	if err != nil {
		return fmt.Errorf("edge: tls: apex certificate for %s not loadable: %w", m.apexDomain, err)
	}
	now := time.Now()
	if !now.Before(leaf.NotAfter) {
		return fmt.Errorf("edge: tls: apex certificate for %s expired at %s", m.apexDomain, leaf.NotAfter)
	}
	if leaf.NotAfter.Sub(now) < minApexCertLifetime {
		return fmt.Errorf("edge: tls: apex certificate for %s expires at %s, less than %s of remaining life", m.apexDomain, leaf.NotAfter, minApexCertLifetime)
	}
	return nil
}

type CertInfo struct {
	Domain   string
	NotAfter time.Time
	Err      error
}

func (m *TLSManager) CertStatus(ctx context.Context) (apex, wildcard CertInfo) {
	apex.Domain = m.apexDomain
	wildcard.Domain = m.wildcardDomain

	if leaf, err := m.loadLeaf(ctx, m.apexDomain); err != nil {
		apex.Err = err
	} else {
		apex.NotAfter = leaf.NotAfter
	}

	if leaf, err := m.loadLeaf(ctx, m.wildcardDomain); err != nil {
		wildcard.Err = err
	} else {
		wildcard.NotAfter = leaf.NotAfter
	}

	return apex, wildcard
}

func (m *TLSManager) loadLeaf(ctx context.Context, sni string) (*x509.Certificate, error) {
	fakeConn, otherEnd := net.Pipe()
	defer fakeConn.Close()
	defer otherEnd.Close()

	hello := &tls.ClientHelloInfo{ServerName: sni, Conn: fakeConn}
	cert, err := m.magic.GetCertificateWithContext(ctx, hello)
	if err != nil {
		return nil, err
	}
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("edge: tls: no certificate available for %s", sni)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("edge: tls: parsing certificate for %s: %w", sni, err)
	}
	return leaf, nil
}
