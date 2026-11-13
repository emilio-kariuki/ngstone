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
)

const (
	ACMECAStaging    = "staging"
	ACMECAProduction = "production"

	DefaultCertStoragePath = "/var/lib/private/ngstoned/certs"
)

type TLSConfig struct {
	Domain      string
	DNSProvider certmagic.DNSProvider
	ACMEEmail   string
	ACMECA      string
	StoragePath string

	PublicAddr          string
	CustomDomainAllowed func(name string) bool
}

type TLSManager struct {
	apexDomain     string
	wildcardDomain string
	magic          *certmagic.Config
	custom         *certmagic.Config
	caURL          string
	apexTLSConfig  *tls.Config
	edgeDomain     string
	cache          *certmagic.Cache
	auto           *certmagic.Config
	allowed        func(string) bool
	issuance       *issuanceLimiter
}

func NewTLSManager(cfg TLSConfig) (*TLSManager, error) {
	if cfg.Domain == "" {
		return nil, errors.New("edge: tls: domain must not be empty")
	}
	if cfg.DNSProvider == nil {
		return nil, errors.New("edge: tls: a DNS provider is required for DNS-01 certificates")
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
			DNSProvider: cfg.DNSProvider,
		},
	}

	edgeDomain := normalizeHost(cfg.Domain)
	var (
		onDemand *certmagic.OnDemandConfig
		onEvent  func(context.Context, string, map[string]any) error
		issuance *issuanceLimiter
		host     string
		port     int
	)
	allowed := cfg.CustomDomainAllowed
	if allowed != nil {
		var err error
		host, port, err = tlsALPNListenAddr(cfg.PublicAddr)
		if err != nil {
			return nil, fmt.Errorf("edge: tls: public address %q: %w", cfg.PublicAddr, err)
		}
		issuance = newIssuanceLimiter(time.Now)
		onDemand = &certmagic.OnDemandConfig{
			DecisionFunc: func(_ context.Context, name string) error {
				if !allowed(name) {
					return errAutoCertNotAllowed
				}
				return nil
			},
		}
		onEvent = issuance.onEvent
	}

	cache, magic, custom, auto := newMagicConfigs(edgeDomain, onDemand, onEvent)
	if auto != nil {
		auto.Issuers = []certmagic.Issuer{newAutoIssuer(auto, caURL, cfg.ACMEEmail, host, port)}
	}

	m := &TLSManager{
		apexDomain:     cfg.Domain,
		wildcardDomain: "*." + cfg.Domain,
		magic:          magic,
		custom:         custom,
		caURL:          caURL,
		edgeDomain:     edgeDomain,
		cache:          cache,
		auto:           auto,
		allowed:        allowed,
		issuance:       issuance,
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

var newMagicCache = certmagic.NewCache

func tlsALPNListenAddr(addr string) (string, int, error) {
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := net.LookupPort("tcp", p)
	if err != nil {
		return "", 0, err
	}
	if port == 0 {
		return "", 0, errors.New("port must not be 0")
	}
	return host, port, nil
}

func newAutoIssuer(cfg *certmagic.Config, caURL, email, host string, port int) *certmagic.ACMEIssuer {
	iss := certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
		CA:                   caURL,
		Email:                email,
		Agreed:               true,
		DisableHTTPChallenge: true,
		ListenHost:           host,
		AltTLSALPNPort:       port,
	})
	iss.DNS01Solver = nil
	return iss
}

func newMagicConfigs(edgeDomain string, onDemand *certmagic.OnDemandConfig, onEvent func(context.Context, string, map[string]any) error) (cache *certmagic.Cache, managed, custom, auto *certmagic.Config) {
	cache = newMagicCache(certmagic.CacheOptions{
		GetConfigForCert: func(c certmagic.Certificate) (*certmagic.Config, error) {
			return configForCert(c, managed, custom, auto, edgeDomain), nil
		},
		Logger: certmagic.Default.Logger,
	})
	managed = certmagic.New(cache, certmagic.Default)
	unstapled := certmagic.Default
	unstapled.OCSP.DisableStapling = true
	custom = certmagic.New(cache, unstapled)
	if onDemand != nil {
		dynamic := certmagic.Default
		dynamic.OnDemand = onDemand
		dynamic.OnEvent = onEvent
		auto = certmagic.New(cache, dynamic)
	}
	return cache, managed, custom, auto
}

func configForCert(c certmagic.Certificate, managed, custom, auto *certmagic.Config, edgeDomain string) *certmagic.Config {
	if c.HasTag(customCertTag) {
		return custom
	}
	if auto != nil && len(c.Names) > 0 && !hostMatchesDomain(c.Names[0], edgeDomain) {
		return auto
	}
	return managed
}

func (m *TLSManager) ManageCerts(ctx context.Context) error {
	return m.magic.ManageSync(ctx, []string{m.wildcardDomain, m.apexDomain})
}

func (m *TLSManager) PublicTLSConfig() *tls.Config {
	if m.auto != nil {
		return &tls.Config{
			GetCertificate: m.publicCertificate,
			NextProtos:     []string{"h2", "http/1.1", acmeTLS1},
		}
	}
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
