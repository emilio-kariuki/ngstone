package edge

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"time"

	"golang.org/x/net/netutil"

	"ngstone/internal/credentials"
	"ngstone/internal/oidc"
)

const (
	adminAuthTypeMTLS        = "mtls"
	adminMTLSMaxConns        = 32
	adminMTLSMaxCertLifetime = 720 * time.Hour
)

var (
	adminMTLSNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._@-]{0,63}$`)
	adminCrossOrigin     = http.NewCrossOriginProtection()

	errAdminCertMissing   = errors.New("management client certificate is missing")
	errAdminCertUntrusted = errors.New("management client certificate is not trusted")
	errAdminCertUsage     = errors.New("management client certificate does not allow client authentication")
	errAdminCertLifetime  = errors.New("management client certificate lifetime is too long")
	errAdminCertName      = errors.New("management client certificate common name is not allowed")
	errAdminCertRole      = errors.New("management client certificate has no management role")
)

type adminCertIdentity struct {
	Principal  oidc.Principal
	CertSHA256 string
}

func loadAdminClientCAs(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("admin client CA file: %w", err)
	}
	pool := x509.NewCertPool()
	count := 0
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("admin client CA file %s must contain only CERTIFICATE blocks", path)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("admin client CA file %s contains an unparsable certificate", path)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return nil, fmt.Errorf("admin client CA file %s contains a certificate that is not a CA", path)
		}
		pool.AddCert(cert)
		count++
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("admin client CA file %s has data after the last certificate", path)
	}
	if count == 0 {
		return nil, fmt.Errorf("admin client CA file %s contains no certificates", path)
	}
	return pool, nil
}

func verifyAdminClientCert(roots *x509.CertPool, chain []*x509.Certificate, now time.Time) (adminCertIdentity, error) {
	if roots == nil || len(chain) == 0 || chain[0] == nil {
		return adminCertIdentity{}, errAdminCertMissing
	}
	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		if cert != nil {
			intermediates.AddCert(cert)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return adminCertIdentity{}, errAdminCertUntrusted
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return adminCertIdentity{}, errAdminCertUsage
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) > adminMTLSMaxCertLifetime {
		return adminCertIdentity{}, errAdminCertLifetime
	}
	name := leaf.Subject.CommonName
	if !adminMTLSNamePattern.MatchString(name) {
		return adminCertIdentity{}, errAdminCertName
	}
	role := ""
	for _, unit := range leaf.Subject.OrganizationalUnit {
		if (unit == oidc.RoleAdmin || unit == oidc.RoleOperator || unit == oidc.RoleViewer) && oidc.RoleRank(unit) > oidc.RoleRank(role) {
			role = unit
		}
	}
	if role == "" {
		return adminCertIdentity{}, errAdminCertRole
	}
	sum := sha256.Sum256(leaf.Raw)
	return adminCertIdentity{
		Principal:  oidc.Principal{Subject: credentials.MTLSOwnerPrefix + name, Name: name, Role: role},
		CertSHA256: hex.EncodeToString(sum[:]),
	}, nil
}

func (s *Server) adminMTLSTLSConfig() *tls.Config {
	base := s.cfg.PublicTLSConfig
	if s.tlsMgr != nil {
		base = s.tlsMgr.ApexTLSConfig()
	}
	cfg := &tls.Config{}
	if base != nil {
		cfg = base.Clone()
	}
	cfg.MinVersion = tls.VersionTLS13
	cfg.MaxVersion = 0
	cfg.NextProtos = nil
	cfg.SessionTicketsDisabled = true
	cfg.GetConfigForClient = nil
	cfg.VerifyPeerCertificate = nil
	cfg.ClientAuth = tls.RequestClientCert
	cfg.ClientCAs = s.adminClientCAs
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if _, err := verifyAdminClientCert(s.adminClientCAs, cs.PeerCertificates, time.Now()); err != nil {
			metricAdminMTLSRejected.Add(1)
			return err
		}
		return nil
	}
	return cfg
}

func (s *Server) newAdminMTLSListener(raw net.Listener) net.Listener {
	return tls.NewListener(netutil.LimitListener(raw, adminMTLSMaxConns), s.adminMTLSTLSConfig())
}

func (s *Server) adminMTLSHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/state", s.handleProtectedDashboardState)
	mux.HandleFunc("/api/v1", s.handleAdminAPI)
	mux.HandleFunc("/api/v1/", s.handleAdminAPI)
	mux.HandleFunc("/", s.handleDashboard)
	reject := func(w http.ResponseWriter) {
		writeAdminError(w, http.StatusForbidden, "certificate_rejected", "a valid management client certificate is required")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || !r.TLS.HandshakeComplete {
			reject(w)
			return
		}
		id, err := verifyAdminClientCert(s.adminClientCAs, r.TLS.PeerCertificates, time.Now())
		if err != nil {
			metricAdminMTLSRejected.Add(1)
			reject(w)
			return
		}
		auth := adminAuth{Principal: id.Principal, AuthType: adminAuthTypeMTLS, CertSHA256: id.CertSHA256}
		mux.ServeHTTP(w, r.WithContext(withAdminAuth(r.Context(), auth)))
	})
}
