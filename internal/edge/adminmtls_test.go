package edge

import (
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ngstone/internal/adminapi"
	"ngstone/internal/adminapi/adminapitest"
	"ngstone/internal/credentials"
	"ngstone/internal/oidc"
	"ngstone/internal/storage"
)

var clientAuthUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

type adminMTLSHarness struct {
	s        *Server
	srv      *httptest.Server
	clientCA *adminapitest.CA
	serverCA *adminapitest.CA
}

func newAdminMTLSTestServer(t *testing.T) *Server {
	t.Helper()
	s := newServerForTest(LimitsConfig{})
	store, err := credentials.Open(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatalf("credentials.Open: %v", err)
	}
	s.credentialStore = store
	return s
}

func newAdminMTLSHarness(t *testing.T, s *Server) *adminMTLSHarness {
	t.Helper()
	h := &adminMTLSHarness{s: s, clientCA: adminapitest.NewCA(t), serverCA: adminapitest.NewCA(t)}
	pool := x509.NewCertPool()
	pool.AddCert(h.clientCA.Cert)
	s.adminClientCAs = pool
	serverCert := h.serverCA.Issue(t, adminapitest.CertOptions{
		CommonName:  "edge",
		IPs:         []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	s.cfg.PublicTLSConfig = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	return h
}

func (h *adminMTLSHarness) start(t *testing.T) {
	t.Helper()
	h.srv = httptest.NewUnstartedServer(h.s.adminMTLSHandler())
	h.srv.TLS = h.s.adminMTLSTLSConfig()
	h.srv.StartTLS()
	t.Cleanup(h.srv.Close)
}

func startAdminMTLS(t *testing.T, s *Server) *adminMTLSHarness {
	t.Helper()
	h := newAdminMTLSHarness(t, s)
	h.start(t)
	return h
}

func (h *adminMTLSHarness) cert(t *testing.T, commonName string, units ...string) tls.Certificate {
	t.Helper()
	return h.clientCA.Issue(t, adminapitest.CertOptions{CommonName: commonName, OUs: units, ExtKeyUsage: clientAuthUsage})
}

func (h *adminMTLSHarness) client(t *testing.T, cert *tls.Certificate) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(h.serverCA.Cert)
	config := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	if cert != nil {
		presented := *cert
		config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &presented, nil
		}
	}
	transport := &http.Transport{TLSClientConfig: config}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

func (h *adminMTLSHarness) do(t *testing.T, client *http.Client, method, path, body string, headers map[string]string) (int, string) {
	t.Helper()
	request, err := http.NewRequest(method, h.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return response.StatusCode, string(data)
}

func adminErrorCode(t *testing.T, body string) string {
	t.Helper()
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("decode admin error %q: %v", body, err)
	}
	return envelope.Error.Code
}

func certPEM(cert tls.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
}

func TestLoadAdminClientCAsRejectsInvalidBundles(t *testing.T) {
	ca := adminapitest.NewCA(t)
	otherCA := adminapitest.NewCA(t)
	leaf := ca.Issue(t, adminapitest.CertOptions{CommonName: "alice", OUs: []string{oidc.RoleViewer}, ExtKeyUsage: clientAuthUsage})
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return path
	}
	join := func(parts ...[]byte) []byte {
		var out []byte
		for _, part := range parts {
			out = append(out, part...)
		}
		return out
	}

	cases := []struct {
		name string
		path string
	}{
		{"missing file", filepath.Join(dir, "absent.pem")},
		{"empty file", write("empty.pem", nil)},
		{"whitespace only", write("blank.pem", []byte("\n \n"))},
		{"private key block holding a certificate", write("key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ca.Cert.Raw}))},
		{"non-CA certificate", write("leaf.pem", certPEM(leaf))},
		{"CA followed by non-CA certificate", write("mixed.pem", join(ca.PEM, certPEM(leaf)))},
		{"certificate followed by garbage", write("trailing.pem", join(ca.PEM, []byte("not a pem block\n")))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := loadAdminClientCAs(tc.path)
			if err == nil {
				t.Fatalf("loadAdminClientCAs accepted %s", tc.name)
			}
			if pool != nil {
				t.Fatalf("loadAdminClientCAs returned a pool alongside error %v", err)
			}
			if strings.Contains(err.Error(), "BEGIN") {
				t.Fatalf("error leaks PEM content: %v", err)
			}
		})
	}

	bundle := write("bundle.pem", join(ca.PEM, []byte("\n"), otherCA.PEM, []byte("\n  \n")))
	pool, err := loadAdminClientCAs(bundle)
	if err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
	if pool == nil {
		t.Fatal("valid bundle returned a nil pool")
	}
	chain := []*x509.Certificate{leaf.Leaf}
	if _, err := verifyAdminClientCert(pool, chain, time.Now()); err != nil {
		t.Fatalf("certificate from bundled CA rejected: %v", err)
	}
}

func TestVerifyAdminClientCert(t *testing.T) {
	ca := adminapitest.NewCA(t)
	otherCA := adminapitest.NewCA(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	now := time.Now()

	issue := func(ca *adminapitest.CA, opts adminapitest.CertOptions) *x509.Certificate {
		return ca.Issue(t, opts).Leaf
	}
	valid := func(commonName string, units ...string) adminapitest.CertOptions {
		return adminapitest.CertOptions{CommonName: commonName, OUs: units, ExtKeyUsage: clientAuthUsage}
	}
	withValidity := func(opts adminapitest.CertOptions, notBefore, notAfter time.Time) adminapitest.CertOptions {
		opts.NotBefore, opts.NotAfter = notBefore, notAfter
		return opts
	}
	lifetime := func(d time.Duration) adminapitest.CertOptions {
		start := now.Add(-time.Minute).Truncate(time.Second)
		return withValidity(valid("alice", oidc.RoleOperator), start, start.Add(d))
	}

	intermediate := ca.Issue(t, adminapitest.CertOptions{CommonName: "ngstone intermediate", IsCA: true, NotAfter: now.Add(12 * time.Hour)})
	intermediateCA := &adminapitest.CA{Cert: intermediate.Leaf, Key: intermediate.PrivateKey.(crypto.Signer)}
	viaIntermediate := issue(intermediateCA, valid("alice", oidc.RoleOperator))

	global := credentials.GlobalOwnerID
	tests := []struct {
		name  string
		roots *x509.CertPool
		chain []*x509.Certificate
		now   time.Time
		want  error
	}{
		{"nil roots", nil, []*x509.Certificate{issue(ca, valid("alice", oidc.RoleOperator))}, now, errAdminCertMissing},
		{"nil chain", roots, nil, now, errAdminCertMissing},
		{"empty chain", roots, []*x509.Certificate{}, now, errAdminCertMissing},
		{"other CA", roots, []*x509.Certificate{issue(otherCA, valid("alice", oidc.RoleOperator))}, now, errAdminCertUntrusted},
		{"expired", roots, []*x509.Certificate{issue(ca, valid("alice", oidc.RoleOperator))}, now.Add(2 * time.Hour), errAdminCertUntrusted},
		{"server auth only", roots, []*x509.Certificate{issue(ca, adminapitest.CertOptions{CommonName: "alice", OUs: []string{oidc.RoleOperator}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})}, now, errAdminCertUntrusted},
		{"no extended key usage", roots, []*x509.Certificate{issue(ca, adminapitest.CertOptions{CommonName: "alice", OUs: []string{oidc.RoleOperator}})}, now, errAdminCertUsage},
		{"any extended key usage only", roots, []*x509.Certificate{issue(ca, adminapitest.CertOptions{CommonName: "alice", OUs: []string{oidc.RoleOperator}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})}, now, errAdminCertUsage},
		{"lifetime above the cap", roots, []*x509.Certificate{issue(ca, lifetime(721*time.Hour))}, now, errAdminCertLifetime},
		{"lifetime at the cap", roots, []*x509.Certificate{issue(ca, lifetime(720*time.Hour))}, now, nil},
		{"uppercase name", roots, []*x509.Certificate{issue(ca, valid("Alice", oidc.RoleOperator))}, now, errAdminCertName},
		{"empty name", roots, []*x509.Certificate{issue(ca, valid("", oidc.RoleOperator))}, now, errAdminCertName},
		{"name with a space", roots, []*x509.Certificate{issue(ca, valid("a b", oidc.RoleOperator))}, now, errAdminCertName},
		{"name of 65 characters", roots, []*x509.Certificate{issue(ca, valid("a"+strings.Repeat("b", 64), oidc.RoleOperator))}, now, errAdminCertName},
		{"name of 64 characters", roots, []*x509.Certificate{issue(ca, valid("a"+strings.Repeat("b", 63), oidc.RoleOperator))}, now, nil},
		{"global owner name", roots, []*x509.Certificate{issue(ca, valid(global, oidc.RoleOperator))}, now, errAdminCertName},
		{"no role", roots, []*x509.Certificate{issue(ca, valid("alice"))}, now, errAdminCertRole},
		{"capitalised role", roots, []*x509.Certificate{issue(ca, valid("alice", "Admin"))}, now, errAdminCertRole},
		{"unknown role", roots, []*x509.Certificate{issue(ca, valid("alice", "superuser"))}, now, errAdminCertRole},
		{"issued through an intermediate", roots, []*x509.Certificate{viaIntermediate, intermediate.Leaf}, now, nil},
		{"intermediate not presented", roots, []*x509.Certificate{viaIntermediate}, now, errAdminCertUntrusted},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifyAdminClientCert(tc.roots, tc.chain, tc.now)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("verifyAdminClientCert: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("verifyAdminClientCert error = %v, want %v", err, tc.want)
			}
		})
	}

	roleCases := []struct {
		units []string
		want  string
	}{
		{[]string{oidc.RoleViewer, oidc.RoleAdmin}, oidc.RoleAdmin},
		{[]string{oidc.RoleAdmin, oidc.RoleViewer}, oidc.RoleAdmin},
		{[]string{"superuser", oidc.RoleOperator, oidc.RoleViewer}, oidc.RoleOperator},
	}
	for _, tc := range roleCases {
		id, err := verifyAdminClientCert(roots, []*x509.Certificate{issue(ca, valid("alice", tc.units...))}, now)
		if err != nil {
			t.Fatalf("verifyAdminClientCert(%v): %v", tc.units, err)
		}
		if id.Principal.Role != tc.want {
			t.Fatalf("role for units %v = %q, want %q", tc.units, id.Principal.Role, tc.want)
		}
	}

	leaf := issue(ca, valid("alice", oidc.RoleOperator))
	id, err := verifyAdminClientCert(roots, []*x509.Certificate{leaf}, now)
	if err != nil {
		t.Fatalf("valid operator rejected: %v", err)
	}
	sum := sha256.Sum256(leaf.Raw)
	if id.Principal.Subject != "mtls:alice" || id.Principal.Name != "alice" || id.Principal.Role != oidc.RoleOperator {
		t.Fatalf("principal = %+v, want mtls:alice / alice / operator", id.Principal)
	}
	if id.CertSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("fingerprint = %q, want %q", id.CertSHA256, hex.EncodeToString(sum[:]))
	}
}

func TestAdminMTLSHandshakeRejectsBadCertificates(t *testing.T) {
	s := newAdminMTLSTestServer(t)
	h := newAdminMTLSHarness(t, s)
	serverCerts := s.cfg.PublicTLSConfig.Certificates
	s.cfg.PublicTLSConfig.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return &tls.Config{Certificates: serverCerts, MinVersion: tls.VersionTLS13}, nil
	}
	h.start(t)

	before := metricAdminMTLSRejected.Value()
	if response, err := h.client(t, nil).Get(h.srv.URL + "/api/v1/status"); err == nil {
		response.Body.Close()
		t.Fatalf("request without a client certificate got status %d, want a transport error", response.StatusCode)
	}
	foreign := adminapitest.NewCA(t).Issue(t, adminapitest.CertOptions{CommonName: "mallory", OUs: []string{oidc.RoleAdmin}, ExtKeyUsage: clientAuthUsage})
	if response, err := h.client(t, &foreign).Get(h.srv.URL + "/api/v1/status"); err == nil {
		response.Body.Close()
		t.Fatalf("request with an untrusted certificate got status %d, want a transport error", response.StatusCode)
	}
	if got := metricAdminMTLSRejected.Value() - before; got < 2 {
		t.Fatalf("rejected counter rose by %d, want at least 2", got)
	}

	viewer := h.cert(t, "vera", oidc.RoleViewer)
	status, body := h.do(t, h.client(t, &viewer), http.MethodGet, "/api/v1/status", "", nil)
	if status != http.StatusOK {
		t.Fatalf("viewer status = %d, want 200; body=%s", status, body)
	}
}

func TestAdminMTLSHandlerReverifiesCertificate(t *testing.T) {
	s := newAdminMTLSTestServer(t)
	ca := adminapitest.NewCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	s.adminClientCAs = pool
	handler := s.adminMTLSHandler()

	now := time.Now()
	expired := ca.Issue(t, adminapitest.CertOptions{CommonName: "alice", OUs: []string{oidc.RoleAdmin}, ExtKeyUsage: clientAuthUsage, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-24 * time.Hour)})
	fresh := ca.Issue(t, adminapitest.CertOptions{CommonName: "alice", OUs: []string{oidc.RoleAdmin}, ExtKeyUsage: clientAuthUsage})

	serve := func(state *tls.ConnectionState) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		request.TLS = state
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	rejected := []struct {
		name  string
		state *tls.ConnectionState
	}{
		{"no TLS state", nil},
		{"handshake incomplete", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{fresh.Leaf}}},
		{"expired certificate", &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{expired.Leaf}}},
		{"no certificate", &tls.ConnectionState{HandshakeComplete: true}},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			recorder := serve(tc.state)
			if recorder.Code != http.StatusForbidden || adminErrorCode(t, recorder.Body.String()) != "certificate_rejected" {
				t.Fatalf("response = %d %s, want 403 certificate_rejected", recorder.Code, recorder.Body.String())
			}
		})
	}
	if recorder := serve(&tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{fresh.Leaf}}); recorder.Code != http.StatusOK {
		t.Fatalf("valid certificate response = %d %s, want 200", recorder.Code, recorder.Body.String())
	}
}

func TestAdminMTLSRoleEnforcementOverLoopback(t *testing.T) {
	s := newAdminMTLSTestServer(t)
	h := startAdminMTLS(t, s)
	viewer := h.cert(t, "vera", oidc.RoleViewer)
	operator := h.cert(t, "olga", oidc.RoleOperator)
	viewerClient := h.client(t, &viewer)
	operatorClient := h.client(t, &operator)

	if status, body := h.do(t, viewerClient, http.MethodGet, "/api/v1/status", "", nil); status != http.StatusOK {
		t.Fatalf("viewer status = %d, want 200; body=%s", status, body)
	}
	if status, body := h.do(t, viewerClient, http.MethodGet, "/api/state", "", nil); status != http.StatusOK {
		t.Fatalf("viewer /api/state = %d, want 200; body=%s", status, body)
	}
	status, body := h.do(t, viewerClient, http.MethodPost, "/api/v1/credentials", `{"subdomain":"demo","ttl":"1h"}`, nil)
	if status != http.StatusForbidden || adminErrorCode(t, body) != "forbidden" {
		t.Fatalf("viewer credential issue = %d %s, want 403 forbidden", status, body)
	}
	if list, err := s.credentialStore.ListForOwnerContext(t.Context(), "mtls:vera"); err != nil || len(list) != 0 {
		t.Fatalf("viewer credentials = %v, %v, want none", list, err)
	}

	status, body = h.do(t, operatorClient, http.MethodPost, "/api/v1/tunnels/unknown/drain", "", nil)
	if status == http.StatusForbidden || status == http.StatusUnauthorized {
		t.Fatalf("operator drain = %d %s, want authorization to pass", status, body)
	}

	for _, path := range []string{"/metrics", "/debug/vars", "/debug/pprof/", "/healthz"} {
		if status, _ := h.do(t, operatorClient, http.MethodGet, path, "", nil); status != http.StatusNotFound {
			t.Fatalf("GET %s on the mTLS listener = %d, want 404", path, status)
		}
	}
}

func TestAdminMTLSIgnoresBearerAndOIDCCookie(t *testing.T) {
	const issueBody = `{"subdomain":"demo","ttl":"1h"}`

	t.Run("bearer", func(t *testing.T) {
		s := newAdminMTLSTestServer(t)
		sum := sha256.Sum256([]byte("admin-secret"))
		s.cfg.AdminTokenSHA256 = sum[:]
		h := startAdminMTLS(t, s)
		viewer := h.cert(t, "vera", oidc.RoleViewer)
		status, body := h.do(t, h.client(t, &viewer), http.MethodPost, "/api/v1/credentials", issueBody, map[string]string{"Authorization": "Bearer admin-secret"})
		if status != http.StatusForbidden || adminErrorCode(t, body) != "forbidden" {
			t.Fatalf("viewer certificate with admin bearer = %d %s, want 403 forbidden", status, body)
		}
	})

	t.Run("oidc session", func(t *testing.T) {
		s, idp, _ := newOIDCTestServer(t, []string{"admins"})
		defer idp.Close()
		h := startAdminMTLS(t, s)
		session, err := oidc.NewSession(oidc.Principal{Subject: "root", Role: oidc.RoleAdmin}, time.Now().UTC(), time.Hour)
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		encoded, err := s.oidcCodec.Encode(session)
		if err != nil {
			t.Fatalf("encode session: %v", err)
		}
		cookies := fmt.Sprintf("%s=%s; %s=%s", oidcSessionCookie, encoded, oidcCSRFCookie, session.CSRF)
		viewer := h.cert(t, "vera", oidc.RoleViewer)
		status, body := h.do(t, h.client(t, &viewer), http.MethodPost, "/api/v1/credentials", issueBody, map[string]string{"Cookie": cookies, "X-Ngstone-CSRF": session.CSRF})
		if status != http.StatusForbidden || adminErrorCode(t, body) != "forbidden" {
			t.Fatalf("viewer certificate with admin session = %d %s, want 403 forbidden", status, body)
		}
	})
}

func TestAdminMTLSRejectsCrossOriginMutation(t *testing.T) {
	s := newAdminMTLSTestServer(t)
	h := startAdminMTLS(t, s)
	operator := h.cert(t, "olga", oidc.RoleOperator)
	client := h.client(t, &operator)
	issue := func(subdomain string, headers map[string]string) (int, string) {
		return h.do(t, client, http.MethodPost, "/api/v1/credentials", fmt.Sprintf(`{"subdomain":%q,"ttl":"1h"}`, subdomain), headers)
	}

	status, body := issue("crosssite", map[string]string{"Sec-Fetch-Site": "same-site"})
	if status != http.StatusForbidden || adminErrorCode(t, body) != "cross_origin_rejected" {
		t.Fatalf("same-site request = %d %s, want 403 cross_origin_rejected", status, body)
	}
	status, body = issue("crossorigin", map[string]string{"Origin": "https://demo." + s.cfg.Domain})
	if status != http.StatusForbidden || adminErrorCode(t, body) != "cross_origin_rejected" {
		t.Fatalf("foreign Origin request = %d %s, want 403 cross_origin_rejected", status, body)
	}
	if status, body = issue("plain", nil); status != http.StatusCreated {
		t.Fatalf("plain request = %d %s, want 201", status, body)
	}
	if status, body = issue("sameorigin", map[string]string{"Sec-Fetch-Site": "same-origin"}); status != http.StatusCreated {
		t.Fatalf("same-origin request = %d %s, want 201", status, body)
	}
	if status, body = h.do(t, client, http.MethodGet, "/api/v1/status", "", map[string]string{"Sec-Fetch-Site": "cross-site"}); status != http.StatusOK {
		t.Fatalf("cross-site GET = %d %s, want 200", status, body)
	}
	list, err := s.credentialStore.ListForOwnerContext(t.Context(), "mtls:olga")
	if err != nil || len(list) != 2 {
		t.Fatalf("credentials after rejected requests = %d, %v, want exactly the 2 allowed ones", len(list), err)
	}
}

func TestNewRejectsAdminMTLSMisconfiguration(t *testing.T) {
	ca := adminapitest.NewCA(t)
	dir := t.TempDir()
	goodCA := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(goodCA, ca.PEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	badCA := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write bad CA: %v", err)
	}

	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{"address only", Config{Domain: "example.com", AdminMTLSAddr: "127.0.0.1:0"}, "admin mTLS needs both an address and a client CA file"},
		{"CA file only", Config{Domain: "example.com", AdminMTLSClientCAFile: goodCA}, "admin mTLS needs both an address and a client CA file"},
		{"insecure mode", Config{Domain: "example.com", Insecure: true, AdminMTLSAddr: "127.0.0.1:0", AdminMTLSClientCAFile: goodCA}, "admin mTLS cannot be combined with insecure mode"},
		{"unparsable CA file", Config{Domain: "example.com", AdminMTLSAddr: "127.0.0.1:0", AdminMTLSClientCAFile: badCA}, "edge:"},
		{"missing CA file", Config{Domain: "example.com", AdminMTLSAddr: "127.0.0.1:0", AdminMTLSClientCAFile: filepath.Join(dir, "absent.pem")}, "edge:"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := New(tc.cfg)
			if err == nil {
				t.Fatalf("New accepted %s", tc.name)
			}
			if srv != nil {
				t.Fatalf("New returned a server alongside error %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}

	srv, err := New(Config{Domain: "example.com", AdminMTLSAddr: "127.0.0.1:0", AdminMTLSClientCAFile: goodCA})
	if err != nil {
		t.Fatalf("New with a valid admin mTLS config: %v", err)
	}
	if srv.adminClientCAs == nil {
		t.Fatal("valid admin mTLS config left adminClientCAs unset")
	}

	disabled, err := New(Config{Domain: "example.com"})
	if err != nil {
		t.Fatalf("New without admin mTLS: %v", err)
	}
	if disabled.adminClientCAs != nil {
		t.Fatal("admin mTLS is enabled without being configured")
	}
}

func TestAdminMTLSOwnershipScoping(t *testing.T) {
	s := newAdminMTLSTestServer(t)
	h := startAdminMTLS(t, s)
	alice := h.cert(t, "alice", oidc.RoleOperator)
	bob := h.cert(t, "bob", oidc.RoleOperator)
	root := h.cert(t, "root", oidc.RoleAdmin)

	status, body := h.do(t, h.client(t, &alice), http.MethodPost, "/api/v1/credentials", `{"subdomain":"alice-demo","ttl":"1h"}`, nil)
	if status != http.StatusCreated {
		t.Fatalf("alice issue = %d %s, want 201", status, body)
	}
	var issued struct {
		Data adminapi.CredentialIssueResponse `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &issued); err != nil {
		t.Fatalf("decode issue: %v", err)
	}
	if issued.Data.Credential.OwnerID != "mtls:alice" {
		t.Fatalf("credential owner = %q, want mtls:alice", issued.Data.Credential.OwnerID)
	}
	id := issued.Data.Credential.ID

	listed := func(cert tls.Certificate) []credentials.Credential {
		status, body := h.do(t, h.client(t, &cert), http.MethodGet, "/api/v1/credentials", "", nil)
		if status != http.StatusOK {
			t.Fatalf("list = %d %s, want 200", status, body)
		}
		var envelope struct {
			Data []credentials.Credential `json:"data"`
		}
		if err := json.Unmarshal([]byte(body), &envelope); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		return envelope.Data
	}
	if got := listed(alice); len(got) != 1 || got[0].ID != id {
		t.Fatalf("alice sees %+v, want her own credential %s", got, id)
	}
	if got := listed(bob); len(got) != 0 {
		t.Fatalf("bob sees %+v, want nothing", got)
	}
	if got := listed(root); len(got) != 1 || got[0].ID != id {
		t.Fatalf("admin certificate sees %+v, want every credential", got)
	}
}

func TestAdminMTLSAuditRecordsActorAndFingerprint(t *testing.T) {
	store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db"), EdgeID: "edge-test"})
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()
	s := newAdminMTLSTestServer(t)
	s.storage = store
	s.credentialStore = store
	h := startAdminMTLS(t, s)
	alice := h.cert(t, "alice", oidc.RoleOperator)

	findEvent := func(message string) opsEvent {
		t.Helper()
		events := s.events.snapshot()
		for i := len(events) - 1; i >= 0; i-- {
			if events[i].Message == message {
				return events[i]
			}
		}
		t.Fatalf("no %q event in %+v", message, events)
		return opsEvent{}
	}

	if status, body := h.do(t, h.client(t, &alice), http.MethodPost, "/api/v1/credentials", `{"subdomain":"alice-demo","ttl":"1h"}`, nil); status != http.StatusCreated {
		t.Fatalf("alice issue = %d %s, want 201", status, body)
	}
	sum := sha256.Sum256(alice.Leaf.Raw)
	event := findEvent("management credential issued")
	if event.Fields["actor_id"] != "mtls:alice" || event.Fields["auth_type"] != "mtls" || event.Fields["cert_sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("mTLS event fields = %+v, want actor mtls:alice, auth_type mtls, certificate fingerprint", event.Fields)
	}
	audit, err := store.ListAudit(t.Context(), 50)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	var durable *storage.AuditEvent
	for i := range audit {
		if audit[i].Action == "management credential issued" {
			durable = &audit[i]
		}
	}
	if durable == nil || durable.ActorID != "mtls:alice" || durable.Metadata["cert_sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("durable audit event = %+v, want actor mtls:alice and the certificate fingerprint", durable)
	}

	response := adminRequest(t, s, http.MethodPost, "/api/v1/credentials", []byte(`{"subdomain":"loopback-demo","ttl":"1h"}`), "127.0.0.1:4041", "")
	if response.Code != http.StatusCreated {
		t.Fatalf("loopback issue = %d %s, want 201", response.Code, response.Body.String())
	}
	event = findEvent("management credential issued")
	if event.Fields["actor_id"] != "admin" || event.Fields["auth_type"] != "loopback" || event.Fields["cert_sha256"] != "" {
		t.Fatalf("loopback event fields = %+v, want actor admin, auth_type loopback, no fingerprint", event.Fields)
	}
}

func TestAdminMTLSKeepsOIDCFlowsOff(t *testing.T) {
	s, idp, _ := newOIDCTestServer(t, []string{"admins"})
	defer idp.Close()
	h := startAdminMTLS(t, s)
	viewer := h.cert(t, "vera", oidc.RoleViewer)
	client := h.client(t, &viewer)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cookies := fmt.Sprintf("%s=stale; %s=stale; %s=stale", oidcSessionCookie, oidcCSRFCookie, oidcStateCookie)

	fetch := func(method, path string, headers map[string]string) (*http.Response, string) {
		t.Helper()
		request, err := http.NewRequest(method, h.srv.URL+path, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		for name, value := range headers {
			request.Header.Set(name, value)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		return response, string(data)
	}

	response, body := fetch(http.MethodGet, "/", map[string]string{"Cookie": cookies})
	if response.StatusCode != http.StatusOK || response.Header.Get("Location") != "" || !strings.Contains(body, "ngstone / ops") {
		t.Fatalf("GET / with a viewer certificate = %d (Location %q), want the dashboard with 200", response.StatusCode, response.Header.Get("Location"))
	}
	if len(response.Header.Values("Set-Cookie")) != 0 {
		t.Fatalf("GET / set cookies %v, want none", response.Header.Values("Set-Cookie"))
	}

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/auth/oidc/start"},
		{http.MethodGet, "/api/v1/auth/oidc/callback?code=c&state=s"},
		{http.MethodGet, "/api/v1/auth/logout"},
		{http.MethodPost, "/api/v1/auth/logout"},
	}
	for _, route := range routes {
		response, body := fetch(route.method, route.path, map[string]string{"Cookie": cookies})
		if response.StatusCode != http.StatusNotFound || adminErrorCode(t, body) != "not_found" {
			t.Fatalf("%s %s on the mTLS listener = %d %s, want 404 not_found", route.method, route.path, response.StatusCode, body)
		}
		if len(response.Header.Values("Set-Cookie")) != 0 {
			t.Fatalf("%s %s set cookies %v, want none", route.method, route.path, response.Header.Values("Set-Cookie"))
		}
	}

	response, body = fetch(http.MethodPost, "/api/v1/auth/logout", map[string]string{"Cookie": cookies, "Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"})
	if response.StatusCode != http.StatusNotFound || len(response.Header.Values("Set-Cookie")) != 0 {
		t.Fatalf("cross-site logout = %d with cookies %v (%s), want 404 and no cookies", response.StatusCode, response.Header.Values("Set-Cookie"), body)
	}

	response, body = fetch(http.MethodGet, "/api/v1/auth/me", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, `"auth_type":"mtls"`) || !strings.Contains(body, `"name":"vera"`) {
		t.Fatalf("GET /api/v1/auth/me = %d %s, want the mTLS principal", response.StatusCode, body)
	}
}

func TestOIDCFlowsStillServedOnOpsHandler(t *testing.T) {
	s, idp, _ := newOIDCTestServer(t, []string{"admins"})
	defer idp.Close()
	serve := func(method, path string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		s.opsMux().ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
		return recorder
	}

	if recorder := serve(http.MethodGet, "/"); recorder.Code != http.StatusFound || recorder.Header().Get("Location") != "/api/v1/auth/oidc/start" {
		t.Fatalf("GET / without a session = %d Location %q, want 302 to the OIDC start route", recorder.Code, recorder.Header().Get("Location"))
	}
	start := serve(http.MethodGet, "/api/v1/auth/oidc/start")
	if start.Code != http.StatusFound || responseCookie(start.Result(), oidcStateCookie) == nil {
		t.Fatalf("OIDC start = %d with state cookie %v, want 302 and a state cookie", start.Code, responseCookie(start.Result(), oidcStateCookie))
	}
	if recorder := serve(http.MethodGet, "/api/v1/auth/oidc/callback"); recorder.Code != http.StatusBadRequest || adminErrorCode(t, recorder.Body.String()) != "oidc_state_invalid" {
		t.Fatalf("OIDC callback without state = %d %s, want 400 oidc_state_invalid", recorder.Code, recorder.Body.String())
	}
	logout := serve(http.MethodPost, "/api/v1/auth/logout")
	if logout.Code != http.StatusFound || logout.Header().Get("Location") != "/" || len(logout.Result().Cookies()) != 3 {
		t.Fatalf("logout = %d Location %q cookies %v, want 302 to / clearing 3 cookies", logout.Code, logout.Header().Get("Location"), logout.Result().Cookies())
	}
}

func TestAdminMTLSRequiresTLS13(t *testing.T) {
	s := newAdminMTLSTestServer(t)
	h := newAdminMTLSHarness(t, s)
	if s.cfg.PublicTLSConfig.MinVersion != 0 {
		t.Fatalf("base config MinVersion = %#x, want unset", s.cfg.PublicTLSConfig.MinVersion)
	}
	h.start(t)
	viewer := h.cert(t, "vera", oidc.RoleViewer)
	roots := x509.NewCertPool()
	roots.AddCert(h.serverCA.Cert)

	handshake := func(maxVersion uint16) error {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", h.srv.Listener.Addr().String(), &tls.Config{
			RootCAs:    roots,
			ServerName: "127.0.0.1",
			MaxVersion: maxVersion,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return &viewer, nil
			},
		})
		if err == nil {
			conn.Close()
		}
		return err
	}
	if err := handshake(0); err != nil {
		t.Fatalf("TLS 1.3 handshake with a valid certificate: %v", err)
	}
	if err := handshake(tls.VersionTLS12); err == nil {
		t.Fatal("handshake limited to TLS 1.2 succeeded, want it refused")
	}
}

func TestAdminMTLSDisablesSessionResumption(t *testing.T) {
	s := newAdminMTLSTestServer(t)
	h := startAdminMTLS(t, s)
	viewer := h.cert(t, "vera", oidc.RoleViewer)
	client := h.client(t, &viewer)
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	transport.DisableKeepAlives = true

	for attempt := 1; attempt <= 2; attempt++ {
		response, err := client.Get(h.srv.URL + "/api/v1/status")
		if err != nil {
			t.Fatalf("request %d: %v", attempt, err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", attempt, response.StatusCode)
		}
		if response.TLS.DidResume {
			t.Fatalf("request %d resumed a TLS session, want a full handshake", attempt)
		}
	}
	if !s.adminMTLSTLSConfig().SessionTicketsDisabled {
		t.Fatal("adminMTLSTLSConfig left session tickets enabled")
	}
}

func TestAdminMTLSHandlerVerifiesAtTheCurrentTime(t *testing.T) {
	s := newAdminMTLSTestServer(t)
	now := time.Now()
	ca := adminapitest.NewCAWithValidity(t, now.Add(-24*time.Hour), now.Add(24*time.Hour))
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	s.adminClientCAs = pool
	handler := s.adminMTLSHandler()

	expired := ca.Issue(t, adminapitest.CertOptions{CommonName: "alice", OUs: []string{oidc.RoleAdmin}, ExtKeyUsage: clientAuthUsage, NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)})
	fresh := ca.Issue(t, adminapitest.CertOptions{CommonName: "alice", OUs: []string{oidc.RoleAdmin}, ExtKeyUsage: clientAuthUsage})
	serve := func(leaf *x509.Certificate) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		request.TLS = &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}

	if recorder := serve(fresh.Leaf); recorder.Code != http.StatusOK {
		t.Fatalf("valid certificate response = %d %s, want 200", recorder.Code, recorder.Body.String())
	}
	if recorder := serve(expired.Leaf); recorder.Code != http.StatusForbidden || adminErrorCode(t, recorder.Body.String()) != "certificate_rejected" {
		t.Fatalf("expired certificate response = %d %s, want 403 certificate_rejected", recorder.Code, recorder.Body.String())
	}
}

func TestAdminMTLSListenerLimitsConnections(t *testing.T) {
	s := newAdminMTLSTestServer(t)
	h := newAdminMTLSHarness(t, s)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: s.adminMTLSHandler()}
	go srv.Serve(s.newAdminMTLSListener(raw))
	t.Cleanup(func() { srv.Close() })
	addr := raw.Addr().String()

	idle := make([]net.Conn, adminMTLSMaxConns)
	for i := range idle {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		t.Cleanup(func() { conn.Close() })
		idle[i] = conn
	}

	viewer := h.cert(t, "vera", oidc.RoleViewer)
	roots := x509.NewCertPool()
	roots.AddCert(h.serverCA.Cert)
	extra, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial extra connection: %v", err)
	}
	t.Cleanup(func() { extra.Close() })
	done := make(chan error, 1)
	go func() {
		done <- tls.Client(extra, &tls.Config{
			RootCAs:    roots,
			ServerName: "127.0.0.1",
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return &viewer, nil
			},
		}).Handshake()
	}()

	select {
	case err := <-done:
		t.Fatalf("connection %d was served while %d idle connections held the limit (handshake error: %v)", adminMTLSMaxConns+1, adminMTLSMaxConns, err)
	case <-time.After(400 * time.Millisecond):
	}
	idle[0].Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handshake after a slot was released: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handshake still blocked after a connection was closed")
	}
}
