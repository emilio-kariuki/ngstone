package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ngstone/internal/adminapi/adminapitest"
)

func TestAdminCommandsUseManagementAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer admin-secret" {
			t.Fatalf("authorization = %q, want bearer token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/status":
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"domain": "example.com",
				"health": map[string]any{"ok": true},
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/observability/tunnels":
			json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{
				"hostname": "demo.example.com", "request_count": 3, "latency_p95_ms": 25, "active_connectors": 1, "bytes_transferred": 128,
			}}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/tunnels":
			json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{
				"hostname": "demo.example.com", "kind": "http", "connectors": []map[string]any{{"alive": true, "healthy": true}},
			}}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/credentials":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"credential": map[string]any{
					"id":         "0123456789abcdef0123456789abcdef",
					"kind":       "http",
					"subdomain":  "demo",
					"created_at": "2026-08-18T12:00:00Z",
					"expires_at": "2026-08-19T12:00:00Z",
				},
				"token": "nst_test_token",
			}})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/credentials/0123456789abcdef0123456789abcdef":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/tunnels/demo/drain":
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"hostname":   "demo.example.com",
				"connectors": 1,
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("NGSTONE_ADMIN_SERVER", server.URL)
	t.Setenv("NGSTONE_ADMIN_TOKEN", "admin-secret")

	if code := cmdAdmin([]string{"status", "--json"}); code != 0 {
		t.Fatalf("admin status exit code = %d, want 0", code)
	}
	if code := cmdAdminStatus([]string{"--json"}); code != 0 {
		t.Fatalf("status shortcut exit code = %d, want 0", code)
	}
	if code := cmdAdminTunnels([]string{"--json"}); code != 0 {
		t.Fatalf("tunnels shortcut exit code = %d, want 0", code)
	}
	if code := cmdAdmin([]string{"observability", "--json"}); code != 0 {
		t.Fatalf("admin observability exit code = %d, want 0", code)
	}
	if code := cmdAdmin([]string{"credentials", "issue", "--subdomain", "demo", "--json"}); code != 0 {
		t.Fatalf("admin credentials issue exit code = %d, want 0", code)
	}
	if code := cmdAdmin([]string{"credentials", "revoke", "0123456789abcdef0123456789abcdef"}); code != 0 {
		t.Fatalf("admin credentials revoke exit code = %d, want 0", code)
	}
	if code := cmdAdmin([]string{"tunnel", "drain", "demo"}); code != 0 {
		t.Fatalf("admin tunnel drain exit code = %d, want 0", code)
	}
	if code := cmdAdminDrainAlias([]string{"demo"}); code != 0 {
		t.Fatalf("drain shortcut exit code = %d, want 0", code)
	}
}

type adminTLSFixture struct {
	url      string
	certPath string
	keyPath  string
	caPath   string
	cn       *string
	auth     *string
	hits     *int
}

func newAdminTLSFixture(t *testing.T) adminTLSFixture {
	t.Helper()
	clientCA := adminapitest.NewCA(t)
	serverCA := adminapitest.NewCA(t)
	clientCert := clientCA.Issue(t, adminapitest.CertOptions{CommonName: "alice", OUs: []string{"operator"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	serverCert := serverCA.Issue(t, adminapitest.CertOptions{CommonName: "edge", IPs: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	clientPool := x509.NewCertPool()
	clientPool.AddCert(clientCA.Cert)

	var cn, auth string
	var hits int
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		cn = r.TLS.PeerCertificates[0].Subject.CommonName
		auth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"domain": "example.com", "health": map[string]any{"ok": true}}})
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientPool}
	server.StartTLS()
	t.Cleanup(server.Close)

	certPath, keyPath := adminapitest.WriteKeyPair(t, t.TempDir(), clientCert)
	caPath := filepath.Join(t.TempDir(), "server-ca.pem")
	if err := os.WriteFile(caPath, serverCA.PEM, 0o600); err != nil {
		t.Fatalf("write CA bundle: %v", err)
	}
	return adminTLSFixture{url: server.URL, certPath: certPath, keyPath: keyPath, caPath: caPath, cn: &cn, auth: &auth, hits: &hits}
}

func TestAdminCommandsPresentClientCertificate(t *testing.T) {
	f := newAdminTLSFixture(t)
	t.Setenv("NGSTONE_ADMIN_SERVER", f.url)
	t.Setenv("NGSTONE_ADMIN_TOKEN", "admin-secret")
	t.Setenv("NGSTONE_ADMIN_CLIENT_CERT", f.certPath)
	t.Setenv("NGSTONE_ADMIN_CLIENT_KEY", f.keyPath)
	t.Setenv("NGSTONE_ADMIN_CA", f.caPath)

	if code := cmdAdminStatus([]string{"--json"}); code != 0 {
		t.Fatalf("admin status exit code = %d, want 0", code)
	}
	if *f.cn != "alice" {
		t.Fatalf("server saw client certificate CN %q, want alice", *f.cn)
	}
	if *f.auth != "" {
		t.Fatalf("server saw Authorization %q, want none when a client certificate is configured", *f.auth)
	}
}

func TestAdminClientRejectsReadableKey(t *testing.T) {
	f := newAdminTLSFixture(t)
	t.Setenv("NGSTONE_ADMIN_TOKEN", "")
	if err := os.Chmod(f.keyPath, 0o644); err != nil {
		t.Fatalf("chmod key: %v", err)
	}
	args := []string{"--json", "--server", f.url, "--client-cert", f.certPath, "--client-key", f.keyPath, "--ca", f.caPath}
	if code := cmdAdminStatus(args); code == 0 {
		t.Fatal("admin status accepted a group/world readable client key")
	}
	if *f.hits != 0 {
		t.Fatalf("server was contacted %d times, want 0", *f.hits)
	}
	if err := os.Chmod(f.keyPath, 0o600); err != nil {
		t.Fatalf("chmod key: %v", err)
	}
	if code := cmdAdminStatus(args); code != 0 {
		t.Fatalf("admin status with an owner-only key exit code = %d, want 0", code)
	}
}

func TestAdminClientRequiresCertAndKeyTogether(t *testing.T) {
	f := newAdminTLSFixture(t)
	t.Setenv("NGSTONE_ADMIN_TOKEN", "")
	for name, args := range map[string][]string{
		"certificate only": {"--client-cert", f.certPath},
		"key only":         {"--client-key", f.keyPath},
	} {
		t.Run(name, func(t *testing.T) {
			full := append([]string{"--json", "--server", f.url, "--ca", f.caPath}, args...)
			if code := cmdAdminStatus(full); code == 0 {
				t.Fatalf("admin status accepted %s", name)
			}
			if *f.hits != 0 {
				t.Fatalf("server was contacted %d times, want 0", *f.hits)
			}
		})
	}
	for name, flags := range map[string]*adminCLIFlags{
		"certificate only": {clientCert: f.certPath, ca: f.caPath},
		"key only":         {clientKey: f.keyPath, ca: f.caPath},
	} {
		if config, err := adminTLSConfig(flags); config != nil || err == nil || !strings.Contains(err.Error(), "must be set together") {
			t.Fatalf("adminTLSConfig with %s = %v, %v, want the set-together error", name, config, err)
		}
	}
	if config, err := adminTLSConfig(&adminCLIFlags{}); config != nil || err != nil {
		t.Fatalf("adminTLSConfig with no TLS flags = %v, %v, want nil, nil", config, err)
	}
}
