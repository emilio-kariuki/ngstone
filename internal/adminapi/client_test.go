package adminapi

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ngstone/internal/adminapi/adminapitest"
)

func TestClientUsesBearerAuthAndEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/status" {
			t.Fatalf("request = %s %s, want GET /api/v1/status", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer admin-secret" {
			t.Fatalf("authorization = %q, want bearer token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"domain": "example.com"}})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "admin-secret")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	var status struct {
		Domain string `json:"domain"`
	}
	if err := client.Get("/api/v1/status", &status); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if status.Domain != "example.com" {
		t.Fatalf("status domain = %q, want example.com", status.Domain)
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	server := httptest.NewServer(http.RedirectHandler("https://example.invalid/", http.StatusFound))
	defer server.Close()

	client, err := NewClient(server.URL, "admin-secret")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	err = client.Get("/api/v1/status", &struct{}{})
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Status != http.StatusFound {
		t.Fatalf("Get error = %T %v, want status 302 APIError", err, err)
	}
}

func TestNewClientRejectsUnsafeBaseURLs(t *testing.T) {
	for _, rawURL := range []string{
		"ftp://127.0.0.1:4041",
		"http://user:pass@127.0.0.1:4041",
		"http://127.0.0.1:4041?token=secret",
	} {
		if _, err := NewClient(rawURL, ""); err == nil {
			t.Fatalf("NewClient(%q) succeeded, want rejection", rawURL)
		}
	}
}

func TestNewClientTLSPresentsClientCertificate(t *testing.T) {
	clientCA := adminapitest.NewCA(t)
	serverCA := adminapitest.NewCA(t)
	clientCert := clientCA.Issue(t, adminapitest.CertOptions{CommonName: "alice", OUs: []string{"operator"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	serverCert := serverCA.Issue(t, adminapitest.CertOptions{CommonName: "edge", IPs: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})

	clientPool := x509.NewCertPool()
	clientPool.AddCert(clientCA.Cert)
	var seenCN, seenAuthorization string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCN = r.TLS.PeerCertificates[0].Subject.CommonName
		seenAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"domain": "example.com"}})
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientPool}
	server.StartTLS()
	defer server.Close()

	serverPool := x509.NewCertPool()
	serverPool.AddCert(serverCA.Cert)
	config := &tls.Config{RootCAs: serverPool, Certificates: []tls.Certificate{clientCert}, MinVersion: tls.VersionTLS13}

	for name, target := range map[string]string{"with scheme": server.URL, "without scheme": strings.TrimPrefix(server.URL, "https://")} {
		t.Run(name, func(t *testing.T) {
			seenCN, seenAuthorization = "", ""
			client, err := NewClientTLS(target, "", config)
			if err != nil {
				t.Fatalf("NewClientTLS: %v", err)
			}
			var status struct {
				Domain string `json:"domain"`
			}
			if err := client.Get("/api/v1/status", &status); err != nil {
				t.Fatalf("Get: %v", err)
			}
			if seenCN != "alice" {
				t.Fatalf("server saw client certificate CN %q, want alice", seenCN)
			}
			if seenAuthorization != "" {
				t.Fatalf("server saw Authorization %q, want none", seenAuthorization)
			}
		})
	}

	plain, err := NewClient(server.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := plain.Get("/api/v1/status", &struct{}{}); err == nil {
		t.Fatal("client without TLS settings reached a server that requires a client certificate")
	}
}

func TestNewClientTLSRequiresHTTPS(t *testing.T) {
	for _, rawURL := range []string{"http://127.0.0.1:4041", "http://edge.example.com"} {
		if _, err := NewClientTLS(rawURL, "", &tls.Config{}); err == nil {
			t.Fatalf("NewClientTLS(%q) accepted TLS settings for a plain http URL", rawURL)
		}
	}
	if _, err := NewClientTLS("http://127.0.0.1:4041", "", nil); err != nil {
		t.Fatalf("NewClientTLS without TLS settings rejected an http URL: %v", err)
	}
}
