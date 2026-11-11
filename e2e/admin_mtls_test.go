package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ngstone/internal/adminapi"
	"ngstone/internal/adminapi/adminapitest"
	"ngstone/internal/edge"
	"ngstone/internal/oidc"
)

func TestAdminMTLSEndToEnd(t *testing.T) {
	const domain = "mgmt.example.com"
	serverCert, serverPool := selfSignedTLSCert(t, domain)
	clientCA := adminapitest.NewCA(t)
	caFile := filepath.Join(t.TempDir(), "admin-ca.pem")
	if err := os.WriteFile(caFile, clientCA.PEM, 0o600); err != nil {
		t.Fatalf("write client CA: %v", err)
	}

	mtlsAddr := freeAddr(t)
	srv, err := edge.New(edge.Config{
		ControlAddr:     freeAddr(t),
		PublicAddr:      freeAddr(t),
		Domain:          domain,
		PublicScheme:    "https",
		CredentialsFile: filepath.Join(t.TempDir(), "credentials.json"),
		PublicTLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			MinVersion:   tls.VersionTLS12,
		},
		AdminMTLSAddr:         mtlsAddr,
		AdminMTLSClientCAFile: caFile,
	})
	if err != nil {
		t.Fatalf("edge.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(fwdStopBudget):
			t.Errorf("edge did not stop within %s", fwdStopBudget)
		}
	})
	waitForPort(t, mtlsAddr)

	newClient := func(cert *tls.Certificate) *adminapi.Client {
		t.Helper()
		config := &tls.Config{ServerName: domain, RootCAs: serverPool, MinVersion: tls.VersionTLS13}
		if cert != nil {
			config.Certificates = []tls.Certificate{*cert}
		}
		client, err := adminapi.NewClientTLS("https://"+mtlsAddr, "", config)
		if err != nil {
			t.Fatalf("NewClientTLS: %v", err)
		}
		return client
	}
	issue := func(cn, role string) tls.Certificate {
		return clientCA.Issue(t, adminapitest.CertOptions{
			CommonName:  cn,
			OUs:         []string{role},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
	}
	operator := issue("alice", oidc.RoleOperator)
	viewer := issue("vera", oidc.RoleViewer)
	request := adminapi.CredentialIssueRequest{Subdomain: "demo", TTL: "1h"}

	var issued adminapi.CredentialIssueResponse
	if err := newClient(&operator).Post("/api/v1/credentials", request, &issued); err != nil {
		t.Fatalf("operator credential issue: %v", err)
	}
	if issued.Credential.OwnerID != "mtls:alice" {
		t.Fatalf("credential owner = %q, want mtls:alice", issued.Credential.OwnerID)
	}

	err = newClient(&viewer).Post("/api/v1/credentials", request, &issued)
	var apiErr *adminapi.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusForbidden {
		t.Fatalf("viewer credential issue error = %v, want an API error with status 403", err)
	}
	if err := newClient(&viewer).Get("/api/v1/status", &struct{}{}); err != nil {
		t.Fatalf("viewer status: %v", err)
	}

	err = newClient(nil).Get("/api/v1/status", &struct{}{})
	if err == nil || errors.As(err, &apiErr) {
		t.Fatalf("client without a certificate error = %v, want a transport error", err)
	}

	tlsConfig := &tls.Config{ServerName: domain, RootCAs: serverPool, Certificates: []tls.Certificate{operator}, MinVersion: tls.VersionTLS13}
	httpClient := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	defer httpClient.CloseIdleConnections()
	resp, err := httpClient.Get("https://" + mtlsAddr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /metrics on the mTLS listener = %d, want 404", resp.StatusCode)
	}
}
