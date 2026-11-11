package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"ngstone/internal/adminapi"
	"ngstone/internal/oidc"
	"ngstone/internal/storage"
)

func newDomainTestServer(t *testing.T) *Server {
	t.Helper()
	store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db"), EdgeID: "edge-test"})
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	s := newTestServer("")
	s.cfg.AdminTokenSHA256 = nil
	s.storage = store
	s.credentialStore = store
	s.events = newEventRing(50)
	return s
}

func adminRequestAs(t *testing.T, s *Server, role, subject, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:4041"
	auth := adminAuth{Principal: oidc.Principal{Subject: subject, Role: role}, AuthType: adminAuthTypeMTLS}
	req = req.WithContext(withAdminAuth(context.Background(), auth))
	recorder := httptest.NewRecorder()
	s.handleAdminAPI(recorder, req)
	return recorder
}

func eventsNamed(s *Server, message string) []opsEvent {
	var out []opsEvent
	for _, event := range s.events.snapshot() {
		if event.Message == message {
			out = append(out, event)
		}
	}
	return out
}

func decodeDomain(t *testing.T, rec *httptest.ResponseRecorder) adminapi.CustomDomain {
	t.Helper()
	var envelope struct {
		Data adminapi.CustomDomain `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode domain: %v; body=%s", err, rec.Body.String())
	}
	return envelope.Data
}

func TestAdminCreateCustomDomainRejectsClientStatus(t *testing.T) {
	s := newDomainTestServer(t)

	rec := adminRequestAs(t, s, oidc.RoleOperator, "alice", http.MethodPost, "/api/v1/domains", []byte(`{"domain":"app.example.org","status":"active"}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator status code = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	rejected := eventsNamed(s, "management custom domain status rejected")
	if len(rejected) != 1 || rejected[0].Level != "warn" || rejected[0].Fields["domain"] != "app.example.org" {
		t.Fatalf("rejection events = %+v", rejected)
	}
	list, err := s.storage.ListCustomDomains(t.Context(), "alice")
	if err != nil || len(list) != 0 {
		t.Fatalf("domains after rejected create = %+v, %v", list, err)
	}

	rec = adminRequestAs(t, s, oidc.RoleAdmin, "root", http.MethodPost, "/api/v1/domains", []byte(`{"domain":"app.example.org","status":"active"}`))
	if rec.Code != http.StatusUnprocessableEntity || !bytes.Contains(rec.Body.Bytes(), []byte("set status with POST /api/v1/domains/{id}/status")) {
		t.Fatalf("global owner status code = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}

	rec = adminRequestAs(t, s, oidc.RoleOperator, "alice", http.MethodPost, "/api/v1/domains", []byte(`{"domain":"app.example.org","status":" pending "}`))
	if rec.Code != http.StatusCreated || decodeDomain(t, rec).Status != "pending" {
		t.Fatalf("pending create = %d; body=%s", rec.Code, rec.Body.String())
	}
	rec = adminRequestAs(t, s, oidc.RoleOperator, "alice", http.MethodPost, "/api/v1/domains", []byte(`{"domain":"two.example.org"}`))
	if rec.Code != http.StatusCreated || decodeDomain(t, rec).Status != "pending" {
		t.Fatalf("create without status = %d; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminCreateCustomDomainRejectsReserved(t *testing.T) {
	s := newDomainTestServer(t)
	s.visitor = &visitorLogin{callback: &url.URL{Scheme: "https", Host: "login.other.net"}}
	for _, domain := range []string{"example.com", "Example.com.", "app.example.com", "deep.app.example.com", "login.other.net", "1.2.3.4", "*.example.org", "[::1]"} {
		body, _ := json.Marshal(map[string]string{"domain": domain})
		rec := adminRequestAs(t, s, oidc.RoleOperator, "alice", http.MethodPost, "/api/v1/domains", body)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("domain %q: status = %d, want 422; body=%s", domain, rec.Code, rec.Body.String())
		}
	}
	list, err := s.storage.ListCustomDomains(t.Context(), "alice")
	if err != nil || len(list) != 0 {
		t.Fatalf("reserved names were stored: %+v, %v", list, err)
	}
	rec := adminRequestAs(t, s, oidc.RoleOperator, "alice", http.MethodPost, "/api/v1/domains", []byte(`{"domain":"notexample.com"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("unrelated domain sharing a suffix string = %d; body=%s", rec.Code, rec.Body.String())
	}
}
