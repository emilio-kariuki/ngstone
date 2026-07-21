package edge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleHealthzInsecureModeReportsOK(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	s.handleHealthz(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d when no TLS manager is configured (insecure mode)", rec.Code, http.StatusOK)
	}
	var resp healthzResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.OK {
		t.Fatalf("resp.OK = false, want true when no TLS manager is configured")
	}
}

func TestHandleHealthzReportsUnloadableCertsAsUnhealthy(t *testing.T) {
	mgr, err := NewTLSManager(TLSConfig{
		Domain:             "healthz-check.invalid",
		CloudflareAPIToken: "unused-in-this-test",
		ACMEEmail:          "ops@healthz-check.invalid",
		StoragePath:        t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewTLSManager: %v", err)
	}

	s := &Server{tlsMgr: mgr}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	s.handleHealthz(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d when neither certificate has ever been obtained", rec.Code, http.StatusServiceUnavailable)
	}
	var resp healthzResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.OK {
		t.Fatalf("resp.OK = true, want false when certs are not loadable")
	}
	if resp.Apex.Domain != "healthz-check.invalid" {
		t.Fatalf("resp.Apex.Domain = %q, want %q", resp.Apex.Domain, "healthz-check.invalid")
	}
	if resp.Apex.Error == "" || resp.Wildcard.Error == "" {
		t.Fatalf("expected both apex and wildcard cert errors to be populated, got %+v", resp)
	}
}
