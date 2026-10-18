package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
