package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
