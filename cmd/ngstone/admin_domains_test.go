package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writer
	done := make(chan string)
	go func() {
		data, _ := io.ReadAll(reader)
		done <- string(data)
	}()
	fn()
	os.Stdout = original
	writer.Close()
	return <-done
}

func TestAdminDomainsActivateDisableAndList(t *testing.T) {
	var posts []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/domains/dom1/status"):
			var body struct {
				Status string `json:"status"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode status body: %v", err)
			}
			posts = append(posts, r.URL.Path+" "+body.Status)
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "dom1", "domain": "app.example.org", "tunnel_id": "tun1", "status": body.Status}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/domains":
			json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "dom1", "domain": "app.example.org", "tunnel_id": "tun1", "status": "active"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("NGSTONE_ADMIN_SERVER", server.URL)
	t.Setenv("NGSTONE_ADMIN_TOKEN", "admin-secret")

	var out string
	var code int
	out = captureStdout(t, func() { code = cmdAdmin([]string{"domains", "activate", "dom1"}) })
	if code != 0 || strings.TrimSpace(out) != "domain app.example.org active" {
		t.Fatalf("activate = %d, %q", code, out)
	}
	out = captureStdout(t, func() { code = cmdAdmin([]string{"domains", "disable", "dom1"}) })
	if code != 0 || strings.TrimSpace(out) != "domain app.example.org disabled" {
		t.Fatalf("disable = %d, %q", code, out)
	}
	if len(posts) != 2 || posts[0] != "/api/v1/domains/dom1/status active" || posts[1] != "/api/v1/domains/dom1/status disabled" {
		t.Fatalf("status requests = %v", posts)
	}
	out = captureStdout(t, func() { code = cmdAdmin([]string{"domains", "list"}) })
	if code != 0 || strings.TrimSpace(out) != "dom1\tapp.example.org\ttun1\tactive" {
		t.Fatalf("list = %d, %q", code, out)
	}
	if code := cmdAdmin([]string{"domains", "activate"}); code != 2 {
		t.Fatalf("activate without id = %d, want 2", code)
	}
	if code := cmdAdmin([]string{"domains", "activate", "missing"}); code == 0 {
		t.Fatal("activate of unknown id succeeded")
	}
}
