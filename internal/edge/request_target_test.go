package edge

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"ngstone/internal/policy"
	"ngstone/internal/webhook"
)

func rawRequestStatus(t *testing.T, addr, requestLine string) int {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(requestLine + "\r\nHost: svc.example.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("%q: no response: %v", requestLine, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestHandlePublicRejectsAmbiguousRequestTargets(t *testing.T) {
	p, err := policy.Parse([]byte(`{"rules":[{"action":"deny","path_prefix":"/admin"}]}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}
	verifier, err := webhook.New(webhook.Config{Provider: webhook.ProviderGitHub, Secret: testWebhookSecret, PathPrefix: "/hooks"})
	if err != nil {
		t.Fatalf("webhook.New: %v", err)
	}
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	var hits atomic.Int64
	as := newFakeAgentSession(t, "target-instance", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ok"))
	})
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "svc.example.com", Session: as, Takeover: true, TrafficPolicy: p, Webhook: verifier}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	ts := httptest.NewServer(http.HandlerFunc(s.handlePublic))
	t.Cleanup(ts.Close)

	rejected := []string{
		"POST a:b:/hooks/github HTTP/1.1",
		"GET a:b:/admin/users HTTP/1.1",
		"GET a:b://x/admin/users HTTP/1.1",
		"GET /a/../admin HTTP/1.1",
		"GET /a/%2e%2e/admin HTTP/1.1",
		"GET /./admin HTTP/1.1",
		"GET /admin/. HTTP/1.1",
		"GET /%2E/admin HTTP/1.1",
	}
	for _, line := range rejected {
		if got := rawRequestStatus(t, ts.Listener.Addr().String(), line); got != http.StatusBadRequest {
			t.Errorf("%q = %d, want 400", line, got)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("origin saw %d requests for rejected targets", n)
	}

	if got := rawRequestStatus(t, ts.Listener.Addr().String(), "GET /admin/users HTTP/1.1"); got != http.StatusForbidden {
		t.Fatalf("normal denied path = %d, want 403", got)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("origin saw %d requests for a denied path", n)
	}

	for _, target := range []string{"/.well-known/x", "/a/..b/c", "/v1.2/x", "/a/b.../c"} {
		if got := rawRequestStatus(t, ts.Listener.Addr().String(), "GET "+target+" HTTP/1.1"); got != http.StatusOK {
			t.Errorf("%s = %d, want 200", target, got)
		}
	}
	if n := hits.Load(); n != 4 {
		t.Fatalf("origin saw %d requests, want 4", n)
	}
}
