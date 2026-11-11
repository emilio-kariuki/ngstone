package edge

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"ngstone/internal/policy"
	"ngstone/internal/proto"
)

func TestHandlePublicEnforcesTrafficPolicyBeforeForwarding(t *testing.T) {
	p, err := policy.Parse([]byte(`{
  "default_action": "deny",
  "rules": [
    {"action": "allow", "path_prefix": "/public"},
    {"action": "allow", "method": "GET", "header": "X-Preview", "header_value": "yes", "path_prefix": "/preview"}
  ]
}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}

	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	as := newEchoAgentSession(t, "policy-instance")
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "svc.example.com", Session: as, Takeover: true, TrafficPolicy: p}); err != nil {
		t.Fatalf("bind: %v", err)
	}

	request := func(method, path string, headerValue string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://svc.example.com"+path, nil)
		req.Host = "svc.example.com"
		req.RemoteAddr = "9.9.9.9:5555"
		if headerValue != "" {
			req.Header.Set("X-Preview", headerValue)
		}
		rec := httptest.NewRecorder()
		s.handlePublic(rec, req)
		return rec
	}

	if rec := request(http.MethodGet, "/private", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("private request status = %d, want 403", rec.Code)
	}
	if rec := request(http.MethodGet, "/public/items", ""); rec.Code != http.StatusOK {
		t.Fatalf("allowed request status = %d, want 200", rec.Code)
	}
	if rec := request(http.MethodGet, "/preview", "yes"); rec.Code != http.StatusOK {
		t.Fatalf("matching header request status = %d, want 200", rec.Code)
	}
	if rec := request(http.MethodPost, "/preview", "yes"); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong method request status = %d, want 403", rec.Code)
	}
}

func TestBuildTrafficPolicyRequiresMatchingDigest(t *testing.T) {
	p, err := policy.Parse([]byte(`{"rules":[{"action":"deny","path_prefix":"/admin"}]}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}
	if _, err := buildTrafficPolicy(proto.Bind{Policy: p, PolicyDigest: "not-the-digest"}); err == nil {
		t.Fatal("buildTrafficPolicy accepted a mismatched digest")
	}
	if _, err := buildTrafficPolicy(proto.Bind{Policy: p, PolicyDigest: p.Digest()}); err != nil {
		t.Fatalf("buildTrafficPolicy rejected a matching digest: %v", err)
	}
}

func TestHandlePublicAppliesTrafficPolicyTransforms(t *testing.T) {
	p, err := policy.Parse([]byte(`{
  "rules": [
    {"action": "transform", "request_headers": {"set": {"X-Env": "prod"}, "add": {"X-Tag": "edge"}, "remove": ["X-Debug"]}},
    {"action": "transform", "path_prefix": "/api", "response_headers": {"set": {"Cache-Control": "no-store"}, "add": {"X-Edge": "1"}, "remove": ["Server"]}}
  ]
}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}

	var mu sync.Mutex
	var seen http.Header
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	as := newFakeAgentSession(t, "transform-instance", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = r.Header.Clone()
		mu.Unlock()
		w.Header().Set("Server", "local-app")
		w.Header().Set("Cache-Control", "max-age=60")
		io.WriteString(w, "ok\n")
	})
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "svc.example.com", Session: as, Takeover: true, TrafficPolicy: p}); err != nil {
		t.Fatalf("bind: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/api/items", nil)
	req.Host = "svc.example.com"
	req.RemoteAddr = "9.9.9.9:5555"
	req.Header.Set("X-Debug", "1")
	req.Header.Add("X-Tag", "client")
	req.Header.Set("X-Forwarded-For", "6.6.6.6")
	rec := httptest.NewRecorder()
	s.handlePublic(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	got := seen
	mu.Unlock()
	if got.Get("X-Env") != "prod" || got.Get("X-Debug") != "" {
		t.Fatalf("agent saw headers %v", got)
	}
	if tags := got.Values("X-Tag"); len(tags) != 2 || tags[0] != "client" || tags[1] != "edge" {
		t.Fatalf("X-Tag = %q", tags)
	}
	if xff := got.Get("X-Forwarded-For"); xff != "6.6.6.6, 9.9.9.9" && xff != "9.9.9.9" {
		t.Fatalf("X-Forwarded-For = %q", xff)
	}
	if rec.Header().Get("Server") != "" || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Edge") != "1" {
		t.Fatalf("response headers = %v", rec.Header())
	}

	other := httptest.NewRequest(http.MethodGet, "http://svc.example.com/web", nil)
	other.Host = "svc.example.com"
	other.RemoteAddr = "9.9.9.9:5555"
	otherRec := httptest.NewRecorder()
	s.handlePublic(otherRec, other)
	if otherRec.Header().Get("Server") != "local-app" || otherRec.Header().Get("X-Edge") != "" {
		t.Fatalf("response transform leaked to a non-matching path: %v", otherRec.Header())
	}
}

func TestHandlePublicRequestHeaderTransformsSurviveConnectionTokens(t *testing.T) {
	p, err := policy.Parse([]byte(`{
  "rules": [
    {"action": "transform", "request_headers": {"set": {"X-Env": "prod", "X-Role": "admin"}, "add": {"X-Tag": "edge"}}}
  ]
}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}

	var mu sync.Mutex
	var seen http.Header
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	as := newFakeAgentSession(t, "connection-instance", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = r.Header.Clone()
		mu.Unlock()
		io.WriteString(w, "ok\n")
	})
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "svc.example.com", Session: as, Takeover: true, TrafficPolicy: p}); err != nil {
		t.Fatalf("bind: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/", nil)
	req.Host = "svc.example.com"
	req.RemoteAddr = "9.9.9.9:5555"
	req.Header.Set("Connection", "X-Env, X-Role, X-Tag")
	req.Header.Set("X-Env", "client")
	req.Header.Set("X-Role", "client")
	req.Header.Set("X-Tag", "client")
	rec := httptest.NewRecorder()
	s.handlePublic(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	got := seen
	mu.Unlock()
	if got.Get("X-Env") != "prod" || got.Get("X-Role") != "admin" {
		t.Fatalf("agent saw headers %v, want policy-set headers to survive Connection tokens", got)
	}
	if tags := got.Values("X-Tag"); len(tags) != 1 || tags[0] != "edge" {
		t.Fatalf("X-Tag = %q, want the policy-added value", tags)
	}
}

func TestHandlePublicAnswersRedirectsAtTheEdge(t *testing.T) {
	p, err := policy.Parse([]byte(`{"rules":[{"action":"redirect","path_prefix":"/old","redirect_url":"/new$path","redirect_status":301}]}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}
	var calls atomic.Int64
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	as := newFakeAgentSession(t, "redirect-instance", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, "ok\n")
	})
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "svc.example.com", Session: as, Takeover: true, TrafficPolicy: p}); err != nil {
		t.Fatalf("bind: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/old/page?x=1", nil)
	req.Host = "svc.example.com"
	req.RemoteAddr = "9.9.9.9:5555"
	rec := httptest.NewRecorder()
	s.handlePublic(rec, req)
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/new/page?x=1" {
		t.Fatalf("redirect = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if calls.Load() != 0 {
		t.Fatal("redirected request reached the agent")
	}
}

func TestHandlePublicCORSPreflightAndResponses(t *testing.T) {
	p, err := policy.Parse([]byte(`{
  "default_action": "deny",
  "rules": [{"action": "allow", "method": "GET", "path_prefix": "/api"}],
  "cors": {"allowed_origins": ["https://app.example"], "allowed_methods": ["GET", "PUT"], "allowed_headers": ["Content-Type"], "allow_credentials": true, "max_age": 300}
}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}
	ac, err := buildAccessControl(proto.Bind{BasicAuthSHA256: []string{policyTestDigest("alice:secret")}})
	if err != nil {
		t.Fatalf("buildAccessControl: %v", err)
	}
	var calls atomic.Int64
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	as := newFakeAgentSession(t, "cors-instance", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Errorf("Authorization reached the agent")
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		io.WriteString(w, "ok\n")
	})
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "svc.example.com", Session: as, Takeover: true, Access: ac, TrafficPolicy: p}); err != nil {
		t.Fatalf("bind: %v", err)
	}

	preflight := httptest.NewRequest(http.MethodOptions, "http://svc.example.com/api/items", nil)
	preflight.Host = "svc.example.com"
	preflight.RemoteAddr = "9.9.9.9:5555"
	preflight.Header.Set("Origin", "https://app.example")
	preflight.Header.Set("Access-Control-Request-Method", "PUT")
	rec := httptest.NewRecorder()
	s.handlePublic(rec, preflight)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example" || rec.Header().Get("Access-Control-Allow-Methods") != "GET, PUT" || rec.Header().Get("Access-Control-Max-Age") != "300" {
		t.Fatalf("preflight headers = %v", rec.Header())
	}
	if calls.Load() != 0 {
		t.Fatal("preflight reached the agent")
	}

	actual := httptest.NewRequest(http.MethodGet, "http://svc.example.com/api/items", nil)
	actual.Host = "svc.example.com"
	actual.RemoteAddr = "9.9.9.9:5555"
	actual.Header.Set("Origin", "https://app.example")
	actual.SetBasicAuth("alice", "secret")
	rec = httptest.NewRecorder()
	s.handlePublic(rec, actual)
	if rec.Code != http.StatusOK {
		t.Fatalf("actual status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Values("Access-Control-Allow-Origin"); len(got) != 1 || got[0] != "https://app.example" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("response headers = %v", rec.Header())
	}

	unauthenticated := httptest.NewRequest(http.MethodGet, "http://svc.example.com/api/items", nil)
	unauthenticated.Host = "svc.example.com"
	unauthenticated.RemoteAddr = "9.9.9.9:5555"
	unauthenticated.Header.Set("Origin", "https://app.example")
	rec = httptest.NewRecorder()
	s.handlePublic(rec, unauthenticated)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", rec.Code)
	}
	if calls.Load() != 1 {
		t.Fatalf("agent calls = %d, want 1", calls.Load())
	}
}

func policyTestDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
