package edge

import (
	"net/http"
	"net/http/httptest"
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
