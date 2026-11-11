package edge

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	if xff := got.Get("X-Forwarded-For"); xff != "9.9.9.9" {
		t.Fatalf("X-Forwarded-For = %q, want 9.9.9.9", xff)
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

func corsPreflightRequest(remoteAddr string) *http.Request {
	req := httptest.NewRequest(http.MethodOptions, "http://svc.example.com/api/items", nil)
	req.Host = "svc.example.com"
	req.RemoteAddr = remoteAddr
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Access-Control-Request-Method", "GET")
	return req
}

func TestHandlePublicCORSPreflightHonoursCIDRAllowList(t *testing.T) {
	p, err := policy.Parse([]byte(`{"rules":[],"cors":{"allowed_origins":["https://app.example"]}}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}
	ac, err := buildAccessControl(proto.Bind{AllowCIDRs: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatalf("buildAccessControl: %v", err)
	}
	var calls atomic.Int64
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	as := newFakeAgentSession(t, "cors-cidr-instance", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	})
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "svc.example.com", Session: as, Takeover: true, Access: ac, TrafficPolicy: p}); err != nil {
		t.Fatalf("bind: %v", err)
	}

	rec := httptest.NewRecorder()
	s.handlePublic(rec, corsPreflightRequest("10.1.2.3:5555"))
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("allowed client preflight = %d %v, want 204 with CORS headers", rec.Code, rec.Header())
	}

	rec = httptest.NewRecorder()
	s.handlePublic(rec, corsPreflightRequest("9.9.9.9:5555"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("preflight from outside allow_cidrs = %d, want 403", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("forbidden preflight carried CORS headers: %v", rec.Header())
	}
	if calls.Load() != 0 {
		t.Fatal("preflight reached the agent")
	}
}

func TestHandlePublicCORSPreflightHonoursRateLimit(t *testing.T) {
	p, err := policy.Parse([]byte(`{"rules":[],"cors":{"allowed_origins":["https://app.example"]}}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}
	s := newServerForTest(LimitsConfig{PerIPRate: 0.01, PerIPBurst: 2})
	as := newEchoAgentSession(t, "cors-rate-instance")
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "svc.example.com", Session: as, Takeover: true, TrafficPolicy: p}); err != nil {
		t.Fatalf("bind: %v", err)
	}

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		s.handlePublic(rec, corsPreflightRequest("9.9.9.9:5555"))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("preflight %d within burst = %d, want 204", i+1, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	s.handlePublic(rec, corsPreflightRequest("9.9.9.9:5555"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("preflight past burst = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("rate-limited preflight carried CORS headers: %v", rec.Header())
	}
}

func TestHandlePublicRedirectDoesNotBypassBasicAuth(t *testing.T) {
	p, err := policy.Parse([]byte(`{"rules":[{"action":"redirect","path_prefix":"/old","redirect_url":"/new$path"}]}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}
	ac, err := buildAccessControl(proto.Bind{BasicAuthSHA256: []string{policyTestDigest("alice:secret")}})
	if err != nil {
		t.Fatalf("buildAccessControl: %v", err)
	}
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	as := newEchoAgentSession(t, "redirect-auth-instance")
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "svc.example.com", Session: as, Takeover: true, Access: ac, TrafficPolicy: p}); err != nil {
		t.Fatalf("bind: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/old/page", nil)
	req.Host = "svc.example.com"
	req.RemoteAddr = "9.9.9.9:5555"
	rec := httptest.NewRecorder()
	s.handlePublic(rec, req)
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("Location") != "" {
		t.Fatalf("unauthenticated redirect request = %d Location=%q, want 401 without Location", rec.Code, rec.Header().Get("Location"))
	}

	authed := httptest.NewRequest(http.MethodGet, "http://svc.example.com/old/page", nil)
	authed.Host = "svc.example.com"
	authed.RemoteAddr = "9.9.9.9:5555"
	authed.SetBasicAuth("alice", "secret")
	rec = httptest.NewRecorder()
	s.handlePublic(rec, authed)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/new/page" {
		t.Fatalf("authenticated redirect request = %d %q, want 302 /new/page", rec.Code, rec.Header().Get("Location"))
	}
}

func TestHandlePublicRedirectDoesNotBypassVisitorLogin(t *testing.T) {
	p, err := policy.Parse([]byte(`{"rules":[{"action":"redirect","path_prefix":"/old","redirect_url":"https://elsewhere.example/new$path"}]}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}
	idp := newFakeVisitorIdP(t)
	s := newVisitorTestServer(t, idp)
	ac, err := buildAccessControl(proto.Bind{OIDC: &proto.OIDCLogin{}})
	if err != nil {
		t.Fatalf("buildAccessControl: %v", err)
	}
	as := newEchoAgentSession(t, "redirect-login-instance")
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "app.example.com", Session: as, Takeover: true, Access: ac, TrafficPolicy: p}); err != nil {
		t.Fatalf("bind: %v", err)
	}

	browser := visitorRequest(t, s, http.MethodGet, "http://app.example.com/old/page", htmlAccept())
	location, _ := url.Parse(browser.Header().Get("Location"))
	if browser.Code != http.StatusFound || location.Host != "example.com" || location.Path != visitorStartPath {
		t.Fatalf("browser = %d Location=%q, want the login wall redirect", browser.Code, browser.Header().Get("Location"))
	}
	api := visitorRequest(t, s, http.MethodGet, "http://app.example.com/old/page", http.Header{"Accept": {"application/json"}})
	if api.Code != http.StatusUnauthorized || api.Header().Get("Location") != "" {
		t.Fatalf("API client = %d Location=%q, want 401 without Location", api.Code, api.Header().Get("Location"))
	}
}

func TestHandlePublicPolicyResponseHeadersOnUpgrade(t *testing.T) {
	p, err := policy.Parse([]byte(`{
  "rules": [{"action": "transform", "response_headers": {"set": {"X-Edge": "1"}, "remove": ["Server"]}}],
  "cors": {"allowed_origins": ["https://app.example"]}
}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	as := newFakeAgentSession(t, "upgrade-policy-instance", func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		io.WriteString(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: test\r\nConnection: Upgrade\r\nServer: local-app\r\n\r\n")
		rw.Flush()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(rw, buf); err != nil {
			return
		}
		rw.Write(buf)
		rw.Flush()
	})
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "svc.example.com", Session: as, Takeover: true, TrafficPolicy: p}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	public := httptest.NewServer(http.HandlerFunc(s.handlePublic))
	t.Cleanup(public.Close)

	conn, err := net.Dial("tcp", public.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: svc.example.com\r\nOrigin: https://app.example\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if resp.Header.Get("X-Edge") != "1" || resp.Header.Get("Server") != "" || resp.Header.Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("upgrade response headers = %v", resp.Header)
	}
	io.WriteString(conn, "ping")
	echo := make([]byte, 4)
	if _, err := io.ReadFull(br, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("echo = %q err=%v, want ping", echo, err)
	}
}

func TestHandlePublicPolicyResponseHeadersOnEventStream(t *testing.T) {
	p, err := policy.Parse([]byte(`{
  "rules": [{"action": "transform", "response_headers": {"set": {"X-Edge": "1"}, "remove": ["Server"]}}],
  "cors": {"allowed_origins": ["https://app.example"]}
}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}
	release := make(chan struct{})
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	as := newFakeAgentSession(t, "sse-policy-instance", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Server", "local-app")
		io.WriteString(w, "data: one\n\n")
		http.NewResponseController(w).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		io.WriteString(w, "data: two\n\n")
	})
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "svc.example.com", Session: as, Takeover: true, TrafficPolicy: p}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	public := httptest.NewServer(http.HandlerFunc(s.handlePublic))
	t.Cleanup(public.Close)

	req, err := http.NewRequest(http.MethodGet, public.URL+"/events", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Host = "svc.example.com"
	req.Header.Set("Origin", "https://app.example")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Edge") != "1" || resp.Header.Get("Server") != "" || resp.Header.Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("event stream response headers = %v", resp.Header)
	}
	br := bufio.NewReader(resp.Body)
	if line, err := br.ReadString('\n'); err != nil || line != "data: one\n" {
		t.Fatalf("first event = %q err=%v", line, err)
	}
	close(release)
	rest, err := io.ReadAll(br)
	if err != nil || !strings.Contains(string(rest), "data: two") {
		t.Fatalf("rest of stream = %q err=%v", rest, err)
	}
}

func TestHandlePublicPolicyResponseHeadersWithHTTP2Trailers(t *testing.T) {
	p, err := policy.Parse([]byte(`{
  "rules": [{"action": "transform", "response_headers": {"set": {"X-Edge": "1"}, "remove": ["Server"]}}],
  "cors": {"allowed_origins": ["https://app.example"]}
}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}
	as := newFakeH2AgentSession(t, "h2-policy-instance", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Server", "local-app")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
		w.Header().Set("Grpc-Status", "0")
	}))
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "grpc.example.com", Session: as, Takeover: true, HTTP2: true, TrafficPolicy: p}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	t.Cleanup(func() { s.registry.ReleaseSession(as) })

	req := httptest.NewRequest(http.MethodPost, "http://grpc.example.com/test.Service/Call", strings.NewReader("request"))
	req.Host = "grpc.example.com"
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.RemoteAddr = "203.0.113.20:4321"
	req.Header.Set("Origin", "https://app.example")
	rec := httptest.NewRecorder()
	s.handlePublic(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "request" {
		t.Fatalf("response = %d %q, want 200 request", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Edge") != "1" || rec.Header().Get("Server") != "" || rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("response headers = %v", rec.Header())
	}
	if got := rec.Result().Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("Grpc-Status trailer = %q, want 0; trailer=%v", got, rec.Result().Trailer)
	}
}

func policyTestDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
