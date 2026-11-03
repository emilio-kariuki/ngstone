package edge

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/webhook"
)

const testWebhookSecret = "whsec_edge_test_secret_value"

type webhookCapture struct {
	mu     sync.Mutex
	bodies []string
}

func (c *webhookCapture) handler(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.bodies = append(c.bodies, string(data))
	c.mu.Unlock()
	io.WriteString(w, "ok")
}

func (c *webhookCapture) received() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.bodies...)
}

func newWebhookTestServer(t *testing.T, limits LimitsConfig, cfg webhook.Config) (*Server, *webhookCapture) {
	t.Helper()
	verifier, err := webhook.New(cfg)
	if err != nil {
		t.Fatalf("webhook.New: %v", err)
	}
	limits.PerIPRate = 1000
	limits.PerIPBurst = 1000
	s := newServerForTest(limits)
	capture := &webhookCapture{}
	as := newFakeAgentSession(t, "webhook-instance", capture.handler)
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "hooks.example.com", Session: as, Takeover: true, Webhook: verifier}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	return s, capture
}

type chunkedReader struct{ r io.Reader }

func (c chunkedReader) Read(p []byte) (int, error) { return c.r.Read(p) }

func webhookRequest(s *Server, path, body string, chunked bool, headers map[string]string) *httptest.ResponseRecorder {
	var reader io.Reader = strings.NewReader(body)
	if chunked {
		reader = chunkedReader{strings.NewReader(body)}
	}
	req := httptest.NewRequest(http.MethodPost, "http://hooks.example.com"+path, reader)
	if chunked {
		req.ContentLength = -1
	}
	req.Host = "hooks.example.com"
	req.RemoteAddr = "203.0.113.7:4444"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.handlePublic(rec, req)
	return rec
}

func TestHandlePublicVerifiesGitHubWebhooks(t *testing.T) {
	s, capture := newWebhookTestServer(t, LimitsConfig{}, webhook.Config{Provider: webhook.ProviderGitHub, Secret: testWebhookSecret, PathPrefix: "/hooks"})
	body := `{"action":"opened","number":1}`
	sig := webhook.GitHubSignature(testWebhookSecret, []byte(body))

	rec := webhookRequest(s, "/hooks/github", body, false, map[string]string{webhook.GitHubSignatureHeader: sig})
	if rec.Code != http.StatusOK {
		t.Fatalf("valid signature status = %d body=%q", rec.Code, rec.Body.String())
	}
	rec = webhookRequest(s, "/hooks/github", body, true, map[string]string{webhook.GitHubSignatureHeader: sig})
	if rec.Code != http.StatusOK {
		t.Fatalf("valid chunked signature status = %d body=%q", rec.Code, rec.Body.String())
	}

	rec = webhookRequest(s, "/hooks/github", strings.Replace(body, "opened", "closed", 1), false, map[string]string{webhook.GitHubSignatureHeader: sig})
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "invalid signature") {
		t.Fatalf("tampered status = %d body=%q", rec.Code, rec.Body.String())
	}
	rec = webhookRequest(s, "/hooks/github", body, false, nil)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "missing signature") {
		t.Fatalf("unsigned status = %d body=%q", rec.Code, rec.Body.String())
	}
	rec = webhookRequest(s, "/other/../hooks/github", body, false, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("dot-segment bypass status = %d body=%q", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), testWebhookSecret) {
		t.Fatal("rejection leaked the secret")
	}

	rec = webhookRequest(s, "/health", "unsigned", false, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("path outside prefix status = %d", rec.Code)
	}

	got := capture.received()
	want := []string{body, body, "unsigned"}
	if len(got) != len(want) {
		t.Fatalf("local app received %d requests (%q), want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("request %d body = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestHandlePublicRejectsExpiredStripeWebhook(t *testing.T) {
	s, capture := newWebhookTestServer(t, LimitsConfig{}, webhook.Config{Provider: webhook.ProviderStripe, Secret: testWebhookSecret, Tolerance: time.Minute})
	body := `{"id":"evt_1","type":"payment_intent.succeeded"}`

	fresh := webhook.StripeSignature(testWebhookSecret, time.Now().Unix(), []byte(body))
	if rec := webhookRequest(s, "/stripe", body, false, map[string]string{webhook.StripeSignatureHeader: fresh}); rec.Code != http.StatusOK {
		t.Fatalf("fresh signature status = %d body=%q", rec.Code, rec.Body.String())
	}
	stale := webhook.StripeSignature(testWebhookSecret, time.Now().Add(-2*time.Minute).Unix(), []byte(body))
	rec := webhookRequest(s, "/stripe", body, false, map[string]string{webhook.StripeSignatureHeader: stale})
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "timestamp outside tolerance") {
		t.Fatalf("stale signature status = %d body=%q", rec.Code, rec.Body.String())
	}
	if n := len(capture.received()); n != 1 {
		t.Fatalf("local app received %d requests, want 1", n)
	}
}

func TestHandlePublicWebhookBodyCap(t *testing.T) {
	s, capture := newWebhookTestServer(t, LimitsConfig{MaxBodyBytes: 64}, webhook.Config{Provider: webhook.ProviderGitHub, Secret: testWebhookSecret})
	body := strings.Repeat("x", 65)
	sig := webhook.GitHubSignature(testWebhookSecret, []byte(body))
	if rec := webhookRequest(s, "/", body, false, map[string]string{webhook.GitHubSignatureHeader: sig}); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("declared oversize status = %d", rec.Code)
	}
	if rec := webhookRequest(s, "/", body, true, map[string]string{webhook.GitHubSignatureHeader: sig}); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked oversize status = %d", rec.Code)
	}
	if n := len(capture.received()); n != 0 {
		t.Fatalf("local app received %d oversize requests", n)
	}
	if got := webhookBodyLimit(LimitsConfig{MaxBodyBytes: DefaultMaxBodyBytes}); got != webhook.MaxBodyBytes {
		t.Fatalf("webhookBodyLimit = %d, want %d", got, webhook.MaxBodyBytes)
	}
}

func bindOverControl(t *testing.T, s *Server, bind proto.Bind) proto.Msg {
	t.Helper()
	client, server, cleanup := newRawSessionPair(t)
	t.Cleanup(cleanup)
	as := newFakeAgentSession(t, "bind-webhook", func(w http.ResponseWriter, r *http.Request) {})
	as.NegotiatedVersion = proto.ProtoVersion
	t.Cleanup(func() { s.registry.ReleaseSession(as) })
	go s.handleBind(context.Background(), as, server.Control(), 7, bind)
	reply, err := client.Control().Read()
	if err != nil {
		t.Fatalf("read bind reply: %v", err)
	}
	return reply
}

func TestHandleBindWebhook(t *testing.T) {
	s := newTestServer("tok")
	s.cfg.OpsAddr = "127.0.0.1:4041"
	s.events = newEventRing(20)

	reply := bindOverControl(t, s, proto.Bind{Kind: proto.KindHTTP, Subdomain: "pay", Webhook: &proto.WebhookVerification{Provider: "Stripe", Secret: testWebhookSecret, ToleranceSeconds: 120}})
	if reply.Type != proto.TypeBindOK {
		t.Fatalf("reply = %s %s", reply.Type, reply.Data)
	}
	ok, err := proto.Decode[proto.BindOK](reply)
	if err != nil || ok.Webhook != webhook.ProviderStripe {
		t.Fatalf("BindOK webhook = %q err=%v", ok.Webhook, err)
	}

	for _, path := range []string{"/api/state", "/api/v1/tunnels"} {
		rec := adminRequest(t, s, http.MethodGet, path, nil, "127.0.0.1:4041", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d body=%s", path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), testWebhookSecret) {
			t.Fatalf("%s exposes the webhook secret: %s", path, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"webhook_provider":"stripe"`) {
			t.Fatalf("%s does not report the webhook provider: %s", path, rec.Body.String())
		}
	}
	for _, event := range s.events.snapshot() {
		for k, v := range event.Fields {
			if strings.Contains(k+v, testWebhookSecret) {
				t.Fatalf("event %+v exposes the webhook secret", event)
			}
		}
	}

	rejected := []proto.Bind{
		{Kind: proto.KindHTTP, Subdomain: "bad1", Webhook: &proto.WebhookVerification{Provider: "paypal", Secret: "s"}},
		{Kind: proto.KindHTTP, Subdomain: "bad2", Webhook: &proto.WebhookVerification{Provider: "github"}},
		{Kind: proto.KindHTTP, Subdomain: "bad3", Webhook: &proto.WebhookVerification{Provider: "slack", Secret: "s", ToleranceSeconds: -1}},
		{Kind: proto.KindHTTP, Subdomain: "bad4", Webhook: &proto.WebhookVerification{Provider: "hmac", Secret: "s"}},
	}
	for _, bind := range rejected {
		reply := bindOverControl(t, s, bind)
		if reply.Type != proto.TypeBindErr {
			t.Fatalf("bind %s accepted: %s", bind.Subdomain, reply.Data)
		}
		e, _ := proto.Decode[proto.BindErr](reply)
		if e.Code != proto.CodeInvalidAccess || strings.Contains(e.Message, "s\"") {
			t.Fatalf("bind %s error = %+v", bind.Subdomain, e)
		}
	}
}

func TestHandleBindTCPRejectsWebhook(t *testing.T) {
	s := newTestServer("tok")
	s.tcpMgr = newTCPManager(20000, 20010, "127.0.0.1", nil)
	reply := bindOverControl(t, s, proto.Bind{Kind: proto.KindTCP, Webhook: &proto.WebhookVerification{Provider: "github", Secret: "s"}})
	if reply.Type != proto.TypeBindErr {
		t.Fatalf("tcp bind with webhook accepted: %s", reply.Data)
	}
}

func TestMultiConnectorWebhookConfigMustMatch(t *testing.T) {
	r := NewRegistry()
	one, _ := webhook.New(webhook.Config{Provider: webhook.ProviderGitHub, Secret: "one"})
	two, _ := webhook.New(webhook.Config{Provider: webhook.ProviderGitHub, Secret: "two"})
	a, cleanA := newTestAgentSession(t, "a")
	b, cleanB := newTestAgentSession(t, "b")
	t.Cleanup(cleanA)
	t.Cleanup(cleanB)
	digest := strings.Repeat("ab", 32)
	if _, _, err := r.BindWithOptions(BindOptions{Host: "mc.example.com", Session: a, MultiConnector: true, ConnectorTokenDigest: digest, Webhook: one}); err != nil {
		t.Fatalf("first bind: %v", err)
	}
	if _, _, err := r.BindWithOptions(BindOptions{Host: "mc.example.com", Session: b, MultiConnector: true, ConnectorTokenDigest: digest, Webhook: two}); err != ErrConnectorConfigMismatch {
		t.Fatalf("mismatched secret bind err = %v, want %v", err, ErrConnectorConfigMismatch)
	}
	if _, _, err := r.BindWithOptions(BindOptions{Host: "mc.example.com", Session: b, MultiConnector: true, ConnectorTokenDigest: digest}); err != ErrConnectorConfigMismatch {
		t.Fatalf("missing webhook bind err = %v, want %v", err, ErrConnectorConfigMismatch)
	}
	same, _ := webhook.New(webhook.Config{Provider: webhook.ProviderGitHub, Secret: "one"})
	if _, _, err := r.BindWithOptions(BindOptions{Host: "mc.example.com", Session: b, MultiConnector: true, ConnectorTokenDigest: digest, Webhook: same}); err != nil {
		t.Fatalf("matching bind: %v", err)
	}
}
