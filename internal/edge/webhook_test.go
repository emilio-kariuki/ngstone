package edge

import (
	"bytes"
	"context"
	"io"
	"log/slog"
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
	for _, path := range []string{"/hooks%2Fgithub", "/x%5Chooks", "/hooks.json", "/index.php/hooks/github", "/x;y"} {
		rec = webhookRequest(s, path, body, false, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("unsigned %s status = %d body=%q", path, rec.Code, rec.Body.String())
		}
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
	defaults, err := LimitsConfig{}.withDefaults()
	if err != nil {
		t.Fatalf("withDefaults: %v", err)
	}
	if got := webhookBodyLimit(defaults); got != DefaultWebhookMaxBodyBytes {
		t.Fatalf("webhookBodyLimit = %d, want %d", got, DefaultWebhookMaxBodyBytes)
	}
	if s.webhookBudget.inUse() != 0 {
		t.Fatalf("webhook budget in use = %d after oversize requests", s.webhookBudget.inUse())
	}
}

func TestHandlePublicWebhookMaxBodyBytes(t *testing.T) {
	s, capture := newWebhookTestServer(t, LimitsConfig{WebhookMaxBodyBytes: 32}, webhook.Config{Provider: webhook.ProviderGitHub, Secret: testWebhookSecret})
	small := strings.Repeat("x", 32)
	if rec := webhookRequest(s, "/", small, true, map[string]string{webhook.GitHubSignatureHeader: webhook.GitHubSignature(testWebhookSecret, []byte(small))}); rec.Code != http.StatusOK {
		t.Fatalf("body at the cap status = %d body=%q", rec.Code, rec.Body.String())
	}
	body := strings.Repeat("x", 33)
	sig := webhook.GitHubSignature(testWebhookSecret, []byte(body))
	for _, chunked := range []bool{false, true} {
		rec := webhookRequest(s, "/", body, chunked, map[string]string{webhook.GitHubSignatureHeader: sig})
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("chunked=%v oversize status = %d", chunked, rec.Code)
		}
	}
	if n := len(capture.received()); n != 1 {
		t.Fatalf("local app received %d requests, want 1", n)
	}
	if s.webhookBudget.inUse() != 0 {
		t.Fatalf("webhook budget in use = %d", s.webhookBudget.inUse())
	}
}

type readTrap struct{ read bool }

func (r *readTrap) Read(p []byte) (int, error) {
	r.read = true
	return 0, io.EOF
}

func TestHandlePublicWebhookRejectsMissingHeaderBeforeReadingBody(t *testing.T) {
	s, capture := newWebhookTestServer(t, LimitsConfig{}, webhook.Config{Provider: webhook.ProviderStripe, Secret: testWebhookSecret})
	for name, headers := range map[string]map[string]string{
		"missing":   nil,
		"malformed": {webhook.StripeSignatureHeader: "garbage"},
	} {
		trap := &readTrap{}
		req := httptest.NewRequest(http.MethodPost, "http://hooks.example.com/stripe", trap)
		req.ContentLength = 1 << 20
		req.Host = "hooks.example.com"
		req.RemoteAddr = "203.0.113.7:4444"
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		s.handlePublic(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s header status = %d body=%q", name, rec.Code, rec.Body.String())
		}
		if trap.read {
			t.Fatalf("%s header: body was read before the signature header was checked", name)
		}
	}
	if n := len(capture.received()); n != 0 {
		t.Fatalf("local app received %d requests", n)
	}
	if s.webhookBudget.inUse() != 0 {
		t.Fatalf("webhook budget in use = %d", s.webhookBudget.inUse())
	}
}

func TestHandlePublicWebhookBufferBudget(t *testing.T) {
	s, capture := newWebhookTestServer(t, LimitsConfig{WebhookMaxBodyBytes: 64, WebhookBufferBytes: 100}, webhook.Config{Provider: webhook.ProviderGitHub, Secret: testWebhookSecret})
	body := strings.Repeat("x", 50)
	headers := map[string]string{webhook.GitHubSignatureHeader: webhook.GitHubSignature(testWebhookSecret, []byte(body))}

	held, ok := s.webhookBudget.reserve(60)
	if !ok {
		t.Fatal("could not reserve part of the budget")
	}
	before := metricRejectedWebhookBuffer.Value()
	for _, chunked := range []bool{false, true} {
		rec := webhookRequest(s, "/", body, chunked, headers)
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
			t.Fatalf("chunked=%v exhausted budget status = %d retry-after=%q", chunked, rec.Code, rec.Header().Get("Retry-After"))
		}
	}
	if got := metricRejectedWebhookBuffer.Value() - before; got != 2 {
		t.Fatalf("webhook buffer rejections = %d, want 2", got)
	}
	if got := s.webhookBudget.inUse(); got != 60 {
		t.Fatalf("webhook budget in use = %d, want 60", got)
	}
	held()

	if rec := webhookRequest(s, "/", body, true, headers); rec.Code != http.StatusOK {
		t.Fatalf("after release status = %d body=%q", rec.Code, rec.Body.String())
	}
	if rec := webhookRequest(s, "/", body+"!", false, headers); rec.Code != http.StatusUnauthorized {
		t.Fatalf("tampered status = %d", rec.Code)
	}
	if n := len(capture.received()); n != 1 {
		t.Fatalf("local app received %d requests, want 1", n)
	}
	if got := s.webhookBudget.inUse(); got != 0 {
		t.Fatalf("webhook budget in use = %d, want 0", got)
	}
}

func TestHandlePublicWebhookHoldsBudgetWhileProxying(t *testing.T) {
	verifier, err := webhook.New(webhook.Config{Provider: webhook.ProviderGitHub, Secret: testWebhookSecret})
	if err != nil {
		t.Fatalf("webhook.New: %v", err)
	}
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	entered := make(chan int64, 1)
	unblock := make(chan struct{})
	as := newFakeAgentSession(t, "webhook-hold", func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		entered <- s.webhookBudget.inUse()
		<-unblock
	})
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "hooks.example.com", Session: as, Takeover: true, Webhook: verifier}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	body := `{"ok":true}`
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- webhookRequest(s, "/", body, false, map[string]string{webhook.GitHubSignatureHeader: webhook.GitHubSignature(testWebhookSecret, []byte(body))})
	}()
	if got := <-entered; got != int64(len(body)) {
		t.Fatalf("webhook budget in use while proxying = %d, want %d", got, len(body))
	}
	close(unblock)
	if rec := <-done; rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%q", rec.Code, rec.Body.String())
	}
	if got := s.webhookBudget.inUse(); got != 0 {
		t.Fatalf("webhook budget in use after proxying = %d", got)
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

	const distinctive = "whsec_DISTINCTIVE_7f3a9c_never_echo"
	logs := &lockedBuffer{}
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prevLogger) })
	rejected := []proto.Bind{
		{Kind: proto.KindHTTP, Subdomain: "bad1", Webhook: &proto.WebhookVerification{Provider: "paypal", Secret: distinctive}},
		{Kind: proto.KindHTTP, Subdomain: "bad2", Webhook: &proto.WebhookVerification{Provider: "github"}},
		{Kind: proto.KindHTTP, Subdomain: "bad3", Webhook: &proto.WebhookVerification{Provider: "slack", Secret: distinctive, ToleranceSeconds: -1}},
		{Kind: proto.KindHTTP, Subdomain: "bad4", Webhook: &proto.WebhookVerification{Provider: "hmac", Secret: distinctive}},
		{Kind: proto.KindHTTP, Subdomain: "bad5", HTTP2: true, Webhook: &proto.WebhookVerification{Provider: "github", Secret: distinctive}},
		{Kind: proto.KindHTTP, Subdomain: "bad6", Webhook: &proto.WebhookVerification{Provider: "github", Secret: distinctive, PathPrefix: "/" + distinctive + "?"}},
	}
	for _, bind := range rejected {
		reply := bindOverControl(t, s, bind)
		if reply.Type != proto.TypeBindErr {
			t.Fatalf("bind %s accepted: %s", bind.Subdomain, reply.Data)
		}
		e, _ := proto.Decode[proto.BindErr](reply)
		if e.Code != proto.CodeInvalidAccess || strings.Contains(e.Message, distinctive) || strings.Contains(string(reply.Data), distinctive) {
			t.Fatalf("bind %s error = %+v", bind.Subdomain, e)
		}
	}
	for _, event := range s.events.snapshot() {
		if strings.Contains(event.Message, distinctive) {
			t.Fatalf("event %+v exposes the webhook secret", event)
		}
		for k, v := range event.Fields {
			if strings.Contains(k+v, distinctive) {
				t.Fatalf("event %+v exposes the webhook secret", event)
			}
		}
	}
	if strings.Contains(logs.String(), distinctive) {
		t.Fatalf("logs expose the webhook secret: %s", logs.String())
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestHandleBindRejectsWebhookWithHTTP2(t *testing.T) {
	s := newTestServer("tok")
	reply := bindOverControl(t, s, proto.Bind{Kind: proto.KindHTTP, Subdomain: "h2hook", HTTP2: true, Webhook: &proto.WebhookVerification{Provider: "github", Secret: testWebhookSecret}})
	if reply.Type != proto.TypeBindErr {
		t.Fatalf("http2 bind with webhook accepted: %s", reply.Data)
	}
	e, _ := proto.Decode[proto.BindErr](reply)
	if e.Code != proto.CodeInvalidAccess || !strings.Contains(e.Message, "HTTP/2") {
		t.Fatalf("error = %+v", e)
	}
	if _, ok := s.registry.Route("h2hook.example.com"); ok {
		t.Fatal("rejected bind left a binding behind")
	}
}

func TestHandleBindRejectsWebhookWithVisitorLogin(t *testing.T) {
	s := newVisitorTestServer(t, newFakeVisitorIdP(t))
	reply := bindOverControl(t, s, proto.Bind{Kind: proto.KindHTTP, Subdomain: "oidchook", OIDC: &proto.OIDCLogin{AllowEmails: []string{"alice@example.com"}}, Webhook: &proto.WebhookVerification{Provider: "github", Secret: testWebhookSecret}})
	if reply.Type != proto.TypeBindErr {
		t.Fatalf("visitor-login bind with webhook accepted: %s", reply.Data)
	}
	e, _ := proto.Decode[proto.BindErr](reply)
	if e.Code != proto.CodeInvalidAccess || !strings.Contains(e.Message, "visitor login") {
		t.Fatalf("error = %+v", e)
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
