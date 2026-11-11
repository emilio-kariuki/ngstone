package edge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"ngstone/internal/adminapi"
	"ngstone/internal/credentials"
	"ngstone/internal/oidc"
	"ngstone/internal/policy"
	"ngstone/internal/proto"
	"ngstone/internal/storage"
)

func TestAdminOwnerIDUsesReservedGlobalScope(t *testing.T) {
	adminRequest := httptest.NewRequest(http.MethodGet, "/api/v1/credentials", nil)
	adminRequest = adminRequest.WithContext(withAdminAuth(context.Background(), adminAuth{Principal: oidc.Principal{Subject: "admin", Role: oidc.RoleAdmin}}))
	if got := adminOwnerID(adminRequest); got != credentials.GlobalOwnerID {
		t.Fatalf("admin owner id = %q, want reserved global scope", got)
	}

	operatorRequest := httptest.NewRequest(http.MethodGet, "/api/v1/credentials", nil)
	operatorRequest = operatorRequest.WithContext(withAdminAuth(context.Background(), adminAuth{Principal: oidc.Principal{Subject: "admin", Role: oidc.RoleOperator}}))
	if got := adminOwnerID(operatorRequest); got != "admin" {
		t.Fatalf("operator owner id = %q, want provider subject", got)
	}

	if got := adminOwnerID(httptest.NewRequest(http.MethodGet, "/api/v1/credentials", nil)); got != credentials.InvalidOwnerID {
		t.Fatalf("missing-auth owner id = %q, want invalid scope", got)
	}
}

func TestAdminAPICredentialLifecycle(t *testing.T) {
	store, err := credentials.Open(t.TempDir() + "/credentials.json")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s := newTestServer("")
	s.cfg.AdminTokenSHA256 = nil
	s.credentialStore = store
	s.events = newEventRing(20)

	statusResponse := adminRequest(t, s, http.MethodGet, "/api/v1/status", nil, "127.0.0.1:4041", "")
	if statusResponse.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200; body=%s", statusResponse.Code, statusResponse.Body.String())
	}
	var statusEnvelope struct {
		Data adminapi.Status `json:"data"`
	}
	if err := json.Unmarshal(statusResponse.Body.Bytes(), &statusEnvelope); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if statusEnvelope.Data.Domain != "example.com" {
		t.Fatalf("status domain = %q, want example.com", statusEnvelope.Data.Domain)
	}

	issueResponse := adminRequest(t, s, http.MethodPost, "/api/v1/credentials", []byte(`{"subdomain":"demo","ttl":"1h"}`), "127.0.0.1:4041", "")
	if issueResponse.Code != http.StatusCreated {
		t.Fatalf("issue code = %d, want 201; body=%s", issueResponse.Code, issueResponse.Body.String())
	}
	var issueEnvelope struct {
		Data adminapi.CredentialIssueResponse `json:"data"`
	}
	if err := json.Unmarshal(issueResponse.Body.Bytes(), &issueEnvelope); err != nil {
		t.Fatalf("decode issue: %v", err)
	}
	if issueEnvelope.Data.Credential.ID == "" || issueEnvelope.Data.Token == "" {
		t.Fatalf("issue response = %+v, want credential and one-time token", issueEnvelope.Data)
	}

	listResponse := adminRequest(t, s, http.MethodGet, "/api/v1/credentials", nil, "127.0.0.1:4041", "")
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list code = %d, want 200", listResponse.Code)
	}
	if bytes.Contains(listResponse.Body.Bytes(), []byte(issueEnvelope.Data.Token)) {
		t.Fatal("list response exposed the plaintext credential token")
	}

	revokeResponse := adminRequest(t, s, http.MethodDelete, "/api/v1/credentials/"+issueEnvelope.Data.Credential.ID, nil, "127.0.0.1:4041", "")
	if revokeResponse.Code != http.StatusNoContent {
		t.Fatalf("revoke code = %d, want 204; body=%s", revokeResponse.Code, revokeResponse.Body.String())
	}
	credential, err := store.Validate(issueEnvelope.Data.Token, time.Now())
	if credential.ID != "" || err != credentials.ErrRevoked {
		t.Fatalf("revoked token validation = %q, %v, want empty credential and ErrRevoked", credential.ID, err)
	}
}

func TestAdminAPIDurablePoliciesAndDomains(t *testing.T) {
	store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db"), EdgeID: "edge-test"})
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()
	s := newTestServer("")
	s.cfg.AdminTokenSHA256 = nil
	s.storage = store
	s.credentialStore = store

	policyResponse := adminRequest(t, s, http.MethodPost, "/api/v1/policies", []byte(`{"name":"web","policy":{"default_action":"deny","rules":[{"action":"allow","path_prefix":"/health"}]}}`), "127.0.0.1:4041", "")
	if policyResponse.Code != http.StatusCreated {
		t.Fatalf("policy code = %d, want 201; body=%s", policyResponse.Code, policyResponse.Body.String())
	}
	var policyEnvelope struct {
		Data adminapi.TrafficPolicy `json:"data"`
	}
	if err := json.Unmarshal(policyResponse.Body.Bytes(), &policyEnvelope); err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	if policyEnvelope.Data.ID == "" || policyEnvelope.Data.Digest == "" {
		t.Fatalf("policy response = %+v", policyEnvelope.Data)
	}

	domainResponse := adminRequest(t, s, http.MethodPost, "/api/v1/domains", []byte(`{"domain":"demo.example.org"}`), "127.0.0.1:4041", "")
	if domainResponse.Code != http.StatusCreated {
		t.Fatalf("domain code = %d, want 201; body=%s", domainResponse.Code, domainResponse.Body.String())
	}
	var domainEnvelope struct {
		Data adminapi.CustomDomain `json:"data"`
	}
	if err := json.Unmarshal(domainResponse.Body.Bytes(), &domainEnvelope); err != nil {
		t.Fatalf("decode domain: %v", err)
	}
	if domainEnvelope.Data.ID == "" || domainEnvelope.Data.Status != "pending" {
		t.Fatalf("domain response = %+v", domainEnvelope.Data)
	}

	listResponse := adminRequest(t, s, http.MethodGet, "/api/v1/domains", nil, "127.0.0.1:4041", "")
	if listResponse.Code != http.StatusOK || !bytes.Contains(listResponse.Body.Bytes(), []byte("demo.example.org")) {
		t.Fatalf("domain list code/body = %d/%s", listResponse.Code, listResponse.Body.String())
	}
}

func TestAdminAPIObservability(t *testing.T) {
	s := newTestServer("")
	s.observability = newObservabilityRegistry()
	s.observability.observeRequest("tunnel-1", "demo.example.com", http.StatusCreated, 20*time.Millisecond, 12, 34)
	response := adminRequest(t, s, http.MethodGet, "/api/v1/observability/tunnels", nil, "127.0.0.1:4041", "")
	if response.Code != http.StatusOK {
		t.Fatalf("observability code = %d, want 200; body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Data []adminapi.TunnelObservability `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode observability: %v", err)
	}
	if len(envelope.Data) != 1 || envelope.Data[0].RequestCount != 1 || envelope.Data[0].StatusCodes["201"] != 1 || envelope.Data[0].BytesTransferred != 46 {
		t.Fatalf("observability data = %+v", envelope.Data)
	}
}

func TestAdminAPIRequiresLoopbackOrBearerToken(t *testing.T) {
	s := newTestServer("")
	s.events = newEventRing(20)

	remote := adminRequest(t, s, http.MethodGet, "/api/v1/status", nil, "203.0.113.20:4041", "")
	if remote.Code != http.StatusForbidden {
		t.Fatalf("remote request code = %d, want 403", remote.Code)
	}

	sum := sha256.Sum256([]byte("admin-secret"))
	s.cfg.AdminTokenSHA256 = sum[:]
	missing := adminRequest(t, s, http.MethodGet, "/api/v1/status", nil, "127.0.0.1:4041", "")
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer code = %d, want 401", missing.Code)
	}
	valid := adminRequest(t, s, http.MethodGet, "/api/v1/status", nil, "203.0.113.20:4041", "Bearer admin-secret")
	if valid.Code != http.StatusOK {
		t.Fatalf("valid bearer code = %d, want 200; body=%s", valid.Code, valid.Body.String())
	}
}

func TestAdminAPIRejectsRepeatedInvalidBearerAttempts(t *testing.T) {
	s := newTestServer("")
	sum := sha256.Sum256([]byte("admin-secret"))
	s.cfg.AdminTokenSHA256 = sum[:]
	for attempt := 0; attempt < maxAuthFailuresPerMinute; attempt++ {
		response := adminRequest(t, s, http.MethodGet, "/api/v1/status", nil, "203.0.113.21:4041", "Bearer wrong")
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d code = %d, want 401", attempt+1, response.Code)
		}
	}
	response := adminRequest(t, s, http.MethodGet, "/api/v1/status", nil, "203.0.113.21:4041", "Bearer wrong")
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited code = %d, want 429", response.Code)
	}
}

func TestAdminTunnelDrainReleasesBinding(t *testing.T) {
	client, server, cleanup := newRawSessionPair(t)
	defer cleanup()
	s := newTestServer("")
	s.events = newEventRing(20)
	as := &AgentSession{ID: "admin-session", InstanceID: "admin-agent", Sess: server, IDGen: proto.NewEdgeIDGen()}
	if _, _, err := s.registry.Bind("demo.example.com", as, true, nil); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	response := adminRequest(t, s, http.MethodPost, "/api/v1/tunnels/demo/drain", nil, "127.0.0.1:4041", "")
	if response.Code != http.StatusAccepted {
		t.Fatalf("drain code = %d, want 202; body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Data adminapi.DrainResponse `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode drain: %v", err)
	}
	if envelope.Data.Hostname != "demo.example.com" || envelope.Data.Connectors != 1 {
		t.Fatalf("drain response = %+v", envelope.Data)
	}

	if err := client.Control().SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	message, err := client.Control().Read()
	if err != nil {
		t.Fatalf("read goodbye: %v", err)
	}
	if message.Type != proto.TypeGoodbye {
		t.Fatalf("drain message type = %q, want goodbye", message.Type)
	}
	for attempt := 0; attempt < 20; attempt++ {
		if _, ok := s.registry.Route("demo.example.com"); !ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("drained tunnel remained routable")
}

func TestAdminTunnelHostValidation(t *testing.T) {
	s := newTestServer("")
	tests := map[string]string{
		"demo":                 "demo.example.com",
		"demo.example.com:443": "demo.example.com",
		"example.com":          "example.com",
	}
	for input, want := range tests {
		got, err := s.adminTunnelHost(input)
		if err != nil {
			t.Fatalf("adminTunnelHost(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("adminTunnelHost(%q) = %q, want %q", input, got, want)
		}
	}
	for _, input := range []string{"www", "foo.bar", "bad..example.com", "../demo"} {
		if _, err := s.adminTunnelHost(input); err == nil {
			t.Fatalf("adminTunnelHost(%q) succeeded, want validation error", input)
		}
	}
}

func adminRequest(t *testing.T, s *Server, method, path string, body []byte, remote, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.RemoteAddr = remote
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	s.opsMux().ServeHTTP(recorder, req)
	return recorder
}

func TestAdminAPITrafficPolicyActionsRoundTrip(t *testing.T) {
	store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db"), EdgeID: "edge-test"})
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()
	s := newTestServer("")
	s.cfg.AdminTokenSHA256 = nil
	s.storage = store
	s.credentialStore = store

	body := []byte(`{"name":"actions","policy":{"rules":[
  {"action":"redirect","path_prefix":"/old","redirect_url":"/new$path","redirect_status":308},
  {"action":"transform","request_headers":{"set":{"x-env":"prod"},"remove":["x-debug"]},"response_headers":{"add":{"x-edge":"1"}}}
],"cors":{"allowed_origins":["https://app.example"],"allowed_methods":["GET"],"allow_credentials":true,"max_age":60}}}`)
	created := adminRequest(t, s, http.MethodPost, "/api/v1/policies", body, "127.0.0.1:4041", "")
	if created.Code != http.StatusCreated {
		t.Fatalf("create code = %d; body=%s", created.Code, created.Body.String())
	}
	var createdEnvelope struct {
		Data adminapi.TrafficPolicy `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdEnvelope); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	listed := adminRequest(t, s, http.MethodGet, "/api/v1/policies", nil, "127.0.0.1:4041", "")
	if listed.Code != http.StatusOK {
		t.Fatalf("list code = %d; body=%s", listed.Code, listed.Body.String())
	}
	var listEnvelope struct {
		Data []adminapi.TrafficPolicy `json:"data"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &listEnvelope); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listEnvelope.Data) != 1 {
		t.Fatalf("listed %d policies, want 1", len(listEnvelope.Data))
	}
	saved := listEnvelope.Data[0]
	parsed, err := policy.Parse(saved.Policy)
	if err != nil {
		t.Fatalf("stored policy does not parse: %v; policy=%s", err, saved.Policy)
	}
	if parsed.Digest() != saved.Digest || saved.Digest != createdEnvelope.Data.Digest {
		t.Fatalf("digest mismatch: parsed=%s saved=%s created=%s", parsed.Digest(), saved.Digest, createdEnvelope.Data.Digest)
	}
	if parsed.CORS == nil || !parsed.CORS.AllowCredentials || parsed.CORS.MaxAge != 60 || len(parsed.Rules) != 2 {
		t.Fatalf("stored policy lost fields: %s", saved.Policy)
	}
	if parsed.Rules[0].RedirectURL != "/new$path" || parsed.Rules[0].RedirectStatus != 308 {
		t.Fatalf("stored redirect = %+v", parsed.Rules[0])
	}
	if parsed.Rules[1].RequestHeaders == nil || parsed.Rules[1].RequestHeaders.Set["X-Env"] != "prod" || parsed.Rules[1].ResponseHeaders == nil || parsed.Rules[1].ResponseHeaders.Add["X-Edge"] != "1" {
		t.Fatalf("stored transform = %s", saved.Policy)
	}

	rejected := adminRequest(t, s, http.MethodPost, "/api/v1/policies", []byte(`{"name":"bad","policy":{"rules":[{"action":"transform","request_headers":{"set":{"X-Forwarded-For":"1.1.1.1"}}}]}}`), "127.0.0.1:4041", "")
	if rejected.Code != http.StatusUnprocessableEntity {
		t.Fatalf("reserved header policy code = %d, want 422", rejected.Code)
	}
}
