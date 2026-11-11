package edge

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ngstone/internal/oidc"
	"ngstone/internal/policy"
	"ngstone/internal/proto"
	"ngstone/internal/webhook"
	"ngstone/internal/webhook/webhooktest"
)

func TestHandleBindTLSRejectsOIDCAndWebhook(t *testing.T) {
	client, server, cleanup := newRawSessionPair(t)
	defer cleanup()
	s := newTestServer("tok")
	as := &AgentSession{ID: "tls-sess", InstanceID: "tls-inst", Sess: server, IDGen: proto.NewEdgeIDGen(), NegotiatedVersion: proto.ProtoVersion}
	for name, bind := range map[string]proto.Bind{
		"oidc":    {Kind: proto.KindTLS, Subdomain: "oidc", OIDC: &proto.OIDCLogin{AllowEmails: []string{"a@example.com"}}},
		"webhook": {Kind: proto.KindTLS, Subdomain: "hook", Webhook: &proto.WebhookVerification{Provider: "github", Secret: testWebhookSecret}},
	} {
		reply := bindOverWire(t, s, as, client, server, bind)
		e, _ := proto.Decode[proto.BindErr](reply)
		if reply.Type != proto.TypeBindErr || e.Code != proto.CodeInvalidAccess || !strings.Contains(e.Message, "not supported for tls tunnels") {
			t.Fatalf("%s: reply = %s %s", name, reply.Type, reply.Data)
		}
		if _, ok := s.registry.RouteTLS(bind.Subdomain + ".example.com"); ok {
			t.Fatalf("%s: rejected tls bind left a binding behind", name)
		}
	}
}

func TestHandleBindRejectsOIDCBelowProtocolV2(t *testing.T) {
	s := newVisitorTestServer(t, newFakeVisitorIdP(t))
	as := newFakeAgentSession(t, "bind-oidc-v1", func(w http.ResponseWriter, r *http.Request) {})
	as.NegotiatedVersion = 1
	reply := bindSessionOverControl(t, s, as, proto.Bind{Kind: proto.KindHTTP, Subdomain: "v1oidc", OIDC: &proto.OIDCLogin{AllowEmails: []string{"alice@example.com"}}})
	e, _ := proto.Decode[proto.BindErr](reply)
	if reply.Type != proto.TypeBindErr || e.Code != proto.CodeInvalidAccess || !strings.Contains(e.Message, "require protocol v2") {
		t.Fatalf("reply = %s %s", reply.Type, reply.Data)
	}
	if _, ok := s.registry.Route("v1oidc.example.com"); ok {
		t.Fatal("rejected bind left a binding behind")
	}
}

func bindRandomHostname(t *testing.T, s *Server, bind proto.Bind) string {
	t.Helper()
	as := newFakeAgentSession(t, "bind-random", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, "ok")
	})
	as.NegotiatedVersion = proto.ProtoVersion
	reply := bindSessionOverControl(t, s, as, bind)
	if reply.Type != proto.TypeBindOK {
		t.Fatalf("reply = %s %s", reply.Type, reply.Data)
	}
	ok, err := proto.Decode[proto.BindOK](reply)
	if err != nil || ok.Hostname == "" || !strings.HasSuffix(ok.Hostname, ".example.com") {
		t.Fatalf("BindOK = %+v err=%v", ok, err)
	}
	return ok.Hostname
}

func publicRequest(s *Server, method, host, path string, headers map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
	req.Host = host
	req.RemoteAddr = "203.0.113.7:4444"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.handlePublic(rec, req)
	return rec
}

func TestRandomHostnameBindKeepsWebhookVerification(t *testing.T) {
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	host := bindRandomHostname(t, s, proto.Bind{Kind: proto.KindHTTP, Webhook: &proto.WebhookVerification{Provider: "github", Secret: testWebhookSecret}})
	body := `{"zen":"x"}`
	if rec := publicRequest(s, http.MethodPost, host, "/", nil, body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned request status = %d body=%q", rec.Code, rec.Body.String())
	}
	signed := map[string]string{webhook.GitHubSignatureHeader: webhooktest.GitHubSignature(testWebhookSecret, []byte(body))}
	if rec := publicRequest(s, http.MethodPost, host, "/", signed, body); rec.Code != http.StatusOK {
		t.Fatalf("signed request status = %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestRandomHostnameBindKeepsTrafficPolicy(t *testing.T) {
	p, err := policy.Parse([]byte(`{"rules":[{"action":"deny","path_prefix":"/admin"}]}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	host := bindRandomHostname(t, s, proto.Bind{Kind: proto.KindHTTP, Policy: p, PolicyDigest: p.Digest()})
	if rec := publicRequest(s, http.MethodGet, host, "/admin/users", nil, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("denied path status = %d body=%q", rec.Code, rec.Body.String())
	}
	if rec := publicRequest(s, http.MethodGet, host, "/home", nil, ""); rec.Code != http.StatusOK {
		t.Fatalf("allowed path status = %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestRandomHostnameBindKeepsBasicAuth(t *testing.T) {
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	host := bindRandomHostname(t, s, proto.Bind{Kind: proto.KindHTTP, BasicAuthSHA256: []string{digestFor("u", "p")}})
	if rec := publicRequest(s, http.MethodGet, host, "/", nil, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous request status = %d body=%q", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	req.Host = host
	req.RemoteAddr = "203.0.113.7:4444"
	req.SetBasicAuth("u", "p")
	rec := httptest.NewRecorder()
	s.handlePublic(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated request status = %d body=%q", rec.Code, rec.Body.String())
	}
}

func newLoginHostTestServer(t *testing.T) *Server {
	t.Helper()
	idp := newFakeVisitorIdP(t)
	s := newTestServer("tok")
	v, err := newVisitorLogin(Config{
		Domain:       "example.com",
		PublicScheme: "https",
		VisitorOIDC: &oidc.Config{
			Issuer:        idp.server.URL,
			ClientID:      "visitor-client",
			ClientSecret:  "visitor-secret",
			CookieSecret:  []byte(strings.Repeat("v", 32)),
			RedirectURL:   "https://login.example.com/.ngstone/auth/callback",
			AllowInsecure: true,
		},
	})
	if err != nil {
		t.Fatalf("newVisitorLogin: %v", err)
	}
	s.visitor = v
	return s
}

func TestHandleBindReservesVisitorLoginHostname(t *testing.T) {
	for _, kind := range []string{proto.KindTLS, proto.KindHTTP} {
		t.Run(kind, func(t *testing.T) {
			client, server, cleanup := newRawSessionPair(t)
			defer cleanup()
			s := newLoginHostTestServer(t)
			as := &AgentSession{ID: "login-sess", InstanceID: "login-inst", Sess: server, IDGen: proto.NewEdgeIDGen(), NegotiatedVersion: proto.ProtoVersion}

			reply := bindOverWire(t, s, as, client, server, proto.Bind{Kind: kind, Subdomain: "login"})
			e, _ := proto.Decode[proto.BindErr](reply)
			if reply.Type != proto.TypeBindErr || e.Code != proto.CodeInvalidSubdomain || !strings.Contains(e.Message, "reserved") {
				t.Fatalf("reply = %s %s", reply.Type, reply.Data)
			}
			if _, ok := s.registry.RouteTLS("login.example.com"); ok {
				t.Fatal("reserved tls bind left a binding behind")
			}
			if _, ok := s.registry.Route("login.example.com"); ok {
				t.Fatal("reserved http bind left a binding behind")
			}

			reply = bindOverWire(t, s, as, client, server, proto.Bind{Kind: kind, Subdomain: "other"})
			if reply.Type != proto.TypeBindOK {
				t.Fatalf("other subdomain reply = %s %s", reply.Type, reply.Data)
			}
		})
	}
}

func TestHandleBindRandomNameSkipsVisitorLoginHostname(t *testing.T) {
	for _, kind := range []string{proto.KindTLS, proto.KindHTTP} {
		t.Run(kind, func(t *testing.T) {
			client, server, cleanup := newRawSessionPair(t)
			defer cleanup()
			s := newLoginHostTestServer(t)
			names := []string{"login", "open"}
			i := 0
			s.randomName = func() string {
				n := names[i]
				if i < len(names)-1 {
					i++
				}
				return n
			}
			as := &AgentSession{ID: "login-sess", InstanceID: "login-inst", Sess: server, IDGen: proto.NewEdgeIDGen(), NegotiatedVersion: proto.ProtoVersion}
			reply := bindOverWire(t, s, as, client, server, proto.Bind{Kind: kind})
			ok, _ := proto.Decode[proto.BindOK](reply)
			if reply.Type != proto.TypeBindOK || ok.Hostname != "open.example.com" {
				t.Fatalf("reply = %s %s", reply.Type, reply.Data)
			}
		})
	}
}

func TestHandleBindAllowsLoginSubdomainWithoutVisitorLogin(t *testing.T) {
	for _, kind := range []string{proto.KindTLS, proto.KindHTTP} {
		t.Run(kind, func(t *testing.T) {
			client, server, cleanup := newRawSessionPair(t)
			defer cleanup()
			s := newTestServer("tok")
			as := &AgentSession{ID: "login-sess", InstanceID: "login-inst", Sess: server, IDGen: proto.NewEdgeIDGen(), NegotiatedVersion: proto.ProtoVersion}
			reply := bindOverWire(t, s, as, client, server, proto.Bind{Kind: kind, Subdomain: "login"})
			if reply.Type != proto.TypeBindOK {
				t.Fatalf("reply = %s %s", reply.Type, reply.Data)
			}
		})
	}
}
