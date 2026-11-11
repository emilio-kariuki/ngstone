package edge

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"ngstone/internal/oidc"
	"ngstone/internal/policy"
	"ngstone/internal/proto"
)

type fakeVisitorIdP struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey

	mu       sync.Mutex
	email    string
	verified bool
	codes    map[string]fakeVisitorGrant
}

type fakeVisitorGrant struct {
	nonce    string
	email    string
	verified bool
}

func newFakeVisitorIdP(t *testing.T) *fakeVisitorIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	idp := &fakeVisitorIdP{t: t, key: key, verified: true, email: "alice@example.org", codes: map[string]fakeVisitorGrant{}}
	idp.server = httptest.NewServer(http.HandlerFunc(idp.serve))
	t.Cleanup(idp.server.Close)
	return idp
}

func (idp *fakeVisitorIdP) setUser(email string, verified bool) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.email = email
	idp.verified = verified
}

func (idp *fakeVisitorIdP) serve(w http.ResponseWriter, r *http.Request) {
	issuer := idp.server.URL
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		json.NewEncoder(w).Encode(oidc.Metadata{
			Issuer:           issuer,
			AuthorizationURL: issuer + "/authorize",
			TokenURL:         issuer + "/token",
			UserInfoURL:      issuer + "/userinfo",
			JWKSURL:          issuer + "/jwks",
		})
	case "/authorize":
		query := r.URL.Query()
		code := randomHex(8)
		idp.mu.Lock()
		idp.codes[code] = fakeVisitorGrant{nonce: query.Get("nonce"), email: idp.email, verified: idp.verified}
		idp.mu.Unlock()
		target, _ := url.Parse(query.Get("redirect_uri"))
		target.RawQuery = url.Values{"code": {code}, "state": {query.Get("state")}}.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
	case "/token":
		r.ParseForm()
		code := r.PostForm.Get("code")
		idp.mu.Lock()
		grant, ok := idp.codes[code]
		idp.mu.Unlock()
		if !ok {
			http.Error(w, "bad code", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"access_token": "at-" + code, "token_type": "Bearer", "id_token": idp.idToken(grant)})
	case "/jwks":
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": "visitor-key", "kty": "RSA", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(idp.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		}}})
	case "/userinfo":
		code := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer at-")
		idp.mu.Lock()
		grant, ok := idp.codes[code]
		idp.mu.Unlock()
		if !ok {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"sub": "sub-" + grant.email, "email": grant.email, "email_verified": grant.verified, "name": "Visitor\r\nInjected"})
	default:
		http.NotFound(w, r)
	}
}

func (idp *fakeVisitorIdP) idToken(grant fakeVisitorGrant) string {
	encode := func(value any) string {
		data, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(data)
	}
	header := encode(map[string]string{"alg": "RS256", "kid": "visitor-key", "typ": "JWT"})
	claims := encode(map[string]any{"iss": idp.server.URL, "sub": "sub-" + grant.email, "aud": "visitor-client", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": grant.nonce})
	digest := sha256.Sum256([]byte(header + "." + claims))
	signature, err := rsa.SignPKCS1v15(rand.Reader, idp.key, crypto.SHA256, digest[:])
	if err != nil {
		idp.t.Fatalf("sign: %v", err)
	}
	return header + "." + claims + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func newVisitorTestServer(t *testing.T, idp *fakeVisitorIdP) *Server {
	t.Helper()
	s, err := New(Config{
		ControlAddr:  "127.0.0.1:0",
		PublicAddr:   "127.0.0.1:0",
		Domain:       "example.com",
		TokenSHA256:  sumToken("tok"),
		PublicScheme: "http",
		Insecure:     true,
		Limits:       LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000},
		VisitorOIDC: &oidc.Config{
			Issuer:        idp.server.URL,
			ClientID:      "visitor-client",
			ClientSecret:  "visitor-secret",
			CookieSecret:  []byte(strings.Repeat("v", 32)),
			AllowInsecure: true,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func newVisitorTCPTestServer(t *testing.T, idp *fakeVisitorIdP) *Server {
	t.Helper()
	s, err := New(Config{
		Domain:       "example.com",
		TokenSHA256:  sumToken("tok"),
		PublicScheme: "http",
		Insecure:     true,
		TCPPortRange: "47100-47110",
		TCPBindAddr:  "127.0.0.1",
		VisitorOIDC: &oidc.Config{
			Issuer:        idp.server.URL,
			ClientID:      "visitor-client",
			CookieSecret:  []byte(strings.Repeat("v", 32)),
			AllowInsecure: true,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

type capturedRequest struct {
	mu     sync.Mutex
	header http.Header
	hits   int
}

func (c *capturedRequest) last() (http.Header, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.header, c.hits
}

func bindVisitorTunnel(t *testing.T, s *Server, host string, bind proto.Bind) *capturedRequest {
	t.Helper()
	captured := &capturedRequest{}
	as := newFakeAgentSession(t, "visitor-"+host, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		captured.mu.Lock()
		captured.header = r.Header.Clone()
		captured.hits++
		captured.mu.Unlock()
		io.WriteString(w, "origin-ok")
	})
	ac, err := buildAccessControl(bind)
	if err != nil {
		t.Fatalf("buildAccessControl: %v", err)
	}
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: host, Session: as, Takeover: true, Access: ac}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	return captured
}

func visitorRequest(t *testing.T, s *Server, method, rawURL string, header http.Header, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, rawURL, nil)
	req.RemoteAddr = "9.9.9.9:4000"
	for name, values := range header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	s.handlePublic(rec, req)
	return rec
}

func htmlAccept() http.Header {
	return http.Header{"Accept": {"text/html,application/xhtml+xml"}}
}

func visitorLoginFlow(t *testing.T, s *Server, idp *fakeVisitorIdP, tunnelURL string) (*httptest.ResponseRecorder, *http.Cookie) {
	t.Helper()
	first := visitorRequest(t, s, http.MethodGet, tunnelURL, htmlAccept())
	if first.Code != http.StatusFound {
		t.Fatalf("unauthenticated browser status = %d, want 302; body=%s", first.Code, first.Body.String())
	}
	start, err := url.Parse(first.Header().Get("Location"))
	if err != nil || start.Host != "example.com" || start.Path != visitorStartPath {
		t.Fatalf("login redirect = %q, want apex start URL", first.Header().Get("Location"))
	}
	startRec := visitorRequest(t, s, http.MethodGet, start.String(), htmlAccept())
	if startRec.Code != http.StatusFound {
		t.Fatalf("start status = %d, body=%s", startRec.Code, startRec.Body.String())
	}
	var stateCookie *http.Cookie
	for _, cookie := range startRec.Result().Cookies() {
		if strings.HasPrefix(cookie.Name, visitorStateCookiePrefix) {
			stateCookie = cookie
		}
	}
	if stateCookie == nil || stateCookie.Path != visitorDefaultCallback || !stateCookie.HttpOnly {
		t.Fatalf("start state cookie = %+v", stateCookie)
	}
	authorize, err := http.NewRequest(http.MethodGet, startRec.Header().Get("Location"), nil)
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authorizeResp, err := client.Do(authorize)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	authorizeResp.Body.Close()
	callbackURL := authorizeResp.Header.Get("Location")
	if !strings.HasPrefix(callbackURL, "http://example.com"+visitorDefaultCallback+"?") {
		t.Fatalf("IdP redirect = %q, want apex callback", callbackURL)
	}
	callback := visitorRequest(t, s, http.MethodGet, callbackURL, htmlAccept(), stateCookie)
	if callback.Code != http.StatusFound {
		return callback, nil
	}
	finishURL, err := url.Parse(callback.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse finish URL: %v", err)
	}
	tunnel, _ := url.Parse(tunnelURL)
	if finishURL.Host != tunnel.Host || finishURL.Path != visitorFinishPath {
		t.Fatalf("callback redirect = %q, want finish on %s", finishURL, tunnel.Host)
	}
	finish := visitorRequest(t, s, http.MethodGet, finishURL.String(), htmlAccept())
	return finish, responseCookie(finish.Result(), visitorSessionCookie)
}

func TestVisitorLoginRedirectsBrowsersAndRejectsAPIClients(t *testing.T) {
	idp := newFakeVisitorIdP(t)
	s := newVisitorTestServer(t, idp)
	captured := bindVisitorTunnel(t, s, "app.example.com", proto.Bind{OIDC: &proto.OIDCLogin{}})

	api := visitorRequest(t, s, http.MethodGet, "http://app.example.com/api", http.Header{"Accept": {"application/json"}})
	if api.Code != http.StatusUnauthorized {
		t.Fatalf("API client status = %d, want 401", api.Code)
	}
	post := visitorRequest(t, s, http.MethodPost, "http://app.example.com/form", htmlAccept())
	if post.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated POST status = %d, want 401", post.Code)
	}
	browser := visitorRequest(t, s, http.MethodGet, "http://app.example.com/dashboard?tab=1", htmlAccept())
	if browser.Code != http.StatusFound {
		t.Fatalf("browser status = %d, want 302", browser.Code)
	}
	location, _ := url.Parse(browser.Header().Get("Location"))
	if location.Scheme != "http" || location.Host != "example.com" || location.Path != visitorStartPath || location.Query().Get("return") == "" {
		t.Fatalf("redirect = %q", location)
	}
	if strings.Contains(location.RawQuery, "dashboard") {
		t.Fatalf("return target must be sealed, got %q", location.RawQuery)
	}
	if _, hits := captured.last(); hits != 0 {
		t.Fatalf("origin was reached %d times without a session", hits)
	}
}

func TestVisitorLoginFlowForwardsIdentityAndStripsCookie(t *testing.T) {
	idp := newFakeVisitorIdP(t)
	s := newVisitorTestServer(t, idp)
	captured := bindVisitorTunnel(t, s, "app.example.com", proto.Bind{OIDC: &proto.OIDCLogin{AllowDomains: []string{"example.org"}}})

	finish, session := visitorLoginFlow(t, s, idp, "http://app.example.com/dashboard?tab=1")
	if finish.Code != http.StatusFound || finish.Header().Get("Location") != "/dashboard?tab=1" {
		t.Fatalf("finish = %d %q", finish.Code, finish.Header().Get("Location"))
	}
	if session == nil || !session.HttpOnly || session.Path != "/" || session.Domain != "" || session.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie = %+v, want host-only HttpOnly Lax cookie", session)
	}

	header := http.Header{
		"Accept":                 {"application/json"},
		"X-Ngstone-User-Email":   {"mallory@evil.test"},
		"X-Ngstone-User-Groups":  {"admins"},
		"x-ngstone-user-subject": {"spoofed"},
	}
	ok := visitorRequest(t, s, http.MethodGet, "http://app.example.com/api", header, &http.Cookie{Name: "app", Value: "keep"}, session)
	if ok.Code != http.StatusOK || ok.Body.String() != "origin-ok" {
		t.Fatalf("authenticated status = %d body=%q", ok.Code, ok.Body.String())
	}
	got, _ := captured.last()
	if got.Get(VisitorEmailHeader) != "alice@example.org" || got.Get(VisitorSubjectHeader) != "sub-alice@example.org" {
		t.Fatalf("identity headers = %v", got)
	}
	if got.Get(VisitorNameHeader) != "VisitorInjected" {
		t.Fatalf("name header = %q, want control characters removed", got.Get(VisitorNameHeader))
	}
	if values := got.Values("X-Ngstone-User-Groups"); len(values) != 0 {
		t.Fatalf("spoofed identity header forwarded: %v", values)
	}
	if values := got.Values(VisitorEmailHeader); len(values) != 1 {
		t.Fatalf("email header values = %v, want exactly one", values)
	}
	cookie := got.Get("Cookie")
	if strings.Contains(cookie, visitorSessionCookie) || !strings.Contains(cookie, "app=keep") {
		t.Fatalf("forwarded Cookie = %q, want session stripped and app cookie kept", cookie)
	}

	replay := visitorRequest(t, s, http.MethodGet, "http://app.example.com"+visitorFinishPath+"?"+url.Values{"ticket": {"bogus"}}.Encode(), htmlAccept())
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("bogus ticket status = %d, want 400", replay.Code)
	}

	logout := visitorRequest(t, s, http.MethodGet, "http://app.example.com"+visitorLogoutPath, htmlAccept(), session)
	cleared := false
	for _, cookie := range logout.Result().Cookies() {
		if cookie.Name == visitorSessionCookie && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if logout.Code != http.StatusOK || !cleared {
		t.Fatalf("logout = %d, cleared=%v", logout.Code, cleared)
	}
}

func TestVisitorLoginDeniesEmailsOutsideAllowList(t *testing.T) {
	idp := newFakeVisitorIdP(t)
	s := newVisitorTestServer(t, idp)
	captured := bindVisitorTunnel(t, s, "app.example.com", proto.Bind{OIDC: &proto.OIDCLogin{AllowEmails: []string{"Bob@Example.org"}}})

	idp.setUser("alice@example.org", true)
	denied, session := visitorLoginFlow(t, s, idp, "http://app.example.com/")
	if denied.Code != http.StatusForbidden || session != nil {
		t.Fatalf("denied email: status %d session %v", denied.Code, session)
	}

	idp.setUser("bob@example.org", false)
	unverified, session := visitorLoginFlow(t, s, idp, "http://app.example.com/")
	if unverified.Code != http.StatusForbidden || session != nil {
		t.Fatalf("unverified email: status %d session %v", unverified.Code, session)
	}

	idp.setUser("bob@example.org", true)
	allowed, session := visitorLoginFlow(t, s, idp, "http://app.example.com/")
	if allowed.Code != http.StatusFound || session == nil {
		t.Fatalf("allowed email: status %d session %v", allowed.Code, session)
	}
	if _, hits := captured.last(); hits != 0 {
		t.Fatalf("origin reached %d times during login", hits)
	}
}

func TestVisitorSessionIsBoundToTunnelHostAndTicketIsSingleUse(t *testing.T) {
	idp := newFakeVisitorIdP(t)
	s := newVisitorTestServer(t, idp)
	bindVisitorTunnel(t, s, "one.example.com", proto.Bind{OIDC: &proto.OIDCLogin{}})
	other := bindVisitorTunnel(t, s, "two.example.com", proto.Bind{OIDC: &proto.OIDCLogin{}})

	first := visitorRequest(t, s, http.MethodGet, "http://one.example.com/", htmlAccept())
	start := visitorRequest(t, s, http.MethodGet, first.Header().Get("Location"), htmlAccept())
	var stateCookie *http.Cookie
	for _, cookie := range start.Result().Cookies() {
		if strings.HasPrefix(cookie.Name, visitorStateCookiePrefix) {
			stateCookie = cookie
		}
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(start.Header().Get("Location"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	callback := visitorRequest(t, s, http.MethodGet, resp.Header.Get("Location"), htmlAccept(), stateCookie)
	finishURL, _ := url.Parse(callback.Header().Get("Location"))

	crossHost := *finishURL
	crossHost.Host = "two.example.com"
	if rec := visitorRequest(t, s, http.MethodGet, crossHost.String(), htmlAccept()); rec.Code != http.StatusBadRequest {
		t.Fatalf("ticket on another host status = %d, want 400", rec.Code)
	}
	finish := visitorRequest(t, s, http.MethodGet, finishURL.String(), htmlAccept())
	session := responseCookie(finish.Result(), visitorSessionCookie)
	if session == nil {
		t.Fatalf("finish did not set a session: %d %s", finish.Code, finish.Body.String())
	}
	if rec := visitorRequest(t, s, http.MethodGet, finishURL.String(), htmlAccept()); rec.Code != http.StatusBadRequest {
		t.Fatalf("replayed ticket status = %d, want 400", rec.Code)
	}
	if rec := visitorRequest(t, s, http.MethodGet, "http://two.example.com/", http.Header{"Accept": {"*/*"}}, session); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session from another host status = %d, want 401", rec.Code)
	}
	if _, hits := other.last(); hits != 0 {
		t.Fatalf("second tunnel reached with first tunnel's session")
	}
	if rec := visitorRequest(t, s, http.MethodGet, "http://example.com"+visitorDefaultCallback+"?state=forged&code=x", htmlAccept(), stateCookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("forged callback status = %d, want 400", rec.Code)
	}
}

func TestVisitorIdentityHeadersStrippedOnOpenTunnels(t *testing.T) {
	idp := newFakeVisitorIdP(t)
	s := newVisitorTestServer(t, idp)
	captured := bindVisitorTunnel(t, s, "open.example.com", proto.Bind{})
	rec := visitorRequest(t, s, http.MethodGet, "http://open.example.com/", http.Header{"X-Ngstone-User-Email": {"admin@example.org"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	got, _ := captured.last()
	if got.Get(VisitorEmailHeader) != "" {
		t.Fatalf("spoofed identity header reached an open tunnel: %q", got.Get(VisitorEmailHeader))
	}
}

func TestVisitorLoginComposesWithBasicAuth(t *testing.T) {
	idp := newFakeVisitorIdP(t)
	s := newVisitorTestServer(t, idp)
	captured := bindVisitorTunnel(t, s, "both.example.com", proto.Bind{BasicAuthSHA256: []string{digestFor("u", "p")}, OIDC: &proto.OIDCLogin{}})

	noBasic := visitorRequest(t, s, http.MethodGet, "http://both.example.com/", htmlAccept())
	if noBasic.Code != http.StatusUnauthorized || !strings.Contains(noBasic.Header().Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("missing basic auth = %d %q", noBasic.Code, noBasic.Header().Get("WWW-Authenticate"))
	}
	basic := http.Header{"Accept": {"text/html"}, "Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("u:p"))}}
	noLogin := visitorRequest(t, s, http.MethodGet, "http://both.example.com/", basic)
	if noLogin.Code != http.StatusFound {
		t.Fatalf("basic auth without login = %d, want 302", noLogin.Code)
	}
	if _, hits := captured.last(); hits != 0 {
		t.Fatal("origin reached without both checks")
	}
}

func TestVisitorLoginBindValidation(t *testing.T) {
	idp := newFakeVisitorIdP(t)
	cases := []struct {
		name   string
		server *Server
		bind   proto.Bind
		code   string
		ok     bool
	}{
		{name: "tcp", server: newVisitorTCPTestServer(t, idp), bind: proto.Bind{Kind: proto.KindTCP, OIDC: &proto.OIDCLogin{}}, code: proto.CodeInvalidAccess},
		{name: "not configured", server: newServerForTest(LimitsConfig{}), bind: proto.Bind{Kind: proto.KindHTTP, Subdomain: "a", OIDC: &proto.OIDCLogin{}}, code: proto.CodeInvalidAccess},
		{name: "bad email", server: newVisitorTestServer(t, idp), bind: proto.Bind{Kind: proto.KindHTTP, Subdomain: "b", OIDC: &proto.OIDCLogin{AllowEmails: []string{"not-an-email"}}}, code: proto.CodeInvalidAccess},
		{name: "ok", server: newVisitorTestServer(t, idp), bind: proto.Bind{Kind: proto.KindHTTP, Subdomain: "c", OIDC: &proto.OIDCLogin{AllowDomains: []string{"@Example.org"}}}, ok: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server, cleanup := newRawSessionPair(t)
			defer cleanup()
			as := &AgentSession{ID: "v", InstanceID: "v-" + tc.name, Sess: server, IDGen: proto.NewEdgeIDGen(), NegotiatedVersion: proto.ProtoVersion}
			if err := writeAndHandleBind(t, tc.server, client, server, as, tc.bind); err != nil {
				t.Fatalf("bind: %v", err)
			}
			reply, err := client.Control().Read()
			if err != nil {
				t.Fatalf("read reply: %v", err)
			}
			if tc.ok {
				bindOK, err := proto.Decode[proto.BindOK](reply)
				if reply.Type != proto.TypeBindOK || err != nil || !bindOK.OIDC {
					t.Fatalf("reply = %s %s, want BindOK acknowledging OIDC", reply.Type, reply.Data)
				}
				rule, _ := tc.server.visitorRuleForHost("c.example.com")
				if rule == nil || len(rule.domains) != 1 || rule.domains[0] != "example.org" {
					t.Fatalf("login rule = %+v", rule)
				}
				return
			}
			bindErr, err := proto.Decode[proto.BindErr](reply)
			if reply.Type != proto.TypeBindErr || err != nil || bindErr.Code != tc.code {
				t.Fatalf("reply = %s %s, want BindErr %s", reply.Type, reply.Data, tc.code)
			}
		})
	}
}

func TestVisitorLoginConfigValidation(t *testing.T) {
	base := func() Config {
		return Config{Domain: "example.com", TokenSHA256: sumToken("tok"), PublicScheme: "https", Insecure: true, VisitorOIDC: &oidc.Config{
			Issuer: "https://idp.example.net", ClientID: "c", CookieSecret: []byte(strings.Repeat("k", 32)),
		}}
	}
	cfg := base()
	cfg.VisitorOIDC.RedirectURL = "https://login.other.net/.ngstone/auth/callback"
	if _, err := New(cfg); err == nil {
		t.Fatal("redirect URL outside the edge domain must be rejected")
	}
	cfg = base()
	cfg.VisitorOIDC.CookieSecret = []byte("short")
	if _, err := New(cfg); err == nil {
		t.Fatal("short cookie secret must be rejected")
	}
	cfg = base()
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.visitor.callback.String(); got != "https://example.com"+visitorDefaultCallback {
		t.Fatalf("default callback = %q", got)
	}
}

func TestSafeReturnPathRejectsOffsiteTargets(t *testing.T) {
	for input, want := range map[string]string{
		"/ok?x=1":               "/ok?x=1",
		"//evil.test/":          "/",
		"/\\evil.test":          "/",
		"https://evil.test/":    "/",
		"":                      "/",
		visitorFinishPath + "?": "/",
	} {
		if got := safeReturnPath(input); got != want {
			t.Errorf("safeReturnPath(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestStripVisitorSessionCookieKeepsOtherCookies(t *testing.T) {
	header := http.Header{"Cookie": {"a=1; " + visitorSessionCookie + "=secret", visitorSessionCookie + "=other", "b=2"}}
	stripVisitorSessionCookie(header)
	if got := header.Values("Cookie"); len(got) != 1 || got[0] != "a=1; b=2" {
		t.Fatalf("Cookie = %q", got)
	}
}

func TestVisitorIdentityFeedsTrafficPolicy(t *testing.T) {
	idp := newFakeVisitorIdP(t)
	s := newVisitorTestServer(t, idp)
	p, err := policy.Parse([]byte(`{"default_action":"allow","rules":[{"action":"allow","path_prefix":"/admin","header":"X-Ngstone-User-Email","header_value":"bob@example.org"},{"action":"deny","path_prefix":"/admin"}]}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}
	as := newEchoAgentSession(t, "visitor-policy")
	ac, err := buildAccessControl(proto.Bind{OIDC: &proto.OIDCLogin{}})
	if err != nil {
		t.Fatalf("buildAccessControl: %v", err)
	}
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "pol.example.com", Session: as, Takeover: true, Access: ac, TrafficPolicy: p}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	idp.setUser("alice@example.org", true)
	_, alice := visitorLoginFlow(t, s, idp, "http://pol.example.com/")
	spoofed := http.Header{"X-Ngstone-User-Email": {"bob@example.org"}}
	if rec := visitorRequest(t, s, http.MethodGet, "http://pol.example.com/admin", spoofed, alice); rec.Code != http.StatusForbidden {
		t.Fatalf("alice spoofing bob on /admin = %d, want 403", rec.Code)
	}
	if rec := visitorRequest(t, s, http.MethodGet, "http://pol.example.com/home", nil, alice); rec.Code != http.StatusOK {
		t.Fatalf("alice on /home = %d, want 200", rec.Code)
	}
	idp.setUser("bob@example.org", true)
	_, bob := visitorLoginFlow(t, s, idp, "http://pol.example.com/")
	if rec := visitorRequest(t, s, http.MethodGet, "http://pol.example.com/admin", nil, bob); rec.Code != http.StatusOK {
		t.Fatalf("bob on /admin = %d, want 200", rec.Code)
	}
}

func bindVisitorH2Tunnel(t *testing.T, s *Server, host string, bind proto.Bind) *capturedRequest {
	t.Helper()
	captured := &capturedRequest{}
	as := newFakeH2AgentSession(t, "visitor-h2-"+host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		captured.mu.Lock()
		captured.header = r.Header.Clone()
		captured.hits++
		captured.mu.Unlock()
		io.WriteString(w, "origin-ok")
	}))
	ac, err := buildAccessControl(bind)
	if err != nil {
		t.Fatalf("buildAccessControl: %v", err)
	}
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: host, Session: as, Takeover: true, Access: ac, HTTP2: true}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	return captured
}

func assertAssertedIdentity(t *testing.T, s *Server, idp *fakeVisitorIdP, captured *capturedRequest, host string) {
	t.Helper()
	idp.setUser("alice@example.org", true)
	_, session := visitorLoginFlow(t, s, idp, "http://"+host+"/")
	if session == nil {
		t.Fatal("login did not produce a session")
	}
	header := http.Header{
		"Accept":                {"application/json"},
		"Connection":            {"X-Ngstone-User-Email, X-Ngstone-User-Subject, X-Ngstone-User-Name"},
		"X_Ngstone_User_Email":  {"ceo@corp.example"},
		"X-Ngstone-User-Email":  {"mallory@evil.test"},
		"X_Ngstone_User_Groups": {"admins"},
	}
	rec := visitorRequest(t, s, http.MethodGet, "http://"+host+"/api", header, session)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	got, _ := captured.last()
	if values := got.Values(VisitorEmailHeader); len(values) != 1 || values[0] != "alice@example.org" {
		t.Fatalf("email header = %q, want exactly the real identity", values)
	}
	if values := got.Values(VisitorSubjectHeader); len(values) != 1 || values[0] != "sub-alice@example.org" {
		t.Fatalf("subject header = %q, want exactly the real identity", values)
	}
	if values := got.Values(VisitorNameHeader); len(values) != 1 || values[0] != "VisitorInjected" {
		t.Fatalf("name header = %q, want exactly the real identity", values)
	}
	for name, values := range got {
		lower := strings.ReplaceAll(strings.ToLower(name), "_", "-")
		if strings.HasPrefix(lower, "x-ngstone-user-") && name != VisitorEmailHeader && name != VisitorSubjectHeader && name != VisitorNameHeader {
			t.Fatalf("spoofed identity header %q=%q reached the upstream", name, values)
		}
	}
}

func TestVisitorIdentityHeadersSurviveConnectionTokens(t *testing.T) {
	idp := newFakeVisitorIdP(t)
	s := newVisitorTestServer(t, idp)
	captured := bindVisitorTunnel(t, s, "app.example.com", proto.Bind{OIDC: &proto.OIDCLogin{}})
	assertAssertedIdentity(t, s, idp, captured, "app.example.com")
}

func TestVisitorIdentityHeadersSurviveConnectionTokensOverHTTP2(t *testing.T) {
	idp := newFakeVisitorIdP(t)
	s := newVisitorTestServer(t, idp)
	captured := bindVisitorH2Tunnel(t, s, "h2.example.com", proto.Bind{OIDC: &proto.OIDCLogin{}})
	assertAssertedIdentity(t, s, idp, captured, "h2.example.com")
}
