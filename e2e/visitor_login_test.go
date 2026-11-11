package e2e

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"ngstone/internal/agent"
	"ngstone/internal/edge"
	"ngstone/internal/oidc"
	"ngstone/internal/proto"
)

type e2eIdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey

	mu    sync.Mutex
	email string
	codes map[string][2]string
}

func newE2EIdP(t *testing.T) *e2eIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	idp := &e2eIdP{key: key, codes: map[string][2]string{}}
	idp.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := idp.server.URL
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(oidc.Metadata{Issuer: issuer, AuthorizationURL: issuer + "/authorize", TokenURL: issuer + "/token", UserInfoURL: issuer + "/userinfo", JWKSURL: issuer + "/jwks"})
		case "/authorize":
			q := r.URL.Query()
			code := sha256Hex(q.Get("state"))[:16]
			idp.mu.Lock()
			idp.codes[code] = [2]string{q.Get("nonce"), idp.email}
			idp.mu.Unlock()
			target, _ := url.Parse(q.Get("redirect_uri"))
			target.RawQuery = url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
			http.Redirect(w, r, target.String(), http.StatusFound)
		case "/token":
			r.ParseForm()
			idp.mu.Lock()
			grant, ok := idp.codes[r.PostForm.Get("code")]
			idp.mu.Unlock()
			if !ok {
				http.Error(w, "bad code", http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"access_token": "at-" + r.PostForm.Get("code"), "token_type": "Bearer", "id_token": idp.idToken(t, grant[0], grant[1])})
		case "/jwks":
			json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kid": "e2e", "kty": "RSA", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})
		case "/userinfo":
			idp.mu.Lock()
			grant, ok := idp.codes[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer at-")]
			idp.mu.Unlock()
			if !ok {
				http.Error(w, "bad token", http.StatusUnauthorized)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"sub": "sub-" + grant[1], "email": grant[1], "email_verified": true, "name": "E2E Visitor"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.server.Close)
	return idp
}

func (idp *e2eIdP) setEmail(email string) {
	idp.mu.Lock()
	idp.email = email
	idp.mu.Unlock()
}

func (idp *e2eIdP) idToken(t *testing.T, nonce, email string) string {
	encode := func(v any) string {
		data, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(data)
	}
	header := encode(map[string]string{"alg": "RS256", "kid": "e2e", "typ": "JWT"})
	claims := encode(map[string]any{"iss": idp.server.URL, "sub": "sub-" + email, "aud": "e2e-client", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": nonce})
	digest := sha256.Sum256([]byte(header + "." + claims))
	sig, err := rsa.SignPKCS1v15(rand.Reader, idp.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Errorf("sign ID token: %v", err)
	}
	return header + "." + claims + "." + base64.RawURLEncoding.EncodeToString(sig)
}

type originCapture struct {
	mu      sync.Mutex
	headers []http.Header
}

func (o *originCapture) handler(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	o.headers = append(o.headers, r.Header.Clone())
	o.mu.Unlock()
	io.WriteString(w, "app:"+r.URL.Path)
}

func (o *originCapture) snapshot() []http.Header {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]http.Header(nil), o.headers...)
}

func browserClient(t *testing.T, publicAddr, domain string) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	return &http.Client{
		Jar:     jar,
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, _ := net.SplitHostPort(addr)
				if host == domain || strings.HasSuffix(host, "."+domain) {
					addr = publicAddr
				}
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}
}

func TestVisitorOIDCLoginEndToEnd(t *testing.T) {
	idp := newE2EIdP(t)
	origin := &originCapture{}
	originSrv := httptest.NewServer(http.HandlerFunc(origin.handler))
	defer originSrv.Close()

	token := "visitor-e2e-token"
	domain := "tun.example.com"
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)
	_, publicPort, _ := net.SplitHostPort(publicAddr)

	edgeSrv, err := edge.New(edge.Config{
		ControlAddr:  controlAddr,
		PublicAddr:   publicAddr,
		Domain:       domain,
		TokenSHA256:  mustSHA256(token),
		PublicScheme: "http",
		Insecure:     true,
		VisitorOIDC: &oidc.Config{
			Issuer:        idp.server.URL,
			ClientID:      "e2e-client",
			ClientSecret:  "e2e-secret",
			RedirectURL:   "http://" + domain + ":" + publicPort + "/.ngstone/auth/callback",
			CookieSecret:  []byte(strings.Repeat("e", 32)),
			AllowInsecure: true,
		},
	})
	if err != nil {
		t.Fatalf("edge.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go edgeSrv.Run(ctx)
	waitForPort(t, controlAddr)

	agt := agent.New(agent.Config{
		ControlAddr: controlAddr,
		Token:       token,
		Subdomain:   "web",
		TargetURL:   originSrv.URL,
		Insecure:    true,
		OIDC:        &proto.OIDCLogin{AllowEmails: []string{"alice@example.org"}, AllowDomains: []string{"corp.example"}},
	})
	go agt.Run(ctx)
	tunnelURL := "http://web." + domain + ":" + publicPort
	waitStatus(t, publicAddr, "web."+domain, "/", http.StatusUnauthorized, 10*time.Second)

	t.Run("api client gets 401", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, tunnelURL+"/api", nil)
		req.Header.Set("Accept", "application/json")
		resp, err := browserClient(t, publicAddr, domain).Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("browser is redirected to the apex callback", func(t *testing.T) {
		client := browserClient(t, publicAddr, domain)
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		req, _ := http.NewRequest(http.MethodGet, tunnelURL+"/page", nil)
		req.Header.Set("Accept", "text/html")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		resp.Body.Close()
		location, _ := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != http.StatusFound || location.Host != domain+":"+publicPort || location.Path != "/.ngstone/auth/start" {
			t.Fatalf("redirect = %d %q", resp.StatusCode, resp.Header.Get("Location"))
		}
	})

	t.Run("denied email never reaches the app", func(t *testing.T) {
		idp.setEmail("mallory@evil.test")
		before := len(origin.snapshot())
		req, _ := http.NewRequest(http.MethodGet, tunnelURL+"/secret", nil)
		req.Header.Set("Accept", "text/html")
		resp, err := browserClient(t, publicAddr, domain).Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
		if after := len(origin.snapshot()); after != before {
			t.Fatalf("origin reached by denied visitor (%d -> %d)", before, after)
		}
	})

	t.Run("allowed email signs in, cookie stripped, headers forwarded", func(t *testing.T) {
		idp.setEmail("bob@corp.example")
		client := browserClient(t, publicAddr, domain)
		req, _ := http.NewRequest(http.MethodGet, tunnelURL+"/welcome?x=1", nil)
		req.Header.Set("Accept", "text/html")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "app:/welcome" {
			t.Fatalf("final response = %d %q", resp.StatusCode, body)
		}
		if resp.Request.URL.String() != tunnelURL+"/welcome?x=1" {
			t.Fatalf("landed on %q, want original URL", resp.Request.URL)
		}
		tunnelHost, _ := url.Parse(tunnelURL)
		apex, _ := url.Parse("http://" + domain + ":" + publicPort + "/")
		var session *http.Cookie
		for _, c := range client.Jar.Cookies(tunnelHost) {
			if c.Name == "ngstone_visitor_session" {
				session = c
			}
		}
		if session == nil {
			t.Fatal("no session cookie stored for the tunnel host")
		}
		for _, c := range client.Jar.Cookies(apex) {
			if c.Name == "ngstone_visitor_session" {
				t.Fatal("session cookie leaked to the apex host")
			}
		}

		client.Jar.SetCookies(tunnelHost, []*http.Cookie{{Name: "app_pref", Value: "dark"}})
		api, _ := http.NewRequest(http.MethodGet, tunnelURL+"/api/me", nil)
		api.Header.Set("Accept", "application/json")
		api.Header.Set("X-Ngstone-User-Email", "ceo@corp.example")
		api.Header.Set("X-Ngstone-User-Role", "admin")
		apiResp, err := client.Do(api)
		if err != nil {
			t.Fatalf("API GET: %v", err)
		}
		apiResp.Body.Close()
		if apiResp.StatusCode != http.StatusOK {
			t.Fatalf("authenticated API status = %d", apiResp.StatusCode)
		}
		seen := origin.snapshot()
		last := seen[len(seen)-1]
		if got := last.Values("X-Ngstone-User-Email"); len(got) != 1 || got[0] != "bob@corp.example" {
			t.Fatalf("origin X-Ngstone-User-Email = %v, want the signed-in user only", got)
		}
		if last.Get("X-Ngstone-User-Subject") != "sub-bob@corp.example" || last.Get("X-Ngstone-User-Name") != "E2E Visitor" {
			t.Fatalf("origin identity headers = %v", last)
		}
		if got := last.Get("X-Ngstone-User-Role"); got != "" {
			t.Fatalf("spoofed X-Ngstone-User-Role reached origin: %q", got)
		}
		cookie := last.Get("Cookie")
		if strings.Contains(cookie, "ngstone_visitor_session") || !strings.Contains(cookie, "app_pref=dark") {
			t.Fatalf("origin Cookie = %q, want session stripped and app cookie kept", cookie)
		}

		otherOrigin := &originCapture{}
		otherSrv := httptest.NewServer(http.HandlerFunc(otherOrigin.handler))
		defer otherSrv.Close()
		go agent.New(agent.Config{
			ControlAddr: controlAddr,
			Token:       token,
			Subdomain:   "other",
			TargetURL:   otherSrv.URL,
			Insecure:    true,
			OIDC:        &proto.OIDCLogin{AllowEmails: []string{"alice@example.org"}, AllowDomains: []string{"corp.example"}},
		}).Run(ctx)
		waitStatus(t, publicAddr, "other."+domain, "/", http.StatusUnauthorized, 10*time.Second)

		noRedirect := &http.Client{
			Transport:     client.Transport,
			Timeout:       5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		otherReq, _ := http.NewRequest(http.MethodGet, "http://other."+domain+":"+publicPort+"/", nil)
		otherReq.AddCookie(&http.Cookie{Name: "ngstone_visitor_session", Value: session.Value})
		otherResp, err := noRedirect.Do(otherReq)
		if err != nil {
			t.Fatalf("request with the first tunnel's session to the second tunnel: %v", err)
		}
		otherResp.Body.Close()
		if otherResp.StatusCode != http.StatusUnauthorized && !(otherResp.StatusCode == http.StatusFound && strings.Contains(otherResp.Header.Get("Location"), "/.ngstone/auth/start")) {
			t.Fatalf("second tunnel answered the first tunnel's session with %d %q, want 401 or a redirect to login", otherResp.StatusCode, otherResp.Header.Get("Location"))
		}
		if got := len(otherOrigin.snapshot()); got != 0 {
			t.Fatalf("second tunnel's origin reached with the first tunnel's session (%d requests)", got)
		}

		replay, _ := http.NewRequest(http.MethodGet, tunnelURL+"/", nil)
		replay.Header.Set("Accept", "application/json")
		replay.AddCookie(&http.Cookie{Name: "ngstone_visitor_session", Value: session.Value})
		replayResp, err := noRedirect.Do(replay)
		if err != nil {
			t.Fatalf("session cookie replay on its own host: %v", err)
		}
		replayResp.Body.Close()
		if replayResp.StatusCode != http.StatusOK {
			t.Fatalf("session cookie replay on its own host = %d, want 200", replayResp.StatusCode)
		}
	})
}
