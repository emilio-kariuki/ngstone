package edge

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"ngstone/internal/oidc"
)

func TestOIDCLoginCreatesSessionAndEnforcesRoleAndCSRF(t *testing.T) {
	s, idp, setNonce := newOIDCTestServer(t, []string{"operators"})
	defer idp.Close()

	start := httptest.NewRecorder()
	startRequest := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/start", nil)
	startRequest.RemoteAddr = "127.0.0.1:4041"
	s.opsMux().ServeHTTP(start, startRequest)
	if start.Code != http.StatusFound {
		t.Fatalf("OIDC start status = %d, body=%s", start.Code, start.Body.String())
	}
	stateCookie := responseCookie(start.Result(), oidcStateCookie)
	if stateCookie == nil {
		t.Fatal("OIDC start did not set state cookie")
	}
	authorizeURL, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	state := authorizeURL.Query().Get("state")
	if state == "" {
		t.Fatal("OIDC start did not include state")
	}
	setNonce(authorizeURL.Query().Get("nonce"))

	callback := httptest.NewRecorder()
	callbackRequest := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?state="+url.QueryEscape(state)+"&code=auth-code", nil)
	callbackRequest.RemoteAddr = "127.0.0.1:4041"
	callbackRequest.AddCookie(stateCookie)
	s.opsMux().ServeHTTP(callback, callbackRequest)
	if callback.Code != http.StatusFound || callback.Header().Get("Location") != "/" {
		t.Fatalf("OIDC callback = status %d location %q body=%s", callback.Code, callback.Header().Get("Location"), callback.Body.String())
	}
	sessionCookie := responseCookie(callback.Result(), oidcSessionCookie)
	csrfCookie := responseCookie(callback.Result(), oidcCSRFCookie)
	if sessionCookie == nil || csrfCookie == nil {
		t.Fatal("OIDC callback did not set session and CSRF cookies")
	}

	me := httptest.NewRecorder()
	meRequest := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	meRequest.AddCookie(sessionCookie)
	s.opsMux().ServeHTTP(me, meRequest)
	if me.Code != http.StatusOK {
		t.Fatalf("OIDC me status = %d, body=%s", me.Code, me.Body.String())
	}
	var envelope struct {
		Data struct {
			Principal oidc.Principal `json:"principal"`
		} `json:"data"`
	}
	if err := json.Unmarshal(me.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode OIDC me: %v", err)
	}
	if envelope.Data.Principal.Subject != "user-1" || envelope.Data.Principal.Role != oidc.RoleOperator {
		t.Fatalf("OIDC principal = %+v", envelope.Data.Principal)
	}

	missingCSRF := httptest.NewRecorder()
	missingCSRFRequest := httptest.NewRequest(http.MethodPost, "/api/v1/credentials", strings.NewReader(`{"subdomain":"demo"}`))
	missingCSRFRequest.AddCookie(sessionCookie)
	s.opsMux().ServeHTTP(missingCSRF, missingCSRFRequest)
	if missingCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d, body=%s", missingCSRF.Code, missingCSRF.Body.String())
	}

	withCSRF := httptest.NewRecorder()
	withCSRFRequest := httptest.NewRequest(http.MethodPost, "/api/v1/credentials", strings.NewReader(`{"subdomain":"demo"}`))
	withCSRFRequest.AddCookie(sessionCookie)
	withCSRFRequest.AddCookie(csrfCookie)
	withCSRFRequest.Header.Set("X-Ngstone-CSRF", csrfCookie.Value)
	s.opsMux().ServeHTTP(withCSRF, withCSRFRequest)
	if withCSRF.Code != http.StatusConflict {
		t.Fatalf("authorized credential request status = %d, body=%s", withCSRF.Code, withCSRF.Body.String())
	}
}

func TestOIDCViewerCannotMutateManagementResources(t *testing.T) {
	s, idp, setNonce := newOIDCTestServer(t, []string{"viewers"})
	defer idp.Close()
	sessionCookie := oidcLoginCookie(t, s, setNonce)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/tunnels/demo/drain", nil)
	request.AddCookie(sessionCookie)
	s.opsMux().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("viewer drain status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestOIDCSessionTamperingIsRejected(t *testing.T) {
	s, idp, setNonce := newOIDCTestServer(t, []string{"viewers"})
	defer idp.Close()
	sessionCookie := oidcLoginCookie(t, s, setNonce)
	if len(sessionCookie.Value) < 2 {
		t.Fatal("session cookie is unexpectedly short")
	}
	value := "A" + sessionCookie.Value[1:]
	if value == sessionCookie.Value {
		value = "B" + sessionCookie.Value[1:]
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	request.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: value})
	s.opsMux().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("tampered session status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
}

func newOIDCTestServer(t *testing.T, groups []string) (*Server, *httptest.Server, func(string)) {
	t.Helper()
	issuer := ""
	nonce := ""
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(oidc.Metadata{
				Issuer:           issuer,
				AuthorizationURL: issuer + "/authorize",
				TokenURL:         issuer + "/token",
				UserInfoURL:      issuer + "/userinfo",
				JWKSURL:          issuer + "/jwks",
			})
		case "/token":
			json.NewEncoder(w).Encode(map[string]string{"access_token": "access-token", "token_type": "Bearer", "id_token": edgeTestIDToken(t, key, issuer, nonce)})
		case "/jwks":
			json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kid": "test-key", "kty": "RSA", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
			}}})
		case "/userinfo":
			json.NewEncoder(w).Encode(map[string]any{"sub": "user-1", "email": "alice@example.com", "groups": groups})
		default:
			http.NotFound(w, r)
		}
	}))
	issuer = idp.URL
	s, err := New(Config{
		Domain:   "example.com",
		Insecure: true,
		OIDC: &oidc.Config{
			Issuer:         issuer,
			ClientID:       "client-id",
			ClientSecret:   "client-secret",
			RedirectURL:    "http://127.0.0.1:4041/api/v1/auth/oidc/callback",
			CookieSecret:   []byte(strings.Repeat("s", 32)),
			AdminGroups:    []string{"admins"},
			OperatorGroups: []string{"operators"},
			ViewerGroups:   []string{"viewers"},
			DefaultRole:    "",
			AllowInsecure:  true,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, idp, func(value string) { nonce = value }
}

func oidcLoginCookie(t *testing.T, s *Server, setNonce func(string)) *http.Cookie {
	t.Helper()
	start := httptest.NewRecorder()
	startRequest := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/start", nil)
	s.opsMux().ServeHTTP(start, startRequest)
	stateCookie := responseCookie(start.Result(), oidcStateCookie)
	authorizeURL, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	setNonce(authorizeURL.Query().Get("nonce"))
	callback := httptest.NewRecorder()
	callbackRequest := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?state="+url.QueryEscape(authorizeURL.Query().Get("state"))+"&code=auth-code", nil)
	callbackRequest.AddCookie(stateCookie)
	s.opsMux().ServeHTTP(callback, callbackRequest)
	if callback.Code != http.StatusFound {
		t.Fatalf("OIDC callback status = %d, body=%s", callback.Code, callback.Body.String())
	}
	return responseCookie(callback.Result(), oidcSessionCookie)
}

func edgeTestIDToken(t *testing.T, key *rsa.PrivateKey, issuer, nonce string) string {
	t.Helper()
	encode := func(value any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal ID token: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	header := encode(map[string]string{"alg": "RS256", "kid": "test-key", "typ": "JWT"})
	claims := encode(map[string]any{"iss": issuer, "sub": "user-1", "aud": "client-id", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": nonce})
	signingInput := []byte(header + "." + claims)
	digest := sha256.Sum256(signingInput)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign ID token: %v", err)
	}
	return header + "." + claims + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func responseCookie(response *http.Response, name string) *http.Cookie {
	for _, cookie := range response.Cookies() {
		if cookie.Name == name && cookie.MaxAge >= 0 {
			return cookie
		}
	}
	return nil
}
