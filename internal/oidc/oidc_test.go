package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuthorizationAndExchangeMapsOIDCGroupsToRole(t *testing.T) {
	issuer := ""
	nonce := ""
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate alternate test key: %v", err)
	}
	signingKey := key
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(Metadata{
				Issuer:           issuer,
				AuthorizationURL: issuer + "/authorize",
				TokenURL:         issuer + "/token",
				UserInfoURL:      issuer + "/userinfo",
				JWKSURL:          issuer + "/jwks",
			})
		case "/token":
			if err := r.ParseForm(); err != nil || r.Form.Get("code_verifier") == "" || r.Form.Get("code") != "auth-code" {
				http.Error(w, "invalid token request", http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"access_token": "access-token", "token_type": "Bearer", "id_token": testIDToken(t, signingKey, issuer, nonce)})
		case "/jwks":
			json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kid": "test-key", "kty": "RSA", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
			}}})
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer access-token" {
				http.Error(w, "missing bearer", http.StatusUnauthorized)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"sub":    "user-1",
				"email":  "alice@example.com",
				"name":   "Alice",
				"groups": []string{"ngstone-operators"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL

	provider, err := New(Config{
		Issuer:         server.URL,
		ClientID:       "client-id",
		ClientSecret:   "client-secret",
		RedirectURL:    "http://127.0.0.1:4041/api/v1/auth/oidc/callback",
		CookieSecret:   []byte(strings.Repeat("s", 32)),
		OperatorGroups: []string{"ngstone-operators"},
		DefaultRole:    RoleViewer,
		AllowInsecure:  true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	authorizationURL, state, err := provider.AuthorizationURL(context.Background())
	if err != nil {
		t.Fatalf("AuthorizationURL: %v", err)
	}
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	if parsed.Query().Get("code_challenge_method") != "S256" || parsed.Query().Get("state") != state.State || parsed.Query().Get("nonce") == "" {
		t.Fatalf("authorization query = %s", parsed.RawQuery)
	}
	nonce = state.Nonce
	principal, err := provider.Exchange(context.Background(), state, "auth-code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if principal.Subject != "user-1" || principal.Role != RoleOperator || principal.Email != "alice@example.com" {
		t.Fatalf("principal = %+v", principal)
	}
	signingKey = wrongKey
	if _, err := provider.Exchange(context.Background(), state, "auth-code"); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("invalid ID token signature error = %v", err)
	}
}

func TestEmailDomainAllowlistRequiresVerifiedEmail(t *testing.T) {
	provider := &Provider{cfg: Config{
		AllowedEmailDomains: []string{"example.com"},
		GroupsClaim:         "groups",
		OperatorGroups:      []string{"operators"},
	}}
	claims := map[string]json.RawMessage{}
	for name, value := range map[string]any{
		"sub":    "user-1",
		"email":  "alice@example.com",
		"groups": []string{"operators"},
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal claim %s: %v", name, err)
		}
		claims[name] = encoded
	}
	if _, err := provider.principalFromClaims(claims); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unverified email error = %v, want ErrForbidden", err)
	}
	verified, err := json.Marshal(true)
	if err != nil {
		t.Fatalf("marshal email_verified: %v", err)
	}
	claims["email_verified"] = verified
	if _, err := provider.principalFromClaims(claims); err != nil {
		t.Fatalf("verified email was rejected: %v", err)
	}
}

func testIDToken(t *testing.T, key *rsa.PrivateKey, issuer, nonce string) string {
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

func TestOIDCCookieCodecRejectsTamperingAndExpiredSession(t *testing.T) {
	codec, err := NewCodec([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	session, err := NewSession(Principal{Subject: "user-1", Role: RoleViewer}, time.Now().UTC(), time.Hour)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	encoded, err := codec.Encode(session)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var decoded Session
	if err := codec.Decode(encoded, &decoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.Subject != session.Subject || decoded.CSRF != session.CSRF {
		t.Fatalf("decoded session = %+v", decoded)
	}
	tamperedBytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode cookie for tampering: %v", err)
	}
	tamperedBytes[len(tamperedBytes)-1] ^= 1
	tampered := base64.RawURLEncoding.EncodeToString(tamperedBytes)
	if err := codec.Decode(tampered, &decoded); err == nil {
		t.Fatal("tampered cookie decoded successfully")
	}
	if session.ExpiresAt.Before(time.Now()) {
		t.Fatal("test session unexpectedly expired")
	}
}

func TestRoleMappingRejectsUsersOutsideConfiguredTeams(t *testing.T) {
	provider, err := New(Config{
		Issuer:        "https://issuer.example.com",
		ClientID:      "client-id",
		RedirectURL:   "https://edge.example.com/callback",
		CookieSecret:  []byte(strings.Repeat("s", 32)),
		ViewerGroups:  []string{"ngstone-viewers"},
		AllowInsecure: false,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = provider.principalFromClaims(map[string]json.RawMessage{
		"sub":    json.RawMessage(`"user-2"`),
		"email":  json.RawMessage(`"bob@example.com"`),
		"groups": json.RawMessage(`["other-team"]`),
	})
	if err != ErrForbidden {
		t.Fatalf("principal error = %v, want ErrForbidden", err)
	}
}
