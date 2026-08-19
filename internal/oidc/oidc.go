package oidc

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"ngstone/internal/credentials"
)

const (
	RoleViewer           = "viewer"
	RoleOperator         = "operator"
	RoleAdmin            = "admin"
	StateLifetime        = 10 * time.Minute
	SessionLifetime      = 8 * time.Hour
	MaxDiscoveryBodySize = 512 << 10
	MaxTokenBodySize     = 1 << 20
	MaxUserInfoBodySize  = 1 << 20
)

var (
	ErrNotConfigured = errors.New("oidc is not configured")
	ErrStateInvalid  = errors.New("oidc state is invalid or expired")
	ErrForbidden     = errors.New("oidc user is not assigned an ngstone role")
	ErrTokenInvalid  = errors.New("oidc provider returned an invalid token response")
)

type Config struct {
	Issuer              string
	ClientID            string
	ClientSecret        string
	RedirectURL         string
	CookieSecret        []byte
	GroupsClaim         string
	AdminGroups         []string
	OperatorGroups      []string
	ViewerGroups        []string
	AllowedEmailDomains []string
	DefaultRole         string
	AllowInsecure       bool
	HTTPClient          *http.Client
}

type Principal struct {
	Subject string   `json:"subject"`
	Email   string   `json:"email,omitempty"`
	Name    string   `json:"name,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	Role    string   `json:"role"`
}

type State struct {
	State        string    `json:"state"`
	Nonce        string    `json:"nonce"`
	CodeVerifier string    `json:"code_verifier"`
	RedirectURL  string    `json:"redirect_url"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type Session struct {
	Principal
	CSRF      string    `json:"csrf"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Metadata struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationURL       string   `json:"authorization_endpoint"`
	TokenURL               string   `json:"token_endpoint"`
	UserInfoURL            string   `json:"userinfo_endpoint"`
	JWKSURL                string   `json:"jwks_uri"`
	ScopesSupported        []string `json:"scopes_supported"`
	ResponseTypesSupported []string `json:"response_types_supported"`
}

type Provider struct {
	cfg      Config
	mu       sync.Mutex
	metadata Metadata
	loadedAt time.Time
	client   *http.Client
}

type Codec struct {
	aead cipher.AEAD
}

func New(cfg Config) (*Provider, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	cfg.AdminGroups = normalizeList(cfg.AdminGroups)
	cfg.OperatorGroups = normalizeList(cfg.OperatorGroups)
	cfg.ViewerGroups = normalizeList(cfg.ViewerGroups)
	cfg.AllowedEmailDomains = normalizeList(cfg.AllowedEmailDomains)
	return &Provider{cfg: cfg, client: cfg.HTTPClient}, nil
}

func ValidateConfig(cfg Config) error {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return ErrNotConfigured
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return errors.New("oidc client id is required")
	}
	issuer, err := parseEndpoint(cfg.Issuer, "issuer", cfg.AllowInsecure)
	if err != nil {
		return err
	}
	if issuer.RawQuery != "" || issuer.Fragment != "" {
		return errors.New("oidc issuer must not contain a query or fragment")
	}
	redirect, err := parseEndpoint(cfg.RedirectURL, "redirect URL", cfg.AllowInsecure)
	if err != nil {
		return err
	}
	if redirect.Path == "" || redirect.Path == "/" {
		return errors.New("oidc redirect URL must include a callback path")
	}
	if len(cfg.CookieSecret) < 32 {
		return errors.New("oidc cookie secret must contain at least 32 bytes")
	}
	if cfg.GroupsClaim != "" && strings.TrimSpace(cfg.GroupsClaim) == "" {
		return errors.New("oidc groups claim must not be empty")
	}
	if cfg.DefaultRole != "" && !validRole(cfg.DefaultRole) {
		return fmt.Errorf("oidc default role %q is invalid", cfg.DefaultRole)
	}
	return nil
}

func NewCodec(secret []byte) (*Codec, error) {
	if len(secret) < 32 {
		return nil, errors.New("oidc cookie secret must contain at least 32 bytes")
	}
	sum := sha256.Sum256(secret)
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, fmt.Errorf("oidc cookie cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("oidc cookie cipher: %w", err)
	}
	return &Codec{aead: aead}, nil
}

func ParseCookieSecret(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("oidc cookie secret is required")
	}
	if len(raw)%2 == 0 {
		if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) >= 32 {
			return decoded, nil
		}
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(raw); err == nil && len(decoded) >= 32 {
			return decoded, nil
		}
	}
	return nil, errors.New("oidc cookie secret must be hex or base64 encoded and contain at least 32 bytes")
}

func (c *Codec) Encode(value any) (string, error) {
	if c == nil || c.aead == nil {
		return "", errors.New("oidc cookie codec is not configured")
	}
	plaintext, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("oidc cookie encode: %w", err)
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("oidc cookie nonce: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (c *Codec) Decode(value string, target any) error {
	if c == nil || c.aead == nil {
		return errors.New("oidc cookie codec is not configured")
	}
	encoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(encoded) < c.aead.NonceSize() {
		return ErrStateInvalid
	}
	nonce := encoded[:c.aead.NonceSize()]
	plaintext, err := c.aead.Open(nil, nonce, encoded[c.aead.NonceSize():], nil)
	if err != nil {
		return ErrStateInvalid
	}
	if err := json.Unmarshal(plaintext, target); err != nil {
		return ErrStateInvalid
	}
	return nil
}

func (p *Provider) AuthorizationURL(ctx context.Context) (string, State, error) {
	if p == nil {
		return "", State{}, ErrNotConfigured
	}
	metadata, err := p.discovery(ctx)
	if err != nil {
		return "", State{}, err
	}
	state, err := newState(p.cfg.RedirectURL)
	if err != nil {
		return "", State{}, err
	}
	query := url.Values{
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {state.RedirectURL},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {state.State},
		"nonce":                 {state.Nonce},
		"code_challenge":        {codeChallenge(state.CodeVerifier)},
		"code_challenge_method": {"S256"},
	}
	authorizeURL, err := url.Parse(metadata.AuthorizationURL)
	if err != nil {
		return "", State{}, errors.New("oidc authorization endpoint is invalid")
	}
	authorizeURL.RawQuery = query.Encode()
	return authorizeURL.String(), state, nil
}

func (p *Provider) Exchange(ctx context.Context, state State, code string) (Principal, error) {
	if p == nil {
		return Principal{}, ErrNotConfigured
	}
	if strings.TrimSpace(code) == "" || state.State == "" || state.CodeVerifier == "" || state.RedirectURL != p.cfg.RedirectURL || time.Now().After(state.ExpiresAt) {
		return Principal{}, ErrStateInvalid
	}
	metadata, err := p.discovery(ctx)
	if err != nil {
		return Principal{}, err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {p.cfg.ClientID},
		"redirect_uri":  {state.RedirectURL},
		"code_verifier": {state.CodeVerifier},
	}
	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, metadata.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Principal{}, fmt.Errorf("oidc token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return Principal{}, fmt.Errorf("oidc token request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxTokenBodySize+1))
	if err != nil {
		return Principal{}, fmt.Errorf("oidc token response: %w", err)
	}
	if len(body) > MaxTokenBodySize {
		return Principal{}, ErrTokenInvalid
	}
	if resp.StatusCode != http.StatusOK {
		return Principal{}, fmt.Errorf("oidc token endpoint returned status %d", resp.StatusCode)
	}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &token); err != nil || token.AccessToken == "" || token.IDToken == "" || !strings.EqualFold(token.TokenType, "bearer") {
		return Principal{}, ErrTokenInvalid
	}
	idClaims, err := p.verifyIDToken(ctx, token.IDToken, state.Nonce, metadata)
	if err != nil {
		return Principal{}, err
	}

	userInfoReq, err := http.NewRequestWithContext(ctx, http.MethodGet, metadata.UserInfoURL, nil)
	if err != nil {
		return Principal{}, fmt.Errorf("oidc userinfo request: %w", err)
	}
	userInfoReq.Header.Set("Authorization", "Bearer "+token.AccessToken)
	userInfoReq.Header.Set("Accept", "application/json")
	userInfoResp, err := p.client.Do(userInfoReq)
	if err != nil {
		return Principal{}, fmt.Errorf("oidc userinfo request: %w", err)
	}
	defer userInfoResp.Body.Close()
	userInfoBody, err := io.ReadAll(io.LimitReader(userInfoResp.Body, MaxUserInfoBodySize+1))
	if err != nil {
		return Principal{}, fmt.Errorf("oidc userinfo response: %w", err)
	}
	if len(userInfoBody) > MaxUserInfoBodySize || userInfoResp.StatusCode != http.StatusOK {
		return Principal{}, errors.New("oidc userinfo request was rejected")
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(userInfoBody, &claims); err != nil {
		return Principal{}, errors.New("oidc userinfo response is invalid")
	}
	principal, err := p.principalFromClaims(claims)
	if err != nil {
		return Principal{}, err
	}
	if principal.Subject != claimString(idClaims, "sub") {
		return Principal{}, errors.New("oidc userinfo subject does not match the ID token")
	}
	return principal, nil
}

func (p *Provider) principalFromClaims(claims map[string]json.RawMessage) (Principal, error) {
	principal := Principal{
		Subject: claimString(claims, "sub"),
		Email:   claimString(claims, "email"),
		Name:    claimString(claims, "name"),
	}
	if principal.Subject == "" {
		return Principal{}, errors.New("oidc userinfo response is missing sub")
	}
	if principal.Subject == credentials.GlobalOwnerID || principal.Subject == credentials.InvalidOwnerID {
		return Principal{}, ErrForbidden
	}
	if len(p.cfg.AllowedEmailDomains) > 0 && !claimBool(claims, "email_verified") {
		return Principal{}, ErrForbidden
	}
	if !emailAllowed(principal.Email, p.cfg.AllowedEmailDomains) {
		return Principal{}, ErrForbidden
	}
	principal.Groups = claimList(claims, p.cfg.GroupsClaim)
	principal.Role = roleForGroups(principal.Groups, p.cfg)
	if principal.Role == "" {
		return Principal{}, ErrForbidden
	}
	if principal.Name == "" {
		principal.Name = principal.Email
	}
	return principal, nil
}

func claimBool(claims map[string]json.RawMessage, name string) bool {
	raw, ok := claims[name]
	if !ok {
		return false
	}
	var value bool
	return json.Unmarshal(raw, &value) == nil && value
}

func (p *Provider) discovery(ctx context.Context) (Metadata, error) {
	p.mu.Lock()
	if p.loadedAt.After(time.Now().Add(-10 * time.Minute)) {
		metadata := p.metadata
		p.mu.Unlock()
		return metadata, nil
	}
	p.mu.Unlock()
	discoveryURL := strings.TrimRight(p.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return Metadata{}, fmt.Errorf("oidc discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return Metadata{}, fmt.Errorf("oidc discovery request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxDiscoveryBodySize+1))
	if err != nil {
		return Metadata{}, fmt.Errorf("oidc discovery response: %w", err)
	}
	if len(body) > MaxDiscoveryBodySize || resp.StatusCode != http.StatusOK {
		return Metadata{}, errors.New("oidc discovery request was rejected")
	}
	var metadata Metadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return Metadata{}, errors.New("oidc discovery response is invalid")
	}
	if normalizeURL(metadata.Issuer) != normalizeURL(p.cfg.Issuer) {
		return Metadata{}, errors.New("oidc discovery issuer does not match configured issuer")
	}
	if err := validateDiscoveredEndpoint(metadata.AuthorizationURL, "authorization endpoint", p.cfg.AllowInsecure); err != nil {
		return Metadata{}, err
	}
	if err := validateDiscoveredEndpoint(metadata.TokenURL, "token endpoint", p.cfg.AllowInsecure); err != nil {
		return Metadata{}, err
	}
	if err := validateDiscoveredEndpoint(metadata.UserInfoURL, "userinfo endpoint", p.cfg.AllowInsecure); err != nil {
		return Metadata{}, err
	}
	if err := validateDiscoveredEndpoint(metadata.JWKSURL, "JWKS endpoint", p.cfg.AllowInsecure); err != nil {
		return Metadata{}, err
	}
	p.mu.Lock()
	p.metadata = metadata
	p.loadedAt = time.Now()
	p.mu.Unlock()
	return metadata, nil
}

func (p *Provider) verifyIDToken(ctx context.Context, raw, expectedNonce string, metadata Metadata) (map[string]json.RawMessage, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("oidc ID token is not a JWT")
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(headerBytes, &header) != nil || header.Algorithm != "RS256" || header.KeyID == "" {
		return nil, errors.New("oidc ID token has an unsupported signing header")
	}
	key, err := p.fetchRSAKey(ctx, metadata.JWKSURL, header.KeyID)
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, digestSHA256([]byte(parts[0]+"."+parts[1])), signature) != nil {
		return nil, errors.New("oidc ID token signature is invalid")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("oidc ID token payload is invalid")
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, errors.New("oidc ID token claims are invalid")
	}
	if normalizeURL(claimString(claims, "iss")) != normalizeURL(p.cfg.Issuer) || claimString(claims, "sub") == "" || claimString(claims, "nonce") != expectedNonce || !audienceContains(claims["aud"], claimString(claims, "azp"), p.cfg.ClientID) {
		return nil, errors.New("oidc ID token claims are invalid")
	}
	var expiresAt int64
	if err := json.Unmarshal(claims["exp"], &expiresAt); err != nil || expiresAt <= time.Now().Unix() {
		return nil, errors.New("oidc ID token is expired")
	}
	var issuedAt int64
	if err := json.Unmarshal(claims["iat"], &issuedAt); err != nil || issuedAt > time.Now().Add(5*time.Minute).Unix() {
		return nil, errors.New("oidc ID token issued-at claim is invalid")
	}
	return claims, nil
}

func (p *Provider) fetchRSAKey(ctx context.Context, rawURL, keyID string) (*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc JWKS request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxDiscoveryBodySize+1))
	if err != nil || len(body) > MaxDiscoveryBodySize || resp.StatusCode != http.StatusOK {
		return nil, errors.New("oidc JWKS request was rejected")
	}
	var document struct {
		Keys []struct {
			KeyID string `json:"kid"`
			Type  string `json:"kty"`
			N     string `json:"n"`
			E     string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, errors.New("oidc JWKS response is invalid")
	}
	for _, jwk := range document.Keys {
		if jwk.KeyID != keyID || jwk.Type != "RSA" || jwk.N == "" || jwk.E == "" {
			continue
		}
		modulus, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return nil, errors.New("oidc JWKS modulus is invalid")
		}
		exponentBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
			return nil, errors.New("oidc JWKS exponent is invalid")
		}
		exponent := 0
		for _, value := range exponentBytes {
			exponent = exponent<<8 | int(value)
		}
		if exponent < 3 || exponent%2 == 0 || len(modulus) < 256 {
			return nil, errors.New("oidc JWKS RSA key is too weak")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}, nil
	}
	return nil, errors.New("oidc JWKS does not contain the ID token key")
}

func audienceContains(raw json.RawMessage, authorizedParty, expected string) bool {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return single == expected
	}
	var values []string
	if json.Unmarshal(raw, &values) != nil {
		return false
	}
	if len(values) > 1 && authorizedParty != expected {
		return false
	}
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func digestSHA256(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}

func newState(redirectURL string) (State, error) {
	state, err := randomString(32)
	if err != nil {
		return State{}, err
	}
	nonce, err := randomString(32)
	if err != nil {
		return State{}, err
	}
	verifier, err := randomString(32)
	if err != nil {
		return State{}, err
	}
	return State{State: state, Nonce: nonce, CodeVerifier: verifier, RedirectURL: redirectURL, ExpiresAt: time.Now().Add(StateLifetime)}, nil
}

func NewSession(principal Principal, now time.Time, ttl time.Duration) (Session, error) {
	if principal.Subject == "" || !validRole(principal.Role) {
		return Session{}, ErrForbidden
	}
	if ttl <= 0 {
		ttl = SessionLifetime
	}
	csrf, err := randomString(32)
	if err != nil {
		return Session{}, err
	}
	return Session{Principal: principal, CSRF: csrf, IssuedAt: now, ExpiresAt: now.Add(ttl)}, nil
}

func RoleRank(role string) int {
	switch role {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

func HasRole(actual, required string) bool {
	return RoleRank(actual) >= RoleRank(required) && RoleRank(required) > 0
}

func claimString(claims map[string]json.RawMessage, name string) string {
	var value string
	if err := json.Unmarshal(claims[name], &value); err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func claimList(claims map[string]json.RawMessage, name string) []string {
	if name == "" {
		return nil
	}
	var values []string
	if err := json.Unmarshal(claims[name], &values); err == nil {
		return normalizeList(values)
	}
	if value := claimString(claims, name); value != "" {
		return normalizeList(strings.Fields(value))
	}
	return nil
}

func roleForGroups(groups []string, cfg Config) string {
	if containsAny(groups, cfg.AdminGroups) {
		return RoleAdmin
	}
	if containsAny(groups, cfg.OperatorGroups) {
		return RoleOperator
	}
	if containsAny(groups, cfg.ViewerGroups) {
		return RoleViewer
	}
	if validRole(cfg.DefaultRole) {
		return cfg.DefaultRole
	}
	return ""
}

func emailAllowed(email string, domains []string) bool {
	if len(domains) == 0 {
		return true
	}
	parts := strings.Split(strings.ToLower(strings.TrimSpace(email)), "@")
	if len(parts) != 2 || parts[1] == "" {
		return false
	}
	for _, domain := range domains {
		if parts[1] == domain {
			return true
		}
	}
	return false
}

func containsAny(values, candidates []string) bool {
	for _, value := range values {
		for _, candidate := range candidates {
			if value == candidate {
				return true
			}
		}
	}
	return false
}

func normalizeList(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func validRole(role string) bool {
	return role == RoleViewer || role == RoleOperator || role == RoleAdmin
}

func parseEndpoint(raw, name string, allowInsecure bool) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("oidc %s must be an absolute http(s) URL", name)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("oidc %s must use http or https", name)
	}
	if u.Scheme == "http" && !allowInsecure && !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("oidc %s must use https outside loopback development", name)
	}
	return u, nil
}

func validateDiscoveredEndpoint(raw, name string, allowInsecure bool) error {
	if _, err := parseEndpoint(raw, name, allowInsecure); err != nil {
		return err
	}
	return nil
}

func normalizeURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func randomString(size int) (string, error) {
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return "", fmt.Errorf("oidc random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func codeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
