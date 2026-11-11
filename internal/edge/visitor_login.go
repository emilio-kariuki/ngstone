package edge

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"ngstone/internal/oidc"
)

const (
	visitorSessionCookie      = "ngstone_visitor_session"
	visitorStateCookiePrefix  = "ngstone_visitor_state_"
	visitorBindCookie         = "ngstone_visitor_bind"
	visitorCookiePrefix       = "ngstone_visitor_"
	visitorCookieHostPrefix   = "__Host-"
	visitorStartPath          = "/.ngstone/auth/start"
	visitorFinishPath         = "/.ngstone/auth/finish"
	visitorLogoutPath         = "/.ngstone/auth/logout"
	visitorDefaultCallback    = "/.ngstone/auth/callback"
	visitorIdentityPrefix     = "x-ngstone-user-"
	edgeHeaderPrefix          = "x-ngstone-"
	VisitorEmailHeader        = "X-Ngstone-User-Email"
	VisitorSubjectHeader      = "X-Ngstone-User-Subject"
	VisitorNameHeader         = "X-Ngstone-User-Name"
	visitorTicketLifetime     = time.Minute
	visitorSessionLifetime    = oidc.SessionLifetime
	visitorCodecLabel         = "ngstone-visitor-login-v1\x00"
	visitorPurposeReturn      = "return"
	visitorPurposeState       = "state"
	visitorPurposeTicket      = "ticket"
	visitorPurposeSession     = "session"
	visitorMaxReturnPathBytes = 2048
	visitorMaxTickets         = 65536
)

type visitorLogin struct {
	provider *oidc.Provider
	codec    *oidc.Codec
	callback *url.URL
	secure   bool

	mu      sync.Mutex
	tickets map[string]time.Time
}

type visitorToken struct {
	Purpose       string      `json:"p"`
	Host          string      `json:"h"`
	Path          string      `json:"u,omitempty"`
	ID            string      `json:"i,omitempty"`
	Subject       string      `json:"s,omitempty"`
	Email         string      `json:"e,omitempty"`
	EmailVerified bool        `json:"v,omitempty"`
	Name          string      `json:"n,omitempty"`
	State         *oidc.State `json:"st,omitempty"`
	Binding       string      `json:"b,omitempty"`
	ExpiresAt     time.Time   `json:"x"`
}

func newVisitorLogin(cfg Config) (*visitorLogin, error) {
	if cfg.VisitorOIDC == nil {
		return nil, nil
	}
	providerCfg := *cfg.VisitorOIDC
	if strings.TrimSpace(providerCfg.RedirectURL) == "" {
		scheme := cfg.PublicScheme
		if scheme == "" {
			scheme = "https"
		}
		providerCfg.RedirectURL = scheme + "://" + cfg.Domain + visitorDefaultCallback
	}
	providerCfg.GroupsClaim = ""
	providerCfg.AdminGroups = nil
	providerCfg.OperatorGroups = nil
	providerCfg.ViewerGroups = nil
	providerCfg.DefaultRole = oidc.RoleViewer
	callback, err := url.Parse(strings.TrimSpace(providerCfg.RedirectURL))
	if err != nil {
		return nil, fmt.Errorf("visitor OIDC redirect URL is invalid: %w", err)
	}
	if cfg.Domain == "" || !hostMatchesDomain(strings.ToLower(callback.Hostname()), strings.ToLower(cfg.Domain)) {
		return nil, fmt.Errorf("visitor OIDC redirect URL host %q must be the edge domain %q or one of its subdomains", callback.Hostname(), cfg.Domain)
	}
	if callback.Path == visitorStartPath || callback.Path == visitorFinishPath || callback.Path == visitorLogoutPath {
		return nil, errors.New("visitor OIDC redirect URL must not use a reserved ngstone auth path")
	}
	provider, err := oidc.New(providerCfg)
	if err != nil {
		return nil, err
	}
	codec, err := oidc.NewCodec(append([]byte(visitorCodecLabel), providerCfg.CookieSecret...))
	if err != nil {
		return nil, err
	}
	return &visitorLogin{
		provider: provider,
		codec:    codec,
		callback: callback,
		secure:   !cfg.Insecure && callback.Scheme == "https",
		tickets:  make(map[string]time.Time),
	}, nil
}

func (v *visitorLogin) servesHost(host string) bool {
	return v != nil && strings.EqualFold(host, v.callback.Hostname())
}

func (v *visitorLogin) handlesApexPath(path string) bool {
	return path == visitorStartPath || path == v.callback.Path
}

func (s *Server) serveVisitorApex(w http.ResponseWriter, r *http.Request) {
	v := s.visitor
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == visitorStartPath {
		s.handleVisitorStart(w, r, v)
		return
	}
	s.handleVisitorCallback(w, r, v)
}

func (s *Server) handleVisitorStart(w http.ResponseWriter, r *http.Request, v *visitorLogin) {
	var ret visitorToken
	if !v.open(r.URL.Query().Get("return"), visitorPurposeReturn, &ret) || !s.visitorReturnHostValid(ret.Host) {
		writeVisitorPage(w, http.StatusBadRequest, "Sign-in link expired", "Go back to the page you were visiting and try again.")
		return
	}
	authorizationURL, state, err := v.provider.AuthorizationURL(r.Context())
	if err != nil {
		writeVisitorPage(w, http.StatusBadGateway, "Sign-in unavailable", "The identity provider could not be reached.")
		return
	}
	sealed, err := v.codec.Encode(visitorToken{Purpose: visitorPurposeState, Host: ret.Host, Path: ret.Path, State: &state, Binding: ret.Binding, ExpiresAt: state.ExpiresAt})
	if err != nil {
		writeVisitorPage(w, http.StatusInternalServerError, "Sign-in failed", "Could not create sign-in state.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     v.cookieName(visitorStateCookieName(state.State)),
		Value:    sealed,
		Path:     v.stateCookiePath(),
		MaxAge:   int(oidc.StateLifetime / time.Second),
		HttpOnly: true,
		Secure:   v.secure,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authorizationURL, http.StatusFound)
}

func (s *Server) handleVisitorCallback(w http.ResponseWriter, r *http.Request, v *visitorLogin) {
	w.Header().Set("Cache-Control", "no-store")
	query := r.URL.Query()
	stateValue := query.Get("state")
	cookieName := v.cookieName(visitorStateCookieName(stateValue))
	if stateValue != "" {
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: v.stateCookiePath(), MaxAge: -1, HttpOnly: true, Secure: v.secure, SameSite: http.SameSiteLaxMode})
	}
	if query.Get("error") != "" {
		writeVisitorPage(w, http.StatusForbidden, "Sign-in cancelled", "The identity provider did not complete the sign-in.")
		return
	}
	cookie, err := r.Cookie(cookieName)
	var st visitorToken
	if stateValue == "" || err != nil || !v.open(cookie.Value, visitorPurposeState, &st) || st.State == nil || subtle.ConstantTimeCompare([]byte(st.State.State), []byte(stateValue)) != 1 || !s.visitorReturnHostValid(st.Host) {
		writeVisitorPage(w, http.StatusBadRequest, "Sign-in expired", "Go back to the page you were visiting and try again.")
		return
	}
	principal, err := v.provider.Exchange(r.Context(), *st.State, query.Get("code"))
	if err != nil {
		if errors.Is(err, oidc.ErrForbidden) {
			metricRejectedUnauthorized.Add(1)
			writeVisitorPage(w, http.StatusForbidden, "Access denied", "Your account is not allowed to sign in to this edge.")
			return
		}
		writeVisitorPage(w, http.StatusBadGateway, "Sign-in failed", "The identity provider rejected the sign-in.")
		return
	}
	rule, routed := s.visitorRuleForHost(stripPort(st.Host))
	if !routed {
		writeVisitorPage(w, http.StatusNotFound, "Tunnel offline", "The tunnel you were visiting is no longer online.")
		return
	}
	if rule == nil {
		writeVisitorPage(w, http.StatusForbidden, "Sign-in not available", "This tunnel does not use visitor sign-in.")
		return
	}
	if !rule.allows(principal.Email, principal.EmailVerified) {
		metricRejectedUnauthorized.Add(1)
		s.recordEvent("warn", "visitor login denied", map[string]string{"hostname": stripPort(st.Host), "subject": principal.Subject})
		writeVisitorPage(w, http.StatusForbidden, "Access denied", "Your account is not allowed to access this tunnel.")
		return
	}
	ticketID, err := randomToken(24)
	if err != nil {
		writeVisitorPage(w, http.StatusInternalServerError, "Sign-in failed", "Could not complete the sign-in.")
		return
	}
	ticket, err := v.codec.Encode(visitorToken{
		Purpose:       visitorPurposeTicket,
		Host:          st.Host,
		Path:          st.Path,
		Binding:       st.Binding,
		ID:            ticketID,
		Subject:       principal.Subject,
		Email:         principal.Email,
		EmailVerified: principal.EmailVerified,
		Name:          principal.Name,
		ExpiresAt:     time.Now().Add(visitorTicketLifetime),
	})
	if err != nil {
		writeVisitorPage(w, http.StatusInternalServerError, "Sign-in failed", "Could not complete the sign-in.")
		return
	}
	finishHost := st.Host
	if port := v.callback.Port(); port != "" {
		finishHost = net.JoinHostPort(st.Host, port)
	}
	target := url.URL{Scheme: v.callback.Scheme, Host: finishHost, Path: visitorFinishPath, RawQuery: url.Values{"ticket": {ticket}}.Encode()}
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (s *Server) visitorReturnHostValid(host string) bool {
	name := strings.ToLower(stripPort(host))
	return name != "" && hostMatchesDomain(name, strings.ToLower(s.cfg.Domain)) && !strings.ContainsAny(host, "/?#@\\")
}

func (s *Server) visitorRuleForHost(host string) (*visitorLoginRule, bool) {
	b, ok := s.registry.Route(host)
	if !ok {
		return nil, false
	}
	if snapshot := b.snapshot.Load(); snapshot != nil {
		return snapshot.access.loginRule(), true
	}
	return b.access.Load().loginRule(), true
}

func (s *Server) authorizeVisitor(w http.ResponseWriter, r *http.Request, rule *visitorLoginRule) (*visitorToken, bool) {
	v := s.visitor
	if v == nil {
		writeVisitorPage(w, http.StatusServiceUnavailable, "Sign-in unavailable", "Visitor login is not configured on this edge.")
		return nil, false
	}
	switch r.URL.Path {
	case visitorFinishPath:
		s.handleVisitorFinish(w, r, v, rule)
		return nil, false
	case visitorLogoutPath:
		v.clearSession(w)
		w.Header().Set("Cache-Control", "no-store")
		writeVisitorPage(w, http.StatusOK, "Signed out", "You have been signed out of this tunnel.")
		return nil, false
	}
	var sessions []visitorToken
	for _, cookie := range r.CookiesNamed(v.cookieName(visitorSessionCookie)) {
		var candidate visitorToken
		if v.open(cookie.Value, visitorPurposeSession, &candidate) && strings.EqualFold(candidate.Host, stripPort(r.Host)) && candidate.Subject != "" {
			sessions = append(sessions, candidate)
		}
	}
	if len(sessions) == 1 {
		session := sessions[0]
		if !rule.allows(session.Email, session.EmailVerified) {
			metricRejectedUnauthorized.Add(1)
			writeVisitorPage(w, http.StatusForbidden, "Access denied", "Your account is not allowed to access this tunnel.")
			return nil, false
		}
		setVisitorIdentity(r.Header, session)
		return &session, true
	}
	metricRejectedUnauthorized.Add(1)
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && acceptsHTML(r) {
		binding, err := randomToken(24)
		if err == nil {
			var start string
			start, err = v.startURL(r, binding)
			if err == nil {
				http.SetCookie(w, v.bindCookie(binding, int(oidc.StateLifetime/time.Second)))
				w.Header().Set("Cache-Control", "no-store")
				http.Redirect(w, r, start, http.StatusFound)
				return nil, false
			}
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "login required", http.StatusUnauthorized)
	return nil, false
}

func (s *Server) handleVisitorFinish(w http.ResponseWriter, r *http.Request, v *visitorLogin, rule *visitorLoginRule) {
	w.Header().Set("Cache-Control", "no-store")
	bound := r.CookiesNamed(v.cookieName(visitorBindCookie))
	var ticket visitorToken
	if !v.open(r.URL.Query().Get("ticket"), visitorPurposeTicket, &ticket) || !strings.EqualFold(stripPort(ticket.Host), stripPort(r.Host)) || ticket.ID == "" || ticket.Subject == "" || len(bound) != 1 || bound[0].Value == "" || subtle.ConstantTimeCompare([]byte(bound[0].Value), []byte(ticket.Binding)) != 1 || !v.consumeTicket(ticket.ID, ticket.ExpiresAt) {
		writeVisitorPage(w, http.StatusBadRequest, "Sign-in expired", "Reload the page you were visiting to sign in again.")
		return
	}
	if !rule.allows(ticket.Email, ticket.EmailVerified) {
		metricRejectedUnauthorized.Add(1)
		writeVisitorPage(w, http.StatusForbidden, "Access denied", "Your account is not allowed to access this tunnel.")
		return
	}
	expiresAt := time.Now().Add(visitorSessionLifetime)
	sealed, err := v.codec.Encode(visitorToken{
		Purpose:       visitorPurposeSession,
		Host:          strings.ToLower(stripPort(r.Host)),
		Subject:       ticket.Subject,
		Email:         ticket.Email,
		EmailVerified: ticket.EmailVerified,
		Name:          ticket.Name,
		ExpiresAt:     expiresAt,
	})
	if err != nil {
		writeVisitorPage(w, http.StatusInternalServerError, "Sign-in failed", "Could not create a session.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     v.cookieName(visitorSessionCookie),
		Value:    sealed,
		Path:     "/",
		MaxAge:   int(visitorSessionLifetime / time.Second),
		HttpOnly: true,
		Secure:   v.secure,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, v.bindCookie("", -1))
	s.recordEvent("info", "visitor login", map[string]string{"hostname": stripPort(r.Host), "subject": ticket.Subject})
	http.Redirect(w, r, safeReturnPath(ticket.Path), http.StatusFound)
}

func (v *visitorLogin) startURL(r *http.Request, binding string) (string, error) {
	path := r.URL.RequestURI()
	if len(path) > visitorMaxReturnPathBytes {
		path = r.URL.EscapedPath()
		if len(path) > visitorMaxReturnPathBytes {
			path = "/"
		}
	}
	sealed, err := v.codec.Encode(visitorToken{Purpose: visitorPurposeReturn, Host: strings.ToLower(stripPort(r.Host)), Path: path, Binding: binding, ExpiresAt: time.Now().Add(oidc.StateLifetime)})
	if err != nil {
		return "", err
	}
	start := url.URL{Scheme: v.callback.Scheme, Host: v.callback.Host, Path: visitorStartPath, RawQuery: url.Values{"return": {sealed}}.Encode()}
	return start.String(), nil
}

func (v *visitorLogin) cookieName(base string) string {
	if v.secure {
		return visitorCookieHostPrefix + base
	}
	return base
}

func (v *visitorLogin) stateCookiePath() string {
	if v.secure {
		return "/"
	}
	return v.callback.Path
}

func (v *visitorLogin) bindCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: v.cookieName(visitorBindCookie), Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: v.secure, SameSite: http.SameSiteLaxMode}
}

func (v *visitorLogin) open(value, purpose string, token *visitorToken) bool {
	if value == "" || v.codec.Decode(value, token) != nil {
		return false
	}
	return token.Purpose == purpose && token.Host != "" && !token.ExpiresAt.IsZero() && time.Now().Before(token.ExpiresAt)
}

func (v *visitorLogin) consumeTicket(id string, expiresAt time.Time) bool {
	now := time.Now()
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.tickets) >= visitorMaxTickets/2 {
		for key, expiry := range v.tickets {
			if now.After(expiry) {
				delete(v.tickets, key)
			}
		}
	}
	if _, used := v.tickets[id]; used || len(v.tickets) >= visitorMaxTickets {
		return false
	}
	v.tickets[id] = expiresAt
	return true
}

func (v *visitorLogin) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: v.cookieName(visitorSessionCookie), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: v.secure, SameSite: http.SameSiteLaxMode})
}

func randomToken(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func visitorStateCookieName(state string) string {
	if len(state) > 16 {
		state = state[:16]
	}
	var b strings.Builder
	b.WriteString(visitorStateCookiePrefix)
	for _, r := range state {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func safeReturnPath(path string) string {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.HasPrefix(path, "/\\") || strings.ContainsAny(path, "\r\n") {
		return "/"
	}
	if path == visitorFinishPath || strings.HasPrefix(path, visitorFinishPath+"?") || path == visitorLogoutPath {
		return "/"
	}
	return path
}

func acceptsHTML(r *http.Request) bool {
	for _, value := range r.Header.Values("Accept") {
		lower := strings.ToLower(value)
		if strings.Contains(lower, "text/html") || strings.Contains(lower, "application/xhtml+xml") {
			return true
		}
	}
	return false
}

func foldHeaderName(name string) string {
	folded := []byte(strings.ToLower(name))
	for i, c := range folded {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			folded[i] = '-'
		}
	}
	return string(folded)
}

func edgeReservedHeader(name string) bool {
	folded := foldHeaderName(name)
	return folded == "forwarded" || folded == "x-real-ip" || strings.HasPrefix(folded, "x-forwarded-") || strings.HasPrefix(folded, edgeHeaderPrefix)
}

func stripEdgeReservedHeaders(header http.Header) {
	for name := range header {
		if edgeReservedHeader(name) {
			delete(header, name)
		}
	}
}

func stripHeadersWithPrefix(header http.Header, prefix string) {
	for name := range header {
		if strings.HasPrefix(foldHeaderName(name), prefix) {
			delete(header, name)
		}
	}
}

func setVisitorIdentity(header http.Header, session visitorToken) {
	header.Set(VisitorSubjectHeader, sanitizeHeaderValue(session.Subject))
	if session.Email != "" {
		header.Set(VisitorEmailHeader, sanitizeHeaderValue(session.Email))
	}
	if session.Name != "" {
		header.Set(VisitorNameHeader, sanitizeHeaderValue(session.Name))
	}
}

func sanitizeHeaderValue(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
}

func stripVisitorCookies(header http.Header) {
	values := header.Values("Cookie")
	if len(values) == 0 {
		return
	}
	kept := make([]string, 0, len(values))
	changed := false
	for _, value := range values {
		parts := strings.Split(value, ";")
		out := parts[:0]
		for _, part := range parts {
			name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			if strings.HasPrefix(strings.TrimPrefix(strings.TrimSpace(name), visitorCookieHostPrefix), visitorCookiePrefix) {
				changed = true
				continue
			}
			out = append(out, part)
		}
		joined := strings.TrimSpace(strings.Join(out, ";"))
		if joined != "" {
			kept = append(kept, joined)
		}
	}
	if !changed {
		return
	}
	header.Del("Cookie")
	if len(kept) > 0 {
		header.Set("Cookie", strings.Join(kept, "; "))
	}
}

func writeVisitorPage(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<!doctype html><html><head><meta charset=\"utf-8\"><title>%s</title></head><body><h1>%s</h1><p>%s</p></body></html>",
		html.EscapeString(title), html.EscapeString(title), html.EscapeString(message))
}
