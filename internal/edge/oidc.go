package edge

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"ngstone/internal/adminapi"
	"ngstone/internal/oidc"
)

const (
	oidcStateCookie   = "ngstone_oidc_state"
	oidcSessionCookie = "ngstone_oidc_session"
	oidcCSRFCookie    = "ngstone_oidc_csrf"
)

type adminAuthContextKey struct{}

type adminAuth struct {
	Principal oidc.Principal
	AuthType  string
	CSRF      string
}

func withAdminAuth(ctx context.Context, auth adminAuth) context.Context {
	return context.WithValue(ctx, adminAuthContextKey{}, auth)
}

func adminAuthFromContext(ctx context.Context) (adminAuth, bool) {
	auth, ok := ctx.Value(adminAuthContextKey{}).(adminAuth)
	return auth, ok
}

func (s *Server) oidcSessionFromRequest(r *http.Request) (oidc.Session, bool) {
	if s == nil || s.oidc == nil || s.oidcCodec == nil {
		return oidc.Session{}, false
	}
	cookie, err := r.Cookie(oidcSessionCookie)
	if err != nil || cookie.Value == "" {
		return oidc.Session{}, false
	}
	var session oidc.Session
	if err := s.oidcCodec.Decode(cookie.Value, &session); err != nil {
		return oidc.Session{}, false
	}
	if session.Subject == "" || session.CSRF == "" || !oidc.HasRole(session.Role, oidc.RoleViewer) || session.ExpiresAt.IsZero() || !time.Now().Before(session.ExpiresAt) {
		return oidc.Session{}, false
	}
	return session, true
}

func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil || s.oidcCodec == nil {
		writeAdminError(w, http.StatusNotFound, "oidc_disabled", "OIDC login is not configured")
		return
	}
	if r.Method != http.MethodGet {
		writeAdminMethodNotAllowed(w, http.MethodGet)
		return
	}
	authorizationURL, state, err := s.oidc.AuthorizationURL(r.Context())
	if err != nil {
		writeAdminError(w, http.StatusBadGateway, "oidc_unavailable", "OIDC provider discovery failed")
		return
	}
	encodedState, err := s.oidcCodec.Encode(state)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "internal_error", "could not create OIDC login state")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookie,
		Value:    encodedState,
		Path:     "/api/v1/auth/oidc",
		MaxAge:   int(oidc.StateLifetime / time.Second),
		HttpOnly: true,
		Secure:   s.oidcSecureCookie(),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, authorizationURL, http.StatusFound)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil || s.oidcCodec == nil {
		writeAdminError(w, http.StatusNotFound, "oidc_disabled", "OIDC login is not configured")
		return
	}
	if r.Method != http.MethodGet {
		writeAdminMethodNotAllowed(w, http.MethodGet)
		return
	}
	s.clearOIDCStateCookie(w)
	if r.URL.Query().Get("error") != "" {
		writeAdminError(w, http.StatusUnauthorized, "oidc_denied", "OIDC login was denied")
		return
	}
	cookie, err := r.Cookie(oidcStateCookie)
	if err != nil || cookie.Value == "" {
		writeAdminError(w, http.StatusBadRequest, "oidc_state_invalid", "OIDC login state is missing or expired")
		return
	}
	var state oidc.State
	if err := s.oidcCodec.Decode(cookie.Value, &state); err != nil || state.State == "" || time.Now().After(state.ExpiresAt) {
		writeAdminError(w, http.StatusBadRequest, "oidc_state_invalid", "OIDC login state is missing or expired")
		return
	}
	if subtle.ConstantTimeCompare([]byte(state.State), []byte(r.URL.Query().Get("state"))) != 1 {
		writeAdminError(w, http.StatusBadRequest, "oidc_state_invalid", "OIDC login state does not match")
		return
	}
	principal, err := s.oidc.Exchange(r.Context(), state, r.URL.Query().Get("code"))
	if err != nil {
		status := http.StatusBadGateway
		code := "oidc_exchange_failed"
		message := "OIDC provider authentication failed"
		if errors.Is(err, oidc.ErrForbidden) {
			status = http.StatusForbidden
			code = "oidc_forbidden"
			message = "your OIDC account is not assigned an ngstone role"
		}
		writeAdminError(w, status, code, message)
		return
	}
	session, err := oidc.NewSession(principal, time.Now().UTC(), oidc.SessionLifetime)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "internal_error", "could not create OIDC session")
		return
	}
	encodedSession, err := s.oidcCodec.Encode(session)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "internal_error", "could not create OIDC session")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oidcSessionCookie,
		Value:    encodedSession,
		Path:     "/",
		MaxAge:   int(oidc.SessionLifetime / time.Second),
		HttpOnly: true,
		Secure:   s.oidcSecureCookie(),
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     oidcCSRFCookie,
		Value:    session.CSRF,
		Path:     "/",
		MaxAge:   int(oidc.SessionLifetime / time.Second),
		HttpOnly: false,
		Secure:   s.oidcSecureCookie(),
		SameSite: http.SameSiteLaxMode,
	})
	s.recordEvent("info", "management OIDC login", map[string]string{
		"actor_id": principal.Subject,
		"role":     principal.Role,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleOIDCMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminMethodNotAllowed(w, http.MethodGet)
		return
	}
	auth, ok := adminAuthFromContext(r.Context())
	if !ok {
		writeAdminError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}
	writeAdminData(w, http.StatusOK, map[string]any{
		"principal": auth.Principal,
		"auth_type": auth.AuthType,
		"csrf":      auth.CSRF,
	})
}

func (s *Server) handleOIDCLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeAdminMethodNotAllowed(w, http.MethodGet, http.MethodPost)
		return
	}
	s.clearOIDCCookie(w, oidcSessionCookie, "/")
	s.clearOIDCCookie(w, oidcCSRFCookie, "/")
	s.clearOIDCStateCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) clearOIDCStateCookie(w http.ResponseWriter) {
	s.clearOIDCCookie(w, oidcStateCookie, "/api/v1/auth/oidc")
}

func (s *Server) clearOIDCCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: name != oidcCSRFCookie,
		Secure:   s.oidcSecureCookie(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) oidcSecureCookie() bool {
	return s.oidc != nil && !s.cfg.Insecure
}

func (s *Server) handleProtectedDashboardState(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r) {
		return
	}
	s.handleDashboardState(w, r)
}

func (s *Server) requiredAdminRole(r *http.Request) string {
	path := strings.TrimPrefix(r.URL.Path, adminapi.APIPrefix)
	if path == "" || path == "/" || path == "/status" || path == "/tunnels" || path == "/observability/tunnels" || path == "/auth/me" || r.URL.Path == "/api/state" {
		return oidc.RoleViewer
	}
	if path == "/screen-sessions" || strings.HasPrefix(path, "/screen-sessions/") {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			return oidc.RoleViewer
		}
		return oidc.RoleOperator
	}
	if strings.HasPrefix(path, "/credentials") || strings.HasPrefix(path, "/policies") || strings.HasPrefix(path, "/domains") || strings.HasSuffix(path, "/drain") {
		return oidc.RoleOperator
	}
	return oidc.RoleAdmin
}

func (s *Server) checkAdminCSRF(w http.ResponseWriter, r *http.Request, auth adminAuth) bool {
	if auth.AuthType != "oidc" || r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	cookie, err := r.Cookie(oidcCSRFCookie)
	if err != nil || cookie.Value == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(auth.CSRF)) != 1 || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Ngstone-CSRF")), []byte(auth.CSRF)) != 1 {
		writeAdminError(w, http.StatusForbidden, "csrf_required", "a valid X-Ngstone-CSRF header is required")
		return false
	}
	return true
}

func (s *Server) authorizeAdminRole(w http.ResponseWriter, r *http.Request, auth adminAuth) bool {
	if !oidc.HasRole(auth.Principal.Role, s.requiredAdminRole(r)) {
		writeAdminError(w, http.StatusForbidden, "forbidden", "your role cannot perform this operation")
		return false
	}
	return s.checkAdminCSRF(w, r, auth)
}

func adminAuthForRequest(r *http.Request) (adminAuth, bool) {
	return adminAuthFromContext(r.Context())
}

func (s *Server) oidcEnabled() bool {
	return s.oidc != nil && s.oidcCodec != nil
}
