package edge

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"ngstone/internal/adminapi"
	"ngstone/internal/credentials"
	"ngstone/internal/oidc"
	"ngstone/internal/policy"
	"ngstone/internal/storage"
)

const (
	adminMaxBodyBytes         = 64 << 10
	adminDefaultCredentialTTL = 24 * time.Hour
)

func (s *Server) handleAdminAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, adminapi.APIPrefix)
	switch path {
	case "/auth/oidc/start":
		s.handleOIDCStart(w, r)
		return
	case "/auth/oidc/callback":
		s.handleOIDCCallback(w, r)
		return
	case "/auth/logout":
		s.handleOIDCLogout(w, r)
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}
	switch {
	case path == "" || path == "/":
		s.handleAdminIndex(w, r)
	case path == "/auth/me":
		s.handleOIDCMe(w, r)
	case path == "/status":
		s.handleAdminStatus(w, r)
	case path == "/tunnels":
		s.handleAdminTunnels(w, r)
	case path == "/observability/tunnels":
		s.handleAdminObservability(w, r)
	case path == "/credentials":
		s.handleAdminCredentials(w, r)
	case strings.HasPrefix(path, "/credentials/"):
		s.handleAdminCredential(w, r, strings.TrimPrefix(path, "/credentials/"))
	case path == "/policies":
		s.handleAdminPolicies(w, r)
	case strings.HasPrefix(path, "/policies/"):
		s.handleAdminPolicy(w, r, strings.TrimPrefix(path, "/policies/"))
	case path == "/domains":
		s.handleAdminDomains(w, r)
	case strings.HasPrefix(path, "/domains/"):
		s.handleAdminDomain(w, r, strings.TrimPrefix(path, "/domains/"))
	case path == "/screen-sessions":
		s.handleAdminScreenSessions(w, r)
	case strings.HasPrefix(path, "/screen-sessions/"):
		s.handleAdminScreenSession(w, r, strings.TrimPrefix(path, "/screen-sessions/"))
	case strings.HasPrefix(path, "/tunnels/") && strings.HasSuffix(path, "/drain"):
		rawHost := strings.TrimSuffix(strings.TrimPrefix(path, "/tunnels/"), "/drain")
		s.handleAdminDrain(w, r, rawHost)
	default:
		writeAdminError(w, http.StatusNotFound, "not_found", "management resource not found")
	}
}

func (s *Server) authorizeAdmin(w http.ResponseWriter, r *http.Request) bool {
	if session, ok := s.oidcSessionFromRequest(r); ok {
		auth := adminAuth{Principal: session.Principal, AuthType: "oidc", CSRF: session.CSRF}
		if !s.authorizeAdminRole(w, r, auth) {
			return false
		}
		*r = *r.WithContext(withAdminAuth(r.Context(), auth))
		return true
	}
	if len(s.cfg.AdminTokenSHA256) == 0 {
		if s.oidcEnabled() {
			w.Header().Set("WWW-Authenticate", `OIDC realm="ngstoned management API"`)
			writeAdminError(w, http.StatusUnauthorized, "unauthorized", "OIDC login or a management bearer token is required")
			return false
		}
		if isLoopbackRemote(r.RemoteAddr) {
			auth := adminAuth{Principal: oidc.Principal{Subject: "admin", Role: oidc.RoleAdmin}, AuthType: "loopback"}
			*r = *r.WithContext(withAdminAuth(r.Context(), auth))
			return true
		}
		writeAdminError(w, http.StatusForbidden, "loopback_required", "management API is available only from loopback")
		return false
	}
	remoteIP := adminRemoteIP(r.RemoteAddr)
	if s.adminLimiter != nil && !s.adminLimiter.allowed(remoteIP) {
		w.Header().Set("Retry-After", "60")
		writeAdminError(w, http.StatusTooManyRequests, "rate_limited", "too many management authentication attempts")
		return false
	}
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, token, ok := strings.Cut(raw, " ")
	if !ok || !strings.EqualFold(scheme, "bearer") || token == "" {
		if s.adminLimiter != nil {
			s.adminLimiter.recordFailure(remoteIP)
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="ngstoned management API"`)
		writeAdminError(w, http.StatusUnauthorized, "unauthorized", "valid bearer authentication is required")
		return false
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	if subtle.ConstantTimeCompare(sum[:], s.cfg.AdminTokenSHA256) != 1 {
		if s.adminLimiter != nil {
			s.adminLimiter.recordFailure(remoteIP)
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="ngstoned management API"`)
		writeAdminError(w, http.StatusUnauthorized, "unauthorized", "valid bearer authentication is required")
		return false
	}
	auth := adminAuth{Principal: oidc.Principal{Subject: "admin", Role: oidc.RoleAdmin}, AuthType: "bearer"}
	*r = *r.WithContext(withAdminAuth(r.Context(), auth))
	return true
}

func adminRemoteIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err == nil && host != "" {
		return host
	}
	return remote
}

func isLoopbackRemote(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func (s *Server) handleAdminIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminMethodNotAllowed(w, http.MethodGet)
		return
	}
	writeAdminData(w, http.StatusOK, map[string]any{
		"version":   1,
		"resources": []string{"status", "tunnels", "observability/tunnels", "credentials", "policies", "domains", "screen-sessions"},
	})
}

func (s *Server) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminMethodNotAllowed(w, http.MethodGet)
		return
	}
	writeAdminData(w, http.StatusOK, s.dashboardState(r))
}

func (s *Server) handleAdminTunnels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminMethodNotAllowed(w, http.MethodGet)
		return
	}
	tunnels := s.dashboardTunnelsForContext(r.Context())
	if tunnels == nil {
		tunnels = []dashboardTunnel{}
	}
	writeAdminData(w, http.StatusOK, tunnels)
}

func (s *Server) handleAdminObservability(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminMethodNotAllowed(w, http.MethodGet)
		return
	}
	metrics := s.observabilitySnapshot(r.Context())
	if metrics == nil {
		metrics = []adminapi.TunnelObservability{}
	}
	writeAdminData(w, http.StatusOK, metrics)
}

func (s *Server) handleAdminCredentials(w http.ResponseWriter, r *http.Request) {
	if s.credentialStore == nil {
		writeAdminError(w, http.StatusConflict, "scoped_credentials_disabled", "scoped credentials are not configured")
		return
	}
	switch r.Method {
	case http.MethodGet:
		list, err := s.credentialStore.ListForOwnerContext(r.Context(), adminOwnerID(r))
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "internal_error", "could not read credentials")
			return
		}
		writeAdminData(w, http.StatusOK, list)
	case http.MethodPost:
		var request adminapi.CredentialIssueRequest
		if err := decodeAdminJSON(w, r, &request); err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid_json", err.Error())
			return
		}
		ttl := adminDefaultCredentialTTL
		if request.TTL != "" {
			parsed, err := time.ParseDuration(request.TTL)
			if err != nil {
				writeAdminError(w, http.StatusUnprocessableEntity, "validation_error", "ttl must be a valid duration")
				return
			}
			ttl = parsed
		}
		issued, err := s.credentialStore.IssueContext(r.Context(), credentials.Spec{
			Kind:       request.Kind,
			Subdomain:  request.Subdomain,
			RemotePort: request.RemotePort,
			OwnerID:    adminOwnerID(r),
		}, ttl)
		if err != nil {
			writeAdminError(w, http.StatusUnprocessableEntity, "validation_error", err.Error())
			return
		}
		s.recordEvent("info", "management credential issued", map[string]string{
			"credential_id": issued.Credential.ID,
			"kind":          issued.Credential.Kind,
		})
		writeAdminData(w, http.StatusCreated, adminapi.CredentialIssueResponse{
			Credential: issued.Credential,
			Token:      issued.Token,
		})
	default:
		writeAdminMethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) handleAdminCredential(w http.ResponseWriter, r *http.Request, rawID string) {
	if s.credentialStore == nil {
		writeAdminError(w, http.StatusConflict, "scoped_credentials_disabled", "scoped credentials are not configured")
		return
	}
	id, err := url.PathUnescape(rawID)
	if err != nil || strings.ContainsAny(id, "/\\") || id == "" {
		writeAdminError(w, http.StatusNotFound, "not_found", "credential not found")
		return
	}
	if r.Method != http.MethodDelete {
		writeAdminMethodNotAllowed(w, http.MethodDelete)
		return
	}
	if err := s.credentialStore.RevokeForOwnerContext(r.Context(), id, adminOwnerID(r)); err != nil {
		if errors.Is(err, credentials.ErrNotFound) {
			writeAdminError(w, http.StatusNotFound, "not_found", "credential not found")
			return
		}
		writeAdminError(w, http.StatusInternalServerError, "internal_error", "could not revoke credential")
		return
	}
	s.recordCredentialEventForID(id, "credential_revoked")
	s.recordEvent("info", "management credential revoked", map[string]string{"credential_id": id})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminPolicies(w http.ResponseWriter, r *http.Request) {
	if s.storage == nil {
		writeAdminError(w, http.StatusConflict, "durable_storage_disabled", "durable control-plane storage is not configured")
		return
	}
	ownerID := adminOwnerID(r)
	switch r.Method {
	case http.MethodGet:
		list, err := s.storage.ListTrafficPolicies(r.Context(), ownerID)
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "internal_error", "could not read traffic policies")
			return
		}
		out := make([]adminapi.TrafficPolicy, 0, len(list))
		for _, value := range list {
			out = append(out, adminapi.TrafficPolicy{
				ID:        value.ID,
				Name:      value.Name,
				OwnerID:   value.OwnerID,
				Digest:    value.Digest,
				Policy:    json.RawMessage(value.PolicyJSON),
				CreatedAt: value.CreatedAt,
				UpdatedAt: value.UpdatedAt,
			})
		}
		writeAdminData(w, http.StatusOK, out)
	case http.MethodPost:
		var request adminapi.TrafficPolicyRequest
		if err := decodeAdminJSON(w, r, &request); err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid_json", err.Error())
			return
		}
		name := strings.TrimSpace(request.Name)
		if name == "" || len(name) > 128 {
			writeAdminError(w, http.StatusUnprocessableEntity, "validation_error", "policy name must be between 1 and 128 characters")
			return
		}
		value, err := policy.Parse(request.Policy)
		if err != nil {
			writeAdminError(w, http.StatusUnprocessableEntity, "validation_error", "policy is invalid")
			return
		}
		id, digest, err := s.storage.UpsertTrafficPolicy(r.Context(), name, ownerID, value)
		if err != nil {
			if errors.Is(err, storage.ErrPolicyConflict) {
				writeAdminError(w, http.StatusConflict, "policy_conflict", "another traffic policy already uses this name or policy digest")
				return
			}
			if !errors.Is(err, storage.ErrInvalid) {
				writeAdminError(w, http.StatusInternalServerError, "internal_error", "could not save traffic policy")
				return
			}
			writeAdminError(w, http.StatusUnprocessableEntity, "validation_error", err.Error())
			return
		}
		list, err := s.storage.ListTrafficPolicies(r.Context(), ownerID)
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "internal_error", "could not read saved traffic policy")
			return
		}
		for _, saved := range list {
			if saved.ID != id {
				continue
			}
			s.recordEvent("info", "management traffic policy saved", map[string]string{"policy_id": saved.ID, "policy_name": saved.Name})
			writeAdminData(w, http.StatusCreated, adminapi.TrafficPolicy{ID: saved.ID, Name: saved.Name, OwnerID: saved.OwnerID, Digest: digest, Policy: json.RawMessage(saved.PolicyJSON), CreatedAt: saved.CreatedAt, UpdatedAt: saved.UpdatedAt})
			return
		}
		writeAdminError(w, http.StatusInternalServerError, "internal_error", "saved traffic policy was not found")
	default:
		writeAdminMethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) handleAdminPolicy(w http.ResponseWriter, r *http.Request, rawID string) {
	if s.storage == nil {
		writeAdminError(w, http.StatusConflict, "durable_storage_disabled", "durable control-plane storage is not configured")
		return
	}
	if r.Method != http.MethodDelete {
		writeAdminMethodNotAllowed(w, http.MethodDelete)
		return
	}
	id, err := url.PathUnescape(rawID)
	if err != nil || strings.ContainsAny(id, "/\\") || id == "" {
		writeAdminError(w, http.StatusNotFound, "not_found", "traffic policy not found")
		return
	}
	if err := s.storage.DeleteTrafficPolicy(r.Context(), id, adminOwnerID(r)); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeAdminError(w, http.StatusNotFound, "not_found", "traffic policy not found")
			return
		}
		if errors.Is(err, storage.ErrTunnelConflict) {
			writeAdminError(w, http.StatusConflict, "policy_in_use", "traffic policy is attached to a tunnel")
			return
		}
		writeAdminError(w, http.StatusInternalServerError, "internal_error", "could not delete traffic policy")
		return
	}
	s.recordEvent("info", "management traffic policy deleted", map[string]string{"policy_id": id})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminDomains(w http.ResponseWriter, r *http.Request) {
	if s.storage == nil {
		writeAdminError(w, http.StatusConflict, "durable_storage_disabled", "durable control-plane storage is not configured")
		return
	}
	ownerID := adminOwnerID(r)
	switch r.Method {
	case http.MethodGet:
		list, err := s.storage.ListCustomDomains(r.Context(), ownerID)
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "internal_error", "could not read custom domains")
			return
		}
		writeAdminData(w, http.StatusOK, list)
	case http.MethodPost:
		var request adminapi.CustomDomainRequest
		if err := decodeAdminJSON(w, r, &request); err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid_json", err.Error())
			return
		}
		domain, err := s.storage.CreateCustomDomain(r.Context(), storage.CustomDomainSpec{Domain: request.Domain, TunnelID: request.TunnelID, OwnerID: ownerID, Status: request.Status})
		if err != nil {
			if errors.Is(err, storage.ErrTunnelConflict) {
				writeAdminError(w, http.StatusConflict, "domain_taken", "custom domain is already registered")
				return
			}
			if errors.Is(err, storage.ErrNotFound) {
				writeAdminError(w, http.StatusNotFound, "tunnel_not_found", "associated tunnel not found")
				return
			}
			if !errors.Is(err, storage.ErrInvalid) {
				writeAdminError(w, http.StatusInternalServerError, "internal_error", "could not save custom domain")
				return
			}
			writeAdminError(w, http.StatusUnprocessableEntity, "validation_error", "custom domain is invalid")
			return
		}
		s.recordEvent("info", "management custom domain registered", map[string]string{"domain_id": domain.ID, "domain": domain.Domain})
		writeAdminData(w, http.StatusCreated, domain)
	default:
		writeAdminMethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) handleAdminDomain(w http.ResponseWriter, r *http.Request, rawID string) {
	if s.storage == nil {
		writeAdminError(w, http.StatusConflict, "durable_storage_disabled", "durable control-plane storage is not configured")
		return
	}
	if r.Method != http.MethodDelete {
		writeAdminMethodNotAllowed(w, http.MethodDelete)
		return
	}
	id, err := url.PathUnescape(rawID)
	if err != nil || strings.ContainsAny(id, "/\\") || id == "" {
		writeAdminError(w, http.StatusNotFound, "not_found", "custom domain not found")
		return
	}
	if err := s.storage.DeleteCustomDomain(r.Context(), id, adminOwnerID(r)); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeAdminError(w, http.StatusNotFound, "not_found", "custom domain not found")
			return
		}
		writeAdminError(w, http.StatusInternalServerError, "internal_error", "could not delete custom domain")
		return
	}
	s.recordEvent("info", "management custom domain deleted", map[string]string{"domain_id": id})
	w.WriteHeader(http.StatusNoContent)
}

func adminOwnerID(r *http.Request) string {
	if auth, ok := adminAuthForRequest(r); ok {
		if oidc.HasRole(auth.Principal.Role, oidc.RoleAdmin) {
			return credentials.GlobalOwnerID
		}
		subject := strings.TrimSpace(auth.Principal.Subject)
		if subject != "" && subject != credentials.GlobalOwnerID && subject != credentials.InvalidOwnerID {
			return subject
		}
	}
	return credentials.InvalidOwnerID
}

func (s *Server) handleAdminDrain(w http.ResponseWriter, r *http.Request, rawHost string) {
	if r.Method != http.MethodPost {
		writeAdminMethodNotAllowed(w, http.MethodPost)
		return
	}
	host, err := s.adminTunnelHost(rawHost)
	if err != nil {
		writeAdminError(w, http.StatusUnprocessableEntity, "validation_error", err.Error())
		return
	}
	sessions := s.sessionsForTunnel(host)
	if len(sessions) == 0 {
		writeAdminError(w, http.StatusNotFound, "not_found", "tunnel not found")
		return
	}
	ownerID := adminOwnerID(r)
	if ownerID != credentials.GlobalOwnerID {
		for _, session := range sessions {
			if ownerID == credentials.InvalidOwnerID || session == nil || session.Credential == nil || session.Credential.OwnerID == "" || session.Credential.OwnerID != ownerID {
				writeAdminError(w, http.StatusNotFound, "not_found", "tunnel not found")
				return
			}
		}
	}
	for _, session := range sessions {
		if session == nil || session.Sess == nil {
			continue
		}
		go s.drainSession(session, session.Sess.Control(), "management drain")
	}
	s.recordEvent("info", "management tunnel drain", map[string]string{
		"hostname":   host,
		"connectors": fmt.Sprintf("%d", len(sessions)),
	})
	writeAdminData(w, http.StatusAccepted, adminapi.DrainResponse{Hostname: host, Connectors: len(sessions)})
}

func (s *Server) adminTunnelHost(rawHost string) (string, error) {
	host, err := url.PathUnescape(rawHost)
	if err != nil {
		return "", errors.New("tunnel hostname is invalid")
	}
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" || strings.ContainsAny(host, "/\\") {
		return "", errors.New("tunnel hostname is invalid")
	}
	host = stripPort(host)
	domain := strings.TrimSpace(strings.ToLower(s.cfg.Domain))
	if domain == "" {
		return "", errors.New("tunnel domain is not configured")
	}
	if !strings.Contains(host, ".") {
		if !validSubdomain(host) {
			return "", errors.New("tunnel subdomain is invalid")
		}
		return host + "." + domain, nil
	}
	if host == domain {
		return host, nil
	}
	suffix := "." + domain
	if !strings.HasSuffix(host, suffix) || !validSubdomain(strings.TrimSuffix(host, suffix)) {
		return "", errors.New("tunnel hostname must belong to the configured domain")
	}
	return host, nil
}

func (s *Server) sessionsForTunnel(host string) []*AgentSession {
	seen := make(map[*AgentSession]struct{})
	var sessions []*AgentSession
	if s.registry != nil {
		for _, session := range s.registry.sessionsForHost(host) {
			if session == nil || session.Sess == nil {
				continue
			}
			if _, ok := seen[session]; !ok {
				seen[session] = struct{}{}
				sessions = append(sessions, session)
			}
		}
	}
	if s.tcpMgr != nil {
		for _, session := range s.tcpMgr.sessionsForHostname(host) {
			if session == nil || session.Sess == nil {
				continue
			}
			if _, ok := seen[session]; !ok {
				seen[session] = struct{}{}
				sessions = append(sessions, session)
			}
		}
	}
	return sessions
}

func decodeAdminJSON(w http.ResponseWriter, r *http.Request, output any) error {
	r.Body = http.MaxBytesReader(w, r.Body, adminMaxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain one JSON value")
		}
		return err
	}
	return nil
}

func writeAdminData(w http.ResponseWriter, status int, data any) {
	setOpsHeaders(w, "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func writeAdminError(w http.ResponseWriter, status int, code, message string) {
	setOpsHeaders(w, "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

func writeAdminMethodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeAdminError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method is not allowed")
}
