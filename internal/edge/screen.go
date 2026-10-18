package edge

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/net/websocket"

	"ngstone/internal/adminapi"
	"ngstone/internal/oidc"
)

const (
	screenPathPrefix           = "/_ngstone/screen/"
	screenSignalSuffix         = "/signal"
	screenWebSocketSubprotocol = "ngstone-screen-v1"
	screenTokenProtocolPrefix  = "ngstone-screen-token-"
	screenDefaultTTL           = 30 * time.Minute
	screenMaxTTL               = 24 * time.Hour
	screenMaxSignalBytes       = 64 << 10
	screenHeartbeatInterval    = 15 * time.Second
	screenHeartbeatTimeout     = 45 * time.Second
	screenTokenBytes           = 32
	screenIDBytes              = 16
)

var (
	errScreenNotFound = errors.New("screen session not found")
	errScreenOccupied = errors.New("screen session role is already connected")
)

type screenRole string

const (
	screenRoleSender screenRole = "sender"
	screenRoleViewer screenRole = "viewer"
)

type screenSignal struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

type screenPeer struct {
	ws      *websocket.Conn
	writeMu sync.Mutex
}

type screenSession struct {
	ID              string
	Name            string
	OwnerID         string
	ViewerURL       string
	MaxViewers      int
	SFU             bool
	CreatedAt       time.Time
	ExpiresAt       time.Time
	SenderTokenHash [sha256.Size]byte
	ViewerTokenHash [sha256.Size]byte
	Sender          *screenPeer
	Viewer          *screenPeer
	Viewers         map[*screenPeer]struct{}
}

type screenIssued struct {
	Session     adminapi.ScreenSession
	SenderToken string
	ViewerToken string
}

type screenRegistry struct {
	mu       sync.Mutex
	sessions map[string]*screenSession
	onExpire func([]string)
}

func newScreenRegistry() *screenRegistry {
	return &screenRegistry{sessions: make(map[string]*screenSession)}
}

func (r *screenRegistry) create(owner, name string, ttl time.Duration, viewerURL func(string) string) (screenIssued, error) {
	return r.createWithOptions(owner, name, ttl, 1, viewerURL)
}

func (r *screenRegistry) createWithOptions(owner, name string, ttl time.Duration, maxViewers int, viewerURL func(string) string) (screenIssued, error) {
	if r == nil {
		return screenIssued{}, errors.New("screen registry is unavailable")
	}
	if ttl <= 0 || ttl > screenMaxTTL {
		return screenIssued{}, errors.New("screen session ttl must be positive and no longer than 24h")
	}
	if maxViewers < 1 || maxViewers > defaultScreenMaxViewers {
		return screenIssued{}, fmt.Errorf("screen session max viewers must be between 1 and %d", defaultScreenMaxViewers)
	}
	if viewerURL == nil {
		return screenIssued{}, errors.New("screen viewer URL builder is unavailable")
	}
	now := time.Now().UTC()
	senderToken, senderHash, err := newScreenToken()
	if err != nil {
		return screenIssued{}, err
	}
	viewerToken, viewerHash, err := newScreenToken()
	if err != nil {
		return screenIssued{}, err
	}
	for attempt := 0; attempt < 4; attempt++ {
		id, err := newScreenID()
		if err != nil {
			return screenIssued{}, err
		}
		session := &screenSession{
			ID:              id,
			Name:            name,
			OwnerID:         owner,
			ViewerURL:       viewerURL(id),
			MaxViewers:      maxViewers,
			SFU:             maxViewers > 1,
			CreatedAt:       now,
			ExpiresAt:       now.Add(ttl),
			SenderTokenHash: senderHash,
			ViewerTokenHash: viewerHash,
			Viewers:         make(map[*screenPeer]struct{}),
		}
		r.mu.Lock()
		if r.sessions == nil {
			r.sessions = make(map[string]*screenSession)
		}
		expired := r.pruneLocked(now)
		_, exists := r.sessions[id]
		if !exists {
			r.sessions[id] = session
			metadata := screenSessionSnapshot(session, now)
			r.mu.Unlock()
			r.notifyExpired(expired)
			return screenIssued{
				Session:     metadata,
				SenderToken: senderToken,
				ViewerToken: viewerToken,
			}, nil
		}
		r.mu.Unlock()
		r.notifyExpired(expired)
	}
	return screenIssued{}, errors.New("could not allocate a screen session id")
}

func (r *screenRegistry) authenticate(id, token string) (screenRole, bool) {
	if r == nil || id == "" || token == "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	r.mu.Lock()
	expired := r.pruneLocked(now)
	session, ok := r.sessions[id]
	if !ok {
		r.mu.Unlock()
		r.notifyExpired(expired)
		return "", false
	}
	senderMatch := subtle.ConstantTimeCompare(sum[:], session.SenderTokenHash[:])
	viewerMatch := subtle.ConstantTimeCompare(sum[:], session.ViewerTokenHash[:])
	var role screenRole
	switch {
	case senderMatch == 1:
		role = screenRoleSender
	case viewerMatch == 1:
		role = screenRoleViewer
	default:
		r.mu.Unlock()
		r.notifyExpired(expired)
		return "", false
	}
	r.mu.Unlock()
	r.notifyExpired(expired)
	return role, true
}

func (r *screenRegistry) attach(id string, role screenRole, peer *screenPeer) (time.Time, *screenPeer, error) {
	if r == nil || peer == nil {
		return time.Time{}, nil, errScreenNotFound
	}
	now := time.Now().UTC()
	r.mu.Lock()
	expired := r.pruneLocked(now)
	session, ok := r.sessions[id]
	if !ok {
		r.mu.Unlock()
		r.notifyExpired(expired)
		return time.Time{}, nil, errScreenNotFound
	}
	var other *screenPeer
	switch role {
	case screenRoleSender:
		if session.Sender != nil {
			r.mu.Unlock()
			r.notifyExpired(expired)
			return time.Time{}, nil, errScreenOccupied
		}
		session.Sender = peer
		other = session.Viewer
	case screenRoleViewer:
		if session.SFU {
			if len(session.Viewers) >= session.MaxViewers {
				r.mu.Unlock()
				r.notifyExpired(expired)
				return time.Time{}, nil, errScreenOccupied
			}
			if session.Viewers == nil {
				session.Viewers = make(map[*screenPeer]struct{})
			}
			session.Viewers[peer] = struct{}{}
			other = session.Sender
		} else {
			if session.Viewer != nil {
				r.mu.Unlock()
				r.notifyExpired(expired)
				return time.Time{}, nil, errScreenOccupied
			}
			session.Viewer = peer
			other = session.Sender
		}
	default:
		r.mu.Unlock()
		r.notifyExpired(expired)
		return time.Time{}, nil, errScreenNotFound
	}
	r.mu.Unlock()
	r.notifyExpired(expired)
	return session.ExpiresAt, other, nil
}

func (r *screenRegistry) available(id string, role screenRole) bool {
	if r == nil {
		return false
	}
	now := time.Now().UTC()
	r.mu.Lock()
	expired := r.pruneLocked(now)
	session, ok := r.sessions[id]
	if !ok {
		r.mu.Unlock()
		r.notifyExpired(expired)
		return false
	}
	available := false
	switch role {
	case screenRoleSender:
		available = session.Sender == nil
	case screenRoleViewer:
		if session.SFU {
			available = len(session.Viewers) < session.MaxViewers
		} else {
			available = session.Viewer == nil
		}
	}
	r.mu.Unlock()
	r.notifyExpired(expired)
	return available
}

func (r *screenRegistry) other(id string, role screenRole, peer *screenPeer) *screenPeer {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	session, ok := r.sessions[id]
	if !ok {
		return nil
	}
	switch role {
	case screenRoleSender:
		if session.Sender != peer {
			return nil
		}
		return session.Viewer
	case screenRoleViewer:
		if session.SFU {
			if _, ok := session.Viewers[peer]; !ok {
				return nil
			}
			return session.Sender
		}
		if session.Viewer != peer {
			return nil
		}
		return session.Sender
	default:
		return nil
	}
}

func (r *screenRegistry) detach(id string, role screenRole, peer *screenPeer) *screenPeer {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	session, ok := r.sessions[id]
	if !ok {
		return nil
	}
	switch role {
	case screenRoleSender:
		if session.Sender != peer {
			return nil
		}
		session.Sender = nil
		return session.Viewer
	case screenRoleViewer:
		if session.SFU {
			if _, ok := session.Viewers[peer]; !ok {
				return nil
			}
			delete(session.Viewers, peer)
			return session.Sender
		}
		if session.Viewer != peer {
			return nil
		}
		session.Viewer = nil
		return session.Sender
	default:
		return nil
	}
}

func (r *screenRegistry) list(owner string, all bool) []adminapi.ScreenSession {
	if r == nil {
		return nil
	}
	now := time.Now().UTC()
	r.mu.Lock()
	expired := r.pruneLocked(now)
	items := make([]adminapi.ScreenSession, 0, len(r.sessions))
	for _, session := range r.sessions {
		if !all && session.OwnerID != owner {
			continue
		}
		items = append(items, screenSessionSnapshot(session, now))
	}
	r.mu.Unlock()
	r.notifyExpired(expired)
	return items
}

func (r *screenRegistry) get(id, owner string, all bool) (adminapi.ScreenSession, error) {
	if r == nil {
		return adminapi.ScreenSession{}, errScreenNotFound
	}
	now := time.Now().UTC()
	r.mu.Lock()
	expired := r.pruneLocked(now)
	session, ok := r.sessions[id]
	if !ok || !all && session.OwnerID != owner {
		r.mu.Unlock()
		r.notifyExpired(expired)
		return adminapi.ScreenSession{}, errScreenNotFound
	}
	item := screenSessionSnapshot(session, now)
	r.mu.Unlock()
	r.notifyExpired(expired)
	return item, nil
}

func (r *screenRegistry) revoke(id, owner string, all bool) error {
	if r == nil {
		return errScreenNotFound
	}
	now := time.Now().UTC()
	r.mu.Lock()
	expired := r.pruneLocked(now)
	session, ok := r.sessions[id]
	if !ok || !all && session.OwnerID != owner {
		r.mu.Unlock()
		r.notifyExpired(expired)
		return errScreenNotFound
	}
	delete(r.sessions, id)
	sender := session.Sender
	viewers := make([]*screenPeer, 0, 1)
	if session.SFU {
		viewers = make([]*screenPeer, 0, len(session.Viewers))
		for peer := range session.Viewers {
			viewers = append(viewers, peer)
		}
	} else if session.Viewer != nil {
		viewers = append(viewers, session.Viewer)
	}
	r.mu.Unlock()
	r.notifyExpired(append(expired, id))
	closeScreenPeer(sender)
	for _, viewer := range viewers {
		closeScreenPeer(viewer)
	}
	return nil
}

func closeScreenPeer(peer *screenPeer) {
	if peer == nil || peer.ws == nil {
		return
	}
	_ = peer.ws.Close()
}

func (r *screenRegistry) exists(id string) bool {
	if r == nil {
		return false
	}
	now := time.Now().UTC()
	r.mu.Lock()
	expired := r.pruneLocked(now)
	_, ok := r.sessions[id]
	r.mu.Unlock()
	r.notifyExpired(expired)
	return ok
}

func (r *screenRegistry) signalConfig(id string, turnURLs []string, turnSecret string) (screenSignalConfig, bool) {
	if r == nil {
		return screenSignalConfig{}, false
	}
	now := time.Now().UTC()
	r.mu.Lock()
	expired := r.pruneLocked(now)
	session, ok := r.sessions[id]
	if !ok {
		r.mu.Unlock()
		r.notifyExpired(expired)
		return screenSignalConfig{}, false
	}
	config := screenSignalConfigFor(session, turnURLs, turnSecret)
	r.mu.Unlock()
	r.notifyExpired(expired)
	return config, true
}

func (r *screenRegistry) isSFU(id string) bool {
	if r == nil {
		return false
	}
	now := time.Now().UTC()
	r.mu.Lock()
	expired := r.pruneLocked(now)
	session, ok := r.sessions[id]
	result := ok && session.SFU
	r.mu.Unlock()
	r.notifyExpired(expired)
	return result
}

func (r *screenRegistry) connectedPeers(id string) (*screenPeer, []*screenPeer, bool) {
	if r == nil {
		return nil, nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	session, ok := r.sessions[id]
	if !ok {
		return nil, nil, false
	}
	viewers := make([]*screenPeer, 0, 1)
	if session.SFU {
		viewers = make([]*screenPeer, 0, len(session.Viewers))
		for peer := range session.Viewers {
			viewers = append(viewers, peer)
		}
	} else if session.Viewer != nil {
		viewers = append(viewers, session.Viewer)
	}
	return session.Sender, viewers, true
}

func (r *screenRegistry) pruneLocked(now time.Time) []string {
	expired := make([]string, 0)
	for id, session := range r.sessions {
		if !now.Before(session.ExpiresAt) {
			delete(r.sessions, id)
			expired = append(expired, id)
		}
	}
	return expired
}

func (r *screenRegistry) notifyExpired(ids []string) {
	if r == nil || len(ids) == 0 || r.onExpire == nil {
		return
	}
	r.onExpire(ids)
}

func (r *screenRegistry) active(id string, now time.Time) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	session, ok := r.sessions[id]
	result := ok && now.Before(session.ExpiresAt)
	r.mu.Unlock()
	return result
}

func screenSessionSnapshot(session *screenSession, now time.Time) adminapi.ScreenSession {
	status := "waiting"
	viewerCount := 0
	if session.SFU {
		viewerCount = len(session.Viewers)
	} else if session.Viewer != nil {
		viewerCount = 1
	}
	if session.Sender != nil && viewerCount > 0 {
		status = "active"
	}
	if !now.Before(session.ExpiresAt) {
		status = "expired"
	}
	return adminapi.ScreenSession{
		ID:              session.ID,
		Name:            session.Name,
		OwnerID:         session.OwnerID,
		Status:          status,
		ViewerURL:       session.ViewerURL,
		MaxViewers:      session.MaxViewers,
		ViewerCount:     viewerCount,
		SFU:             session.SFU,
		CreatedAt:       session.CreatedAt,
		ExpiresAt:       session.ExpiresAt,
		SenderConnected: session.Sender != nil,
		ViewerConnected: viewerCount > 0,
	}
}

func newScreenID() (string, error) {
	buf := make([]byte, screenIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("creating screen session id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func newScreenToken() (string, [sha256.Size]byte, error) {
	buf := make([]byte, screenTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", [sha256.Size]byte{}, fmt.Errorf("creating screen session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	return token, sha256.Sum256([]byte(token)), nil
}

func (p *screenPeer) send(message screenSignal) error {
	if p == nil || p.ws == nil {
		return errors.New("screen peer is unavailable")
	}
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	if len(data) > screenMaxSignalBytes {
		return errors.New("screen signaling message is too large")
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return websocket.Message.Send(p.ws, string(data))
}

func (s *Server) handleAdminScreenSessions(w http.ResponseWriter, r *http.Request) {
	if s.screens == nil {
		writeAdminError(w, http.StatusServiceUnavailable, "screen_sharing_unavailable", "screen sharing is not configured")
		return
	}
	switch r.Method {
	case http.MethodGet:
		items := s.screens.list(adminOwnerID(r), adminIsGlobalAdmin(r))
		if items == nil {
			items = []adminapi.ScreenSession{}
		}
		writeAdminData(w, http.StatusOK, items)
	case http.MethodPost:
		var request adminapi.ScreenSessionRequest
		if err := decodeAdminJSON(w, r, &request); err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid_json", err.Error())
			return
		}
		name, err := normalizeScreenName(request.Name)
		if err != nil {
			writeAdminError(w, http.StatusUnprocessableEntity, "validation_error", err.Error())
			return
		}
		ttl, err := parseScreenTTL(request.TTL)
		if err != nil {
			writeAdminError(w, http.StatusUnprocessableEntity, "validation_error", err.Error())
			return
		}
		maxViewers := request.MaxViewers
		if maxViewers == 0 {
			maxViewers = 1
		}
		maxAllowed := s.screenMaxViewers
		if maxAllowed == 0 {
			maxAllowed = defaultScreenMaxViewers
		}
		if maxViewers < 1 || maxViewers > maxAllowed {
			writeAdminError(w, http.StatusUnprocessableEntity, "validation_error", fmt.Sprintf("max_viewers must be between 1 and %d", maxAllowed))
			return
		}
		issued, err := s.screens.createWithOptions(adminOwnerID(r), name, ttl, maxViewers, func(id string) string {
			return s.screenViewerURL(r, id)
		})
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "internal_error", "could not create screen session")
			return
		}
		joinURL := screenJoinURL(issued.Session.ViewerURL, issued.ViewerToken)
		s.recordEvent("info", "screen session created", map[string]string{
			"screen_session_id":   issued.Session.ID,
			"screen_session_name": issued.Session.Name,
		})
		writeAdminData(w, http.StatusCreated, adminapi.ScreenSessionCreateResponse{
			Session:     issued.Session,
			SenderToken: issued.SenderToken,
			ViewerToken: issued.ViewerToken,
			ViewerURL:   joinURL,
		})
	default:
		writeAdminMethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) handleAdminScreenSession(w http.ResponseWriter, r *http.Request, rawID string) {
	if s.screens == nil {
		writeAdminError(w, http.StatusServiceUnavailable, "screen_sharing_unavailable", "screen sharing is not configured")
		return
	}
	id, err := url.PathUnescape(rawID)
	if err != nil || !isScreenSessionID(id) {
		writeAdminError(w, http.StatusNotFound, "not_found", "screen session not found")
		return
	}
	owner, all := adminOwnerID(r), adminIsGlobalAdmin(r)
	switch r.Method {
	case http.MethodGet:
		item, err := s.screens.get(id, owner, all)
		if err != nil {
			writeAdminError(w, http.StatusNotFound, "not_found", "screen session not found")
			return
		}
		writeAdminData(w, http.StatusOK, item)
	case http.MethodDelete:
		if err := s.screens.revoke(id, owner, all); err != nil {
			writeAdminError(w, http.StatusNotFound, "not_found", "screen session not found")
			return
		}
		s.closeScreenSFU(id)
		s.recordEvent("info", "screen session revoked", map[string]string{"screen_session_id": id})
		w.WriteHeader(http.StatusNoContent)
	default:
		writeAdminMethodNotAllowed(w, http.MethodGet, http.MethodDelete)
	}
}

func adminIsGlobalAdmin(r *http.Request) bool {
	auth, ok := adminAuthForRequest(r)
	return ok && oidc.HasRole(auth.Principal.Role, oidc.RoleAdmin)
}

func normalizeScreenName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "screen", nil
	}
	if len([]rune(name)) > 80 {
		return "", errors.New("screen session name must be 80 characters or fewer")
	}
	for _, char := range name {
		if unicode.IsControl(char) {
			return "", errors.New("screen session name contains a control character")
		}
	}
	return name, nil
}

func parseScreenTTL(raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return screenDefaultTTL, nil
	}
	ttl, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil || ttl <= 0 || ttl > screenMaxTTL {
		return 0, errors.New("screen session ttl must be positive and no longer than 24h")
	}
	return ttl, nil
}

func isScreenSessionID(id string) bool {
	if len(id) != screenIDBytes*2 {
		return false
	}
	for _, char := range id {
		if char < '0' || char > '9' && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func screenPublicPath(path string) (string, bool, bool) {
	if !strings.HasPrefix(path, screenPathPrefix) {
		return "", false, false
	}
	raw := strings.TrimPrefix(path, screenPathPrefix)
	isSignal := strings.HasSuffix(raw, screenSignalSuffix)
	if isSignal {
		raw = strings.TrimSuffix(raw, screenSignalSuffix)
	}
	if !isScreenSessionID(raw) {
		return "", false, false
	}
	return raw, isSignal, true
}

func (s *Server) screenViewerURL(r *http.Request, id string) string {
	host := strings.TrimSpace(s.cfg.Domain)
	if host == "" {
		host = r.Host
	}
	scheme := strings.TrimSpace(s.cfg.PublicScheme)
	if scheme == "" {
		scheme = "https"
	}
	if s.cfg.Insecure {
		scheme = "http"
	}
	return (&url.URL{Scheme: scheme, Host: host, Path: screenPathPrefix + id}).String()
}

func screenJoinURL(base, token string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	u.Fragment = "token=" + token
	return u.String()
}

func (s *Server) handleScreenPublic(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Domain != "" && !hostMatchesDomain(stripPort(r.Host), s.cfg.Domain) {
		http.NotFound(w, r)
		return
	}
	if r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	id, isSignal, ok := screenPublicPath(r.URL.Path)
	if !ok || s.screens == nil {
		http.NotFound(w, r)
		return
	}
	if isSignal {
		s.handleScreenSignal(w, r, id)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.screens.exists(id) {
		http.NotFound(w, r)
		return
	}
	setScreenHeaders(w, "text/html; charset=utf-8")
	fmt.Fprint(w, screenViewerHTML)
}

func (s *Server) handleScreenSignal(w http.ResponseWriter, r *http.Request, id string) {
	if s.screens != nil && s.screens.isSFU(id) {
		s.handleScreenSFUSignal(w, r, id)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.ProtoMajor >= 2 {
		http.Error(w, "screen signaling requires HTTP/1.1", http.StatusUpgradeRequired)
		return
	}
	if _, ok := w.(http.Hijacker); !ok {
		http.Error(w, "screen signaling unavailable", http.StatusNotImplemented)
		return
	}
	var releaseOnce sync.Once
	admission := s.screenAdmission()
	release := func() {
		if admission != nil {
			releaseOnce.Do(admission.release)
		}
	}
	if admission == nil || !admission.tryAcquire() {
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}
	defer release()
	var role screenRole
	wsServer := websocket.Server{
		Handshake: func(config *websocket.Config, request *http.Request) error {
			if !screenOriginAllowed(request) {
				return errors.New("screen websocket origin is not allowed")
			}
			token, ok := screenTokenFromProtocols(request.Header.Get("Sec-WebSocket-Protocol"))
			if !ok {
				return errors.New("screen websocket subprotocol and token are required")
			}
			role, ok = s.screens.authenticate(id, token)
			if !ok {
				return errors.New("screen session token is invalid or expired")
			}
			if !s.screens.available(id, role) {
				return errScreenOccupied
			}
			config.Protocol = []string{screenWebSocketSubprotocol}
			return nil
		},
		Handler: func(ws *websocket.Conn) {
			defer release()
			ws.PayloadType = websocket.TextFrame
			ws.MaxPayloadBytes = screenMaxSignalBytes
			peer := &screenPeer{ws: ws}
			expiresAt, other, err := s.screens.attach(id, role, peer)
			if err != nil {
				_ = ws.Close()
				return
			}
			if err := ws.SetDeadline(screenHeartbeatDeadline(expiresAt)); err != nil {
				_ = ws.Close()
				_ = s.screens.detach(id, role, peer)
				return
			}
			if err := s.sendScreenConfig(peer, id); err != nil {
				_ = ws.Close()
				_ = s.screens.detach(id, role, peer)
				return
			}
			heartbeatDone := make(chan struct{})
			defer close(heartbeatDone)
			go func() {
				ticker := time.NewTicker(screenHeartbeatInterval)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						if err := peer.send(screenSignal{Type: "ping"}); err != nil {
							_ = ws.Close()
							return
						}
					case <-heartbeatDone:
						return
					}
				}
			}()
			if other == nil {
				if err := peer.send(screenSignal{Type: "waiting"}); err != nil {
					_ = ws.Close()
				}
			} else {
				_ = peer.send(screenSignal{Type: "peer_joined"})
				_ = other.send(screenSignal{Type: "peer_joined"})
			}
			defer func() {
				other := s.screens.detach(id, role, peer)
				if other != nil {
					_ = other.send(screenSignal{Type: "peer_left"})
				}
			}()
			for {
				var message screenSignal
				if err := websocket.JSON.Receive(ws, &message); err != nil {
					return
				}
				if err := ws.SetDeadline(screenHeartbeatDeadline(expiresAt)); err != nil {
					return
				}
				switch message.Type {
				case "ping":
					if err := peer.send(screenSignal{Type: "pong"}); err != nil {
						return
					}
					continue
				case "pong":
					continue
				}
				if err := validateScreenSignal(role, message); err != nil {
					_ = peer.send(screenSignal{Type: "error", Data: json.RawMessage(`{"code":"invalid_message"}`)})
					return
				}
				other := s.screens.other(id, role, peer)
				if other != nil {
					if err := other.send(message); err != nil {
						return
					}
				}
				if message.Type == "bye" {
					return
				}
			}
		},
	}
	wsServer.ServeHTTP(w, r)
}

func (s *Server) sendScreenConfig(peer *screenPeer, id string) error {
	config, ok := s.screens.signalConfig(id, s.screenTURNURLs, s.screenTURNSecret)
	if !ok {
		return errScreenNotFound
	}
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return peer.send(screenSignal{Type: "config", Data: data})
}

func screenTokenFromProtocols(raw string) (string, bool) {
	hasVersion := false
	token := ""
	tokenCount := 0
	for _, value := range strings.Split(raw, ",") {
		protocol := strings.TrimSpace(value)
		switch {
		case protocol == screenWebSocketSubprotocol:
			hasVersion = true
		case strings.HasPrefix(protocol, screenTokenProtocolPrefix):
			tokenCount++
			if tokenCount == 1 {
				token = strings.TrimPrefix(protocol, screenTokenProtocolPrefix)
			}
		}
	}
	if !hasVersion || token == "" || tokenCount != 1 {
		return "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	return token, err == nil && len(decoded) == screenTokenBytes
}

func screenOriginAllowed(r *http.Request) bool {
	raw := strings.TrimSpace(r.Header.Get("Origin"))
	if raw == "" {
		return true
	}
	origin, err := url.Parse(raw)
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.Host == "" || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.User != nil {
		return false
	}
	return strings.EqualFold(origin.Host, r.Host)
}

func validateScreenSignal(role screenRole, message screenSignal) error {
	if message.Type == "" {
		return errors.New("screen signaling message type is required")
	}
	if len(message.Data) > screenMaxSignalBytes {
		return errors.New("screen signaling data is too large")
	}
	switch message.Type {
	case "offer":
		if role != screenRoleSender {
			return errors.New("only the sender may send an offer")
		}
	case "answer":
		if role != screenRoleViewer {
			return errors.New("only the viewer may send an answer")
		}
	case "ice":
	case "bye", "ping", "pong":
		return nil
	default:
		return errors.New("unknown screen signaling message type")
	}
	if len(message.Data) == 0 || !json.Valid(message.Data) {
		return errors.New("screen signaling data must be valid JSON")
	}
	return nil
}

func screenHeartbeatDeadline(expiresAt time.Time) time.Time {
	deadline := time.Now().Add(screenHeartbeatTimeout)
	if expiresAt.Before(deadline) {
		return expiresAt
	}
	return deadline
}

func setScreenHeaders(w http.ResponseWriter, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; media-src 'self' blob:; connect-src 'self' ws: wss:; base-uri 'none'; frame-ancestors 'none'")
}

const screenViewerHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>ngstone screen</title>
  <style>
    :root { color-scheme: dark; font-family: system-ui, sans-serif; }
    body { background: #081011; color: #e3f1ed; margin: 0; min-height: 100vh; display: grid; place-items: center; }
    main { width: min(1100px, 94vw); }
    video { width: 100%; max-height: 82vh; background: #020505; border: 1px solid #24413f; border-radius: 12px; display: block; }
    p { color: #8da9a3; margin: 0.8rem 0 0; }
    #diagnostics { color: #66847d; font: 0.82rem ui-monospace, SFMono-Regular, Menlo, monospace; }
    code { color: #c9f37b; }
  </style>
</head>
<body>
  <main>
    <video id="screen" autoplay playsinline controls></video>
    <p id="status">Preparing the direct connection.</p>
    <p id="diagnostics" aria-live="polite">ICE: waiting · frames: 0 · bytes: 0</p>
  </main>
  <script>
    (() => {
      const status = document.getElementById("status");
      const diagnostics = document.getElementById("diagnostics");
      const video = document.getElementById("screen");
      const params = new URLSearchParams(window.location.hash.slice(1));
      const setStatus = (value) => { status.textContent = value; };
      const setDiagnostics = (value) => { diagnostics.textContent = value; };
      const tokenStorageKey = "ngstone-screen-token:" + window.location.pathname;
      let token = params.get("token");
      let tokenStored = false;
      try {
        if (token) {
          window.sessionStorage.setItem(tokenStorageKey, token);
          tokenStored = window.sessionStorage.getItem(tokenStorageKey) === token;
        } else {
          token = window.sessionStorage.getItem(tokenStorageKey);
          tokenStored = Boolean(token);
        }
      } catch (_) {
        tokenStored = false;
      }
      let hasDecodedFrame = false;
      let mediaRouteFailed = false;
      let statsTimer = null;
      const attemptPlayback = async () => {
        if (!video.srcObject) {
          return;
        }
        try {
          await video.play();
          if (!hasDecodedFrame && !mediaRouteFailed) {
            setStatus("Video connected; waiting for the first frame.");
          }
        } catch (_) {
          if (!mediaRouteFailed) {
            setStatus("Video connected. Tap the video to start playback.");
          }
        }
      };
      const attachVideo = (stream) => {
        video.muted = true;
        video.srcObject = stream;
        setStatus("Video track received; waiting for frames.");
        void attemptPlayback();
      };
      video.onloadedmetadata = () => { void attemptPlayback(); };
      video.onplaying = () => {
        hasDecodedFrame = true;
        setStatus("Receiving the screen through ngstone.");
      };
      video.onwaiting = () => {
        if (!hasDecodedFrame && !mediaRouteFailed && (!peer || peer.iceConnectionState !== "failed")) {
          setStatus("Connected; waiting for video frames.");
        }
      };
      video.onerror = () => setStatus("The browser could not decode the screen video.");
      if (!token) {
        setStatus("This viewer link is missing its access token.");
        return;
      }
      if (params.has("token") && tokenStored) {
        history.replaceState(null, "", window.location.pathname);
      }
      let peer = null;
      let remoteDescriptionReady = false;
      const pendingCandidates = [];
      const ensurePeer = (iceServers) => {
        if (peer) {
          return;
        }
        const normalizedServers = Array.isArray(iceServers) ? iceServers.flatMap((server) => {
          if (!server || typeof server !== "object") {
            return [];
          }
          const urls = Array.isArray(server.urls) ? server.urls : [server.urls];
          const validURLs = urls.filter((value) => typeof value === "string" && /^(stun|stuns|turn|turns):/i.test(value));
          if (validURLs.length === 0) {
            return [];
          }
          return [{
            urls: validURLs,
            ...(typeof server.username === "string" ? {username: server.username} : {}),
            ...(typeof server.credential === "string" ? {credential: server.credential} : {})
          }];
        }) : [];
        peer = new RTCPeerConnection({iceServers: normalizedServers});
        peer.ontrack = (event) => {
          if (event.streams && event.streams[0]) {
            attachVideo(event.streams[0]);
          } else {
            attachVideo(new MediaStream([event.track]));
          }
          event.track.onunmute = () => { void attemptPlayback(); };
          event.track.onended = () => setStatus("The sender stopped sharing its screen.");
        };
        peer.oniceconnectionstatechange = () => {
          const state = peer.iceConnectionState;
          setDiagnostics("ICE: " + state + " · frames: 0 · bytes: 0");
          if (state === "failed") {
            mediaRouteFailed = true;
            setStatus("ICE could not find a media route. Configure STUN/TURN on the edge.");
          } else if (state === "disconnected") {
            setStatus("The media connection was interrupted; waiting to reconnect.");
          }
        };
        peer.onconnectionstatechange = () => {
          if (peer.connectionState === "failed") {
            mediaRouteFailed = true;
            setStatus("The WebRTC connection failed. Check ICE/TURN reachability.");
          }
        };
        peer.onicecandidate = (event) => {
          if (!event.candidate || socket.readyState !== WebSocket.OPEN) {
            return;
          }
          const candidate = event.candidate;
          socket.send(JSON.stringify({type: "ice", data: {
            candidate: candidate.candidate,
            sdpMid: candidate.sdpMid,
            sdpMLineIndex: candidate.sdpMLineIndex,
            usernameFragment: candidate.usernameFragment
          }}));
        };
        const pollStats = async () => {
          if (!peer) {
            return;
          }
          try {
            const report = await peer.getStats();
            let inbound = null;
            report.forEach((stat) => {
              if (stat.type === "inbound-rtp" && (stat.kind === "video" || stat.mediaType === "video")) {
                inbound = stat;
              }
            });
            const frames = inbound ? (inbound.framesDecoded ?? inbound.framesReceived ?? 0) : 0;
            const bytes = inbound ? (inbound.bytesReceived ?? 0) : 0;
            if (frames > 0) {
              hasDecodedFrame = true;
              setStatus("Receiving the screen through ngstone.");
            } else if (peer.iceConnectionState === "connected" && inbound) {
              setStatus("WebRTC connected; waiting for video packets. Check TURN/ICE if this persists.");
            }
            setDiagnostics("ICE: " + peer.iceConnectionState + " · frames: " + frames + " · bytes: " + bytes + " · " + (video.videoWidth || 0) + "×" + (video.videoHeight || 0));
          } catch (_) {
            setDiagnostics("ICE: " + peer.iceConnectionState + " · browser stats unavailable");
          }
          statsTimer = window.setTimeout(pollStats, 2000);
        };
        void pollStats();
      };
      const signalURL = new URL(window.location.href);
      signalURL.hash = "";
      signalURL.protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      signalURL.pathname = window.location.pathname.replace(/\/$/, "") + "/signal";
      const socket = new WebSocket(signalURL, ["ngstone-screen-v1", "ngstone-screen-token-" + token]);
      socket.onopen = () => setStatus("Waiting for the native sender.");
      socket.onclose = () => setStatus("The screen session has ended.");
      socket.onerror = () => setStatus("The screen signaling connection failed.");
      socket.onmessage = async (event) => {
        let message;
        try {
          message = JSON.parse(event.data);
        } catch (_) {
          setStatus("The sender sent invalid signaling data.");
          return;
        }
        if (message.type === "waiting") {
          setStatus("Waiting for the native sender.");
          return;
        }
        if (message.type === "ping") {
          socket.send(JSON.stringify({type: "pong"}));
          return;
        }
        if (message.type === "pong") {
          return;
        }
        if (message.type === "config") {
          const config = message.data && typeof message.data === "object" ? message.data : {};
          ensurePeer(config.ice_servers);
          setStatus(config.mode === "sfu" ? "Connected to the ngstone screen SFU." : "Waiting for the sender.");
          return;
        }
        if (message.type === "peer_joined") {
          setStatus("Connected to the sender; negotiating video.");
          return;
        }
        if (message.type === "peer_left" || message.type === "bye") {
          setStatus("The sender disconnected.");
          return;
        }
        if (message.type === "error") {
          setStatus("The screen session rejected signaling data.");
          return;
        }
        try {
          if (message.type === "offer") {
            ensurePeer([]);
            await peer.setRemoteDescription(message.data);
            remoteDescriptionReady = true;
            while (pendingCandidates.length > 0) {
              await peer.addIceCandidate(pendingCandidates.shift());
            }
            const answer = await peer.createAnswer();
            await peer.setLocalDescription(answer);
            socket.send(JSON.stringify({type: "answer", data: {
              type: answer.type,
              sdp: answer.sdp
            }}));
          } else if (message.type === "ice") {
            if (!remoteDescriptionReady) {
              pendingCandidates.push(message.data);
            } else {
              await peer.addIceCandidate(message.data);
            }
          }
        } catch (_) {
          setStatus("The browser could not apply the sender's WebRTC data.");
        }
      };
    })();
  </script>
</body>
</html>`
