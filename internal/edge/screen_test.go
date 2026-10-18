package edge

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"ngstone/internal/adminapi"
)

func TestExpiredSFUSessionClosesServerState(t *testing.T) {
	s := newServerForTest(LimitsConfig{})
	const sessionID = "expired-sfu"
	s.screens.mu.Lock()
	s.screens.sessions[sessionID] = &screenSession{
		ID:        sessionID,
		ExpiresAt: time.Now().Add(-time.Minute),
		Viewers:   make(map[*screenPeer]struct{}),
	}
	s.screens.mu.Unlock()
	s.screenSFUMu.Lock()
	s.screenSFUs[sessionID] = newScreenSFU(sessionID, nil)
	s.screenSFUMu.Unlock()

	if s.screens.exists(sessionID) {
		t.Fatal("expired screen session still exists")
	}
	s.screenSFUMu.Lock()
	_, ok := s.screenSFUs[sessionID]
	s.screenSFUMu.Unlock()
	if ok {
		t.Fatal("expired screen SFU was not closed")
	}
}

func TestRevokedSFUSessionClosesServerState(t *testing.T) {
	s := newServerForTest(LimitsConfig{})
	const sessionID = "revoked-sfu"
	s.screens.mu.Lock()
	s.screens.sessions[sessionID] = &screenSession{
		ID:        sessionID,
		ExpiresAt: time.Now().Add(time.Minute),
		Viewers:   make(map[*screenPeer]struct{}),
	}
	s.screens.mu.Unlock()
	s.screenSFUMu.Lock()
	s.screenSFUs[sessionID] = newScreenSFU(sessionID, nil)
	s.screenSFUMu.Unlock()

	if err := s.screens.revoke(sessionID, "", true); err != nil {
		t.Fatalf("revoke screen session: %v", err)
	}
	s.screenSFUMu.Lock()
	_, ok := s.screenSFUs[sessionID]
	s.screenSFUMu.Unlock()
	if ok {
		t.Fatal("revoked screen SFU was not closed")
	}
}

func TestAdminScreenSessionLifecycle(t *testing.T) {
	s := newTestServer("")
	s.screens = newScreenRegistry()
	s.events = newEventRing(20)

	createResponse := adminRequest(t, s, http.MethodPost, "/api/v1/screen-sessions", []byte(`{"name":"demo","ttl":"5m"}`), "127.0.0.1:4041", "")
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create code = %d, want 201; body=%s", createResponse.Code, createResponse.Body.String())
	}
	var createEnvelope struct {
		Data adminapi.ScreenSessionCreateResponse `json:"data"`
	}
	if err := json.Unmarshal(createResponse.Body.Bytes(), &createEnvelope); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	created := createEnvelope.Data
	if !isScreenSessionID(created.Session.ID) || created.SenderToken == "" || created.ViewerToken == "" {
		t.Fatalf("create response = %+v", created)
	}
	if !strings.HasPrefix(created.ViewerURL, created.Session.ViewerURL+"#token=") {
		t.Fatalf("viewer URL = %q, want token fragment", created.ViewerURL)
	}
	if !strings.Contains(created.ViewerURL, created.ViewerToken) {
		t.Fatal("viewer URL did not contain the returned viewer token")
	}

	listResponse := adminRequest(t, s, http.MethodGet, "/api/v1/screen-sessions", nil, "127.0.0.1:4041", "")
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list code = %d, want 200; body=%s", listResponse.Code, listResponse.Body.String())
	}
	if bytes.Contains(listResponse.Body.Bytes(), []byte(created.SenderToken)) || bytes.Contains(listResponse.Body.Bytes(), []byte(created.ViewerToken)) {
		t.Fatal("screen session list exposed a plaintext participant token")
	}
	var listEnvelope struct {
		Data []adminapi.ScreenSession `json:"data"`
	}
	if err := json.Unmarshal(listResponse.Body.Bytes(), &listEnvelope); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(listEnvelope.Data) != 1 || listEnvelope.Data[0].ID != created.Session.ID || listEnvelope.Data[0].Status != "waiting" {
		t.Fatalf("list data = %+v", listEnvelope.Data)
	}

	getResponse := adminRequest(t, s, http.MethodGet, "/api/v1/screen-sessions/"+created.Session.ID, nil, "127.0.0.1:4041", "")
	if getResponse.Code != http.StatusOK {
		t.Fatalf("get code = %d, want 200; body=%s", getResponse.Code, getResponse.Body.String())
	}

	if role, ok := s.screens.authenticate(created.Session.ID, created.SenderToken); !ok || role != screenRoleSender {
		t.Fatalf("sender token authentication = %q/%t", role, ok)
	}
	if role, ok := s.screens.authenticate(created.Session.ID, created.ViewerToken); !ok || role != screenRoleViewer {
		t.Fatalf("viewer token authentication = %q/%t", role, ok)
	}

	revokeResponse := adminRequest(t, s, http.MethodDelete, "/api/v1/screen-sessions/"+created.Session.ID, nil, "127.0.0.1:4041", "")
	if revokeResponse.Code != http.StatusNoContent {
		t.Fatalf("revoke code = %d, want 204; body=%s", revokeResponse.Code, revokeResponse.Body.String())
	}
	if _, ok := s.screens.authenticate(created.Session.ID, created.SenderToken); ok {
		t.Fatal("revoked sender token still authenticated")
	}
	getAfterRevoke := adminRequest(t, s, http.MethodGet, "/api/v1/screen-sessions/"+created.Session.ID, nil, "127.0.0.1:4041", "")
	if getAfterRevoke.Code != http.StatusNotFound {
		t.Fatalf("get after revoke code = %d, want 404", getAfterRevoke.Code)
	}
}

func TestScreenViewerPageIsReservedAndTokenFree(t *testing.T) {
	s := newTestServer("")
	s.screens = newScreenRegistry()
	issued, err := s.screens.create("admin", "demo", time.Minute, func(id string) string {
		return "https://example.com" + screenPathPrefix + id
	})
	if err != nil {
		t.Fatalf("create screen session: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, screenPathPrefix+issued.Session.ID, nil)
	request.Host = "example.com"
	s.handleScreenPublic(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("viewer page code = %d, want 200", recorder.Code)
	}
	page := recorder.Body.String()
	if !strings.Contains(page, "RTCPeerConnection") || strings.Contains(page, issued.ViewerToken) {
		t.Fatal("viewer page does not contain the direct WebRTC viewer without embedding the token")
	}
	for _, required := range []string{"video.muted = true", "video.play()", "getStats()", "ICE: waiting", "sessionStorage", "ngstone-screen-token:"} {
		if !strings.Contains(page, required) {
			t.Fatalf("viewer page is missing playback diagnostic %q", required)
		}
	}
	if recorder.Header().Get("Content-Security-Policy") == "" || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("viewer security headers = %+v", recorder.Header())
	}

	wrongHost := httptest.NewRecorder()
	wrongRequest := httptest.NewRequest(http.MethodGet, screenPathPrefix+issued.Session.ID, nil)
	wrongRequest.Host = "attacker.example.net"
	s.handleScreenPublic(wrongHost, wrongRequest)
	if wrongHost.Code != http.StatusNotFound {
		t.Fatalf("wrong host code = %d, want 404", wrongHost.Code)
	}

	queryResponse := httptest.NewRecorder()
	queryRequest := httptest.NewRequest(http.MethodGet, screenPathPrefix+issued.Session.ID+"?token="+issued.ViewerToken, nil)
	queryRequest.Host = "example.com"
	s.handleScreenPublic(queryResponse, queryRequest)
	if queryResponse.Code != http.StatusNotFound {
		t.Fatalf("query token code = %d, want 404", queryResponse.Code)
	}
}

func TestScreenSignalingForwardsOfferAnswerAndICE(t *testing.T) {
	s := newTestServer("")
	s.cfg.Domain = "127.0.0.1"
	s.screens = newScreenRegistry()
	s.unauthSem = newGlobalSemaphore(4)
	s.screenTURNURLs = []string{"turn:turn.example.com:3478", "stun:stun.example.com:3478"}
	s.screenTURNSecret = "test-turn-secret"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handlePublicListener(r.Context(), w, r)
	}))
	defer ts.Close()
	issued, err := s.screens.create("admin", "demo", time.Minute, func(id string) string {
		return "http://" + ts.Listener.Addr().String() + screenPathPrefix + id
	})
	if err != nil {
		t.Fatalf("create screen session: %v", err)
	}
	wsURL := "ws://" + ts.Listener.Addr().String() + screenPathPrefix + issued.Session.ID + screenSignalSuffix
	sender := dialScreenPeer(t, wsURL, issued.SenderToken)
	defer sender.Close()
	sender.SetReadDeadline(time.Now().Add(time.Second))
	var senderConfig screenSignal
	if err := websocket.JSON.Receive(sender, &senderConfig); err != nil {
		t.Fatalf("receive sender config: %v", err)
	}
	if senderConfig.Type != "config" || !strings.Contains(string(senderConfig.Data), `"mode":"direct"`) {
		t.Fatalf("sender config = %+v", senderConfig)
	}
	var senderICEConfig screenSignalConfig
	if err := json.Unmarshal(senderConfig.Data, &senderICEConfig); err != nil {
		t.Fatalf("decode sender ICE config: %v", err)
	}
	if len(senderICEConfig.ICEServers) != 2 || senderICEConfig.ICEServers[0].Username == "" || senderICEConfig.ICEServers[0].Credential == "" || senderICEConfig.ICEServers[1].Username != "" {
		t.Fatalf("sender ICE config = %+v", senderICEConfig)
	}
	if strings.Contains(senderICEConfig.ICEServers[0].Credential, s.screenTURNSecret) {
		t.Fatal("sender ICE config exposed the TURN shared secret")
	}
	var waiting screenSignal
	if err := websocket.JSON.Receive(sender, &waiting); err != nil {
		t.Fatalf("receive sender waiting event: %v", err)
	}
	if waiting.Type != "waiting" {
		t.Fatalf("sender initial event = %q, want waiting", waiting.Type)
	}

	viewer := dialScreenPeer(t, wsURL, issued.ViewerToken)
	defer viewer.Close()
	sender.SetReadDeadline(time.Now().Add(time.Second))
	viewer.SetReadDeadline(time.Now().Add(time.Second))
	var viewerConfig screenSignal
	if err := websocket.JSON.Receive(viewer, &viewerConfig); err != nil {
		t.Fatalf("receive viewer config: %v", err)
	}
	if viewerConfig.Type != "config" {
		t.Fatalf("viewer config = %+v", viewerConfig)
	}
	var senderJoined, viewerJoined screenSignal
	if err := websocket.JSON.Receive(sender, &senderJoined); err != nil {
		t.Fatalf("receive sender joined event: %v", err)
	}
	if err := websocket.JSON.Receive(viewer, &viewerJoined); err != nil {
		t.Fatalf("receive viewer joined event: %v", err)
	}
	if senderJoined.Type != "peer_joined" || viewerJoined.Type != "peer_joined" {
		t.Fatalf("joined events = %q/%q", senderJoined.Type, viewerJoined.Type)
	}

	offer := screenSignal{Type: "offer", Data: json.RawMessage(`{"type":"offer","sdp":"sender-sdp"}`)}
	if err := websocket.JSON.Send(sender, offer); err != nil {
		t.Fatalf("send offer: %v", err)
	}
	var forwardedOffer screenSignal
	if err := websocket.JSON.Receive(viewer, &forwardedOffer); err != nil {
		t.Fatalf("receive offer: %v", err)
	}
	if forwardedOffer.Type != "offer" || string(forwardedOffer.Data) != string(offer.Data) {
		t.Fatalf("forwarded offer = %+v", forwardedOffer)
	}

	answer := screenSignal{Type: "answer", Data: json.RawMessage(`{"type":"answer","sdp":"viewer-sdp"}`)}
	if err := websocket.JSON.Send(viewer, answer); err != nil {
		t.Fatalf("send answer: %v", err)
	}
	var forwardedAnswer screenSignal
	if err := websocket.JSON.Receive(sender, &forwardedAnswer); err != nil {
		t.Fatalf("receive answer: %v", err)
	}
	if forwardedAnswer.Type != "answer" || string(forwardedAnswer.Data) != string(answer.Data) {
		t.Fatalf("forwarded answer = %+v", forwardedAnswer)
	}

	ice := screenSignal{Type: "ice", Data: json.RawMessage(`{"candidate":"candidate:1","sdpMid":"0","sdpMLineIndex":0}`)}
	if err := websocket.JSON.Send(sender, ice); err != nil {
		t.Fatalf("send ice: %v", err)
	}
	var forwardedICE screenSignal
	if err := websocket.JSON.Receive(viewer, &forwardedICE); err != nil {
		t.Fatalf("receive ice: %v", err)
	}
	if forwardedICE.Type != "ice" || string(forwardedICE.Data) != string(ice.Data) {
		t.Fatalf("forwarded ice = %+v", forwardedICE)
	}

	thirdConfig, err := websocket.NewConfig(wsURL, "http://"+ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("third websocket config: %v", err)
	}
	thirdConfig.Protocol = []string{screenWebSocketSubprotocol, screenTokenProtocolPrefix + issued.SenderToken}
	if _, err := websocket.DialConfig(thirdConfig); err == nil {
		t.Fatal("second sender connection succeeded")
	}
}

func TestScreenSFUSignalingAllowsMultipleViewers(t *testing.T) {
	s := newTestServer("")
	s.cfg.Domain = "127.0.0.1"
	s.screens = newScreenRegistry()
	s.unauthSem = newGlobalSemaphore(8)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handlePublicListener(r.Context(), w, r)
	}))
	defer ts.Close()
	issued, err := s.screens.createWithOptions("admin", "demo", time.Minute, 3, func(id string) string {
		return "http://" + ts.Listener.Addr().String() + screenPathPrefix + id
	})
	if err != nil {
		t.Fatalf("create SFU screen session: %v", err)
	}
	wsURL := "ws://" + ts.Listener.Addr().String() + screenPathPrefix + issued.Session.ID + screenSignalSuffix
	sender := dialScreenPeer(t, wsURL, issued.SenderToken)
	defer sender.Close()
	readScreenConfigAndEvent(t, sender, "waiting")
	viewers := make([]*websocket.Conn, 0, 2)
	for i := 0; i < 2; i++ {
		viewer := dialScreenPeer(t, wsURL, issued.ViewerToken)
		viewers = append(viewers, viewer)
		defer viewer.Close()
		readScreenConfigAndEvent(t, viewer, "peer_joined")
	}
	for i := 0; i < 2; i++ {
		readScreenEvent(t, sender, "peer_joined")
	}
	item, err := s.screens.get(issued.Session.ID, "admin", false)
	if err != nil {
		t.Fatalf("get SFU session: %v", err)
	}
	if item.ViewerCount != 2 || !item.SFU || item.MaxViewers != 3 {
		t.Fatalf("SFU session after viewers = %+v", item)
	}
}

func readScreenConfigAndEvent(t *testing.T, ws *websocket.Conn, event string) {
	t.Helper()
	ws.SetReadDeadline(time.Now().Add(time.Second))
	var config screenSignal
	if err := websocket.JSON.Receive(ws, &config); err != nil {
		t.Fatalf("receive SFU config: %v", err)
	}
	if config.Type != "config" || !strings.Contains(string(config.Data), `"mode":"sfu"`) {
		t.Fatalf("SFU config = %+v", config)
	}
	readScreenEvent(t, ws, event)
}

func readScreenEvent(t *testing.T, ws *websocket.Conn, want string) {
	t.Helper()
	var event screenSignal
	if err := websocket.JSON.Receive(ws, &event); err != nil {
		t.Fatalf("receive screen event %q: %v", want, err)
	}
	if event.Type != want {
		t.Fatalf("screen event = %q, want %q", event.Type, want)
	}
}

func dialScreenPeer(t *testing.T, wsURL, token string) *websocket.Conn {
	t.Helper()
	location, err := url.Parse(wsURL)
	if err != nil {
		t.Fatalf("parse websocket URL: %v", err)
	}
	config, err := websocket.NewConfig(wsURL, "http://"+location.Host)
	if err != nil {
		t.Fatalf("websocket config: %v", err)
	}
	config.Protocol = []string{screenWebSocketSubprotocol, screenTokenProtocolPrefix + token}
	ws, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	return ws
}

func TestScreenSignalValidationAndProtocolParsing(t *testing.T) {
	token, _, err := newScreenToken()
	if err != nil {
		t.Fatalf("new screen token: %v", err)
	}
	parsed, ok := screenTokenFromProtocols(screenWebSocketSubprotocol + ", " + screenTokenProtocolPrefix + token)
	if !ok || parsed != token {
		t.Fatalf("parsed token = %q/%t", parsed, ok)
	}
	for _, raw := range []string{"", screenWebSocketSubprotocol, screenTokenProtocolPrefix + token, screenWebSocketSubprotocol + ", bad"} {
		if _, ok := screenTokenFromProtocols(raw); ok {
			t.Fatalf("invalid protocol %q was accepted", raw)
		}
	}
	if err := validateScreenSignal(screenRoleSender, screenSignal{Type: "answer", Data: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("sender answer was accepted")
	}
	if err := validateScreenSignal(screenRoleViewer, screenSignal{Type: "offer", Data: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("viewer offer was accepted")
	}
	if err := validateScreenSignal(screenRoleSender, screenSignal{Type: "offer", Data: json.RawMessage(`{"sdp":"ok"}`)}); err != nil {
		t.Fatalf("valid offer rejected: %v", err)
	}
	if err := validateScreenSignal(screenRoleSender, screenSignal{Type: "ice", Data: json.RawMessage(`{"candidate":"ok"}`)}); err != nil {
		t.Fatalf("valid ice rejected: %v", err)
	}
}
