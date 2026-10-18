package edge

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/websocket"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

func TestControlWebSocketRejectsAdmissionDuringShutdown(t *testing.T) {
	s := &Server{unauthSem: newGlobalSemaphore(1), controlDraining: true}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleWebSocketControl(context.Background(), w, r)
	}))
	defer ts.Close()
	resp, err := http.Get(ts.URL + controlWebSocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("shutdown admission status = %d; want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
	if !s.unauthSem.tryAcquire() {
		t.Fatal("rejected websocket connection consumed an unauthenticated-session slot")
	}
	s.unauthSem.release()
}

func TestControlWebSocketCarriesAuthenticatedSession(t *testing.T) {
	token := "fallback-token"
	sum := sha256.Sum256([]byte(token))
	s := &Server{
		cfg:         Config{TokenSHA256: sum[:]},
		authLimiter: newAuthRateLimiter(),
		registry:    NewRegistry(),
		unauthSem:   newGlobalSemaphore(2),
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleWebSocketControl(r.Context(), w, r)
	}))
	defer ts.Close()

	wsURL := "ws://" + ts.Listener.Addr().String() + controlWebSocketPath
	config, err := websocket.NewConfig(wsURL, "http://"+ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("websocket config: %v", err)
	}
	config.Protocol = []string{controlWebSocketSubprotocol}
	ws, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	sess, err := tunnel.Client(ws)
	if err != nil {
		t.Fatalf("tunnel client: %v", err)
	}
	defer sess.Close("test done")

	idgen := proto.NewAgentIDGen()
	if err := sess.Control().Write(proto.TypeAuth, idgen.Next(), proto.Auth{
		Token:         token,
		InstanceID:    "fallback-test",
		ProtoVersions: proto.SupportedVersions,
	}); err != nil {
		t.Fatalf("auth write: %v", err)
	}
	message, err := sess.Control().Read()
	if err != nil {
		t.Fatalf("auth response: %v", err)
	}
	if message.Type != proto.TypeAuthOK {
		t.Fatalf("auth response type = %q, want %q", message.Type, proto.TypeAuthOK)
	}
	if err := sess.Control().Write(proto.TypeGoodbye, idgen.Next(), proto.Goodbye{Reason: "test done"}); err != nil {
		t.Fatalf("goodbye write: %v", err)
	}
}

func TestControlWebSocketRejectsMissingSubprotocol(t *testing.T) {
	s := &Server{unauthSem: newGlobalSemaphore(1)}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleWebSocketControl(r.Context(), w, r)
	}))
	defer ts.Close()

	wsURL := "ws://" + ts.Listener.Addr().String() + controlWebSocketPath
	_, err := websocket.Dial(wsURL, "", "http://"+ts.Listener.Addr().String())
	if err == nil {
		t.Fatal("websocket dial without the ngstone subprotocol succeeded")
	}
	if !s.unauthSem.tryAcquire() {
		t.Fatal("failed websocket handshake leaked the unauthenticated-session slot")
	}
	s.unauthSem.release()
}
