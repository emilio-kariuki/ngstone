package edge

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/net/websocket"
)

const (
	controlWebSocketPath        = "/_ngstone/control"
	controlWebSocketSubprotocol = "ngstone-control-v1"
)

type websocketAddr struct {
	network string
	value   string
}

func (a websocketAddr) Network() string { return a.network }
func (a websocketAddr) String() string  { return a.value }

type websocketNetConn struct {
	*websocket.Conn
	local  net.Addr
	remote net.Addr
}

func (c *websocketNetConn) LocalAddr() net.Addr  { return c.local }
func (c *websocketNetConn) RemoteAddr() net.Addr { return c.remote }

func (s *Server) handlePublicListener(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == controlWebSocketPath {
		s.handleWebSocketControl(ctx, w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, screenPathPrefix) {
		s.handleScreenPublic(w, r)
		return
	}
	s.handlePublic(w, r)
}

func (s *Server) handleWebSocketControl(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.ProtoMajor >= 2 {
		http.Error(w, "websocket fallback requires HTTP/1.1", http.StatusUpgradeRequired)
		return
	}
	if _, ok := w.(http.Hijacker); !ok {
		http.Error(w, "websocket fallback unavailable", http.StatusNotImplemented)
		return
	}
	if !s.acceptControl() {
		http.Error(w, "edge is shutting down", http.StatusServiceUnavailable)
		return
	}
	defer s.controlConns.Done()
	admission := s.fallbackAdmission()
	if admission == nil || !admission.tryAcquire() {
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(admission.release) }
	defer release()
	wsServer := websocket.Server{
		Handshake: func(config *websocket.Config, request *http.Request) error {
			if !hasControlSubprotocol(request.Header.Get("Sec-WebSocket-Protocol")) {
				return errors.New("ngstone control websocket subprotocol is required")
			}
			config.Protocol = []string{controlWebSocketSubprotocol}
			return nil
		},
		Handler: func(ws *websocket.Conn) {
			defer release()
			ws.PayloadType = websocket.BinaryFrame
			conn := &websocketNetConn{
				Conn:   ws,
				local:  websocketAddr{network: "tcp", value: r.Host},
				remote: websocketAddr{network: "tcp", value: r.RemoteAddr},
			}
			s.handleControlConnTransport(ctx, conn, release, false)
		},
	}
	wsServer.ServeHTTP(w, r)
}

func hasControlSubprotocol(raw string) bool {
	for _, protocol := range strings.Split(raw, ",") {
		if strings.TrimSpace(protocol) == controlWebSocketSubprotocol {
			return true
		}
	}
	return false
}
