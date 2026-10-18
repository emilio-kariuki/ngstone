package edge

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
	"golang.org/x/net/websocket"
)

var errScreenSFUUnavailable = errors.New("screen SFU is unavailable")

const screenSFUKeyframeInterval = 500 * time.Millisecond

type screenSFU struct {
	mu                         sync.Mutex
	id                         string
	configuration              webrtc.Configuration
	senderPeer                 *screenPeer
	senderPC                   *webrtc.PeerConnection
	senderRemoteDescriptionSet bool
	pendingSenderICE           []webrtc.ICECandidateInit
	senderTrackSSRC            uint32
	lastKeyframeRequest        time.Time
	localTrack                 *webrtc.TrackLocalStaticRTP
	viewers                    map[*screenPeer]*screenSFUViewer
	closed                     bool
}

type screenSFUViewer struct {
	peer                 *screenPeer
	pc                   *webrtc.PeerConnection
	remoteDescriptionSet bool
	pendingICE           []webrtc.ICECandidateInit
	negotiating          bool
	generation           uint64
}

func newScreenSFU(id string, servers []screenICEServer) *screenSFU {
	iceServers := make([]webrtc.ICEServer, 0, len(servers))
	for _, server := range servers {
		iceServers = append(iceServers, webrtc.ICEServer{
			URLs:       append([]string(nil), server.URLs...),
			Username:   server.Username,
			Credential: server.Credential,
		})
	}
	return &screenSFU{
		id:            id,
		configuration: webrtc.Configuration{ICEServers: iceServers},
		viewers:       make(map[*screenPeer]*screenSFUViewer),
	}
}

func (s *Server) screenSFUFor(id string) (*screenSFU, error) {
	if s == nil || s.screens == nil {
		return nil, errScreenSFUUnavailable
	}
	config, ok := s.screens.signalConfig(id, s.screenTURNURLs, s.screenTURNSecret)
	if !ok || config.Mode != "sfu" {
		return nil, errScreenSFUUnavailable
	}
	s.screenSFUMu.Lock()
	defer s.screenSFUMu.Unlock()
	if s.screenSFUs == nil {
		s.screenSFUs = make(map[string]*screenSFU)
	}
	if existing := s.screenSFUs[id]; existing != nil {
		return existing, nil
	}
	if !s.screens.active(id, time.Now().UTC()) {
		return nil, errScreenSFUUnavailable
	}
	sfu := newScreenSFU(id, config.ICEServers)
	s.screenSFUs[id] = sfu
	return sfu, nil
}

func (s *Server) expireScreenSFUs(ids []string) {
	for _, id := range ids {
		s.closeScreenSFU(id)
	}
}

func (s *Server) closeScreenSFU(id string) {
	if s == nil {
		return
	}
	s.screenSFUMu.Lock()
	sfu := s.screenSFUs[id]
	delete(s.screenSFUs, id)
	s.screenSFUMu.Unlock()
	if sfu != nil {
		sfu.close()
	}
}

func (s *Server) closeAllScreenSFUs() {
	if s == nil {
		return
	}
	s.screenSFUMu.Lock()
	sfus := make([]*screenSFU, 0, len(s.screenSFUs))
	for id, sfu := range s.screenSFUs {
		delete(s.screenSFUs, id)
		sfus = append(sfus, sfu)
	}
	s.screenSFUMu.Unlock()
	for _, sfu := range sfus {
		if sfu != nil {
			sfu.close()
		}
	}
}

func (s *screenSFU) attachSender(peer *screenPeer) error {
	if peer == nil {
		return errScreenSFUUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errScreenSFUUnavailable
	}
	if s.senderPeer != nil && s.senderPeer != peer {
		return errScreenOccupied
	}
	s.senderPeer = peer
	return nil
}

func (s *screenSFU) addViewer(peer *screenPeer) error {
	if peer == nil {
		return errScreenSFUUnavailable
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errScreenSFUUnavailable
	}
	if _, exists := s.viewers[peer]; exists {
		s.mu.Unlock()
		return nil
	}
	viewer := &screenSFUViewer{peer: peer}
	s.viewers[peer] = viewer
	ready := s.localTrack != nil
	s.mu.Unlock()
	if ready {
		return s.negotiateViewer(viewer)
	}
	return nil
}

func (s *screenSFU) handleSenderOffer(peer *screenPeer, data json.RawMessage) error {
	var offer webrtc.SessionDescription
	if err := json.Unmarshal(data, &offer); err != nil || offer.Type != webrtc.SDPTypeOffer || offer.SDP == "" {
		return errors.New("sender offer is invalid")
	}
	s.mu.Lock()
	if s.closed || s.senderPeer != peer {
		s.mu.Unlock()
		return errScreenSFUUnavailable
	}
	if s.senderPC != nil {
		s.mu.Unlock()
		return errors.New("sender offer was already received")
	}
	pc, err := webrtc.NewPeerConnection(s.configuration)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("creating SFU sender peer connection: %w", err)
	}
	s.senderPC = pc
	s.senderRemoteDescriptionSet = false
	s.pendingSenderICE = nil
	s.mu.Unlock()

	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		data, marshalErr := json.Marshal(candidate.ToJSON())
		if marshalErr == nil {
			_ = peer.send(screenSignal{Type: "ice", Data: data})
		}
	})
	pc.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		if track.Kind() == webrtc.RTPCodecTypeVideo {
			s.acceptTrack(track)
		}
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			s.resetSenderPC(pc)
		}
	})
	if _, err := pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{
		Direction: webrtc.RTPTransceiverDirectionRecvonly,
	}); err != nil {
		s.resetSenderPC(pc)
		return fmt.Errorf("creating SFU receiver transceiver: %w", err)
	}
	if err := pc.SetRemoteDescription(offer); err != nil {
		s.resetSenderPC(pc)
		return fmt.Errorf("setting SFU sender offer: %w", err)
	}
	s.mu.Lock()
	if s.senderPeer != peer || s.senderPC != pc || s.closed {
		s.mu.Unlock()
		s.resetSenderPC(pc)
		return errScreenSFUUnavailable
	}
	s.senderRemoteDescriptionSet = true
	pendingICE := append([]webrtc.ICECandidateInit(nil), s.pendingSenderICE...)
	s.pendingSenderICE = nil
	s.mu.Unlock()
	for _, candidate := range pendingICE {
		if err := pc.AddICECandidate(candidate); err != nil {
			s.resetSenderPC(pc)
			return fmt.Errorf("adding queued SFU sender ICE: %w", err)
		}
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		s.resetSenderPC(pc)
		return fmt.Errorf("creating SFU sender answer: %w", err)
	}
	if err := pc.SetLocalDescription(answer); err != nil {
		s.resetSenderPC(pc)
		return fmt.Errorf("setting SFU sender answer: %w", err)
	}
	local := pc.LocalDescription()
	if local == nil {
		s.resetSenderPC(pc)
		return errors.New("SFU sender local description is unavailable")
	}
	data, err = json.Marshal(local)
	if err != nil {
		s.resetSenderPC(pc)
		return fmt.Errorf("encoding SFU sender answer: %w", err)
	}
	return peer.send(screenSignal{Type: "answer", Data: data})
}

func (s *screenSFU) handleViewerAnswer(peer *screenPeer, data json.RawMessage) error {
	var answer webrtc.SessionDescription
	if err := json.Unmarshal(data, &answer); err != nil || answer.Type != webrtc.SDPTypeAnswer || answer.SDP == "" {
		return errors.New("viewer answer is invalid")
	}
	s.mu.Lock()
	viewer := s.viewers[peer]
	pc := (*webrtc.PeerConnection)(nil)
	if viewer != nil {
		pc = viewer.pc
	}
	s.mu.Unlock()
	if viewer == nil || pc == nil {
		return errors.New("viewer peer connection is not ready")
	}
	if err := pc.SetRemoteDescription(answer); err != nil {
		return fmt.Errorf("setting SFU viewer answer: %w", err)
	}
	s.mu.Lock()
	if current := s.viewers[peer]; current != viewer || viewer.pc != pc {
		s.mu.Unlock()
		return errScreenSFUUnavailable
	}
	viewer.remoteDescriptionSet = true
	pending := append([]webrtc.ICECandidateInit(nil), viewer.pendingICE...)
	viewer.pendingICE = nil
	s.mu.Unlock()
	for _, candidate := range pending {
		if err := pc.AddICECandidate(candidate); err != nil {
			return fmt.Errorf("adding queued SFU viewer ICE: %w", err)
		}
	}
	return nil
}

func (s *screenSFU) handleICE(role screenRole, peer *screenPeer, data json.RawMessage) error {
	var candidate webrtc.ICECandidateInit
	if err := json.Unmarshal(data, &candidate); err != nil || candidate.Candidate == "" {
		return errors.New("ICE candidate is invalid")
	}
	s.mu.Lock()
	var pc *webrtc.PeerConnection
	if role == screenRoleSender {
		if s.senderPeer == peer {
			if s.senderPC == nil || !s.senderRemoteDescriptionSet {
				s.pendingSenderICE = append(s.pendingSenderICE, candidate)
				s.mu.Unlock()
				return nil
			}
			pc = s.senderPC
		}
	} else if viewer := s.viewers[peer]; viewer != nil {
		if viewer.pc == nil || !viewer.remoteDescriptionSet {
			viewer.pendingICE = append(viewer.pendingICE, candidate)
			s.mu.Unlock()
			return nil
		}
		pc = viewer.pc
	}
	s.mu.Unlock()
	if pc == nil {
		return errors.New("ICE candidate arrived before peer negotiation")
	}
	if err := pc.AddICECandidate(candidate); err != nil {
		return fmt.Errorf("adding ICE candidate: %w", err)
	}
	return nil
}

func (s *screenSFU) acceptTrack(remote *webrtc.TrackRemote) {
	local, err := webrtc.NewTrackLocalStaticRTP(remote.Codec().RTPCodecCapability, "ngstone-screen", "ngstone-screen")
	if err != nil {
		return
	}
	s.mu.Lock()
	if s.closed || s.localTrack != nil {
		s.mu.Unlock()
		return
	}
	s.localTrack = local
	s.senderTrackSSRC = uint32(remote.SSRC())
	viewers := make([]*screenSFUViewer, 0, len(s.viewers))
	for _, viewer := range s.viewers {
		viewers = append(viewers, viewer)
	}
	s.mu.Unlock()

	go s.forwardTrack(remote, local)
	for _, viewer := range viewers {
		go func(viewer *screenSFUViewer) {
			_ = s.negotiateViewer(viewer)
		}(viewer)
	}
}

func (s *screenSFU) requestKeyframe() {
	if s == nil {
		return
	}
	now := time.Now()
	s.mu.Lock()
	if s.closed || s.senderPC == nil || s.senderTrackSSRC == 0 ||
		!s.lastKeyframeRequest.IsZero() && now.Sub(s.lastKeyframeRequest) < screenSFUKeyframeInterval {
		s.mu.Unlock()
		return
	}
	pc := s.senderPC
	mediaSSRC := s.senderTrackSSRC
	s.lastKeyframeRequest = now
	s.mu.Unlock()
	_ = pc.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: mediaSSRC}})
}

func (s *screenSFU) forwardTrack(remote *webrtc.TrackRemote, local *webrtc.TrackLocalStaticRTP) {
	buffer := make([]byte, 64<<10)
	for {
		count, _, err := remote.Read(buffer)
		if err != nil {
			return
		}
		if _, err := local.Write(buffer[:count]); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			return
		}
	}
}

func (s *screenSFU) negotiateViewer(viewer *screenSFUViewer) error {
	s.mu.Lock()
	if s.closed || viewer == nil || s.viewers[viewer.peer] != viewer || s.localTrack == nil || viewer.negotiating {
		s.mu.Unlock()
		return nil
	}
	viewer.negotiating = true
	viewer.generation++
	generation := viewer.generation
	track := s.localTrack
	s.mu.Unlock()

	pc, err := webrtc.NewPeerConnection(s.configuration)
	if err != nil {
		s.markViewerNegotiationDone(viewer, generation)
		return fmt.Errorf("creating SFU viewer peer connection: %w", err)
	}
	s.mu.Lock()
	current := s.viewers[viewer.peer]
	if current != viewer || viewer.generation != generation || !viewer.negotiating || s.closed {
		s.mu.Unlock()
		_ = pc.Close()
		return nil
	}
	previousPC := viewer.pc
	viewer.pc = pc
	viewer.remoteDescriptionSet = false
	viewer.pendingICE = nil
	s.mu.Unlock()
	if previousPC != nil && previousPC != pc {
		_ = previousPC.Close()
	}
	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		data, marshalErr := json.Marshal(candidate.ToJSON())
		if marshalErr == nil {
			_ = viewer.peer.send(screenSignal{Type: "ice", Data: data})
		}
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			s.removeViewer(viewer.peer)
		}
	})
	rtpSender, err := pc.AddTrack(track)
	if err != nil {
		s.discardViewerPC(viewer, pc)
		_ = pc.Close()
		return fmt.Errorf("adding SFU viewer track: %w", err)
	}
	go drainScreenRTCP(rtpSender, s.requestKeyframe)
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		s.discardViewerPC(viewer, pc)
		_ = pc.Close()
		return fmt.Errorf("creating SFU viewer offer: %w", err)
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		s.discardViewerPC(viewer, pc)
		_ = pc.Close()
		return fmt.Errorf("setting SFU viewer offer: %w", err)
	}
	s.mu.Lock()
	current = s.viewers[viewer.peer]
	if current != viewer || viewer.generation != generation || viewer.pc != pc || s.closed {
		s.mu.Unlock()
		s.discardViewerPC(viewer, pc)
		_ = pc.Close()
		return nil
	}
	viewer.negotiating = false
	s.mu.Unlock()
	local := pc.LocalDescription()
	if local == nil {
		s.discardViewerPC(viewer, pc)
		_ = pc.Close()
		return errors.New("SFU viewer local description is unavailable")
	}
	data, err := json.Marshal(local)
	if err != nil {
		s.discardViewerPC(viewer, pc)
		_ = pc.Close()
		return fmt.Errorf("encoding SFU viewer offer: %w", err)
	}
	if err := viewer.peer.send(screenSignal{Type: "offer", Data: data}); err != nil {
		s.discardViewerPC(viewer, pc)
		_ = pc.Close()
		return err
	}
	return nil
}

func (s *screenSFU) markViewerNegotiationDone(viewer *screenSFUViewer, generation uint64) {
	s.mu.Lock()
	if viewer != nil && viewer.generation == generation {
		viewer.negotiating = false
	}
	s.mu.Unlock()
}

func (s *screenSFU) discardViewerPC(viewer *screenSFUViewer, pc *webrtc.PeerConnection) {
	s.mu.Lock()
	if viewer != nil && s.viewers[viewer.peer] == viewer && viewer.pc == pc {
		viewer.pc = nil
		viewer.remoteDescriptionSet = false
		viewer.pendingICE = nil
		viewer.negotiating = false
		viewer.generation++
	}
	s.mu.Unlock()
}

func (s *screenSFU) removeViewer(peer *screenPeer) {
	if peer == nil {
		return
	}
	s.mu.Lock()
	viewer := s.viewers[peer]
	delete(s.viewers, peer)
	var pc *webrtc.PeerConnection
	if viewer != nil {
		pc = viewer.pc
		viewer.pc = nil
	}
	s.mu.Unlock()
	if pc != nil {
		_ = pc.Close()
	}
}

func (s *screenSFU) resetSenderPC(pc *webrtc.PeerConnection) {
	s.mu.Lock()
	if s.senderPC != pc {
		s.mu.Unlock()
		return
	}
	s.senderPC = nil
	s.senderRemoteDescriptionSet = false
	s.pendingSenderICE = nil
	s.senderTrackSSRC = 0
	s.lastKeyframeRequest = time.Time{}
	s.localTrack = nil
	sender := s.senderPeer
	viewerConnections := make([]*webrtc.PeerConnection, 0, len(s.viewers))
	for _, viewer := range s.viewers {
		if viewer.pc != nil {
			viewerConnections = append(viewerConnections, viewer.pc)
		}
		viewer.pc = nil
		viewer.remoteDescriptionSet = false
		viewer.pendingICE = nil
		viewer.negotiating = false
		viewer.generation++
	}
	s.mu.Unlock()
	_ = pc.Close()
	for _, viewerPC := range viewerConnections {
		_ = viewerPC.Close()
	}
	if sender != nil {
		_ = sender.send(screenSignal{Type: "peer_joined"})
	}
}

func (s *screenSFU) removePeer(peer *screenPeer, role screenRole) []*screenPeer {
	if s == nil || peer == nil {
		return nil
	}
	s.mu.Lock()
	if role == screenRoleSender {
		if s.senderPeer != peer {
			s.mu.Unlock()
			return nil
		}
		s.senderPeer = nil
		pc := s.senderPC
		s.senderPC = nil
		s.senderRemoteDescriptionSet = false
		s.pendingSenderICE = nil
		s.senderTrackSSRC = 0
		s.lastKeyframeRequest = time.Time{}
		s.localTrack = nil
		viewers := make([]*screenPeer, 0, len(s.viewers))
		viewerConnections := make([]*webrtc.PeerConnection, 0, len(s.viewers))
		for _, viewer := range s.viewers {
			viewers = append(viewers, viewer.peer)
			if viewer.pc != nil {
				viewerConnections = append(viewerConnections, viewer.pc)
			}
			viewer.pc = nil
			viewer.remoteDescriptionSet = false
			viewer.pendingICE = nil
			viewer.negotiating = false
			viewer.generation++
		}
		s.mu.Unlock()
		if pc != nil {
			_ = pc.Close()
		}
		for _, viewerPC := range viewerConnections {
			_ = viewerPC.Close()
		}
		return viewers
	}
	viewer := s.viewers[peer]
	delete(s.viewers, peer)
	var viewerPC *webrtc.PeerConnection
	if viewer != nil {
		viewerPC = viewer.pc
		viewer.pc = nil
	}
	s.mu.Unlock()
	if viewerPC != nil {
		_ = viewerPC.Close()
	}
	return nil
}

func (s *screenSFU) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	senderPC := s.senderPC
	s.senderPC = nil
	s.senderRemoteDescriptionSet = false
	s.pendingSenderICE = nil
	s.senderTrackSSRC = 0
	s.lastKeyframeRequest = time.Time{}
	viewerConnections := make([]*webrtc.PeerConnection, 0, len(s.viewers))
	for _, viewer := range s.viewers {
		if viewer.pc != nil {
			viewerConnections = append(viewerConnections, viewer.pc)
			viewer.pc = nil
		}
		viewer.remoteDescriptionSet = false
		viewer.pendingICE = nil
		viewer.negotiating = false
		viewer.generation++
	}
	s.viewers = make(map[*screenPeer]*screenSFUViewer)
	s.mu.Unlock()
	if senderPC != nil {
		_ = senderPC.Close()
	}
	for _, viewerPC := range viewerConnections {
		_ = viewerPC.Close()
	}
}

func drainScreenRTCP(sender *webrtc.RTPSender, requestKeyframe func()) {
	if sender == nil || requestKeyframe == nil {
		return
	}
	for {
		packets, _, err := sender.ReadRTCP()
		if err != nil {
			return
		}
		for _, packet := range packets {
			if isScreenKeyframeRequest(packet) {
				requestKeyframe()
			}
		}
	}
}

func isScreenKeyframeRequest(packet rtcp.Packet) bool {
	switch packet.(type) {
	case *rtcp.PictureLossIndication, *rtcp.FullIntraRequest:
		return true
	default:
		return false
	}
}

func (s *Server) handleScreenSFUSignal(w http.ResponseWriter, r *http.Request, id string) {
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
	admission := s.screenAdmission()
	if admission == nil || !admission.tryAcquire() {
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}
	defer admission.release()
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
			if !ok || !s.screens.isSFU(id) {
				return errors.New("screen session token is invalid or expired")
			}
			if !s.screens.available(id, role) {
				return errScreenOccupied
			}
			config.Protocol = []string{screenWebSocketSubprotocol}
			return nil
		},
		Handler: func(ws *websocket.Conn) {
			ws.PayloadType = websocket.TextFrame
			ws.MaxPayloadBytes = screenMaxSignalBytes
			peer := &screenPeer{ws: ws}
			expiresAt, _, err := s.screens.attach(id, role, peer)
			if err != nil {
				_ = ws.Close()
				return
			}
			sfu, err := s.screenSFUFor(id)
			if err != nil {
				_ = s.screens.detach(id, role, peer)
				_ = ws.Close()
				return
			}
			defer func() {
				peers := s.screens.detach(id, role, peer)
				left := sfu.removePeer(peer, role)
				if role == screenRoleSender {
					for _, viewer := range left {
						_ = viewer.send(screenSignal{Type: "peer_left"})
					}
				} else if peers != nil {
					_ = peers.send(screenSignal{Type: "peer_left"})
				}
			}()
			if err := ws.SetDeadline(screenHeartbeatDeadline(expiresAt)); err != nil {
				_ = ws.Close()
				return
			}
			if err := s.sendScreenConfig(peer, id); err != nil {
				_ = ws.Close()
				return
			}
			if role == screenRoleSender {
				if err := sfu.attachSender(peer); err != nil {
					_ = ws.Close()
					return
				}
			} else if err := sfu.addViewer(peer); err != nil {
				_ = ws.Close()
				return
			}
			heartbeatDone := make(chan struct{})
			defer close(heartbeatDone)
			go screenHeartbeat(peer, ws, heartbeatDone)

			sender, viewers, _ := s.screens.connectedPeers(id)
			if role == screenRoleSender {
				if len(viewers) == 0 {
					_ = peer.send(screenSignal{Type: "waiting"})
				} else {
					_ = peer.send(screenSignal{Type: "peer_joined"})
					for _, viewer := range viewers {
						_ = viewer.send(screenSignal{Type: "peer_joined"})
					}
				}
			} else if sender == nil {
				_ = peer.send(screenSignal{Type: "waiting"})
			} else {
				_ = peer.send(screenSignal{Type: "peer_joined"})
				_ = sender.send(screenSignal{Type: "peer_joined"})
			}

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
				var signalErr error
				switch message.Type {
				case "offer":
					signalErr = sfu.handleSenderOffer(peer, message.Data)
				case "answer":
					signalErr = sfu.handleViewerAnswer(peer, message.Data)
				case "ice":
					signalErr = sfu.handleICE(role, peer, message.Data)
				case "bye":
					return
				}
				if signalErr != nil {
					_ = peer.send(screenSignal{Type: "error", Data: json.RawMessage(`{"code":"negotiation_failed"}`)})
					return
				}
			}
		},
	}
	wsServer.ServeHTTP(w, r)
}

func screenHeartbeat(peer *screenPeer, ws *websocket.Conn, done <-chan struct{}) {
	ticker := time.NewTicker(screenHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := peer.send(screenSignal{Type: "ping"}); err != nil {
				_ = ws.Close()
				return
			}
		case <-done:
			return
		}
	}
}
