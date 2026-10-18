package edge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
	"golang.org/x/net/websocket"
)

type lockedScreenWebSocket struct {
	mu sync.Mutex
	ws *websocket.Conn
}

func TestScreenSFURecognizesKeyframeFeedbackAndThrottlesRequests(t *testing.T) {
	if !isScreenKeyframeRequest(&rtcp.PictureLossIndication{}) {
		t.Fatal("PLI was not recognized as keyframe feedback")
	}
	if !isScreenKeyframeRequest(&rtcp.FullIntraRequest{}) {
		t.Fatal("FIR was not recognized as keyframe feedback")
	}
	if isScreenKeyframeRequest(&rtcp.ReceiverReport{}) {
		t.Fatal("receiver report was recognized as keyframe feedback")
	}

	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("create peer connection: %v", err)
	}
	defer pc.Close()
	sfu := newScreenSFU("test", nil)
	sfu.senderPC = pc
	sfu.senderTrackSSRC = 1234
	sfu.requestKeyframe()
	first := sfu.lastKeyframeRequest
	if first.IsZero() {
		t.Fatal("keyframe request was not recorded")
	}
	sfu.requestKeyframe()
	if !sfu.lastKeyframeRequest.Equal(first) {
		t.Fatal("keyframe request was not throttled")
	}
}

func (w *lockedScreenWebSocket) send(t *testing.T, message screenSignal) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := websocket.JSON.Send(w.ws, message); err != nil {
		t.Fatalf("send screen signal %q: %v", message.Type, err)
	}
}

func (w *lockedScreenWebSocket) receive(t *testing.T) screenSignal {
	t.Helper()
	for {
		var message screenSignal
		if err := websocket.JSON.Receive(w.ws, &message); err != nil {
			t.Fatalf("receive screen signal: %v", err)
		}
		t.Logf("received screen signal %q", message.Type)
		if message.Type == "ping" {
			w.send(t, screenSignal{Type: "pong"})
			continue
		}
		return message
	}
}

func TestScreenSFUForwardsNegotiatedVideoTrack(t *testing.T) {
	s := newTestServer("")
	s.cfg.Domain = "127.0.0.1"
	s.screens = newScreenRegistry()
	s.unauthSem = newGlobalSemaphore(8)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handlePublicListener(r.Context(), w, r)
	}))
	defer ts.Close()
	issued, err := s.screens.createWithOptions("admin", "demo", time.Minute, 2, func(id string) string {
		return "http://" + ts.Listener.Addr().String() + screenPathPrefix + id
	})
	if err != nil {
		t.Fatalf("create SFU session: %v", err)
	}
	wsURL := "ws://" + ts.Listener.Addr().String() + screenPathPrefix + issued.Session.ID + screenSignalSuffix
	senderWS := &lockedScreenWebSocket{ws: dialScreenPeer(t, wsURL, issued.SenderToken)}
	defer senderWS.ws.Close()
	if got := senderWS.receive(t).Type; got != "config" {
		t.Fatalf("sender first message = %q, want config", got)
	}
	if got := senderWS.receive(t).Type; got != "waiting" {
		t.Fatalf("sender second message = %q, want waiting", got)
	}
	viewerWS := &lockedScreenWebSocket{ws: dialScreenPeer(t, wsURL, issued.ViewerToken)}
	defer viewerWS.ws.Close()
	if got := viewerWS.receive(t).Type; got != "config" {
		t.Fatalf("viewer first message = %q, want config", got)
	}
	if got := viewerWS.receive(t).Type; got != "peer_joined" {
		t.Fatalf("viewer second message = %q, want peer_joined", got)
	}
	if got := senderWS.receive(t).Type; got != "peer_joined" {
		t.Fatalf("sender join message = %q, want peer_joined", got)
	}

	senderPC, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("create sender peer connection: %v", err)
	}
	defer senderPC.Close()
	track, err := webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8, ClockRate: 90000},
		"video",
		"sender",
	)
	if err != nil {
		t.Fatalf("create sender track: %v", err)
	}
	if _, err := senderPC.AddTrack(track); err != nil {
		t.Fatalf("add sender track: %v", err)
	}
	senderPC.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		data, marshalErr := json.Marshal(candidate.ToJSON())
		if marshalErr != nil {
			t.Errorf("marshal sender ICE: %v", marshalErr)
			return
		}
		senderWS.send(t, screenSignal{Type: "ice", Data: data})
	})
	offer, err := senderPC.CreateOffer(nil)
	if err != nil {
		t.Fatalf("create sender offer: %v", err)
	}
	if err := senderPC.SetLocalDescription(offer); err != nil {
		t.Fatalf("set sender offer: %v", err)
	}
	offerData, err := json.Marshal(senderPC.LocalDescription())
	if err != nil {
		t.Fatalf("marshal sender offer: %v", err)
	}
	senderWS.send(t, screenSignal{Type: "offer", Data: offerData})

	var pendingSenderCandidates []webrtc.ICECandidateInit
	senderRemoteSet := false
	for !senderRemoteSet {
		message := senderWS.receive(t)
		switch message.Type {
		case "ice":
			var candidate webrtc.ICECandidateInit
			if err := json.Unmarshal(message.Data, &candidate); err != nil {
				t.Fatalf("decode sender ICE: %v", err)
			}
			if senderRemoteSet {
				if err := senderPC.AddICECandidate(candidate); err != nil {
					t.Fatalf("add sender ICE: %v", err)
				}
			} else {
				pendingSenderCandidates = append(pendingSenderCandidates, candidate)
			}
		case "answer":
			var answer webrtc.SessionDescription
			if err := json.Unmarshal(message.Data, &answer); err != nil {
				t.Fatalf("decode sender answer: %v", err)
			}
			if err := senderPC.SetRemoteDescription(answer); err != nil {
				t.Fatalf("set sender answer: %v", err)
			}
			senderRemoteSet = true
			for _, candidate := range pendingSenderCandidates {
				if err := senderPC.AddICECandidate(candidate); err != nil {
					t.Fatalf("add queued sender ICE: %v", err)
				}
			}
		}
	}
	senderSignalsDone := make(chan struct{})
	go func() {
		defer close(senderSignalsDone)
		for {
			var message screenSignal
			if err := websocket.JSON.Receive(senderWS.ws, &message); err != nil {
				return
			}
			if message.Type == "ping" {
				senderWS.send(t, screenSignal{Type: "pong"})
				continue
			}
			t.Logf("received sender screen signal %q", message.Type)
		}
	}()
	defer func() {
		_ = senderWS.ws.Close()
		<-senderSignalsDone
	}()

	mediaStop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		var sequence uint16 = 1
		for {
			select {
			case <-ticker.C:
				_ = track.WriteRTP(&rtp.Packet{
					Header:  rtp.Header{Version: 2, PayloadType: 96, SequenceNumber: sequence, Timestamp: uint32(sequence) * 3_000, SSRC: 1234},
					Payload: []byte{0x90, 0x60, 0x00},
				})
				sequence++
			case <-mediaStop:
				return
			}
		}
	}()
	defer close(mediaStop)

	viewerPC, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("create viewer peer connection: %v", err)
	}
	defer viewerPC.Close()
	if _, err := viewerPC.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{
		Direction: webrtc.RTPTransceiverDirectionRecvonly,
	}); err != nil {
		t.Fatalf("add viewer transceiver: %v", err)
	}
	trackReceived := make(chan struct{}, 1)
	viewerPC.OnTrack(func(*webrtc.TrackRemote, *webrtc.RTPReceiver) {
		select {
		case trackReceived <- struct{}{}:
		default:
		}
	})
	viewerPC.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		data, marshalErr := json.Marshal(candidate.ToJSON())
		if marshalErr != nil {
			t.Errorf("marshal viewer ICE: %v", marshalErr)
			return
		}
		viewerWS.send(t, screenSignal{Type: "ice", Data: data})
	})

	var pendingViewerCandidates []webrtc.ICECandidateInit
	viewerRemoteSet := false
	for !viewerRemoteSet {
		message := viewerWS.receive(t)
		switch message.Type {
		case "ice":
			var candidate webrtc.ICECandidateInit
			if err := json.Unmarshal(message.Data, &candidate); err != nil {
				t.Fatalf("decode viewer ICE: %v", err)
			}
			if viewerRemoteSet {
				if err := viewerPC.AddICECandidate(candidate); err != nil {
					t.Fatalf("add viewer ICE: %v", err)
				}
			} else {
				pendingViewerCandidates = append(pendingViewerCandidates, candidate)
			}
		case "offer":
			var viewerOffer webrtc.SessionDescription
			if err := json.Unmarshal(message.Data, &viewerOffer); err != nil {
				t.Fatalf("decode viewer offer: %v", err)
			}
			if err := viewerPC.SetRemoteDescription(viewerOffer); err != nil {
				t.Fatalf("set viewer offer: %v", err)
			}
			answer, answerErr := viewerPC.CreateAnswer(nil)
			if answerErr != nil {
				t.Fatalf("create viewer answer: %v", answerErr)
			}
			if err := viewerPC.SetLocalDescription(answer); err != nil {
				t.Fatalf("set viewer answer: %v", err)
			}
			answerData, marshalErr := json.Marshal(viewerPC.LocalDescription())
			if marshalErr != nil {
				t.Fatalf("marshal viewer answer: %v", marshalErr)
			}
			viewerWS.send(t, screenSignal{Type: "answer", Data: answerData})
			viewerRemoteSet = true
			for _, candidate := range pendingViewerCandidates {
				if err := viewerPC.AddICECandidate(candidate); err != nil {
					t.Fatalf("add queued viewer ICE: %v", err)
				}
			}
		}
	}

	select {
	case <-trackReceived:
	case <-time.After(2 * time.Second):
		t.Fatal("viewer did not receive the forwarded SFU track")
	}
}
