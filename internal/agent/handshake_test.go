package agent

import (
	"errors"
	"net"
	"testing"
	"time"

	"ngstone/internal/proto"
)

func TestHandshakeFatalWhenEdgeNegotiatesV1WithAccessControlConfigured(t *testing.T) {
	agentSess, edgeSess, cleanup := newTestSessionPair(t)
	defer cleanup()

	a := New(Config{BasicAuthSHA256: []string{"deadbeef"}})
	idgen := proto.NewAgentIDGen()

	edgeDone := make(chan error, 1)
	go func() {
		msg, err := edgeSess.Control().Read()
		if err != nil {
			edgeDone <- err
			return
		}
		if msg.Type != proto.TypeAuth {
			edgeDone <- errors.New("expected auth as first message, got " + string(msg.Type))
			return
		}
		edgeDone <- edgeSess.Control().Write(proto.TypeAuthOK, msg.ID, proto.AuthOK{
			ProtoVersion:  1,
			SessionID:     "fake-session",
			ServerVersion: "fake-edge/old",
		})
	}()

	type handshakeResult struct {
		err error
	}
	resultCh := make(chan handshakeResult, 1)
	go func() {
		_, err := a.handshake(agentSess, idgen)
		resultCh <- handshakeResult{err: err}
	}()

	var err error
	select {
	case r := <-resultCh:
		err = r.err
	case <-time.After(3 * time.Second):
		t.Fatal("handshake did not return within 3s; with an edge that only negotiated v1, it must fail fast instead of sending a Bind and waiting for a reply")
	}

	if err == nil {
		t.Fatal("expected handshake to fail when the edge only negotiates protocol v1 but access control is configured")
	}
	if !errors.Is(err, errFatalHandshake) {
		t.Fatalf("handshake err = %v, want errFatalHandshake", err)
	}

	if writeErr := <-edgeDone; writeErr != nil {
		t.Fatalf("edge side: %v", writeErr)
	}

	edgeSess.Control().SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, readErr := edgeSess.Control().Read()
	if readErr == nil {
		t.Fatal("agent sent a message after the fatal handshake error; expected no Bind to be written")
	}
	var ne net.Error
	if !errors.As(readErr, &ne) || !ne.Timeout() {
		t.Fatalf("expected a read timeout (proving no Bind was ever sent), got: %v", readErr)
	}
}

func TestHandshakeFatalWhenEdgeSelectsUnsupportedProtocolVersion(t *testing.T) {
	agentSess, edgeSess, cleanup := newTestSessionPair(t)
	defer cleanup()

	a := New(Config{Kind: proto.KindHTTP, TargetURL: "http://127.0.0.1:1"})
	idgen := proto.NewAgentIDGen()

	edgeDone := make(chan error, 1)
	go func() {
		msg, err := edgeSess.Control().Read()
		if err != nil {
			edgeDone <- err
			return
		}
		if msg.Type != proto.TypeAuth {
			edgeDone <- errors.New("expected auth as first message, got " + string(msg.Type))
			return
		}
		edgeDone <- edgeSess.Control().Write(proto.TypeAuthOK, msg.ID, proto.AuthOK{
			ProtoVersion:  99,
			SessionID:     "fake-session",
			ServerVersion: "fake-edge/hostile",
		})
	}()

	type handshakeResult struct {
		err error
	}
	resultCh := make(chan handshakeResult, 1)
	go func() {
		_, err := a.handshake(agentSess, idgen)
		resultCh <- handshakeResult{err: err}
	}()

	var err error
	select {
	case r := <-resultCh:
		err = r.err
	case <-time.After(3 * time.Second):
		t.Fatal("handshake did not return within 3s; an edge selecting an unsupported protocol version must be rejected instead of trusted")
	}

	if err == nil {
		t.Fatal("expected handshake to fail when the edge selects a protocol version the agent never offered")
	}
	if !errors.Is(err, errFatalHandshake) {
		t.Fatalf("handshake err = %v, want errFatalHandshake", err)
	}

	if writeErr := <-edgeDone; writeErr != nil {
		t.Fatalf("edge side: %v", writeErr)
	}

	edgeSess.Control().SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, readErr := edgeSess.Control().Read()
	if readErr == nil {
		t.Fatal("agent sent a message after the fatal handshake error; expected no Bind to be written")
	}
	var ne net.Error
	if !errors.As(readErr, &ne) || !ne.Timeout() {
		t.Fatalf("expected a read timeout (proving no Bind was ever sent), got: %v", readErr)
	}
}

func TestHandshakeFatalWhenTCPKindHasBasicAuthConfigured(t *testing.T) {
	agentSess, edgeSess, cleanup := newTestSessionPair(t)
	defer cleanup()

	a := New(Config{Kind: proto.KindTCP, BasicAuthSHA256: []string{"deadbeef"}})
	idgen := proto.NewAgentIDGen()

	edgeDone := make(chan error, 1)
	go func() {
		msg, err := edgeSess.Control().Read()
		if err != nil {
			edgeDone <- err
			return
		}
		if msg.Type != proto.TypeAuth {
			edgeDone <- errors.New("expected auth as first message, got " + string(msg.Type))
			return
		}
		edgeDone <- edgeSess.Control().Write(proto.TypeAuthOK, msg.ID, proto.AuthOK{
			ProtoVersion:  2,
			SessionID:     "fake-session",
			ServerVersion: "fake-edge/new",
		})
	}()

	type handshakeResult struct {
		err error
	}
	resultCh := make(chan handshakeResult, 1)
	go func() {
		_, err := a.handshake(agentSess, idgen)
		resultCh <- handshakeResult{err: err}
	}()

	var err error
	select {
	case r := <-resultCh:
		err = r.err
	case <-time.After(3 * time.Second):
		t.Fatal("handshake did not return within 3s; a tcp tunnel with basic auth configured must fail fast instead of silently dropping auth")
	}

	if err == nil {
		t.Fatal("expected handshake to fail when a tcp tunnel is configured with basic auth")
	}
	if !errors.Is(err, errFatalHandshake) {
		t.Fatalf("handshake err = %v, want errFatalHandshake", err)
	}

	if writeErr := <-edgeDone; writeErr != nil {
		t.Fatalf("edge side: %v", writeErr)
	}

	edgeSess.Control().SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, readErr := edgeSess.Control().Read()
	if readErr == nil {
		t.Fatal("agent sent a message after the fatal handshake error; expected no Bind to be written")
	}
	var ne net.Error
	if !errors.As(readErr, &ne) || !ne.Timeout() {
		t.Fatalf("expected a read timeout (proving no Bind was ever sent), got: %v", readErr)
	}
}

func TestHandshakeSetsRealmOnlyWhenDigestsArePresent(t *testing.T) {
	runCase := func(t *testing.T, cfg Config) proto.Bind {
		agentSess, edgeSess, cleanup := newTestSessionPair(t)
		defer cleanup()

		a := New(cfg)
		idgen := proto.NewAgentIDGen()

		bindCh := make(chan proto.Bind, 1)
		edgeErrCh := make(chan error, 1)
		go func() {
			msg, err := edgeSess.Control().Read()
			if err != nil {
				edgeErrCh <- err
				return
			}
			if msg.Type != proto.TypeAuth {
				edgeErrCh <- errors.New("expected auth as first message, got " + string(msg.Type))
				return
			}
			if err := edgeSess.Control().Write(proto.TypeAuthOK, msg.ID, proto.AuthOK{
				ProtoVersion:  2,
				SessionID:     "fake-session",
				ServerVersion: "fake-edge/new",
			}); err != nil {
				edgeErrCh <- err
				return
			}

			bindMsg, err := edgeSess.Control().Read()
			if err != nil {
				edgeErrCh <- err
				return
			}
			if bindMsg.Type != proto.TypeBind {
				edgeErrCh <- errors.New("expected bind, got " + string(bindMsg.Type))
				return
			}
			bind, err := proto.Decode[proto.Bind](bindMsg)
			if err != nil {
				edgeErrCh <- err
				return
			}
			bindCh <- bind
			edgeErrCh <- edgeSess.Control().Write(proto.TypeBindOK, bindMsg.ID, proto.BindOK{
				Hostname: "foo.example.com",
				URL:      "http://foo.example.com",
			})
		}()

		resultCh := make(chan error, 1)
		go func() {
			_, err := a.handshake(agentSess, idgen)
			resultCh <- err
		}()

		var bind proto.Bind
		select {
		case bind = <-bindCh:
		case <-time.After(3 * time.Second):
			t.Fatal("edge did not receive a Bind within 3s")
		}

		if err := <-resultCh; err != nil {
			t.Fatalf("handshake: %v", err)
		}
		if edgeErr := <-edgeErrCh; edgeErr != nil {
			t.Fatalf("edge side: %v", edgeErr)
		}
		return bind
	}

	t.Run("with digests", func(t *testing.T) {
		bind := runCase(t, Config{
			Kind:            proto.KindHTTP,
			TargetURL:       "http://127.0.0.1:1",
			BasicAuthSHA256: []string{"deadbeef"},
			BasicAuthRealm:  "restricted",
		})
		if bind.BasicAuthRealm != "restricted" {
			t.Fatalf("bind.BasicAuthRealm = %q, want %q", bind.BasicAuthRealm, "restricted")
		}
	})

	t.Run("realm without digests is a no-op", func(t *testing.T) {
		bind := runCase(t, Config{
			Kind:           proto.KindHTTP,
			TargetURL:      "http://127.0.0.1:1",
			BasicAuthRealm: "restricted",
		})
		if bind.BasicAuthRealm != "" {
			t.Fatalf("bind.BasicAuthRealm = %q, want empty (realm without credentials must be a no-op)", bind.BasicAuthRealm)
		}
	})
}

func TestHandshakeSucceedsWithV1WhenNoAccessControlConfigured(t *testing.T) {
	agentSess, edgeSess, cleanup := newTestSessionPair(t)
	defer cleanup()

	a := New(Config{Kind: proto.KindHTTP, TargetURL: "http://127.0.0.1:1"})
	idgen := proto.NewAgentIDGen()

	go func() {
		msg, err := edgeSess.Control().Read()
		if err != nil || msg.Type != proto.TypeAuth {
			return
		}
		edgeSess.Control().Write(proto.TypeAuthOK, msg.ID, proto.AuthOK{
			ProtoVersion:  1,
			SessionID:     "fake-session",
			ServerVersion: "fake-edge/old",
		})

		bindMsg, err := edgeSess.Control().Read()
		if err != nil || bindMsg.Type != proto.TypeBind {
			return
		}
		edgeSess.Control().Write(proto.TypeBindOK, bindMsg.ID, proto.BindOK{
			Hostname: "foo.example.com",
			URL:      "http://foo.example.com",
		})
	}()

	bindOK, err := a.handshake(agentSess, idgen)
	if err != nil {
		t.Fatalf("handshake should succeed against a v1 edge when no access control is configured: %v", err)
	}
	if bindOK.Hostname != "foo.example.com" {
		t.Fatalf("bindOK.Hostname = %q, want %q", bindOK.Hostname, "foo.example.com")
	}
}
