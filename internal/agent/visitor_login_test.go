package agent

import (
	"errors"
	"testing"
	"time"

	"ngstone/internal/proto"
)

func TestHandshakeOIDCLoginIsSentAndRequiresAcknowledgment(t *testing.T) {
	for _, acknowledge := range []bool{true, false} {
		t.Run(map[bool]string{true: "acknowledged", false: "missing_acknowledgment"}[acknowledge], func(t *testing.T) {
			agentSess, edgeSess, cleanup := newTestSessionPair(t)
			defer cleanup()

			login := &proto.OIDCLogin{AllowDomains: []string{"example.org"}}
			a := New(Config{Kind: proto.KindHTTP, TargetURL: "http://127.0.0.1:1", OIDC: login})
			edgeDone := make(chan error, 1)
			go func() {
				msg, err := edgeSess.Control().Read()
				if err != nil {
					edgeDone <- err
					return
				}
				if err := edgeSess.Control().Write(proto.TypeAuthOK, msg.ID, proto.AuthOK{ProtoVersion: 2}); err != nil {
					edgeDone <- err
					return
				}
				bindMsg, err := edgeSess.Control().Read()
				if err != nil {
					edgeDone <- err
					return
				}
				bind, err := proto.Decode[proto.Bind](bindMsg)
				if err != nil {
					edgeDone <- err
					return
				}
				if bind.OIDC == nil || len(bind.OIDC.AllowDomains) != 1 || bind.OIDC.AllowDomains[0] != "example.org" {
					edgeDone <- errors.New("bind did not carry the OIDC login rule")
					return
				}
				edgeDone <- edgeSess.Control().Write(proto.TypeBindOK, bindMsg.ID, proto.BindOK{Hostname: "foo.example.com", URL: "http://foo.example.com", OIDC: acknowledge})
			}()

			_, handshakeErr := a.handshake(agentSess, proto.NewAgentIDGen())
			if acknowledge && handshakeErr != nil {
				t.Fatalf("handshake: %v", handshakeErr)
			}
			if !acknowledge && !errors.Is(handshakeErr, errFatalHandshake) {
				t.Fatalf("handshake error = %v, want fatal acknowledgment error", handshakeErr)
			}
			select {
			case edgeErr := <-edgeDone:
				if edgeErr != nil {
					t.Fatalf("edge side: %v", edgeErr)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("edge side did not finish")
			}
		})
	}
}

func TestHandshakeOIDCLoginRejectedForTCP(t *testing.T) {
	agentSess, edgeSess, cleanup := newTestSessionPair(t)
	defer cleanup()

	a := New(Config{Kind: proto.KindTCP, TargetURL: "127.0.0.1:1", OIDC: &proto.OIDCLogin{}})
	edgeDone := make(chan error, 1)
	go func() {
		msg, err := edgeSess.Control().Read()
		if err != nil {
			edgeDone <- err
			return
		}
		edgeDone <- edgeSess.Control().Write(proto.TypeAuthOK, msg.ID, proto.AuthOK{ProtoVersion: 2})
	}()
	_, handshakeErr := a.handshake(agentSess, proto.NewAgentIDGen())
	if !errors.Is(handshakeErr, errFatalHandshake) {
		t.Fatalf("handshake error = %v, want fatal error for tcp OIDC", handshakeErr)
	}
	if err := <-edgeDone; err != nil {
		t.Fatalf("edge side: %v", err)
	}
}
