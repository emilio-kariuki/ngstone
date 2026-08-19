package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"ngstone/internal/policy"
	"ngstone/internal/proto"
)

func TestHandshakeTrafficPolicyIsSentAndAcknowledged(t *testing.T) {
	p, err := policy.Parse([]byte(`{"default_action":"deny","rules":[{"action":"allow","path_prefix":"/health"}]}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}

	for _, acknowledge := range []bool{true, false} {
		t.Run(map[bool]string{true: "acknowledged", false: "missing acknowledgment"}[acknowledge], func(t *testing.T) {
			agentSess, edgeSess, cleanup := newTestSessionPair(t)
			defer cleanup()

			a := New(Config{Kind: proto.KindHTTP, TargetURL: "http://127.0.0.1:1", Policy: p})
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
				if bind.Policy == nil || bind.PolicyDigest != p.Digest() {
					edgeDone <- errors.New("bind did not carry the policy and its digest")
					return
				}
				policyDigest := ""
				if acknowledge {
					policyDigest = bind.PolicyDigest
				}
				edgeDone <- edgeSess.Control().Write(proto.TypeBindOK, bindMsg.ID, proto.BindOK{
					Hostname:     "foo.example.com",
					URL:          "http://foo.example.com",
					PolicyDigest: policyDigest,
				})
			}()

			_, handshakeErr := a.handshake(agentSess, proto.NewAgentIDGen())
			if acknowledge {
				if handshakeErr != nil {
					t.Fatalf("handshake: %v", handshakeErr)
				}
			} else {
				if handshakeErr == nil || !errors.Is(handshakeErr, errFatalHandshake) {
					t.Fatalf("handshake error = %v, want fatal acknowledgment error", handshakeErr)
				}
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

func TestHandshakeTrafficPolicyRequiresProtocolV2(t *testing.T) {
	p, err := policy.Parse([]byte(`{"rules":[{"action":"deny","path_prefix":"/admin"}]}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}
	agentSess, edgeSess, cleanup := newTestSessionPair(t)
	defer cleanup()

	a := New(Config{Policy: p})
	edgeDone := make(chan error, 1)
	go func() {
		msg, err := edgeSess.Control().Read()
		if err != nil {
			edgeDone <- err
			return
		}
		edgeDone <- edgeSess.Control().Write(proto.TypeAuthOK, msg.ID, proto.AuthOK{ProtoVersion: 1})
	}()

	_, handshakeErr := a.handshake(agentSess, proto.NewAgentIDGen())
	if handshakeErr == nil || !errors.Is(handshakeErr, errFatalHandshake) {
		t.Fatalf("handshake error = %v, want fatal protocol compatibility error", handshakeErr)
	}
	if err := <-edgeDone; err != nil {
		t.Fatalf("edge side: %v", err)
	}
}

func TestHandshakeHTTP2IsSentAndRequiresAcknowledgment(t *testing.T) {
	for _, acknowledge := range []bool{true, false} {
		t.Run(map[bool]string{true: "acknowledged", false: "missing_acknowledgment"}[acknowledge], func(t *testing.T) {
			agentSess, edgeSess, cleanup := newTestSessionPair(t)
			defer cleanup()

			a := New(Config{Kind: proto.KindHTTP, TargetURL: "http://127.0.0.1:1", HTTP2: true})
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
				if !bind.HTTP2 {
					edgeDone <- errors.New("bind did not carry HTTP/2 mode")
					return
				}
				ack := proto.BindOK{Hostname: "foo.example.com", URL: "http://foo.example.com", HTTP2: acknowledge}
				edgeDone <- edgeSess.Control().Write(proto.TypeBindOK, bindMsg.ID, ack)
			}()

			_, handshakeErr := a.handshake(agentSess, proto.NewAgentIDGen())
			if acknowledge {
				if handshakeErr != nil {
					t.Fatalf("handshake: %v", handshakeErr)
				}
			} else if handshakeErr == nil || !errors.Is(handshakeErr, errFatalHandshake) {
				t.Fatalf("handshake error = %v, want fatal acknowledgment error", handshakeErr)
			}
			select {
			case err := <-edgeDone:
				if err != nil {
					t.Fatalf("edge side: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("edge side did not finish")
			}
		})
	}
}

func TestHandshakeMultiConnectorIsSentAndRequiresAcknowledgment(t *testing.T) {
	for _, acknowledge := range []bool{true, false} {
		t.Run(map[bool]string{true: "acknowledged", false: "missing_acknowledgment"}[acknowledge], func(t *testing.T) {
			agentSess, edgeSess, cleanup := newTestSessionPair(t)
			defer cleanup()

			a := New(Config{Kind: proto.KindHTTP, TargetURL: "http://127.0.0.1:1", MultiConnector: true, ConnectorToken: "pool-secret"})
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
				if !bind.MultiConnector {
					edgeDone <- errors.New("bind did not carry multiple-connector mode")
					return
				}
				digest := sha256.Sum256([]byte("pool-secret"))
				if bind.ConnectorTokenSHA256 != hex.EncodeToString(digest[:]) {
					edgeDone <- errors.New("bind did not carry the connector token digest")
					return
				}
				edgeDone <- edgeSess.Control().Write(proto.TypeBindOK, bindMsg.ID, proto.BindOK{
					Hostname:       "foo.example.com",
					URL:            "http://foo.example.com",
					MultiConnector: acknowledge,
				})
			}()

			_, handshakeErr := a.handshake(agentSess, proto.NewAgentIDGen())
			if acknowledge {
				if handshakeErr != nil {
					t.Fatalf("handshake: %v", handshakeErr)
				}
			} else if handshakeErr == nil || !errors.Is(handshakeErr, errFatalHandshake) {
				t.Fatalf("handshake error = %v, want fatal acknowledgment error", handshakeErr)
			}
			select {
			case err := <-edgeDone:
				if err != nil {
					t.Fatalf("edge side: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("edge side did not finish")
			}
		})
	}
}
