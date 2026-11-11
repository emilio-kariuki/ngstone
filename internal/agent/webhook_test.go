package agent

import (
	"errors"
	"strings"
	"testing"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/webhook"
)

func TestHandshakeWebhookIsSentAndAcknowledged(t *testing.T) {
	cfg := &webhook.Config{Provider: "Slack", Secret: "slack-signing-secret", PathPrefix: "/slack", Tolerance: 2 * time.Minute}
	for _, acknowledge := range []bool{true, false} {
		t.Run(map[bool]string{true: "acknowledged", false: "missing acknowledgment"}[acknowledge], func(t *testing.T) {
			agentSess, edgeSess, cleanup := newTestSessionPair(t)
			defer cleanup()

			a := New(Config{Kind: proto.KindHTTP, TargetURL: "http://127.0.0.1:1", Webhook: cfg})
			edgeDone := make(chan error, 1)
			go func() {
				msg, err := edgeSess.Control().Read()
				if err != nil {
					edgeDone <- err
					return
				}
				if err := edgeSess.Control().Write(proto.TypeAuthOK, msg.ID, proto.AuthOK{ProtoVersion: 3}); err != nil {
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
				want := proto.WebhookVerification{Provider: "slack", Secret: "slack-signing-secret", PathPrefix: "/slack", ToleranceSeconds: 120}
				if bind.Webhook == nil || *bind.Webhook != want {
					edgeDone <- errors.New("bind did not carry the normalized webhook configuration")
					return
				}
				ack := ""
				if acknowledge {
					ack = bind.Webhook.Provider
				}
				edgeDone <- edgeSess.Control().Write(proto.TypeBindOK, bindMsg.ID, proto.BindOK{Hostname: "foo.example.com", URL: "http://foo.example.com", Webhook: ack})
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

func TestHandshakeWebhookRejectsTCPAndOldEdges(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		version int
	}{
		{name: "tcp", cfg: Config{Kind: proto.KindTCP, TargetURL: "127.0.0.1:1", Webhook: &webhook.Config{Provider: "github", Secret: "s"}}, version: 3},
		{name: "protocol v1", cfg: Config{Kind: proto.KindHTTP, TargetURL: "http://127.0.0.1:1", Webhook: &webhook.Config{Provider: "github", Secret: "s"}}, version: 1},
		{name: "invalid config", cfg: Config{Kind: proto.KindHTTP, TargetURL: "http://127.0.0.1:1", Webhook: &webhook.Config{Provider: "hmac", Secret: "s"}}, version: 3},
		{name: "plaintext to remote edge", cfg: Config{Kind: proto.KindHTTP, TargetURL: "http://127.0.0.1:1", ControlAddr: "edge.example.com:4443", Insecure: true, Webhook: &webhook.Config{Provider: "github", Secret: "s"}}, version: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agentSess, edgeSess, cleanup := newTestSessionPair(t)
			defer cleanup()
			a := New(tc.cfg)
			edgeDone := make(chan error, 1)
			go func() {
				msg, err := edgeSess.Control().Read()
				if err != nil {
					edgeDone <- err
					return
				}
				edgeDone <- edgeSess.Control().Write(proto.TypeAuthOK, msg.ID, proto.AuthOK{ProtoVersion: tc.version})
			}()
			_, handshakeErr := a.handshake(agentSess, proto.NewAgentIDGen())
			if !errors.Is(handshakeErr, errFatalHandshake) {
				t.Fatalf("handshake error = %v, want fatal error", handshakeErr)
			}
			if err := <-edgeDone; err != nil {
				t.Fatalf("edge side: %v", err)
			}
		})
	}
}

func TestWebhookBindRefusesPlaintextToRemoteEdge(t *testing.T) {
	secret := "whsec_DISTINCTIVE_agent_plaintext"
	cases := []struct {
		addr     string
		insecure bool
		ok       bool
	}{
		{addr: "127.0.0.1:4443", insecure: true, ok: true},
		{addr: "127.0.0.2:4443", insecure: true, ok: true},
		{addr: "[::1]:4443", insecure: true, ok: true},
		{addr: "localhost:4443", insecure: true, ok: true},
		{addr: "LOCALHOST:4443", insecure: true, ok: true},
		{addr: "edge.example.com:4443", insecure: false, ok: true},
		{addr: "edge.example.com:4443", insecure: true},
		{addr: "10.0.0.1:4443", insecure: true},
		{addr: "localhost.example.com:4443", insecure: true},
		{addr: ":4443", insecure: true},
		{addr: "", insecure: true},
	}
	for _, tc := range cases {
		a := New(Config{Kind: proto.KindHTTP, TargetURL: "http://127.0.0.1:1", ControlAddr: tc.addr, Insecure: tc.insecure, Webhook: &webhook.Config{Provider: "github", Secret: secret}})
		bind, err := a.webhookBind(3)
		if tc.ok {
			if err != nil || bind == nil || bind.Secret != secret {
				t.Errorf("addr %q insecure %v: bind %v err %v, want accepted", tc.addr, tc.insecure, bind, err)
			}
			continue
		}
		if bind != nil || !errors.Is(err, errFatalHandshake) || !strings.Contains(err.Error(), "plaintext") {
			t.Errorf("addr %q insecure %v: bind %v err %v, want plaintext refusal", tc.addr, tc.insecure, bind, err)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("addr %q: refusal exposes the secret: %v", tc.addr, err)
		}
	}
}
