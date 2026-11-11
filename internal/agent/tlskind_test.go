package agent

import (
	"errors"
	"strings"
	"testing"

	"ngstone/internal/policy"
	"ngstone/internal/proto"
	"ngstone/internal/webhook"
)

func TestTLSKindSplicesThroughTCPPipe(t *testing.T) {
	a := New(Config{Kind: proto.KindTLS, TargetURL: "127.0.0.1:8443"})
	if got := a.bindKind(); got != proto.KindTLS {
		t.Fatalf("bindKind = %q, want tls", got)
	}
	srv, err := a.newServer()
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	pipe, ok := srv.(*tcpServer)
	if !ok {
		t.Fatalf("newServer = %T, want *tcpServer", srv)
	}
	if pipe.target != "127.0.0.1:8443" {
		t.Fatalf("tcp pipe target = %q", pipe.target)
	}
	if got := a.advertisedURL(proto.BindOK{Hostname: "secure.example.com", URL: "tls://secure.example.com"}); got != "tls://secure.example.com" {
		t.Fatalf("advertisedURL = %q", got)
	}
}

func TestHandshakeRejectsUnsupportedTLSOptions(t *testing.T) {
	p, err := policy.Parse([]byte(`{"default_action":"deny","rules":[{"action":"allow","path_prefix":"/health"}]}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}
	base := Config{Kind: proto.KindTLS, TargetURL: "127.0.0.1:8443"}
	cases := []struct {
		name string
		mod  func(*Config)
		want string
	}{
		{"oidc", func(c *Config) { c.OIDC = &proto.OIDCLogin{AllowEmails: []string{"alice@example.com"}} }, "not supported for tls tunnels"},
		{"webhook", func(c *Config) { c.Webhook = &webhook.Config{Provider: "github", Secret: "s"} }, "only supported for http tunnels"},
		{"policy", func(c *Config) { c.Policy = p }, "not supported for tls tunnels"},
		{"basic auth", func(c *Config) { c.BasicAuthSHA256 = []string{strings.Repeat("a", 64)} }, "not supported for tls tunnels"},
		{"http2", func(c *Config) { c.HTTP2 = true }, "not supported for tls tunnels"},
		{"multi connector", func(c *Config) { c.MultiConnector = true }, "not supported for tls tunnels"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agentSess, edgeSess, cleanup := newTestSessionPair(t)
			defer cleanup()
			failFastControl(t, agentSess, edgeSess)

			cfg := base
			tc.mod(&cfg)
			a := New(cfg)
			sawBind := make(chan bool, 1)
			go func() {
				msg, err := edgeSess.Control().Read()
				if err != nil {
					sawBind <- false
					return
				}
				if err := edgeSess.Control().Write(proto.TypeAuthOK, msg.ID, proto.AuthOK{ProtoVersion: 3}); err != nil {
					sawBind <- false
					return
				}
				next, err := edgeSess.Control().Read()
				sawBind <- err == nil && next.Type == proto.TypeBind
			}()
			_, handshakeErr := a.handshake(agentSess, proto.NewAgentIDGen())
			if !errors.Is(handshakeErr, errFatalHandshake) {
				t.Fatalf("handshake error = %v, want fatal handshake error", handshakeErr)
			}
			if !strings.Contains(handshakeErr.Error(), tc.want) {
				t.Fatalf("handshake error = %q, want substring %q", handshakeErr, tc.want)
			}
			agentSess.Close("test done")
			if <-sawBind {
				t.Fatal("agent sent a Bind despite the unsupported option")
			}
		})
	}
}
