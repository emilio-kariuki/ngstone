package edge

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"ngstone/internal/credentials"
	"ngstone/internal/proto"
	"ngstone/internal/storage"
)

func TestHandleBindTLSCredentialScope(t *testing.T) {
	cases := []struct {
		name     string
		spec     credentials.Spec
		bind     proto.Bind
		wantOK   bool
		wantHost string
	}{
		{name: "tls credential binds its subdomain", spec: credentials.Spec{Kind: credentials.KindTLS, Subdomain: "secure"}, bind: proto.Bind{Kind: proto.KindTLS, Subdomain: "secure"}, wantOK: true, wantHost: "secure.example.com"},
		{name: "subdomain case is normalised", spec: credentials.Spec{Kind: credentials.KindTLS, Subdomain: "secure"}, bind: proto.Bind{Kind: proto.KindTLS, Subdomain: "SECURE"}, wantOK: true, wantHost: "secure.example.com"},
		{name: "tls credential rejects another subdomain", spec: credentials.Spec{Kind: credentials.KindTLS, Subdomain: "secure"}, bind: proto.Bind{Kind: proto.KindTLS, Subdomain: "other"}},
		{name: "tls credential rejects http bind", spec: credentials.Spec{Kind: credentials.KindTLS, Subdomain: "secure"}, bind: proto.Bind{Kind: proto.KindHTTP, Subdomain: "secure"}},
		{name: "http credential rejects tls bind", spec: credentials.Spec{Kind: credentials.KindHTTP, Subdomain: "secure"}, bind: proto.Bind{Kind: proto.KindTLS, Subdomain: "secure"}},
		{name: "preview credential rejects tls bind", spec: credentials.Spec{Kind: credentials.KindPreview}, bind: proto.Bind{Kind: proto.KindTLS}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db"), EdgeID: "edge-a"})
			if err != nil {
				t.Fatalf("open storage: %v", err)
			}
			defer store.Close()
			ctx := context.Background()
			issued, err := store.IssueContext(ctx, tc.spec, time.Hour)
			if err != nil {
				t.Fatalf("issue credential: %v", err)
			}
			client, server, cleanup := newRawSessionPair(t)
			defer cleanup()
			s := newTestServer("")
			s.cfg.TokenSHA256 = nil
			s.storage = store
			s.credentialStore = store
			as := &AgentSession{ID: "session-a", InstanceID: "instance-a", Sess: server, IDGen: proto.NewEdgeIDGen(), NegotiatedVersion: 3, Credential: &issued.Credential}
			s.handleBind(ctx, as, server.Control(), 1, tc.bind)
			reply, err := client.Control().Read()
			if err != nil {
				t.Fatalf("read bind reply: %v", err)
			}
			if tc.wantOK {
				if reply.Type != proto.TypeBindOK {
					t.Fatalf("reply = %+v, want bind_ok", reply)
				}
				if _, ok := s.registry.RouteTLS(tc.wantHost); !ok {
					t.Fatalf("RouteTLS(%q) found no binding", tc.wantHost)
				}
				return
			}
			bindErr, _ := proto.Decode[proto.BindErr](reply)
			if reply.Type != proto.TypeBindErr || bindErr.Code != proto.CodeCredentialScope {
				t.Fatalf("reply = %+v %+v, want bind_err credential_scope", reply, bindErr)
			}
		})
	}
}
