package edge

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"ngstone/internal/access"
	"ngstone/internal/proto"
	"ngstone/internal/storage"
)

func TestDurableBindOwnershipAcrossEdges(t *testing.T) {
	store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db"), EdgeID: "edge-a"})
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	clientA, serverA, cleanupA := newRawSessionPair(t)
	defer cleanupA()
	first := newTestServer("")
	first.cfg.TokenSHA256 = nil
	first.storage = store
	first.credentialStore = store
	asA := &AgentSession{ID: "session-a", InstanceID: "instance-a", Sess: serverA, IDGen: proto.NewEdgeIDGen(), NegotiatedVersion: 2}
	first.handleBind(context.Background(), asA, serverA.Control(), 1, proto.Bind{Kind: proto.KindHTTP, Name: "web", Subdomain: "demo"})
	firstReply, err := clientA.Control().Read()
	if err != nil {
		t.Fatalf("read first bind: %v", err)
	}
	if firstReply.Type != proto.TypeBindOK {
		t.Fatalf("first bind reply = %q", firstReply.Type)
	}

	clientB, serverB, cleanupB := newRawSessionPair(t)
	defer cleanupB()
	second := newTestServer("")
	second.cfg.TokenSHA256 = nil
	second.storage = store
	second.credentialStore = store
	asB := &AgentSession{ID: "session-b", InstanceID: "instance-b", Sess: serverB, IDGen: proto.NewEdgeIDGen(), NegotiatedVersion: 2}
	second.handleBind(context.Background(), asB, serverB.Control(), 2, proto.Bind{Kind: proto.KindHTTP, Name: "web", Subdomain: "demo"})
	secondReply, err := clientB.Control().Read()
	if err != nil {
		t.Fatalf("read conflicting bind: %v", err)
	}
	var bindErr proto.BindErr
	if secondReply.Type != proto.TypeBindErr || json.Unmarshal(secondReply.Data, &bindErr) != nil || bindErr.Code != proto.CodeSubdomainTaken {
		t.Fatalf("conflicting bind reply = %+v", secondReply)
	}

	first.registry.ReleaseSession(asA)
	first.releaseDurableSession(asA)
	second.handleBind(context.Background(), asB, serverB.Control(), 3, proto.Bind{Kind: proto.KindHTTP, Name: "web", Subdomain: "demo"})
	thirdReply, err := clientB.Control().Read()
	if err != nil {
		t.Fatalf("read reclaimed bind: %v", err)
	}
	if thirdReply.Type != proto.TypeBindOK {
		t.Fatalf("reclaimed bind reply = %q", thirdReply.Type)
	}

	tunnels, err := store.ListTunnels(t.Context())
	if err != nil {
		t.Fatalf("list durable tunnels: %v", err)
	}
	if len(tunnels) != 1 || len(tunnels[0].Connectors) != 1 || tunnels[0].Connectors[0].SessionID != "session-b" {
		t.Fatalf("durable tunnels = %+v", tunnels)
	}
}

func TestDurableAccessJSONIsUnchangedWithoutVisitorLogin(t *testing.T) {
	cases := []struct {
		name      string
		bind      proto.Bind
		raw       string
		canonical string
	}{
		{
			name:      "empty",
			bind:      proto.Bind{},
			raw:       `{}`,
			canonical: `{}`,
		},
		{
			name: "basic auth realm and cidrs",
			bind: proto.Bind{
				BasicAuthSHA256: []string{"B3A8E0E1F9AB1BFE3A36F231F676F78BB30A519D2B21E6C530C0EEE8EBB4A5D0", "0000000000000000000000000000000000000000000000000000000000000001"},
				BasicAuthRealm:  "My \"Realm\"",
				AllowCIDRs:      []string{"10.1.2.3/8", "192.168.0.0/16"},
			},
			raw:       `{"basic_auth_sha256":["B3A8E0E1F9AB1BFE3A36F231F676F78BB30A519D2B21E6C530C0EEE8EBB4A5D0","0000000000000000000000000000000000000000000000000000000000000001"],"basic_auth_realm":"My \"Realm\"","allow_cidrs":["10.1.2.3/8","192.168.0.0/16"]}`,
			canonical: `{"basic_auth_sha256":["0000000000000000000000000000000000000000000000000000000000000001","b3a8e0e1f9ab1bfe3a36f231f676f78bb30a519d2b21e6c530c0eee8ebb4a5d0"],"basic_auth_realm":"My Realm","allow_cidrs":["10.0.0.0/8","192.168.0.0/16"]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := durableAccessJSON(tc.bind)
			if raw != tc.raw {
				t.Fatalf("durableAccessJSON = %s, want %s", raw, tc.raw)
			}
			canonical, err := access.CanonicalJSON(raw)
			if err != nil || canonical != tc.canonical {
				t.Fatalf("CanonicalJSON = %s, %v; want %s", canonical, err, tc.canonical)
			}
		})
	}
}

func TestDurableAccessJSONRecordsVisitorLogin(t *testing.T) {
	cases := []struct {
		name      string
		bind      proto.Bind
		canonical string
	}{
		{name: "wall without lists", bind: proto.Bind{OIDC: &proto.OIDCLogin{}}, canonical: `{"visitor_login":{}}`},
		{name: "wall with lists", bind: proto.Bind{OIDC: &proto.OIDCLogin{AllowEmails: []string{"Bob@Example.org", "alice@example.org"}, AllowDomains: []string{"@Example.net"}}}, canonical: `{"visitor_login":{"allow_emails":["alice@example.org","bob@example.org"],"allow_domains":["example.net"]}}`},
		{name: "wall with basic auth", bind: proto.Bind{BasicAuthSHA256: []string{"0000000000000000000000000000000000000000000000000000000000000001"}, OIDC: &proto.OIDCLogin{AllowDomains: []string{"example.org"}}}, canonical: `{"basic_auth_sha256":["0000000000000000000000000000000000000000000000000000000000000001"],"basic_auth_realm":"ngstone","visitor_login":{"allow_domains":["example.org"]}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			canonical, err := access.CanonicalJSON(durableAccessJSON(tc.bind))
			if err != nil || canonical != tc.canonical {
				t.Fatalf("CanonicalJSON = %s, %v; want %s", canonical, err, tc.canonical)
			}
		})
	}
}
