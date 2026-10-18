package edge

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

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
