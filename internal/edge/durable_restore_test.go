package edge

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"ngstone/internal/credentials"
	"ngstone/internal/proto"
	"ngstone/internal/storage"
	"ngstone/internal/tunnel"
)

type restoreFixture struct {
	s      *Server
	store  *storage.Store
	oldAS  *AgentSession
	newAS  *AgentSession
	client tunnel.Session
	server tunnel.Session
	lease  storage.Lease
}

func newRestoreFixture(t *testing.T, kind, hostname string) (*restoreFixture, func()) {
	t.Helper()
	store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db")})
	if err != nil {
		t.Fatal(err)
	}
	client, server, cleanup := newRawSessionPair(t)
	s := newTestServer("tok")
	s.cfg.PublicAddr = ":443"
	s.storage = store
	oldAS := &AgentSession{ID: "old-sess", InstanceID: "inst-x", Sess: server, IDGen: proto.NewEdgeIDGen(), NegotiatedVersion: proto.ProtoVersion, Credential: &credentials.Credential{}}
	newAS := &AgentSession{ID: "new-sess", InstanceID: "inst-x", Sess: server, IDGen: proto.NewEdgeIDGen(), NegotiatedVersion: proto.ProtoVersion}
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: hostname, Session: oldAS, TLS: kind == "tls"}); err != nil {
		t.Fatalf("old session local bind: %v", err)
	}
	lease, err := store.AcquireLease(context.Background(), storage.LeaseRequest{
		Hostname: hostname, Kind: kind, OwnerID: durableOwnerID(newAS),
		InstanceID: "inst-x", SessionID: oldAS.ID, EdgeID: store.EdgeID(),
	})
	if err != nil {
		t.Fatalf("seed old lease: %v", err)
	}
	oldAS.rememberDurableLease(durableLeaseKey(kind, hostname, 0), lease.ID)
	return &restoreFixture{s: s, store: store, oldAS: oldAS, newAS: newAS, client: client, server: server, lease: lease}, func() {
		s.registry.ReleaseSession(oldAS)
		s.registry.ReleaseSession(newAS)
		store.Close()
		cleanup()
	}
}

func (f *restoreFixture) assertOldLeaseRestored(t *testing.T, hostname string, wantNew int64) {
	t.Helper()
	tunnels, err := f.store.ListTunnels(context.Background())
	if err != nil {
		t.Fatalf("list tunnels: %v", err)
	}
	found := false
	for _, tun := range tunnels {
		if tun.Hostname != hostname {
			continue
		}
		found = true
		if tun.Status != "active" || tun.SessionID != f.oldAS.ID || len(tun.Connectors) != 1 || tun.Connectors[0].SessionID != f.oldAS.ID || tun.Connectors[0].ID != f.lease.ID {
			t.Fatalf("tunnel %s after the failed bind = %+v, want the old session's lease %s restored", hostname, tun, f.lease.ID)
		}
	}
	if !found {
		t.Fatalf("tunnel %s missing after the failed bind", hostname)
	}
	if err := f.s.renewDurableSession(f.oldAS); err != nil {
		t.Fatalf("old session renewal after the failed bind = %v, want nil", err)
	}
	ctx := context.Background()
	if n, err := f.store.RenewSessionLeases(ctx, f.store.EdgeID(), f.oldAS.ID, time.Now()); err != nil || n != 1 {
		t.Fatalf("old session renews %d leases, err %v, want 1", n, err)
	}
	if n, err := f.store.RenewSessionLeases(ctx, f.store.EdgeID(), f.newAS.ID, time.Now()); err != nil || n != wantNew {
		t.Fatalf("new session holds %d leases, err %v, want %d", n, err, wantNew)
	}
}

func requireBindErr(t *testing.T, reply proto.Msg, code string) {
	t.Helper()
	e, _ := proto.Decode[proto.BindErr](reply)
	if reply.Type != proto.TypeBindErr || e.Code != code {
		t.Fatalf("reply = %s %s, want bind_err %s", reply.Type, reply.Data, code)
	}
}

func TestHandleBindHTTPLocalBindFailureRestoresOldLease(t *testing.T) {
	f, cleanup := newRestoreFixture(t, "http", "taken.example.com")
	defer cleanup()
	reply := bindOverWire(t, f.s, f.newAS, f.client, f.server, proto.Bind{Kind: proto.KindHTTP, Subdomain: "taken"})
	requireBindErr(t, reply, proto.CodeSubdomainTaken)
	f.assertOldLeaseRestored(t, "taken.example.com", 0)
}

func TestHandleBindHTTPRandomNameLocalBindFailureRestoresOldLease(t *testing.T) {
	f, cleanup := newRestoreFixture(t, "http", "taken.example.com")
	defer cleanup()
	names := []string{"taken", "open"}
	i := 0
	f.s.randomName = func() string {
		n := names[i]
		if i < len(names)-1 {
			i++
		}
		return n
	}
	reply := bindOverWire(t, f.s, f.newAS, f.client, f.server, proto.Bind{Kind: proto.KindHTTP})
	ok, _ := proto.Decode[proto.BindOK](reply)
	if reply.Type != proto.TypeBindOK || ok.Hostname != "open.example.com" {
		t.Fatalf("reply = %s %s, want bind_ok on open.example.com", reply.Type, reply.Data)
	}
	f.assertOldLeaseRestored(t, "taken.example.com", 1)
}

func TestHandleBindTLSLocalBindFailureRestoresOldLease(t *testing.T) {
	f, cleanup := newRestoreFixture(t, "tls", "taken.example.com")
	defer cleanup()
	reply := bindOverWire(t, f.s, f.newAS, f.client, f.server, proto.Bind{Kind: proto.KindTLS, Subdomain: "taken"})
	requireBindErr(t, reply, proto.CodeSubdomainTaken)
	f.assertOldLeaseRestored(t, "taken.example.com", 0)
}
