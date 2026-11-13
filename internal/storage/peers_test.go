package storage

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ngstone/internal/access"
)

func forEachPeerStore(t *testing.T, fn func(t *testing.T, s *Store)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) {
		fn(t, openTestStore(t, filepath.Join(t.TempDir(), "control.db")))
	})
	t.Run("postgres", func(t *testing.T) {
		fn(t, openPostgresTestStore(t, postgresSchemaDSN(t), "edge-a"))
	})
}

func seedPeer(t *testing.T, s *Store, edgeID string, expiresAt time.Time) {
	t.Helper()
	peer := EdgePeer{EdgeID: edgeID, PeerAddr: edgeID + ".internal:7443", SPKISHA256: "pin-" + edgeID, ExpiresAt: expiresAt}
	if err := s.UpsertEdgePeer(context.Background(), peer); err != nil {
		t.Fatalf("upsert peer %s: %v", edgeID, err)
	}
}

func seedLease(t *testing.T, s *Store, hostname, kind, accessJSON string) {
	t.Helper()
	_, err := s.AcquireLease(context.Background(), LeaseRequest{
		Hostname: hostname, Kind: kind, EdgeID: "edge-b", OwnerID: "owner-1",
		InstanceID: "instance-" + kind, SessionID: "session-" + kind,
		AccessJSON: accessJSON, ExpiresAt: time.Now().Add(time.Hour),
		RemotePort: map[string]int{"tcp": 9000}[kind],
	})
	if err != nil {
		t.Fatalf("acquire %s lease: %v", kind, err)
	}
}

func seedMultiLease(t *testing.T, s *Store, hostname, edgeID, instance string) {
	t.Helper()
	_, err := s.AcquireLease(context.Background(), LeaseRequest{
		Hostname: hostname, Kind: "tls", EdgeID: edgeID, OwnerID: "owner-1",
		InstanceID: instance, SessionID: "session-" + instance,
		MultiConnector: true, ConnectorTokenDigest: "digest",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("acquire multi-connector lease %s on %s: %v", instance, edgeID, err)
	}
}

func TestMigrationCreatesEdgePeers(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		seedPeer(t, s, "edge-b", time.Now().Add(time.Hour))
		peers, err := s.LiveEdgePeers(context.Background(), time.Now())
		if err != nil || len(peers) != 1 || peers[0].EdgeID != "edge-b" {
			t.Fatalf("live peers = %+v, %v", peers, err)
		}
	})
}

func TestLookupHostOwnersReturnsLiveRemoteOwner(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		seedLease(t, s, "app.example.com", "http", "")
		seedPeer(t, s, "edge-b", time.Now().Add(time.Hour))
		for _, host := range []string{"app.example.com", " APP.Example.com "} {
			peers, err := s.LookupHostOwners(context.Background(), host, "edge-a", time.Now())
			if err != nil || len(peers) != 1 {
				t.Fatalf("lookup %q = %+v, %v", host, peers, err)
			}
			peer := peers[0]
			if peer.EdgeID != "edge-b" || peer.PeerAddr != "edge-b.internal:7443" || peer.SPKISHA256 != "pin-edge-b" {
				t.Fatalf("lookup %q peer = %+v", host, peer)
			}
		}
	})
}

func TestLookupHostOwnersExcludesSelf(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		seedLease(t, s, "app.example.com", "http", "")
		seedPeer(t, s, "edge-b", time.Now().Add(time.Hour))
		peers, err := s.LookupHostOwners(context.Background(), "app.example.com", "edge-b", time.Now())
		if err != nil || len(peers) != 0 {
			t.Fatalf("lookup excluding owner = %+v, %v", peers, err)
		}
	})
}

func TestLookupHostOwnersIgnoresExpiredPeer(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		seedLease(t, s, "app.example.com", "http", "")
		seedPeer(t, s, "edge-b", time.Now().Add(-time.Minute))
		if peers, err := s.LookupHostOwners(context.Background(), "app.example.com", "edge-a", time.Now()); err != nil || len(peers) != 0 {
			t.Fatalf("lookup with expired peer = %+v, %v", peers, err)
		}
	})
}

func TestLookupHostOwnersIgnoresExpiredLease(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		seedLease(t, s, "app.example.com", "http", "")
		seedPeer(t, s, "edge-b", time.Now().Add(3*time.Hour))
		if peers, err := s.LookupHostOwners(context.Background(), "app.example.com", "edge-a", time.Now().Add(2*time.Hour)); err != nil || len(peers) != 0 {
			t.Fatalf("lookup after lease expiry = %+v, %v", peers, err)
		}
	})
}

func TestLookupHostOwnersIgnoresTCPKind(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		seedLease(t, s, "tcp.example.com", "tcp", "")
		seedLease(t, s, "tls.example.com", "tls", "")
		seedPeer(t, s, "edge-b", time.Now().Add(time.Hour))
		if peers, err := s.LookupHostOwners(context.Background(), "tcp.example.com", "edge-a", time.Now()); err != nil || len(peers) != 0 {
			t.Fatalf("tcp lookup = %+v, %v", peers, err)
		}
		if peers, err := s.LookupHostOwners(context.Background(), "tls.example.com", "edge-a", time.Now()); err != nil || len(peers) != 1 || peers[0].EdgeID != "edge-b" {
			t.Fatalf("tls lookup = %+v, %v", peers, err)
		}
	})
}

func TestLookupHostOwnersReturnsEveryEdgeInOrder(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		seedMultiLease(t, s, "app.example.com", "edge-c", "instance-1")
		seedMultiLease(t, s, "app.example.com", "edge-b", "instance-2")
		seedPeer(t, s, "edge-c", time.Now().Add(time.Hour))
		seedPeer(t, s, "edge-b", time.Now().Add(time.Hour))
		peers, err := s.LookupHostOwners(context.Background(), "app.example.com", "edge-a", time.Now())
		if err != nil || len(peers) != 2 || peers[0].EdgeID != "edge-b" || peers[1].EdgeID != "edge-c" {
			t.Fatalf("lookup = %+v, %v; want edge-b then edge-c", peers, err)
		}
		peers, err = s.LookupHostOwners(context.Background(), "app.example.com", "edge-b", time.Now())
		if err != nil || len(peers) != 1 || peers[0].EdgeID != "edge-c" {
			t.Fatalf("lookup excluding edge-b = %+v, %v", peers, err)
		}
	})
}

func TestLookupHostOwnersReturnsEdgeOnceForSeveralLeases(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		seedMultiLease(t, s, "app.example.com", "edge-b", "instance-1")
		seedMultiLease(t, s, "app.example.com", "edge-b", "instance-2")
		seedPeer(t, s, "edge-b", time.Now().Add(time.Hour))
		peers, err := s.LookupHostOwners(context.Background(), "app.example.com", "edge-a", time.Now())
		if err != nil || len(peers) != 1 || peers[0].EdgeID != "edge-b" {
			t.Fatalf("lookup = %+v, %v; want edge-b once", peers, err)
		}
	})
}

func TestLookupHostOwnersWrapsErrors(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		s.Close()
		_, err := s.LookupHostOwners(context.Background(), "app.example.com", "edge-a", time.Now())
		if err == nil || !strings.Contains(err.Error(), "storage: lookup host owners") {
			t.Fatalf("lookup on a closed store err = %v, want it wrapped with its own context", err)
		}
	})
}

func TestLiveEdgePeersSkipsExpired(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		seedPeer(t, s, "edge-c", time.Now().Add(time.Hour))
		seedPeer(t, s, "edge-b", time.Now().Add(time.Hour))
		seedPeer(t, s, "edge-d", time.Now().Add(-time.Minute))
		peers, err := s.LiveEdgePeers(context.Background(), time.Now())
		if err != nil || len(peers) != 2 || peers[0].EdgeID != "edge-b" || peers[1].EdgeID != "edge-c" {
			t.Fatalf("live peers = %+v, %v", peers, err)
		}
	})
}

func TestUpsertEdgePeerReplacesPin(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		seedPeer(t, s, "edge-b", time.Now().Add(time.Hour))
		replacement := EdgePeer{EdgeID: "edge-b", PeerAddr: "new.internal:7443", SPKISHA256: "pin-new", ExpiresAt: time.Now().Add(time.Hour)}
		if err := s.UpsertEdgePeer(ctx, replacement); err != nil {
			t.Fatalf("replace peer: %v", err)
		}
		peers, err := s.LiveEdgePeers(ctx, time.Now())
		if err != nil || len(peers) != 1 || peers[0].PeerAddr != "new.internal:7443" || peers[0].SPKISHA256 != "pin-new" {
			t.Fatalf("peers after replace = %+v, %v", peers, err)
		}
		if err := s.UpsertEdgePeer(ctx, EdgePeer{EdgeID: "edge-b", PeerAddr: "x", ExpiresAt: time.Now()}); err == nil {
			t.Fatal("upsert without pin succeeded")
		}
	})
}

func TestDeleteEdgePeer(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		seedPeer(t, s, "edge-b", time.Now().Add(time.Hour))
		if err := s.DeleteEdgePeer(ctx, "edge-b"); err != nil {
			t.Fatalf("delete peer: %v", err)
		}
		if err := s.DeleteEdgePeer(ctx, "edge-b"); err != nil {
			t.Fatalf("delete missing peer: %v", err)
		}
		if peers, err := s.LiveEdgePeers(ctx, time.Now()); err != nil || len(peers) != 0 {
			t.Fatalf("peers after delete = %+v, %v", peers, err)
		}
	})
}

func TestLookupHostAccessReturnsAccessJSON(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		raw := `{"visitor_login":{"allow_domains":["corp.example"]}}`
		want, err := access.CanonicalJSON(raw)
		if err != nil {
			t.Fatalf("canonical access json: %v", err)
		}
		seedLease(t, s, "app.example.com", "http", raw)
		seedLease(t, s, "tls.example.com", "tls", raw)
		seedPeer(t, s, "edge-b", time.Now().Add(time.Hour))
		got, ok, err := s.LookupHostAccess(ctx, "App.Example.com", time.Now())
		if err != nil || !ok || got != want {
			t.Fatalf("access = %q, %v, %v; want %q", got, ok, err, want)
		}
		if got, ok, err := s.LookupHostAccess(ctx, "tls.example.com", time.Now()); err != nil || ok {
			t.Fatalf("tls access = %q, %v, %v", got, ok, err)
		}
		seedPeer(t, s, "edge-b", time.Now().Add(-time.Minute))
		if got, ok, err := s.LookupHostAccess(ctx, "app.example.com", time.Now()); err != nil || ok {
			t.Fatalf("access with expired peer = %q, %v, %v", got, ok, err)
		}
	})
}

func TestLookupHostAccessIgnoresExpiredLease(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		seedLease(t, s, "app.example.com", "http", "")
		seedPeer(t, s, "edge-b", time.Now().Add(3*time.Hour))
		if _, ok, err := s.LookupHostAccess(context.Background(), "app.example.com", time.Now()); err != nil || !ok {
			t.Fatalf("access with a live lease = %v, %v", ok, err)
		}
		if got, ok, err := s.LookupHostAccess(context.Background(), "app.example.com", time.Now().Add(2*time.Hour)); err != nil || ok {
			t.Fatalf("access after lease expiry = %q, %v, %v", got, ok, err)
		}
	})
}

func seedPortLease(t *testing.T, s *Store, hostname, kind, edgeID string, port int) {
	t.Helper()
	_, err := s.AcquireLease(context.Background(), LeaseRequest{
		Hostname: hostname, Kind: kind, EdgeID: edgeID, OwnerID: "owner-1",
		InstanceID: "instance-" + edgeID + kind, SessionID: "session-" + edgeID + kind,
		ExpiresAt: time.Now().Add(time.Hour), RemotePort: port,
	})
	if err != nil {
		t.Fatalf("acquire %s lease on %s port %d: %v", kind, edgeID, port, err)
	}
}

func TestLiveRemoteTCPPorts(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		live := time.Now().Add(time.Hour)

		t.Run("returns remote owner", func(t *testing.T) {
			seedPortLease(t, s, "returns.example.com", "tcp", "edge-b1", 9001)
			seedPeer(t, s, "edge-b1", live)
			got, err := s.LiveRemoteTCPPorts(ctx, " Returns.Example.com ", "edge-a", 9000, 9100, time.Now(), 10)
			if err != nil || len(got) != 1 || len(got[9001]) != 1 {
				t.Fatalf("ports = %+v, %v", got, err)
			}
			owner := got[9001][0]
			if owner.EdgeID != "edge-b1" || owner.PeerAddr != "edge-b1.internal:7443" || owner.SPKISHA256 != "pin-edge-b1" {
				t.Fatalf("owner = %+v", owner)
			}
		})

		t.Run("excludes own leases", func(t *testing.T) {
			seedPortLease(t, s, "own.example.com", "tcp", "edge-self2", 9011)
			seedPortLease(t, s, "own.example.com", "tcp", "edge-b2", 9012)
			seedPeer(t, s, "edge-self2", live)
			seedPeer(t, s, "edge-b2", live)
			got, err := s.LiveRemoteTCPPorts(ctx, "own.example.com", "edge-self2", 9000, 9100, time.Now(), 10)
			if err != nil || len(got) != 1 || len(got[9012]) != 1 || got[9012][0].EdgeID != "edge-b2" {
				t.Fatalf("ports = %+v, %v; want only edge-b2 on 9012", got, err)
			}
		})

		t.Run("excludes expired lease", func(t *testing.T) {
			seedPortLease(t, s, "lease.example.com", "tcp", "edge-b3", 9021)
			seedPeer(t, s, "edge-b3", time.Now().Add(3*time.Hour))
			got, err := s.LiveRemoteTCPPorts(ctx, "lease.example.com", "edge-a", 9000, 9100, time.Now().Add(2*time.Hour), 10)
			if err != nil || len(got) != 0 {
				t.Fatalf("ports after lease expiry = %+v, %v", got, err)
			}
		})

		t.Run("excludes expired peer", func(t *testing.T) {
			seedPortLease(t, s, "peer.example.com", "tcp", "edge-b4", 9031)
			seedPeer(t, s, "edge-b4", time.Now().Add(-time.Minute))
			got, err := s.LiveRemoteTCPPorts(ctx, "peer.example.com", "edge-a", 9000, 9100, time.Now(), 10)
			if err != nil || len(got) != 0 {
				t.Fatalf("ports with expired peer = %+v, %v", got, err)
			}
		})

		t.Run("excludes ports outside range", func(t *testing.T) {
			seedPortLease(t, s, "range.example.com", "tcp", "edge-b5", 9041)
			seedPortLease(t, s, "range.example.com", "tcp", "edge-b5", 9500)
			seedPeer(t, s, "edge-b5", live)
			got, err := s.LiveRemoteTCPPorts(ctx, "range.example.com", "edge-a", 9000, 9100, time.Now(), 10)
			if err != nil || len(got) != 1 || len(got[9041]) != 1 {
				t.Fatalf("ports = %+v, %v; want only 9041", got, err)
			}
		})

		t.Run("excludes other tunnel kinds", func(t *testing.T) {
			seedPortLease(t, s, "kind.example.com", "http", "edge-b6", 0)
			seedPortLease(t, s, "kindtls.example.com", "tls", "edge-b6", 0)
			seedPeer(t, s, "edge-b6", live)
			for _, host := range []string{"kind.example.com", "kindtls.example.com"} {
				got, err := s.LiveRemoteTCPPorts(ctx, host, "edge-a", 0, 9100, time.Now(), 10)
				if err != nil || len(got) != 0 {
					t.Fatalf("ports for %s = %+v, %v; want none", host, got, err)
				}
			}
		})

		t.Run("limit caps rows", func(t *testing.T) {
			for port := 9061; port <= 9063; port++ {
				seedPortLease(t, s, "limit.example.com", "tcp", "edge-b7", port)
			}
			seedPeer(t, s, "edge-b7", live)
			got, err := s.LiveRemoteTCPPorts(ctx, "limit.example.com", "edge-a", 9000, 9100, time.Now(), 2)
			if err != nil || len(got) != 2 || len(got[9061]) != 1 || len(got[9062]) != 1 {
				t.Fatalf("ports = %+v, %v; want the first two ports", got, err)
			}
		})

		t.Run("wraps errors", func(t *testing.T) {
			s.Close()
			_, err := s.LiveRemoteTCPPorts(ctx, "x.example.com", "edge-a", 9000, 9100, time.Now(), 10)
			if err == nil || !strings.Contains(err.Error(), "storage: live remote tcp ports") {
				t.Fatalf("err = %v, want it wrapped with its own context", err)
			}
		})
	})
}
