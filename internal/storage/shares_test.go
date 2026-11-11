package storage

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func seedLiveShare(t *testing.T, s *Store, dirKey, shareID, edgeID string) {
	t.Helper()
	if err := s.PublishShare(context.Background(), dirKey, shareID, edgeID, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("publish share: %v", err)
	}
}

func TestPublishShareLookupRoundTrip(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		seedPeer(t, s, "edge-b", time.Now().Add(time.Hour))
		seedLiveShare(t, s, "key-1", "share-1", "edge-b")
		peer, ok, err := s.LookupShareEdge(context.Background(), "key-1", "edge-a", time.Now())
		if err != nil || !ok {
			t.Fatalf("lookup = %+v, %v, %v", peer, ok, err)
		}
		if peer.EdgeID != "edge-b" || peer.PeerAddr != "edge-b.internal:7443" || peer.SPKISHA256 != "pin-edge-b" {
			t.Fatalf("lookup peer = %+v", peer)
		}
		if _, ok, err := s.LookupShareEdge(context.Background(), "key-unknown", "edge-a", time.Now()); err != nil || ok {
			t.Fatalf("lookup unknown = %v, %v", ok, err)
		}
	})
}

func TestPublishShareRepointsAndClearsRevoked(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		seedPeer(t, s, "edge-b", time.Now().Add(time.Hour))
		seedPeer(t, s, "edge-c", time.Now().Add(time.Hour))
		seedLiveShare(t, s, "key-1", "share-1", "edge-b")
		if ok, err := s.RevokeShare(ctx, "share-1", time.Now()); err != nil || !ok {
			t.Fatalf("revoke = %v, %v", ok, err)
		}
		if _, ok, _ := s.LookupShareEdge(ctx, "key-1", "edge-a", time.Now()); ok {
			t.Fatal("revoked share is still returned")
		}
		seedLiveShare(t, s, "key-1", "share-2", "edge-c")
		peer, ok, err := s.LookupShareEdge(ctx, "key-1", "edge-a", time.Now())
		if err != nil || !ok || peer.EdgeID != "edge-c" {
			t.Fatalf("lookup after republish = %+v, %v, %v", peer, ok, err)
		}
		if ids, err := s.RevokedShares(ctx, "edge-b", time.Now(), 10); err != nil || len(ids) != 0 {
			t.Fatalf("revoked after republish = %v, %v", ids, err)
		}
	})
}

func TestWithdrawShareIsGuardedByEdgeID(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		seedPeer(t, s, "edge-b", time.Now().Add(time.Hour))
		seedLiveShare(t, s, "key-1", "share-1", "edge-b")
		if err := s.WithdrawShare(ctx, "key-1", "edge-c"); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := s.LookupShareEdge(ctx, "key-1", "edge-a", time.Now()); !ok {
			t.Fatal("withdraw by another edge deleted the row")
		}
		if err := s.WithdrawShare(ctx, "key-1", "edge-b"); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := s.LookupShareEdge(ctx, "key-1", "edge-a", time.Now()); ok {
			t.Fatal("withdraw by the owning edge kept the row")
		}
	})
}

func TestPurgeEdgeSharesRemovesOnlyThatEdge(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		seedPeer(t, s, "edge-b", time.Now().Add(time.Hour))
		seedPeer(t, s, "edge-c", time.Now().Add(time.Hour))
		seedLiveShare(t, s, "key-1", "share-1", "edge-b")
		seedLiveShare(t, s, "key-2", "share-2", "edge-c")
		if err := s.PurgeEdgeShares(ctx, "edge-b"); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := s.LookupShareEdge(ctx, "key-1", "edge-a", time.Now()); ok {
			t.Fatal("purged row still returned")
		}
		if _, ok, _ := s.LookupShareEdge(ctx, "key-2", "edge-a", time.Now()); !ok {
			t.Fatal("purge removed another edge's row")
		}
	})
}

func TestShareExpiry(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		seedPeer(t, s, "edge-b", time.Now().Add(3*time.Hour))
		seedLiveShare(t, s, "key-1", "share-1", "edge-b")
		later := time.Now().Add(2 * time.Hour)
		if _, ok, err := s.LookupShareEdge(ctx, "key-1", "edge-a", later); err != nil || ok {
			t.Fatalf("lookup after expiry = %v, %v", ok, err)
		}
		if err := s.DeleteExpiredShares(ctx, time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := s.LookupShareEdge(ctx, "key-1", "edge-a", time.Now()); !ok {
			t.Fatal("DeleteExpiredShares removed a live row")
		}
		if err := s.DeleteExpiredShares(ctx, later); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := s.LookupShareEdge(ctx, "key-1", "edge-a", time.Now()); ok {
			t.Fatal("DeleteExpiredShares kept an expired row")
		}
	})
}

func TestRevokeShareHidesRowAndListsForOwner(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		seedPeer(t, s, "edge-b", time.Now().Add(time.Hour))
		seedPeer(t, s, "edge-c", time.Now().Add(time.Hour))
		seedLiveShare(t, s, "key-1", "share-1", "edge-b")
		seedLiveShare(t, s, "key-2", "share-2", "edge-c")
		if ok, err := s.RevokeShare(ctx, "missing", time.Now()); err != nil || ok {
			t.Fatalf("revoke missing = %v, %v", ok, err)
		}
		if ok, err := s.RevokeShare(ctx, "share-1", time.Now().Add(2*time.Hour)); err != nil || ok {
			t.Fatalf("revoke expired = %v, %v", ok, err)
		}
		if ok, err := s.RevokeShare(ctx, "share-1", time.Now()); err != nil || !ok {
			t.Fatalf("revoke = %v, %v", ok, err)
		}
		if _, ok, _ := s.LookupShareEdge(ctx, "key-1", "edge-a", time.Now()); ok {
			t.Fatal("revoked row still returned by lookup")
		}
		ids, err := s.RevokedShares(ctx, "edge-b", time.Now(), 10)
		if err != nil || !reflect.DeepEqual(ids, []string{"share-1"}) {
			t.Fatalf("revoked for edge-b = %v, %v", ids, err)
		}
		if ids, err := s.RevokedShares(ctx, "edge-c", time.Now(), 10); err != nil || len(ids) != 0 {
			t.Fatalf("revoked for edge-c = %v, %v", ids, err)
		}
	})
}

func TestLookupShareEdgeExcludesOwnEdge(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		seedPeer(t, s, "edge-b", time.Now().Add(time.Hour))
		seedLiveShare(t, s, "key-1", "share-1", "edge-b")
		if _, ok, err := s.LookupShareEdge(context.Background(), "key-1", "edge-b", time.Now()); err != nil || ok {
			t.Fatalf("lookup excluding own edge = %v, %v", ok, err)
		}
	})
}

func TestLookupShareEdgeRequiresLivePeer(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		seedLiveShare(t, s, "key-1", "share-1", "edge-b")
		if _, ok, err := s.LookupShareEdge(ctx, "key-1", "edge-a", time.Now()); err != nil || ok {
			t.Fatalf("lookup without peer row = %v, %v", ok, err)
		}
		seedPeer(t, s, "edge-b", time.Now().Add(-time.Minute))
		if _, ok, err := s.LookupShareEdge(ctx, "key-1", "edge-a", time.Now()); err != nil || ok {
			t.Fatalf("lookup with expired peer = %v, %v", ok, err)
		}
	})
}

func TestShareDirectoryColumns(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		rows, err := s.db.QueryContext(context.Background(), `SELECT * FROM share_directory LIMIT 0`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"dir_key", "share_id", "edge_id", "expires_at", "revoked"}
		if !reflect.DeepEqual(cols, want) {
			t.Fatalf("share_directory columns = %v, want %v", cols, want)
		}
	})
}

func TestMigrationCreatesShareDirectoryFresh(t *testing.T) {
	forEachPeerStore(t, func(t *testing.T, s *Store) {
		var applied int
		if err := s.db.QueryRowContext(context.Background(), `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&applied); err != nil || applied != 6 {
			t.Fatalf("applied migrations = %d, %v, want 6", applied, err)
		}
		seedPeer(t, s, "edge-b", time.Now().Add(time.Hour))
		seedLiveShare(t, s, "key-1", "share-1", "edge-b")
	})
}

func TestMigrationUpgradesFromVersion5(t *testing.T) {
	reopen := func(t *testing.T, s *Store, open func() *Store) *Store {
		t.Helper()
		ctx := context.Background()
		if _, err := s.db.ExecContext(ctx, `DROP TABLE share_directory`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version >= 6`); err != nil {
			t.Fatal(err)
		}
		seedPeer(t, s, "edge-b", time.Now().Add(time.Hour))
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		return open()
	}
	check := func(t *testing.T, s *Store) {
		t.Helper()
		var applied int
		if err := s.db.QueryRowContext(context.Background(), `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&applied); err != nil || applied != 6 {
			t.Fatalf("applied migrations = %d, %v, want 6", applied, err)
		}
		seedLiveShare(t, s, "key-1", "share-1", "edge-b")
		if _, ok, err := s.LookupShareEdge(context.Background(), "key-1", "edge-a", time.Now()); err != nil || !ok {
			t.Fatalf("lookup after upgrade = %v, %v", ok, err)
		}
		if peers, err := s.LiveEdgePeers(context.Background(), time.Now()); err != nil || len(peers) != 1 {
			t.Fatalf("peers after upgrade = %+v, %v", peers, err)
		}
	}
	t.Run("sqlite", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "control.db")
		s := openTestStore(t, path)
		check(t, reopen(t, s, func() *Store { return openTestStore(t, path) }))
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := postgresSchemaDSN(t)
		s := openPostgresTestStore(t, dsn, "edge-a")
		check(t, reopen(t, s, func() *Store { return openPostgresTestStore(t, dsn, "edge-a") }))
	})
}
