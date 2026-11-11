package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"ngstone/internal/credentials"
	"ngstone/internal/storage/storagetest"
)

func postgresSchemaDSN(t *testing.T) string {
	t.Helper()
	return storagetest.PostgresSchemaDSN(t)
}

func openPostgresTestStore(t *testing.T, dsn, edgeID string) *Store {
	t.Helper()
	store, err := Open(Config{DSN: dsn, EdgeID: edgeID, LeaseTTL: time.Minute})
	if err != nil {
		t.Fatalf("open postgres store %s: %v", edgeID, err)
	}
	if store.Driver() != DriverPostgres {
		store.Close()
		t.Fatalf("driver = %q, want %q", store.Driver(), DriverPostgres)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestPostgresStoreRoundTrip(t *testing.T) {
	dsn := postgresSchemaDSN(t)
	store := openPostgresTestStore(t, dsn, "edge-a")
	ctx := context.Background()

	issued, err := store.Issue(credentials.Spec{Kind: credentials.KindTLS, Subdomain: "Secure", OwnerID: "owner-1"}, time.Hour)
	if err != nil {
		t.Fatalf("issue tls credential: %v", err)
	}
	got, err := store.Validate(issued.Token, time.Now())
	if err != nil {
		t.Fatalf("validate tls credential: %v", err)
	}
	if got.Kind != credentials.KindTLS || got.Subdomain != "secure" || got.RemotePort != 0 {
		t.Fatalf("validated credential = %+v, want kind tls subdomain secure", got)
	}

	for _, kind := range []string{"http", "tls"} {
		hostname := kind + "-host.example.com"
		lease, err := store.AcquireLease(ctx, LeaseRequest{
			Hostname: hostname, Kind: kind, OwnerID: "owner-1",
			InstanceID: "instance-" + kind, SessionID: "session-" + kind,
		})
		if err != nil {
			t.Fatalf("acquire %s lease: %v", kind, err)
		}
		renewed, err := store.RenewSessionLeases(ctx, "", "session-"+kind, time.Now())
		if err != nil || renewed != 1 {
			t.Fatalf("renew %s lease = %d, %v, want 1", kind, renewed, err)
		}
		if err := store.ReleaseLease(ctx, lease.ID); err != nil {
			t.Fatalf("release %s lease: %v", kind, err)
		}
	}
}

func TestPostgresConcurrentHTTPAndTLSClaims(t *testing.T) {
	dsn := postgresSchemaDSN(t)
	first := openPostgresTestStore(t, dsn, "edge-a")
	second := openPostgresTestStore(t, dsn, "edge-b")
	for i := 0; i < 200; i++ {
		hostname := fmt.Sprintf("host-%d.example.com", i)
		requests := []struct {
			store *Store
			kind  string
		}{
			{store: first, kind: "http"},
			{store: second, kind: "tls"},
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		results := make(chan error, len(requests))
		for _, item := range requests {
			item := item
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := item.store.AcquireLease(context.Background(), LeaseRequest{
					Name: hostname, Hostname: hostname, Kind: item.kind, OwnerID: "owner",
					InstanceID: "instance-" + item.kind, SessionID: "session-" + item.kind,
					AccessJSON: `{}`, AllowCIDRsJSON: `[]`,
				})
				results <- err
			}()
		}
		close(start)
		wg.Wait()
		close(results)
		successes := 0
		for err := range results {
			if err == nil {
				successes++
			} else if !errors.Is(err, ErrHostnameKindConflict) {
				t.Fatalf("iteration %d: cross-kind claim error = %v", i, err)
			}
		}
		if successes != 1 {
			t.Fatalf("iteration %d: cross-kind claim successes = %d, want 1", i, successes)
		}
	}
}
