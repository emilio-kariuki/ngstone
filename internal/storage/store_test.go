package storage

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"ngstone/internal/credentials"
	"ngstone/internal/policy"
)

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	store, err := Open(Config{DSN: path, EdgeID: "edge-test", LeaseTTL: time.Second})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestSQLiteCredentialPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")
	store := openTestStore(t, path)
	issued, err := store.IssueAt(credentials.Spec{Kind: credentials.KindHTTP, Subdomain: "demo", OwnerID: "owner-1"}, time.Hour, time.Unix(100, 0))
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}
	if _, err := store.Validate(issued.Token, time.Unix(101, 0)); err != nil {
		t.Fatalf("validate credential: %v", err)
	}
	store.Close()

	reopened := openTestStore(t, path)
	list, err := reopened.List()
	if err != nil {
		t.Fatalf("list credentials after reopen: %v", err)
	}
	if len(list) != 1 || list[0].OwnerID != "owner-1" {
		t.Fatalf("credentials after reopen = %+v", list)
	}
	if err := reopened.Revoke(issued.Credential.ID); err != nil {
		t.Fatalf("revoke credential: %v", err)
	}
	if _, err := reopened.Validate(issued.Token, time.Unix(101, 0)); !errors.Is(err, credentials.ErrRevoked) {
		t.Fatalf("validate revoked credential error = %v", err)
	}
}

func TestSQLiteCredentialOwnerScoping(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "control.db"))
	first, err := store.Issue(credentials.Spec{Kind: credentials.KindHTTP, Subdomain: "one", OwnerID: "team-a"}, time.Hour)
	if err != nil {
		t.Fatalf("issue first credential: %v", err)
	}
	second, err := store.Issue(credentials.Spec{Kind: credentials.KindHTTP, Subdomain: "two", OwnerID: "team-b"}, time.Hour)
	if err != nil {
		t.Fatalf("issue second credential: %v", err)
	}
	list, err := store.ListForOwner("team-a")
	if err != nil {
		t.Fatalf("list team-a credentials: %v", err)
	}
	if len(list) != 1 || list[0].ID != first.Credential.ID {
		t.Fatalf("team-a credentials = %+v", list)
	}
	if err := store.RevokeForOwner(first.Credential.ID, "team-b"); !errors.Is(err, credentials.ErrNotFound) {
		t.Fatalf("cross-owner revoke error = %v, want ErrNotFound", err)
	}
	if _, err := store.Validate(first.Token, time.Now()); err != nil {
		t.Fatalf("cross-owner revoke changed credential: %v", err)
	}
	if err := store.RevokeForOwner(first.Credential.ID, "team-a"); err != nil {
		t.Fatalf("owner revoke: %v", err)
	}
	if _, err := store.Validate(first.Token, time.Now()); !errors.Is(err, credentials.ErrRevoked) {
		t.Fatalf("owner-revoked credential error = %v, want ErrRevoked", err)
	}
	if _, err := store.Validate(second.Token, time.Now()); err != nil {
		t.Fatalf("other owner's credential error = %v", err)
	}
}

func TestLeaseConflictRenewalAndRelease(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "control.db"))
	base := LeaseRequest{
		Name:           "demo",
		Hostname:       "demo.example.com",
		Kind:           "http",
		OwnerID:        "credential-1",
		InstanceID:     "instance-1",
		SessionID:      "session-1",
		HTTP2:          true,
		AccessJSON:     `{}`,
		AllowCIDRsJSON: `[]`,
	}
	first, err := store.AcquireLease(context.Background(), base)
	if err != nil {
		t.Fatalf("acquire first lease: %v", err)
	}
	other := base
	other.InstanceID = "instance-2"
	other.SessionID = "session-2"
	if _, err := store.AcquireLease(context.Background(), other); !errors.Is(err, ErrTunnelConflict) {
		t.Fatalf("second lease error = %v, want conflict", err)
	}
	reconnect := base
	reconnect.SessionID = "session-3"
	reconnected, err := store.AcquireLease(context.Background(), reconnect)
	if err != nil {
		t.Fatalf("reconnect lease: %v", err)
	}
	if reconnected.TunnelID != first.TunnelID || reconnected.SessionID != "session-3" {
		t.Fatalf("reconnect lease = %+v", reconnected)
	}
	if count, err := store.RenewSessionLeases(context.Background(), "edge-test", "session-3", time.Now()); err != nil || count != 1 {
		t.Fatalf("renew session leases = %d, %v", count, err)
	}
	if err := store.ReleaseSession(context.Background(), "edge-test", "session-3"); err != nil {
		t.Fatalf("release session: %v", err)
	}
	tunnels, err := store.ListTunnels(context.Background())
	if err != nil {
		t.Fatalf("list tunnels: %v", err)
	}
	if len(tunnels) != 1 || tunnels[0].Status != "offline" || len(tunnels[0].Connectors) != 0 {
		t.Fatalf("tunnels after release = %+v", tunnels)
	}
}

func TestMultiConnectorLeases(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "control.db"))
	base := LeaseRequest{
		Name:                 "pool",
		Hostname:             "pool.example.com",
		Kind:                 "http",
		OwnerID:              "credential-1",
		InstanceID:           "instance-1",
		SessionID:            "session-1",
		MultiConnector:       true,
		ConnectorTokenDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	if _, err := store.AcquireLease(context.Background(), base); err != nil {
		t.Fatalf("acquire first connector: %v", err)
	}
	second := base
	second.InstanceID = "instance-2"
	second.SessionID = "session-2"
	if _, err := store.AcquireLease(context.Background(), second); err != nil {
		t.Fatalf("acquire second connector: %v", err)
	}
	tunnels, err := store.ListTunnels(context.Background())
	if err != nil {
		t.Fatalf("list multi connector tunnel: %v", err)
	}
	if len(tunnels) != 1 || len(tunnels[0].Connectors) != 2 {
		t.Fatalf("multi connector tunnel = %+v", tunnels)
	}
}

func TestAuditPoliciesAndCustomDomains(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "control.db"))
	p := &policy.Policy{DefaultAction: "deny", Rules: []policy.Rule{{Action: "allow", PathPrefix: "/health"}}}
	policyID, digest, err := store.UpsertTrafficPolicy(context.Background(), "demo", "owner-1", p)
	if err != nil {
		t.Fatalf("upsert policy: %v", err)
	}
	if policyID == "" || digest != p.Digest() {
		t.Fatalf("policy identity = %q %q", policyID, digest)
	}
	if _, err := store.CreateCustomDomain(context.Background(), CustomDomainSpec{Domain: "demo.example.org", OwnerID: "owner-1", Status: "active"}); err != nil {
		t.Fatalf("create custom domain: %v", err)
	}
	if err := store.RecordAudit(context.Background(), AuditEvent{Action: "created", ResourceType: "policy", ResourceID: policyID, Metadata: map[string]string{"source": "test"}}); err != nil {
		t.Fatalf("record audit: %v", err)
	}
	policies, err := store.ListTrafficPolicies(context.Background(), "owner-1")
	if err != nil || len(policies) != 1 {
		t.Fatalf("policies = %+v, err %v", policies, err)
	}
	domains, err := store.ListCustomDomains(context.Background(), "owner-1")
	if err != nil || len(domains) != 1 || domains[0].Domain != "demo.example.org" {
		t.Fatalf("domains = %+v, err %v", domains, err)
	}
	events, err := store.ListAudit(context.Background(), 10)
	if err != nil || len(events) != 1 || events[0].Metadata["source"] != "test" {
		t.Fatalf("events = %+v, err %v", events, err)
	}
}

func TestTrafficPolicyNameAndDigestConflict(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "control.db"))
	first := &policy.Policy{DefaultAction: "allow", Rules: []policy.Rule{{Action: "deny", PathPrefix: "/private"}}}
	second := &policy.Policy{DefaultAction: "deny", Rules: []policy.Rule{{Action: "allow", PathPrefix: "/health"}}}
	if _, _, err := store.UpsertTrafficPolicy(context.Background(), "first", "owner-1", first); err != nil {
		t.Fatalf("save first policy: %v", err)
	}
	if _, _, err := store.UpsertTrafficPolicy(context.Background(), "second", "owner-1", second); err != nil {
		t.Fatalf("save second policy: %v", err)
	}
	if _, _, err := store.UpsertTrafficPolicy(context.Background(), "first", "owner-1", second); !errors.Is(err, ErrPolicyConflict) {
		t.Fatalf("conflicting policy save error = %v", err)
	}
}

func TestDatabaseTimeStringsSortChronologically(t *testing.T) {
	older := nowString(time.Date(2026, time.August, 18, 12, 0, 0, 900000000, time.UTC))
	newer := nowString(time.Date(2026, time.August, 18, 12, 0, 1, 0, time.UTC))
	if older >= newer {
		t.Fatalf("database timestamps do not sort chronologically: %q >= %q", older, newer)
	}
}

func TestConcurrentSingleLeaseClaims(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "control.db"))
	base := LeaseRequest{Name: "race", Hostname: "race.example.com", Kind: "http", OwnerID: "owner", AccessJSON: `{}`, AllowCIDRsJSON: `[]`}
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			request := base
			request.InstanceID = "instance-" + string(rune('a'+i))
			request.SessionID = "session-" + string(rune('a'+i))
			_, err := store.AcquireLease(context.Background(), request)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrTunnelConflict) {
			t.Fatalf("concurrent claim error = %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent claim successes = %d, want 1", successes)
	}
}

func TestConcurrentClaimsAcrossStoreConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")
	first := openTestStore(t, path)
	second := openTestStore(t, path)
	base := LeaseRequest{Name: "shared", Hostname: "shared.example.com", Kind: "http", OwnerID: "owner", AccessJSON: `{}`, AllowCIDRsJSON: `[]`}
	requests := []struct {
		store      *Store
		instanceID string
		sessionID  string
	}{
		{store: first, instanceID: "edge-a-instance", sessionID: "edge-a-session"},
		{store: second, instanceID: "edge-b-instance", sessionID: "edge-b-session"},
	}
	var wg sync.WaitGroup
	results := make(chan error, len(requests))
	for _, item := range requests {
		item := item
		wg.Add(1)
		go func() {
			defer wg.Done()
			request := base
			request.InstanceID = item.instanceID
			request.SessionID = item.sessionID
			_, err := item.store.AcquireLease(context.Background(), request)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrTunnelConflict) {
			t.Fatalf("cross-connection claim error = %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("cross-connection claim successes = %d, want 1", successes)
	}
}

func TestConcurrentStoreOpenRunsMigrationOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")
	stores := make(chan *Store, 2)
	errorsCh := make(chan error, 2)
	var wg sync.WaitGroup
	for _, edgeID := range []string{"edge-a", "edge-b"} {
		edgeID := edgeID
		wg.Add(1)
		go func() {
			defer wg.Done()
			store, err := Open(Config{DSN: path, EdgeID: edgeID})
			if err != nil {
				errorsCh <- err
				return
			}
			stores <- store
		}()
	}
	wg.Wait()
	close(stores)
	close(errorsCh)
	for err := range errorsCh {
		t.Fatalf("concurrent store open: %v", err)
	}
	opened := 0
	for store := range stores {
		opened++
		store.Close()
	}
	if opened != 2 {
		t.Fatalf("opened stores = %d, want 2", opened)
	}
}
