package storage

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"ngstone/internal/access"
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

func TestSQLiteTLSCredentialRoundTrip(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "control.db"))
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
	list, err := store.List()
	if err != nil || len(list) != 1 || list[0].Kind != credentials.KindTLS || list[0].Subdomain != "secure" {
		t.Fatalf("list = %+v, %v, want one tls credential for secure", list, err)
	}
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
	if first.Replaced {
		t.Fatal("a fresh lease reported replacing another")
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
	if !reconnected.Replaced {
		t.Fatal("a same-instance reconnect did not report replacing the live lease")
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

func TestMultiConnectorLeasesRequireMatchingLoginRule(t *testing.T) {
	cases := []struct {
		name    string
		first   string
		second  string
		wantErr error
	}{
		{name: "identical emails bind", first: `{"visitor_login":{"allow_emails":["a@example.org"]}}`, second: `{"visitor_login":{"allow_emails":["A@example.org"]}}`},
		{name: "identical empty wall binds", first: `{"visitor_login":{}}`, second: `{"visitor_login":{}}`},
		{name: "no wall binds", first: `{}`, second: `{}`},
		{name: "differing emails", first: `{"visitor_login":{"allow_emails":["a@example.org"]}}`, second: `{"visitor_login":{"allow_emails":["b@example.org"]}}`, wantErr: ErrTunnelConflict},
		{name: "differing domains", first: `{"visitor_login":{"allow_domains":["example.org"]}}`, second: `{"visitor_login":{"allow_domains":["example.net"]}}`, wantErr: ErrTunnelConflict},
		{name: "no wall then empty wall", first: `{}`, second: `{"visitor_login":{}}`, wantErr: ErrTunnelConflict},
		{name: "empty wall then no wall", first: `{"visitor_login":{}}`, second: `{}`, wantErr: ErrTunnelConflict},
		{name: "restricted wall then empty wall", first: `{"visitor_login":{"allow_domains":["example.org"]}}`, second: `{"visitor_login":{}}`, wantErr: ErrTunnelConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := openTestStore(t, filepath.Join(t.TempDir(), "control.db"))
			request := LeaseRequest{
				Name:                 "pool",
				Hostname:             "pool.example.com",
				Kind:                 "http",
				OwnerID:              "credential-1",
				InstanceID:           "instance-1",
				SessionID:            "session-1",
				MultiConnector:       true,
				ConnectorTokenDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				AccessJSON:           tc.first,
			}
			if _, err := store.AcquireLease(context.Background(), request); err != nil {
				t.Fatalf("acquire first connector: %v", err)
			}
			request.InstanceID = "instance-2"
			request.SessionID = "session-2"
			request.AccessJSON = tc.second
			_, err := store.AcquireLease(context.Background(), request)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("second connector error = %v, want %v", err, tc.wantErr)
			}
		})
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
	if _, err := store.CreateCustomDomain(context.Background(), CustomDomainSpec{Domain: "demo.example.org", OwnerID: "owner-1"}); err != nil {
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

func TestConcurrentHTTPAndTLSClaimsAcrossStoreConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")
	first := openTestStore(t, path)
	second := openTestStore(t, path)
	for i := 0; i < 20; i++ {
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

func restoreLeaseRequest(hostname, sessionID, accessJSON string) LeaseRequest {
	return LeaseRequest{
		Hostname: hostname, Kind: "http", OwnerID: "owner-1",
		InstanceID: "instance-1", SessionID: sessionID, AccessJSON: accessJSON,
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

func assertRenewed(t *testing.T, s *Store, sessionID string, want int64) {
	t.Helper()
	got, err := s.RenewSessionLeases(context.Background(), s.EdgeID(), sessionID, time.Now())
	if err != nil || got != want {
		t.Fatalf("renew %s = %d, %v, want %d", sessionID, got, err, want)
	}
}

func testRestoreReplacedLease(t *testing.T, s *Store) {
	ctx := context.Background()
	l1, err := s.AcquireLease(ctx, restoreLeaseRequest("restore.example.com", "s1", ""))
	if err != nil {
		t.Fatalf("acquire s1: %v", err)
	}
	l2, err := s.AcquireLease(ctx, restoreLeaseRequest("restore.example.com", "s2", ""))
	if err != nil {
		t.Fatalf("acquire s2: %v", err)
	}
	if !l2.Replaced {
		t.Fatal("second lease did not report replacing the first")
	}
	restored, err := s.RestoreReplacedLease(ctx, l2)
	if err != nil || !restored {
		t.Fatalf("restore = %v, %v, want true", restored, err)
	}
	assertRenewed(t, s, "s1", 1)
	assertRenewed(t, s, "s2", 0)
	tunnels, err := s.ListTunnels(ctx)
	if err != nil {
		t.Fatalf("list tunnels: %v", err)
	}
	if len(tunnels) != 1 || tunnels[0].SessionID != "s1" || len(tunnels[0].Connectors) != 1 || tunnels[0].Connectors[0].ID != l1.ID {
		t.Fatalf("tunnels after restore = %+v, want the s1 lease restored", tunnels)
	}
	if err := s.ReleaseLease(ctx, l1.ID); err != nil {
		t.Fatalf("release restored lease: %v", err)
	}
	tunnels, err = s.ListTunnels(ctx)
	if err != nil {
		t.Fatalf("list tunnels: %v", err)
	}
	if len(tunnels) != 1 || len(tunnels[0].Connectors) != 0 {
		t.Fatalf("tunnels after release = %+v, want no connectors", tunnels)
	}

	seedPeer(t, s, s.EdgeID(), time.Now().Add(time.Hour))
	accessOne := `{"visitor_login":{"allow_domains":["one.example"]}}`
	accessTwo := `{"visitor_login":{"allow_domains":["two.example"]}}`
	if _, err := s.AcquireLease(ctx, restoreLeaseRequest("access.example.com", "s1", accessOne)); err != nil {
		t.Fatalf("acquire access s1: %v", err)
	}
	replacing, err := s.AcquireLease(ctx, restoreLeaseRequest("access.example.com", "s2", accessTwo))
	if err != nil {
		t.Fatalf("acquire access s2: %v", err)
	}
	wantTwo, _ := access.CanonicalJSON(accessTwo)
	if got, ok, err := s.LookupHostAccess(ctx, "access.example.com", time.Now()); err != nil || !ok || got != wantTwo {
		t.Fatalf("access before restore = %q, %v, %v, want %q", got, ok, err, wantTwo)
	}
	if restored, err := s.RestoreReplacedLease(ctx, replacing); err != nil || !restored {
		t.Fatalf("restore access lease = %v, %v, want true", restored, err)
	}
	wantOne, _ := access.CanonicalJSON(accessOne)
	if got, ok, err := s.LookupHostAccess(ctx, "access.example.com", time.Now()); err != nil || !ok || got != wantOne {
		t.Fatalf("access after restore = %q, %v, %v, want %q", got, ok, err, wantOne)
	}
}

func testRestoreReplacedLeaseSkipsSuperseded(t *testing.T, s *Store) {
	ctx := context.Background()
	l1, err := s.AcquireLease(ctx, restoreLeaseRequest("superseded.example.com", "s1", ""))
	if err != nil {
		t.Fatalf("acquire s1: %v", err)
	}
	if restored, err := s.RestoreReplacedLease(ctx, l1); err != nil || restored {
		t.Fatalf("restore of a non-replaced lease = %v, %v, want false, nil", restored, err)
	}
	l2, err := s.AcquireLease(ctx, restoreLeaseRequest("superseded.example.com", "s2", ""))
	if err != nil {
		t.Fatalf("acquire s2: %v", err)
	}
	if _, err := s.AcquireLease(ctx, restoreLeaseRequest("superseded.example.com", "s3", "")); err != nil {
		t.Fatalf("acquire s3: %v", err)
	}
	if restored, err := s.RestoreReplacedLease(ctx, l2); err != nil || restored {
		t.Fatalf("restore of a superseded lease = %v, %v, want false, nil", restored, err)
	}
	assertRenewed(t, s, "s3", 1)
	assertRenewed(t, s, "s1", 0)
}

func TestRestoreReplacedLease(t *testing.T) {
	testRestoreReplacedLease(t, openTestStore(t, filepath.Join(t.TempDir(), "control.db")))
}

func TestRestoreReplacedLeaseSkipsSuperseded(t *testing.T) {
	testRestoreReplacedLeaseSkipsSuperseded(t, openTestStore(t, filepath.Join(t.TempDir(), "control.db")))
}
