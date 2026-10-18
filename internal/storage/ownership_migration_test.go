package storage

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"ngstone/internal/credentials"
	"ngstone/internal/policy"
)

func TestOwnershipMigrationPreservesPoliciesAndAssociations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")
	s := openTestStore(t, path)
	allow := &policy.Policy{DefaultAction: "allow"}
	deny := &policy.Policy{DefaultAction: "deny"}
	principalPolicy, _, err := s.UpsertTrafficPolicy(t.Context(), "shared", "alice", allow)
	if err != nil {
		t.Fatal(err)
	}
	var requests []LeaseRequest
	var leases []Lease
	for i, name := range []string{"first", "second", "ownerless"} {
		owner := "alice"
		if i == 2 {
			owner = ""
		}
		issued, err := s.Issue(credentials.Spec{Subdomain: name, OwnerID: owner}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		value := deny
		if i == 1 {
			value = allow
		}
		request := LeaseRequest{Name: "shared", Hostname: name + ".example.com", Kind: "http", OwnerID: issued.Credential.ID, InstanceID: name, SessionID: name, Policy: value}
		lease, err := s.AcquireLease(t.Context(), request)
		if err != nil {
			t.Fatal(err)
		}
		requests, leases = append(requests, request), append(leases, lease)
	}
	domain, err := s.CreateCustomDomain(t.Context(), CustomDomainSpec{Domain: "custom.example.org", OwnerID: credentials.GlobalOwnerID, TunnelID: leases[0].TunnelID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(t.Context(), `DELETE FROM schema_migrations WHERE version = 4`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTestStore(t, path)
	for i, lease := range leases {
		wantOwner := "alice"
		if i == 2 {
			wantOwner = requests[i].OwnerID
		}
		var owner, connectorOwner, policyID string
		if err := s.db.QueryRowContext(t.Context(), `SELECT owner_id, policy_id FROM tunnels WHERE id = $1`, lease.TunnelID).Scan(&owner, &policyID); err != nil {
			t.Fatal(err)
		}
		if err := s.db.QueryRowContext(t.Context(), `SELECT owner_id FROM connector_leases WHERE id = $1`, lease.ID).Scan(&connectorOwner); err != nil {
			t.Fatal(err)
		}
		if owner != wantOwner || connectorOwner != wantOwner {
			t.Fatalf("migrated owners = %q, %q; want %q", owner, connectorOwner, wantOwner)
		}
		if i == 1 && policyID != principalPolicy {
			t.Fatal("identical policy was not merged into existing principal policy")
		}
		requests[i].OwnerID = wantOwner
		requests[i].SessionID += "-reconnected"
		if _, err := s.AcquireLease(t.Context(), requests[i]); err != nil {
			t.Fatalf("reconnect after migration: %v", err)
		}
	}
	policies, err := s.ListTrafficPolicies(t.Context(), "alice")
	if err != nil || len(policies) != 2 || policies[0].Name == policies[1].Name {
		t.Fatalf("preserved principal policies = %v, %v", policies, err)
	}
	requests[0].Policy = &policy.Policy{DefaultAction: "deny", Rules: []policy.Rule{{Action: "allow", PathPrefix: "/health"}}}
	if _, err := s.AcquireLease(t.Context(), requests[0]); err != nil {
		t.Fatalf("reconfigure migrated tunnel: %v", err)
	}
	var policyDigest, tunnelDigest string
	if err := s.db.QueryRowContext(t.Context(), `SELECT p.digest, t.policy_digest FROM tunnels t JOIN traffic_policies p ON p.id = t.policy_id WHERE t.id = $1`, leases[1].TunnelID).Scan(&policyDigest, &tunnelDigest); err != nil {
		t.Fatal(err)
	}
	if policyDigest != allow.Digest() || tunnelDigest != allow.Digest() {
		t.Fatal("reconfiguring a migrated tunnel overwrote its sibling's policy")
	}
	if _, err := s.CreateCustomDomain(t.Context(), CustomDomainSpec{Domain: "own.example.org", OwnerID: "alice", TunnelID: leases[0].TunnelID}); err != nil {
		t.Fatalf("owner cannot associate migrated tunnel: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTestStore(t, path)
	var tunnelID string
	if err := s.db.QueryRowContext(t.Context(), `SELECT tunnel_id FROM custom_domains WHERE id = $1`, domain.ID).Scan(&tunnelID); err != nil || tunnelID != leases[0].TunnelID {
		t.Fatalf("existing domain association = %q, %v", tunnelID, err)
	}
	if got, err := s.ListTrafficPolicies(t.Context(), "alice"); err != nil || len(got) != 3 {
		t.Fatalf("policies after second reopen = %v, %v", got, err)
	}
}

func TestLeaseReconnectCannotChangeActiveOwner(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), "control.db"))
	request := LeaseRequest{Hostname: "demo.example.com", Kind: "http", OwnerID: "alice", InstanceID: "known-instance", SessionID: "first"}
	if _, err := s.AcquireLease(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	request.OwnerID, request.SessionID = "bob", "second"
	if _, err := s.AcquireLease(t.Context(), request); !errors.Is(err, ErrTunnelConflict) {
		t.Fatalf("cross-owner reconnect = %v", err)
	}
	request.OwnerID = "alice"
	request.AccessJSON = `{"allow_cidrs":["127.0.0.0/8"]}`
	request.AllowCIDRsJSON = `["127.0.0.0/8"]`
	if _, err := s.AcquireLease(t.Context(), request); err != nil {
		t.Fatalf("owner could not replace its single connector settings: %v", err)
	}
}
