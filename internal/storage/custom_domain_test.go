package storage

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ngstone/internal/credentials"
)

func forEachDialect(t *testing.T, fn func(t *testing.T, open func() *Store)) {
	t.Run("sqlite", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "control.db")
		fn(t, func() *Store { return openTestStore(t, path) })
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := postgresSchemaDSN(t)
		fn(t, func() *Store { return openPostgresTestStore(t, dsn, "edge-a") })
	})
}

func createTunnel(t *testing.T, s *Store, hostname, kind, owner string, port int) string {
	t.Helper()
	lease, err := s.AcquireLease(t.Context(), LeaseRequest{Hostname: hostname, Kind: kind, RemotePort: port, OwnerID: owner, InstanceID: hostname, SessionID: hostname})
	if err != nil {
		t.Fatalf("acquire lease %s: %v", hostname, err)
	}
	return lease.TunnelID
}

func TestCreateCustomDomainIsAlwaysPending(t *testing.T) {
	forEachDialect(t, func(t *testing.T, open func() *Store) {
		s := open()
		tunnelID := createTunnel(t, s, "web.example.com", "http", "alice", 0)
		domain, err := s.CreateCustomDomain(t.Context(), CustomDomainSpec{Domain: "App.Example.org.", OwnerID: "alice", TunnelID: tunnelID})
		if err != nil {
			t.Fatal(err)
		}
		if domain.Status != "pending" || domain.Domain != "app.example.org" {
			t.Fatalf("created domain = %+v", domain)
		}
		var status string
		if err := s.db.QueryRowContext(t.Context(), `SELECT status FROM custom_domains WHERE id = $1`, domain.ID).Scan(&status); err != nil || status != "pending" {
			t.Fatalf("stored status = %q, %v", status, err)
		}
	})
}

func TestCreateCustomDomainTunnelEligibility(t *testing.T) {
	forEachDialect(t, func(t *testing.T, open func() *Store) {
		s := open()
		tcpTunnel := createTunnel(t, s, "raw.example.com", "tcp", "alice", 20001)
		httpTunnel := createTunnel(t, s, "web.example.com", "http", "alice", 0)
		cases := []struct {
			name   string
			spec   CustomDomainSpec
			wantIs error
		}{
			{"tcp kind", CustomDomainSpec{Domain: "a.example.org", OwnerID: "alice", TunnelID: tcpTunnel}, ErrInvalid},
			{"foreign owner", CustomDomainSpec{Domain: "b.example.org", OwnerID: "bob", TunnelID: httpTunnel}, ErrNotFound},
			{"unknown tunnel", CustomDomainSpec{Domain: "c.example.org", OwnerID: "alice", TunnelID: "missing"}, ErrNotFound},
			{"global owner tcp", CustomDomainSpec{Domain: "d.example.org", OwnerID: credentials.GlobalOwnerID, TunnelID: tcpTunnel}, ErrInvalid},
			{"global owner http", CustomDomainSpec{Domain: "e.example.org", OwnerID: credentials.GlobalOwnerID, TunnelID: httpTunnel}, nil},
			{"no tunnel", CustomDomainSpec{Domain: "f.example.org", OwnerID: "bob"}, nil},
		}
		for _, tc := range cases {
			_, err := s.CreateCustomDomain(t.Context(), tc.spec)
			if tc.wantIs == nil && err != nil || tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("%s: error = %v, want %v", tc.name, err, tc.wantIs)
			}
		}
	})
}

func TestMigration7ResetsCustomDomainStatus(t *testing.T) {
	forEachDialect(t, func(t *testing.T, open func() *Store) {
		s := open()
		domain, err := s.CreateCustomDomain(t.Context(), CustomDomainSpec{Domain: "old.example.org", OwnerID: "alice"})
		if err != nil {
			t.Fatal(err)
		}
		for _, statement := range []string{
			`UPDATE custom_domains SET status = 'active' WHERE id = '` + domain.ID + `'`,
			`ALTER TABLE custom_domains DROP COLUMN activated_at`,
			`DELETE FROM schema_migrations WHERE version >= 7`,
		} {
			if _, err := s.db.ExecContext(t.Context(), statement); err != nil {
				t.Fatalf("%s: %v", statement, err)
			}
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		s = open()
		var status string
		var activatedAt *string
		if err := s.db.QueryRowContext(t.Context(), `SELECT status, activated_at FROM custom_domains WHERE id = $1`, domain.ID).Scan(&status, &activatedAt); err != nil {
			t.Fatalf("read migrated row: %v", err)
		}
		if status != "pending" || activatedAt != nil {
			t.Fatalf("migrated row = %q, %v; want pending and a null activated_at", status, activatedAt)
		}
	})
}

func TestNormalizeCustomDomain(t *testing.T) {
	long := strings.Repeat("a", 64)
	cases := []struct {
		raw  string
		want string
		ok   bool
	}{
		{"app.example.org", "app.example.org", true},
		{" App.Example.ORG. ", "app.example.org", true},
		{"a-b.example.co.uk", "a-b.example.co.uk", true},
		{"xn--bcher-kva.example", "xn--bcher-kva.example", true},
		{"1.2.3.4", "", false},
		{"::1", "", false},
		{"[::1]", "", false},
		{"*.x.org", "", false},
		{"a_b.org", "", false},
		{"localhost", "", false},
		{"app.123", "", false},
		{long + ".example.org", "", false},
		{strings.Repeat("a.", 130) + "org", "", false},
		{"bücher.example", "", false},
		{"a..example.org", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := NormalizeCustomDomain(tc.raw)
		if got != tc.want || ok != tc.ok {
			t.Errorf("NormalizeCustomDomain(%q) = %q, %v; want %q, %v", tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}

func TestSetCustomDomainStatusTransitions(t *testing.T) {
	forEachDialect(t, func(t *testing.T, open func() *Store) {
		s := open()
		ctx := t.Context()
		create := func(domain, tunnelID string) CustomDomain {
			t.Helper()
			value, err := s.CreateCustomDomain(ctx, CustomDomainSpec{Domain: domain, OwnerID: "alice", TunnelID: tunnelID})
			if err != nil {
				t.Fatalf("create %s: %v", domain, err)
			}
			return value
		}
		httpTunnel := createTunnel(t, s, "web.example.com", "http", "alice", 0)
		good := create("good.example.org", httpTunnel)

		active, err := s.SetCustomDomainStatus(ctx, good.ID, "active")
		if err != nil || active.Status != "active" || active.ActivatedAt == nil {
			t.Fatalf("activate = %+v, %v", active, err)
		}
		disabled, err := s.SetCustomDomainStatus(ctx, good.ID, "disabled")
		if err != nil || disabled.Status != "disabled" || disabled.ActivatedAt != nil {
			t.Fatalf("disable = %+v, %v", disabled, err)
		}
		var activatedAt *string
		if err := s.db.QueryRowContext(ctx, s.bind(`SELECT activated_at FROM custom_domains WHERE id = $1`), good.ID).Scan(&activatedAt); err != nil || activatedAt != nil {
			t.Fatalf("stored activated_at = %v, %v", activatedAt, err)
		}
		if _, err := s.SetCustomDomainStatus(ctx, good.ID, "pending"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("pending status error = %v, want ErrInvalid", err)
		}

		kindDomain := create("kind.example.org", createTunnel(t, s, "kind.example.com", "http", "alice", 0))
		portDomain := create("port.example.org", createTunnel(t, s, "port.example.com", "http", "alice", 0))
		noTunnel := create("none.example.org", "")
		for _, statement := range []string{
			`UPDATE tunnels SET kind = 'tcp' WHERE hostname = 'kind.example.com'`,
			`UPDATE tunnels SET remote_port = 20001 WHERE hostname = 'port.example.com'`,
		} {
			if _, err := s.db.ExecContext(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
		for name, id := range map[string]string{"tcp kind": kindDomain.ID, "non-zero port": portDomain.ID, "no tunnel": noTunnel.ID} {
			if _, err := s.SetCustomDomainStatus(ctx, id, "active"); !errors.Is(err, ErrInvalid) {
				t.Errorf("%s: error = %v, want ErrInvalid", name, err)
			}
			var status string
			if err := s.db.QueryRowContext(ctx, s.bind(`SELECT status FROM custom_domains WHERE id = $1`), id).Scan(&status); err != nil || status != "pending" {
				t.Errorf("%s: stored status = %q, %v; want pending", name, status, err)
			}
		}
		if _, err := s.SetCustomDomainStatus(ctx, "missing", "active"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unknown id error = %v, want ErrNotFound", err)
		}
		if _, err := s.SetCustomDomainStatus(ctx, "missing", "disabled"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unknown id disable error = %v, want ErrNotFound", err)
		}
	})
}

func TestActivateSnapshotsTunnelOwner(t *testing.T) {
	forEachDialect(t, func(t *testing.T, open func() *Store) {
		s := open()
		ctx := t.Context()
		tunnelID := createTunnel(t, s, "web.example.com", "http", "bob", 0)
		global, err := s.CreateCustomDomain(ctx, CustomDomainSpec{Domain: "global.example.org", OwnerID: credentials.GlobalOwnerID, TunnelID: tunnelID})
		if err != nil {
			t.Fatal(err)
		}
		activated, err := s.SetCustomDomainStatus(ctx, global.ID, "active")
		if err != nil || activated.OwnerID != "bob" {
			t.Fatalf("activated owner = %q, %v; want bob", activated.OwnerID, err)
		}

		owned, err := s.CreateCustomDomain(ctx, CustomDomainSpec{Domain: "owned.example.org", OwnerID: "bob", TunnelID: tunnelID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE tunnels SET owner_id = 'carol' WHERE hostname = 'web.example.com'`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SetCustomDomainStatus(ctx, owned.ID, "active"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("activation after tunnel owner change = %v, want ErrInvalid", err)
		}
	})
}

func TestLookupCustomDomainTargetRequiresOwnerMatch(t *testing.T) {
	forEachDialect(t, func(t *testing.T, open func() *Store) {
		s := open()
		ctx := t.Context()
		tunnelID := createTunnel(t, s, "web.example.com", "http", "alice", 0)
		domain, err := s.CreateCustomDomain(ctx, CustomDomainSpec{Domain: "app.example.org", OwnerID: "alice", TunnelID: tunnelID})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok, err := s.LookupCustomDomainTarget(ctx, "app.example.org"); err != nil || ok {
			t.Fatalf("pending lookup = %v, %v; want miss", ok, err)
		}
		if _, err := s.SetCustomDomainStatus(ctx, domain.ID, "active"); err != nil {
			t.Fatal(err)
		}
		target, ok, err := s.LookupCustomDomainTarget(ctx, "app.example.org")
		if err != nil || !ok || target != (CustomDomainTarget{Hostname: "web.example.com", Kind: "http", OwnerID: "alice"}) {
			t.Fatalf("active lookup = %+v, %v, %v", target, ok, err)
		}
		if _, ok, err := s.LookupCustomDomainTarget(ctx, "other.example.org"); err != nil || ok {
			t.Fatalf("unknown lookup = %v, %v", ok, err)
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE tunnels SET owner_id = 'mallory' WHERE hostname = 'web.example.com'`); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := s.LookupCustomDomainTarget(ctx, "app.example.org"); err != nil || ok {
			t.Fatalf("lookup after tunnel owner change = %v, %v; want miss", ok, err)
		}
	})
}

func TestLookupCustomDomainRequiresActivatedAt(t *testing.T) {
	forEachDialect(t, func(t *testing.T, open func() *Store) {
		s := open()
		ctx := t.Context()
		tunnelID := createTunnel(t, s, "web.example.com", "http", "alice", 0)
		domain, err := s.CreateCustomDomain(ctx, CustomDomainSpec{Domain: "app.example.org", OwnerID: "alice", TunnelID: tunnelID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.ExecContext(ctx, s.bind(`UPDATE custom_domains SET status = 'active' WHERE id = $1`), domain.ID); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := s.LookupCustomDomainTarget(ctx, "app.example.org"); err != nil || ok {
			t.Fatalf("active without activated_at = %v, %v; want miss", ok, err)
		}
		if _, err := s.SetCustomDomainStatus(ctx, domain.ID, "active"); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := s.LookupCustomDomainTarget(ctx, "app.example.org"); err != nil || !ok {
			t.Fatalf("activated lookup = %v, %v", ok, err)
		}
		if _, err := s.SetCustomDomainStatus(ctx, domain.ID, "disabled"); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := s.LookupCustomDomainTarget(ctx, "app.example.org"); err != nil || ok {
			t.Fatalf("disabled lookup = %v, %v; want miss", ok, err)
		}
		for _, status := range []string{"disabled", "pending"} {
			if _, err := s.db.ExecContext(ctx, s.bind(`UPDATE custom_domains SET status = $2, activated_at = $3 WHERE id = $1`), domain.ID, status, nowString(time.Now().UTC())); err != nil {
				t.Fatal(err)
			}
			if _, ok, err := s.LookupCustomDomainTarget(ctx, "app.example.org"); err != nil || ok {
				t.Fatalf("%s with activated_at lookup = %v, %v; want miss", status, ok, err)
			}
		}
	})
}
