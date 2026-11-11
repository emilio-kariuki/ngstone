package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestTLSLeaseSharesHostnameNamespaceWithHTTP(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "control.db"))
	ctx := context.Background()
	tlsLease := LeaseRequest{
		Name:       "secure",
		Hostname:   "secure.example.com",
		Kind:       "tls",
		OwnerID:    "owner-1",
		InstanceID: "instance-1",
		SessionID:  "session-1",
	}
	lease, err := store.AcquireLease(ctx, tlsLease)
	if err != nil {
		t.Fatalf("acquire tls lease: %v", err)
	}
	if lease.Kind != "tls" {
		t.Fatalf("lease kind = %q, want tls", lease.Kind)
	}

	httpLease := tlsLease
	httpLease.Kind = "http"
	httpLease.SessionID = "session-2"
	_, err = store.AcquireLease(ctx, httpLease)
	if !errors.Is(err, ErrHostnameKindConflict) || !errors.Is(err, ErrTunnelConflict) {
		t.Fatalf("http lease on a tls hostname err = %v, want ErrHostnameKindConflict wrapping ErrTunnelConflict", err)
	}

	if err := store.ReleaseLease(ctx, lease.ID); err != nil {
		t.Fatalf("release tls lease: %v", err)
	}
	if _, err := store.AcquireLease(ctx, httpLease); err != nil {
		t.Fatalf("http lease after the tls lease was released: %v", err)
	}
	other := tlsLease
	other.SessionID = "session-3"
	if _, err := store.AcquireLease(ctx, other); !errors.Is(err, ErrHostnameKindConflict) {
		t.Fatalf("tls lease on an http hostname err = %v, want ErrHostnameKindConflict", err)
	}

	withPort := tlsLease
	withPort.Hostname = "port.example.com"
	withPort.RemotePort = 443
	if _, err := store.AcquireLease(ctx, withPort); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tls lease with a remote port err = %v, want ErrInvalid", err)
	}
}
