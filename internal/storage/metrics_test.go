package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestTunnelMetricsPersistAndAccumulate(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "control.db"))
	firstLease, err := store.AcquireLease(context.Background(), LeaseRequest{
		Name:       "first",
		Hostname:   "first.example.com",
		Kind:       "http",
		OwnerID:    "owner",
		InstanceID: "instance-first",
		SessionID:  "session-first",
	})
	if err != nil {
		t.Fatalf("acquire first lease: %v", err)
	}
	secondLease, err := store.AcquireLease(context.Background(), LeaseRequest{
		Name:       "second",
		Hostname:   "second.example.com",
		Kind:       "http",
		OwnerID:    "owner",
		InstanceID: "instance-second",
		SessionID:  "session-second",
	})
	if err != nil {
		t.Fatalf("acquire second lease: %v", err)
	}
	if err := store.UpsertTunnelMetrics(context.Background(), TunnelMetricDelta{
		TunnelID:       firstLease.TunnelID,
		Hostname:       firstLease.Hostname,
		RequestCount:   3,
		BytesIn:        10,
		BytesOut:       20,
		StatusCounts:   map[string]int64{"200": 2, "500": 1},
		LatencyBuckets: map[string]int64{"10": 2, "100": 1},
		Reconnects:     1,
	}); err != nil {
		t.Fatalf("upsert first metrics: %v", err)
	}
	if err := store.UpsertTunnelMetrics(context.Background(), TunnelMetricDelta{
		TunnelID:          firstLease.TunnelID,
		Hostname:          firstLease.Hostname,
		RequestCount:      2,
		BytesIn:           4,
		BytesOut:          8,
		StatusCounts:      map[string]int64{"200": 2},
		LatencyBuckets:    map[string]int64{"10": 1, "+Inf": 1},
		CredentialRevoked: 1,
	}); err != nil {
		t.Fatalf("accumulate first metrics: %v", err)
	}
	if err := store.UpsertTunnelMetrics(context.Background(), TunnelMetricDelta{
		TunnelID:       secondLease.TunnelID,
		Hostname:       secondLease.Hostname,
		RequestCount:   1,
		StatusCounts:   map[string]int64{"201": 1},
		LatencyBuckets: map[string]int64{"25": 1},
	}); err != nil {
		t.Fatalf("upsert second metrics: %v", err)
	}

	metrics, err := store.ListTunnelMetrics(context.Background())
	if err != nil {
		t.Fatalf("list metrics: %v", err)
	}
	if len(metrics) != 2 {
		t.Fatalf("metric count = %d, want 2", len(metrics))
	}
	first := metrics[0]
	if first.TunnelID != firstLease.TunnelID || first.RequestCount != 5 || first.BytesIn != 14 || first.BytesOut != 28 || first.Reconnects != 1 || first.CredentialRevoked != 1 {
		t.Fatalf("first metrics = %+v", first)
	}
	if first.StatusCounts["200"] != 4 || first.StatusCounts["500"] != 1 || first.LatencyBuckets["10"] != 3 || first.LatencyBuckets["+Inf"] != 1 {
		t.Fatalf("first metric distributions = status=%v latency=%v", first.StatusCounts, first.LatencyBuckets)
	}
	if _, err := time.Parse(time.RFC3339Nano, first.UpdatedAt.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("updated timestamp = %v", first.UpdatedAt)
	}
	second := metrics[1]
	if second.TunnelID != secondLease.TunnelID || second.RequestCount != 1 || second.StatusCounts["201"] != 1 || second.LatencyBuckets["25"] != 1 {
		t.Fatalf("second metrics = %+v", second)
	}
}
