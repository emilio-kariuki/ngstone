package storage

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

type TunnelMetricDelta struct {
	TunnelID          string
	Hostname          string
	RequestCount      int64
	BytesIn           int64
	BytesOut          int64
	StatusCounts      map[string]int64
	LatencyBuckets    map[string]int64
	Reconnects        int64
	CredentialExpired int64
	CredentialRevoked int64
}

type TunnelMetric struct {
	TunnelID          string           `json:"tunnel_id"`
	Hostname          string           `json:"hostname"`
	RequestCount      int64            `json:"request_count"`
	BytesIn           int64            `json:"bytes_in"`
	BytesOut          int64            `json:"bytes_out"`
	StatusCounts      map[string]int64 `json:"status_counts"`
	LatencyBuckets    map[string]int64 `json:"-"`
	Reconnects        int64            `json:"reconnects"`
	CredentialExpired int64            `json:"credential_expired"`
	CredentialRevoked int64            `json:"credential_revoked"`
	UpdatedAt         time.Time        `json:"updated_at"`
}

func (s *Store) UpsertTunnelMetrics(ctx context.Context, delta TunnelMetricDelta) error {
	delta.TunnelID = strings.TrimSpace(delta.TunnelID)
	delta.Hostname = strings.TrimSpace(delta.Hostname)
	if delta.TunnelID == "" || delta.Hostname == "" || delta.RequestCount < 0 || delta.BytesIn < 0 || delta.BytesOut < 0 || delta.Reconnects < 0 || delta.CredentialExpired < 0 || delta.CredentialRevoked < 0 {
		return ErrInvalid
	}
	for key, value := range delta.StatusCounts {
		if strings.TrimSpace(key) == "" || value < 0 {
			return ErrInvalid
		}
	}
	for key, value := range delta.LatencyBuckets {
		if strings.TrimSpace(key) == "" || value < 0 {
			return ErrInvalid
		}
	}
	now := nowString(time.Now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("storage: begin metrics update: %w", err)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO tunnel_metrics(tunnel_id, hostname, request_count, bytes_in, bytes_out, reconnects, credential_expired, credential_revoked, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT(tunnel_id) DO UPDATE SET hostname = excluded.hostname, request_count = tunnel_metrics.request_count + excluded.request_count, bytes_in = tunnel_metrics.bytes_in + excluded.bytes_in, bytes_out = tunnel_metrics.bytes_out + excluded.bytes_out, reconnects = tunnel_metrics.reconnects + excluded.reconnects, credential_expired = tunnel_metrics.credential_expired + excluded.credential_expired, credential_revoked = tunnel_metrics.credential_revoked + excluded.credential_revoked, updated_at = excluded.updated_at`), delta.TunnelID, delta.Hostname, delta.RequestCount, delta.BytesIn, delta.BytesOut, delta.Reconnects, delta.CredentialExpired, delta.CredentialRevoked, now)
	if err != nil {
		return fmt.Errorf("storage: update tunnel metrics: %w", err)
	}
	statusKeys := sortedMetricKeys(delta.StatusCounts)
	for _, status := range statusKeys {
		if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO tunnel_metric_status(tunnel_id, status_code, count_value) VALUES ($1, $2, $3) ON CONFLICT(tunnel_id, status_code) DO UPDATE SET count_value = tunnel_metric_status.count_value + excluded.count_value`), delta.TunnelID, status, delta.StatusCounts[status]); err != nil {
			return fmt.Errorf("storage: update tunnel status metrics: %w", err)
		}
	}
	latencyKeys := sortedMetricKeys(delta.LatencyBuckets)
	for _, bucket := range latencyKeys {
		if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO tunnel_metric_latency(tunnel_id, bucket, count_value) VALUES ($1, $2, $3) ON CONFLICT(tunnel_id, bucket) DO UPDATE SET count_value = tunnel_metric_latency.count_value + excluded.count_value`), delta.TunnelID, bucket, delta.LatencyBuckets[bucket]); err != nil {
			return fmt.Errorf("storage: update tunnel latency metrics: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("storage: commit tunnel metrics: %w", err)
	}
	return nil
}

func sortedMetricKeys(values map[string]int64) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (s *Store) ListTunnelMetrics(ctx context.Context) ([]TunnelMetric, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tunnel_id, hostname, request_count, bytes_in, bytes_out, reconnects, credential_expired, credential_revoked, updated_at FROM tunnel_metrics ORDER BY hostname, tunnel_id`)
	if err != nil {
		return nil, fmt.Errorf("storage: list tunnel metrics: %w", err)
	}
	defer rows.Close()
	byID := make(map[string]int)
	var out []TunnelMetric
	for rows.Next() {
		var metric TunnelMetric
		var updatedAt string
		if err := rows.Scan(&metric.TunnelID, &metric.Hostname, &metric.RequestCount, &metric.BytesIn, &metric.BytesOut, &metric.Reconnects, &metric.CredentialExpired, &metric.CredentialRevoked, &updatedAt); err != nil {
			return nil, fmt.Errorf("storage: scan tunnel metrics: %w", err)
		}
		metric.UpdatedAt, err = parseTime(updatedAt)
		if err != nil {
			return nil, err
		}
		metric.StatusCounts = make(map[string]int64)
		metric.LatencyBuckets = make(map[string]int64)
		out = append(out, metric)
		byID[metric.TunnelID] = len(out) - 1
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: list tunnel metrics: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("storage: close tunnel metrics: %w", err)
	}
	statusRows, err := s.db.QueryContext(ctx, `SELECT tunnel_id, status_code, count_value FROM tunnel_metric_status ORDER BY tunnel_id, status_code`)
	if err != nil {
		return nil, fmt.Errorf("storage: list tunnel status metrics: %w", err)
	}
	for statusRows.Next() {
		var tunnelID, status string
		var count int64
		if err := statusRows.Scan(&tunnelID, &status, &count); err != nil {
			statusRows.Close()
			return nil, fmt.Errorf("storage: scan tunnel status metrics: %w", err)
		}
		if index, ok := byID[tunnelID]; ok {
			out[index].StatusCounts[status] = count
		}
	}
	if err := statusRows.Err(); err != nil {
		statusRows.Close()
		return nil, fmt.Errorf("storage: list tunnel status metrics: %w", err)
	}
	statusRows.Close()
	latencyRows, err := s.db.QueryContext(ctx, `SELECT tunnel_id, bucket, count_value FROM tunnel_metric_latency ORDER BY tunnel_id, bucket`)
	if err != nil {
		return nil, fmt.Errorf("storage: list tunnel latency metrics: %w", err)
	}
	for latencyRows.Next() {
		var tunnelID, bucket string
		var count int64
		if err := latencyRows.Scan(&tunnelID, &bucket, &count); err != nil {
			latencyRows.Close()
			return nil, fmt.Errorf("storage: scan tunnel latency metrics: %w", err)
		}
		if index, ok := byID[tunnelID]; ok {
			out[index].LatencyBuckets[bucket] = count
		}
	}
	if err := latencyRows.Err(); err != nil {
		latencyRows.Close()
		return nil, fmt.Errorf("storage: list tunnel latency metrics: %w", err)
	}
	latencyRows.Close()
	return out, nil
}

func (s *Store) GetTunnelMetrics(ctx context.Context, tunnelID string) (TunnelMetric, error) {
	metrics, err := s.ListTunnelMetrics(ctx)
	if err != nil {
		return TunnelMetric{}, err
	}
	for _, metric := range metrics {
		if metric.TunnelID == tunnelID {
			return metric, nil
		}
	}
	return TunnelMetric{}, ErrNotFound
}
