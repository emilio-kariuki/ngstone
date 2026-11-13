package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type EdgePeer struct {
	EdgeID     string
	PeerAddr   string
	SPKISHA256 string
	ExpiresAt  time.Time
}

func (s *Store) UpsertEdgePeer(ctx context.Context, p EdgePeer) error {
	p.EdgeID = strings.TrimSpace(p.EdgeID)
	p.PeerAddr = strings.TrimSpace(p.PeerAddr)
	p.SPKISHA256 = strings.TrimSpace(p.SPKISHA256)
	if p.EdgeID == "" || p.PeerAddr == "" || p.SPKISHA256 == "" {
		return ErrInvalid
	}
	if _, err := s.exec(ctx, `INSERT INTO edge_peers (edge_id, peer_addr, spki_sha256, expires_at) VALUES ($1, $2, $3, $4) ON CONFLICT(edge_id) DO UPDATE SET peer_addr = excluded.peer_addr, spki_sha256 = excluded.spki_sha256, expires_at = excluded.expires_at`, p.EdgeID, p.PeerAddr, p.SPKISHA256, nowString(p.ExpiresAt)); err != nil {
		return fmt.Errorf("storage: upsert edge peer: %w", err)
	}
	return nil
}

func (s *Store) DeleteEdgePeer(ctx context.Context, edgeID string) error {
	if _, err := s.exec(ctx, `DELETE FROM edge_peers WHERE edge_id = $1`, edgeID); err != nil {
		return fmt.Errorf("storage: delete edge peer: %w", err)
	}
	return nil
}

func (s *Store) LiveEdgePeers(ctx context.Context, now time.Time) ([]EdgePeer, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT edge_id, peer_addr, spki_sha256, expires_at FROM edge_peers WHERE expires_at > $1 ORDER BY edge_id`), nowString(now))
	if err != nil {
		return nil, fmt.Errorf("storage: list edge peers: %w", err)
	}
	defer rows.Close()
	var out []EdgePeer
	for rows.Next() {
		peer, err := scanEdgePeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, peer)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: list edge peers: %w", err)
	}
	return out, nil
}

func (s *Store) LookupHostOwners(ctx context.Context, hostname, excludeEdgeID string, now time.Time) ([]EdgePeer, error) {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT DISTINCT e.edge_id, e.peer_addr, e.spki_sha256, e.expires_at FROM tunnels t JOIN connector_leases l ON l.tunnel_id = t.id JOIN edge_peers e ON e.edge_id = l.edge_id WHERE t.hostname = $1 AND t.kind IN ('http', 'tls') AND t.remote_port = 0 AND l.expires_at > $2 AND e.expires_at > $2 AND e.edge_id <> $3 ORDER BY e.edge_id LIMIT 8`), hostname, nowString(now), excludeEdgeID)
	if err != nil {
		return nil, fmt.Errorf("storage: lookup host owners: %w", err)
	}
	defer rows.Close()
	var out []EdgePeer
	for rows.Next() {
		peer, err := scanEdgePeer(rows)
		if err != nil {
			return nil, fmt.Errorf("storage: lookup host owners: %w", err)
		}
		out = append(out, peer)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: lookup host owners: %w", err)
	}
	return out, nil
}

func (s *Store) LiveRemoteTCPPorts(ctx context.Context, hostname, excludeEdgeID string, lo, hi int, now time.Time, limit int) (map[int][]EdgePeer, error) {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT t.remote_port, e.edge_id, e.peer_addr, e.spki_sha256, e.expires_at FROM tunnels t JOIN connector_leases l ON l.tunnel_id = t.id JOIN edge_peers e ON e.edge_id = l.edge_id WHERE t.hostname = $1 AND t.kind = 'tcp' AND t.remote_port BETWEEN $2 AND $3 AND l.expires_at > $4 AND e.expires_at > $4 AND l.edge_id <> $5 GROUP BY t.remote_port, e.edge_id, e.peer_addr, e.spki_sha256, e.expires_at ORDER BY t.remote_port, e.edge_id LIMIT $6`), hostname, lo, hi, nowString(now), excludeEdgeID, limit)
	if err != nil {
		return nil, fmt.Errorf("storage: live remote tcp ports: %w", err)
	}
	defer rows.Close()
	out := make(map[int][]EdgePeer)
	for rows.Next() {
		var port int
		var peer EdgePeer
		var expiresAt string
		if err := rows.Scan(&port, &peer.EdgeID, &peer.PeerAddr, &peer.SPKISHA256, &expiresAt); err != nil {
			return nil, fmt.Errorf("storage: live remote tcp ports: %w", err)
		}
		peer.ExpiresAt, err = parseTime(expiresAt)
		if err != nil {
			return nil, fmt.Errorf("storage: live remote tcp ports: %w", err)
		}
		out[port] = append(out[port], peer)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: live remote tcp ports: %w", err)
	}
	return out, nil
}

func (s *Store) LookupHostAccess(ctx context.Context, hostname string, now time.Time) (string, bool, error) {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	var accessJSON string
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT t.access_json FROM tunnels t JOIN connector_leases l ON l.tunnel_id = t.id JOIN edge_peers e ON e.edge_id = l.edge_id WHERE t.hostname = $1 AND t.kind = 'http' AND t.remote_port = 0 AND l.expires_at > $2 AND e.expires_at > $2 ORDER BY e.edge_id LIMIT 1`), hostname, nowString(now)).Scan(&accessJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("storage: lookup host access: %w", err)
	}
	return accessJSON, true, nil
}

type edgePeerScanner interface {
	Scan(dest ...any) error
}

func scanEdgePeer(row edgePeerScanner) (EdgePeer, error) {
	var peer EdgePeer
	var expiresAt string
	if err := row.Scan(&peer.EdgeID, &peer.PeerAddr, &peer.SPKISHA256, &expiresAt); err != nil {
		return EdgePeer{}, fmt.Errorf("storage: scan edge peer: %w", err)
	}
	parsed, err := parseTime(expiresAt)
	if err != nil {
		return EdgePeer{}, fmt.Errorf("storage: parse edge peer expiry: %w", err)
	}
	peer.ExpiresAt = parsed
	return peer, nil
}
