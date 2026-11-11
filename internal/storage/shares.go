package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

func (s *Store) PublishShare(ctx context.Context, dirKey, shareID, edgeID string, expiresAt time.Time) error {
	if dirKey == "" || shareID == "" || edgeID == "" {
		return ErrInvalid
	}
	if _, err := s.exec(ctx, `INSERT INTO share_directory (dir_key, share_id, edge_id, expires_at, revoked) VALUES ($1, $2, $3, $4, 0) ON CONFLICT(dir_key) DO UPDATE SET share_id = excluded.share_id, edge_id = excluded.edge_id, expires_at = excluded.expires_at, revoked = 0`, dirKey, shareID, edgeID, nowString(expiresAt)); err != nil {
		return fmt.Errorf("storage: publish share: %w", err)
	}
	return nil
}

func (s *Store) WithdrawShare(ctx context.Context, dirKey, edgeID string) error {
	if _, err := s.exec(ctx, `DELETE FROM share_directory WHERE dir_key = $1 AND edge_id = $2`, dirKey, edgeID); err != nil {
		return fmt.Errorf("storage: withdraw share: %w", err)
	}
	return nil
}

func (s *Store) PurgeEdgeShares(ctx context.Context, edgeID string) error {
	if _, err := s.exec(ctx, `DELETE FROM share_directory WHERE edge_id = $1`, edgeID); err != nil {
		return fmt.Errorf("storage: purge edge shares: %w", err)
	}
	return nil
}

func (s *Store) DeleteExpiredShares(ctx context.Context, now time.Time) error {
	if _, err := s.exec(ctx, `DELETE FROM share_directory WHERE expires_at <= $1`, nowString(now)); err != nil {
		return fmt.Errorf("storage: delete expired shares: %w", err)
	}
	return nil
}

func (s *Store) RevokeShare(ctx context.Context, shareID string, now time.Time) (bool, error) {
	res, err := s.exec(ctx, `UPDATE share_directory SET revoked = 1 WHERE share_id = $1 AND expires_at > $2`, shareID, nowString(now))
	if err != nil {
		return false, fmt.Errorf("storage: revoke share: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("storage: revoke share: %w", err)
	}
	return n > 0, nil
}

func (s *Store) RevokedShares(ctx context.Context, edgeID string, now time.Time, limit int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT share_id FROM share_directory WHERE edge_id = $1 AND revoked = 1 AND expires_at > $2 ORDER BY share_id LIMIT $3`), edgeID, nowString(now), limit)
	if err != nil {
		return nil, fmt.Errorf("storage: list revoked shares: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("storage: list revoked shares: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: list revoked shares: %w", err)
	}
	return out, nil
}

func (s *Store) LookupShareEdge(ctx context.Context, dirKey, excludeEdgeID string, now time.Time) (EdgePeer, bool, error) {
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT e.edge_id, e.peer_addr, e.spki_sha256, e.expires_at FROM share_directory d JOIN edge_peers e ON e.edge_id = d.edge_id WHERE d.dir_key = $1 AND d.revoked = 0 AND d.expires_at > $2 AND e.expires_at > $2 AND d.edge_id <> $3 LIMIT 1`), dirKey, nowString(now), excludeEdgeID)
	peer, err := scanEdgePeer(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return EdgePeer{}, false, nil
		}
		return EdgePeer{}, false, fmt.Errorf("storage: lookup share edge: %w", err)
	}
	return peer, true, nil
}
