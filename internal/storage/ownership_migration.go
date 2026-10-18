package storage

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
)

type ownershipPolicy struct {
	id, name, owner, target, digest string
}

func migrateCredentialOwners(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT p.id, p.name, p.owner_id, COALESCE(NULLIF(c.owner_id, ''), p.owner_id), p.digest FROM traffic_policies p LEFT JOIN credentials c ON c.id = p.owner_id ORDER BY p.id`)
	if err != nil {
		return err
	}
	var policies []ownershipPolicy
	owners := map[string]bool{}
	for rows.Next() {
		var p ownershipPolicy
		if err := rows.Scan(&p.id, &p.name, &p.owner, &p.target, &p.digest); err != nil {
			rows.Close()
			return err
		}
		policies = append(policies, p)
		owners[p.owner], owners[p.target] = true, true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	sort.SliceStable(policies, func(i, j int) bool {
		return policies[i].owner == policies[i].target && policies[j].owner != policies[j].target
	})
	byDigest := map[[2]string]string{}
	byName := map[[2]string]bool{}
	reserved := map[[2]string]bool{}
	for _, p := range policies {
		reserved[[2]string{p.target, p.name}] = true
		if p.owner == p.target {
			continue
		}
		staged := "__ngstone_migration_v4_" + p.id
		for owners[staged] {
			staged += "_"
		}
		owners[staged] = true
		if _, err := tx.ExecContext(ctx, `UPDATE traffic_policies SET owner_id = $1 WHERE id = $2`, staged, p.id); err != nil {
			return err
		}
	}
	for _, p := range policies {
		key := [2]string{p.target, p.digest}
		if keeper := byDigest[key]; keeper != "" {
			if _, err := tx.ExecContext(ctx, `UPDATE tunnels SET policy_id = $1 WHERE policy_id = $2`, keeper, p.id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM traffic_policies WHERE id = $1`, p.id); err != nil {
				return err
			}
			continue
		}
		name := p.name
		if byName[[2]string{p.target, name}] {
			name += "-" + p.id
			for reserved[[2]string{p.target, name}] {
				name += "_"
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE traffic_policies SET owner_id = $1, name = $2 WHERE id = $3`, p.target, name, p.id); err != nil {
			return err
		}
		byDigest[key] = p.id
		byName[[2]string{p.target, name}] = true
		reserved[[2]string{p.target, name}] = true
	}
	for _, table := range []string{"tunnels", "connector_leases"} {
		query := fmt.Sprintf(`UPDATE %s SET owner_id = (SELECT c.owner_id FROM credentials c WHERE c.id = %s.owner_id) WHERE EXISTS (SELECT 1 FROM credentials c WHERE c.id = %s.owner_id AND c.owner_id <> '')`, table, table, table)
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}
	return nil
}
