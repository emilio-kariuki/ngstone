package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"ngstone/internal/credentials"
)

func migrate(ctx context.Context, db *sql.DB, driver string) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("storage: create migration table: %w", err)
	}
	var applied int
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&applied); err != nil {
		return fmt.Errorf("storage: inspect migrations: %w", err)
	}
	if applied < 1 {
		statements := []string{
			`CREATE TABLE IF NOT EXISTS traffic_policies (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				owner_id TEXT NOT NULL,
				digest TEXT NOT NULL,
				policy_json TEXT NOT NULL,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				UNIQUE(owner_id, name),
				UNIQUE(owner_id, digest)
			)`,
			`CREATE TABLE IF NOT EXISTS tunnels (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				hostname TEXT NOT NULL,
				kind TEXT NOT NULL,
				remote_port INTEGER NOT NULL DEFAULT 0,
				owner_id TEXT NOT NULL,
				status TEXT NOT NULL,
				edge_id TEXT NOT NULL,
				instance_id TEXT NOT NULL,
				session_id TEXT NOT NULL,
				http2 INTEGER NOT NULL DEFAULT 0,
				multi_connector INTEGER NOT NULL DEFAULT 0,
				connector_token_digest TEXT NOT NULL DEFAULT '',
				allow_cidrs_json TEXT NOT NULL DEFAULT '[]',
				access_json TEXT NOT NULL DEFAULT '{}',
				policy_id TEXT,
				policy_digest TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				expires_at TEXT,
				UNIQUE(hostname, kind, remote_port),
				FOREIGN KEY(policy_id) REFERENCES traffic_policies(id) ON DELETE SET NULL
			)`,
			`CREATE TABLE IF NOT EXISTS custom_domains (
				id TEXT PRIMARY KEY,
				domain TEXT NOT NULL UNIQUE,
				tunnel_id TEXT,
				owner_id TEXT NOT NULL,
				status TEXT NOT NULL,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				FOREIGN KEY(tunnel_id) REFERENCES tunnels(id) ON DELETE SET NULL
			)`,
			`CREATE TABLE IF NOT EXISTS credentials (
				id TEXT PRIMARY KEY,
				kind TEXT NOT NULL,
				subdomain TEXT NOT NULL DEFAULT '',
				remote_port INTEGER NOT NULL DEFAULT 0,
				owner_id TEXT NOT NULL DEFAULT '',
				token_hash TEXT NOT NULL UNIQUE,
				created_at TEXT NOT NULL,
				expires_at TEXT NOT NULL,
				revoked_at TEXT
			)`,
			`CREATE TABLE IF NOT EXISTS connector_leases (
				id TEXT PRIMARY KEY,
				tunnel_id TEXT NOT NULL,
				instance_id TEXT NOT NULL,
				session_id TEXT NOT NULL,
				edge_id TEXT NOT NULL,
				owner_id TEXT NOT NULL,
				acquired_at TEXT NOT NULL,
				renewed_at TEXT NOT NULL,
				expires_at TEXT NOT NULL,
				UNIQUE(tunnel_id, instance_id),
				UNIQUE(tunnel_id, session_id),
				FOREIGN KEY(tunnel_id) REFERENCES tunnels(id) ON DELETE CASCADE
			)`,
			`CREATE TABLE IF NOT EXISTS audit_events (
				id TEXT PRIMARY KEY,
				edge_id TEXT NOT NULL,
				actor_id TEXT NOT NULL DEFAULT '',
				action TEXT NOT NULL,
				resource_type TEXT NOT NULL,
				resource_id TEXT NOT NULL DEFAULT '',
				metadata_json TEXT NOT NULL DEFAULT '{}',
				created_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_connector_leases_expiry ON connector_leases(expires_at)`,
			`CREATE INDEX IF NOT EXISTS idx_connector_leases_tunnel ON connector_leases(tunnel_id)`,
			`CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at)`,
			`CREATE INDEX IF NOT EXISTS idx_tunnels_status ON tunnels(status)`,
			`CREATE INDEX IF NOT EXISTS idx_custom_domains_tunnel ON custom_domains(tunnel_id)`,
		}
		if err := applyMigration(ctx, db, driver, 1, statements); err != nil {
			return err
		}
		applied = 1
	}
	if applied < 2 {
		statements := []string{
			`CREATE TABLE IF NOT EXISTS tunnel_metrics (
				tunnel_id TEXT PRIMARY KEY,
				hostname TEXT NOT NULL,
				request_count INTEGER NOT NULL DEFAULT 0,
				bytes_in INTEGER NOT NULL DEFAULT 0,
				bytes_out INTEGER NOT NULL DEFAULT 0,
				reconnects INTEGER NOT NULL DEFAULT 0,
				credential_expired INTEGER NOT NULL DEFAULT 0,
				credential_revoked INTEGER NOT NULL DEFAULT 0,
				updated_at TEXT NOT NULL,
				FOREIGN KEY(tunnel_id) REFERENCES tunnels(id) ON DELETE CASCADE
			)`,
			`CREATE TABLE IF NOT EXISTS tunnel_metric_status (
				tunnel_id TEXT NOT NULL,
				status_code TEXT NOT NULL,
				count_value INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY(tunnel_id, status_code),
				FOREIGN KEY(tunnel_id) REFERENCES tunnels(id) ON DELETE CASCADE
			)`,
			`CREATE TABLE IF NOT EXISTS tunnel_metric_latency (
				tunnel_id TEXT NOT NULL,
				bucket TEXT NOT NULL,
				count_value INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY(tunnel_id, bucket),
				FOREIGN KEY(tunnel_id) REFERENCES tunnels(id) ON DELETE CASCADE
			)`,
			`CREATE INDEX IF NOT EXISTS idx_tunnel_metrics_updated_at ON tunnel_metrics(updated_at)`,
		}
		if err := applyMigration(ctx, db, driver, 2, statements); err != nil {
			return err
		}
	}
	if applied < 3 {
		statements := []string{
			fmt.Sprintf(`UPDATE credentials SET owner_id = '%s' WHERE owner_id = 'admin'`, credentials.GlobalOwnerID),
			fmt.Sprintf(`UPDATE traffic_policies SET owner_id = '%s' WHERE owner_id = 'admin'`, credentials.GlobalOwnerID),
			fmt.Sprintf(`UPDATE tunnels SET owner_id = '%s' WHERE owner_id = 'admin'`, credentials.GlobalOwnerID),
			fmt.Sprintf(`UPDATE connector_leases SET owner_id = '%s' WHERE owner_id = 'admin'`, credentials.GlobalOwnerID),
			fmt.Sprintf(`UPDATE custom_domains SET owner_id = '%s' WHERE owner_id = 'admin'`, credentials.GlobalOwnerID),
		}
		if err := applyMigration(ctx, db, driver, 3, statements); err != nil {
			return err
		}
	}
	if applied < 4 {
		if err := applyMigration(ctx, db, driver, 4, nil); err != nil {
			return err
		}
	}
	return nil
}

func applyMigration(ctx context.Context, db *sql.DB, driver string, version int, statements []string) error {
	for attempt := 0; attempt < 6; attempt++ {
		err := applyMigrationOnce(ctx, db, driver, version, statements)
		if err == nil || !isBusyError(err) {
			return err
		}
		delay := time.Duration(10*(1<<attempt)) * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return fmt.Errorf("storage: migration %d remained locked", version)
}

func applyMigrationOnce(ctx context.Context, db *sql.DB, driver string, version int, statements []string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("storage: begin migration %d: %w", version, err)
	}
	if version == 4 {
		if err := migrateCredentialOwners(ctx, tx); err != nil {
			tx.Rollback()
			return fmt.Errorf("storage: migrate credential ownership: %w", err)
		}
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			tx.Rollback()
			return fmt.Errorf("storage: migrate schema %d: %w", version, err)
		}
	}
	placeholder := "$1"
	if driver == DriverSQLite {
		placeholder = "?"
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO schema_migrations(version, applied_at) VALUES (%d, %s)`, version, placeholder), nowString(time.Now())); err != nil {
		tx.Rollback()
		var applied int
		if checkErr := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&applied); checkErr == nil && applied >= version {
			return nil
		}
		return fmt.Errorf("storage: record migration %d: %w", version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("storage: commit migration %d: %w", version, err)
	}
	return nil
}
