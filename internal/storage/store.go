package storage

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"ngstone/internal/access"
	"ngstone/internal/credentials"
	"ngstone/internal/policy"
)

const (
	DriverSQLite    = "sqlite"
	DriverPostgres  = "postgres"
	DefaultSQLite   = "file:/var/lib/ngstoned/control.db"
	DefaultLeaseTTL = 45 * time.Second
)

var (
	ErrTunnelConflict          = errors.New("storage: tunnel lease conflict")
	ErrConnectorConfigMismatch = errors.New("storage: connector configuration mismatch")
	ErrLeaseLost               = errors.New("storage: connector lease lost")
	ErrPolicyConflict          = errors.New("storage: traffic policy conflict")
	ErrNotFound                = errors.New("storage: record not found")
	ErrInvalid                 = errors.New("storage: invalid record")
	domainRE                   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

type Config struct {
	Driver   string
	DSN      string
	EdgeID   string
	LeaseTTL time.Duration
}

type Store struct {
	db       *sql.DB
	driver   string
	edgeID   string
	leaseTTL time.Duration
}

type LeaseRequest struct {
	Name                 string
	Hostname             string
	Kind                 string
	RemotePort           int
	OwnerID              string
	InstanceID           string
	SessionID            string
	EdgeID               string
	Takeover             bool
	HTTP2                bool
	MultiConnector       bool
	ConnectorTokenDigest string
	AllowCIDRsJSON       string
	AccessJSON           string
	Policy               *policy.Policy
	PolicyDigest         string
	ExpiresAt            time.Time
}

type Lease struct {
	ID          string
	TunnelID    string
	Hostname    string
	Kind        string
	RemotePort  int
	InstanceID  string
	SessionID   string
	EdgeID      string
	OwnerID     string
	AcquiredAt  time.Time
	RenewedAt   time.Time
	ExpiresAt   time.Time
	Reconnected bool
}

type Tunnel struct {
	ID             string           `json:"id"`
	Name           string           `json:"name"`
	Hostname       string           `json:"hostname"`
	Kind           string           `json:"kind"`
	RemotePort     int              `json:"remote_port,omitempty"`
	OwnerID        string           `json:"owner_id"`
	Status         string           `json:"status"`
	EdgeID         string           `json:"edge_id"`
	InstanceID     string           `json:"instance_id"`
	SessionID      string           `json:"session_id"`
	HTTP2          bool             `json:"http2"`
	MultiConnector bool             `json:"multi_connector"`
	PolicyDigest   string           `json:"policy_digest,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
	ExpiresAt      *time.Time       `json:"expires_at,omitempty"`
	Connectors     []LeaseConnector `json:"connectors"`
}

type LeaseConnector struct {
	ID         string    `json:"id"`
	InstanceID string    `json:"instance_id"`
	SessionID  string    `json:"session_id"`
	EdgeID     string    `json:"edge_id"`
	OwnerID    string    `json:"owner_id"`
	AcquiredAt time.Time `json:"acquired_at"`
	RenewedAt  time.Time `json:"renewed_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type AuditEvent struct {
	ID           string            `json:"id"`
	EdgeID       string            `json:"edge_id"`
	ActorID      string            `json:"actor_id,omitempty"`
	Action       string            `json:"action"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

type CustomDomain struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	TunnelID  string    `json:"tunnel_id,omitempty"`
	OwnerID   string    `json:"owner_id"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type CustomDomainSpec struct {
	Domain   string
	TunnelID string
	OwnerID  string
	Status   string
}

type TrafficPolicy struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	OwnerID    string    `json:"owner_id"`
	Digest     string    `json:"digest"`
	PolicyJSON string    `json:"policy_json"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func Open(cfg Config) (*Store, error) {
	driver, dsn, err := resolveDatabase(cfg.Driver, cfg.DSN)
	if err != nil {
		return nil, err
	}
	if driver == DriverSQLite {
		if err := ensureSQLiteDirectory(dsn); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open(driverName(driver), dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: open database: %w", err)
	}
	if driver == DriverSQLite {
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := configureDatabase(ctx, db, driver); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrate(ctx, db, driver); err != nil {
		db.Close()
		return nil, err
	}
	edgeID := strings.TrimSpace(cfg.EdgeID)
	if edgeID == "" {
		edgeID, err = randomID()
		if err != nil {
			db.Close()
			return nil, err
		}
	}
	leaseTTL := cfg.LeaseTTL
	if leaseTTL <= 0 {
		leaseTTL = DefaultLeaseTTL
	}
	return &Store{db: db, driver: driver, edgeID: edgeID, leaseTTL: leaseTTL}, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Driver() string {
	if s == nil {
		return ""
	}
	return s.driver
}

func (s *Store) EdgeID() string {
	if s == nil {
		return ""
	}
	return s.edgeID
}

func resolveDatabase(driver, dsn string) (string, string, error) {
	driver = strings.ToLower(strings.TrimSpace(driver))
	dsn = strings.TrimSpace(dsn)
	if driver == "" {
		if strings.HasPrefix(strings.ToLower(dsn), "postgres://") || strings.HasPrefix(strings.ToLower(dsn), "postgresql://") {
			driver = DriverPostgres
		} else {
			driver = DriverSQLite
		}
	}
	switch driver {
	case "sqlite", "sqlite3", "sqlite3-modernc":
		driver = DriverSQLite
		if dsn == "" {
			dsn = DefaultSQLite
		}
		return driver, normalizeSQLiteDSN(dsn), nil
	case "postgres", "postgresql", "pgx":
		driver = DriverPostgres
		if dsn == "" {
			return "", "", errors.New("storage: PostgreSQL DSN is required")
		}
		return driver, dsn, nil
	default:
		return "", "", fmt.Errorf("storage: unsupported database driver %q", driver)
	}
}

func driverName(driver string) string {
	if driver == DriverPostgres {
		return "pgx"
	}
	return "sqlite"
}

func normalizeSQLiteDSN(dsn string) string {
	if strings.HasPrefix(strings.ToLower(dsn), "sqlite://") {
		dsn = dsn[len("sqlite://"):]
		if dsn == "" {
			dsn = ":memory:"
		}
	}
	if dsn == ":memory:" {
		return "file::memory:?cache=shared"
	}
	if strings.HasPrefix(dsn, "file:") {
		return dsn
	}
	return "file:" + dsn
}

func ensureSQLiteDirectory(dsn string) error {
	path := strings.TrimPrefix(dsn, "file:")
	if path == "" || strings.HasPrefix(path, ":memory:") || strings.HasPrefix(path, "file::memory:") {
		return nil
	}
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("storage: create SQLite directory: %w", err)
	}
	return nil
}

func configureDatabase(ctx context.Context, db *sql.DB, driver string) error {
	var pingErr error
	for attempt := 0; attempt < 6; attempt++ {
		pingErr = db.PingContext(ctx)
		if pingErr == nil || !isBusyError(pingErr) {
			break
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
	if pingErr != nil {
		return fmt.Errorf("storage: ping database: %w", pingErr)
	}
	if driver != DriverSQLite {
		return nil
	}
	for _, statement := range []string{
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA foreign_keys = ON`,
		`PRAGMA journal_mode = WAL`,
	} {
		var err error
		for attempt := 0; attempt < 6; attempt++ {
			_, err = db.ExecContext(ctx, statement)
			if err == nil || !isBusyError(err) {
				break
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
		if err != nil {
			return fmt.Errorf("storage: configure SQLite: %w", err)
		}
	}
	return nil
}

func (s *Store) bind(query string) string {
	return query
}

func (s *Store) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(ctx, s.bind(query), args...)
}

func randomID() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("storage: generate id: %w", err)
	}
	return hex.EncodeToString(data), nil
}

func nowString(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
}

func parseTime(raw string) (time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, raw)
}

func intBool(value bool) int {
	if value {
		return 1
	}
	return 0
}

func asBool(value int) bool {
	return value != 0
}

func isUniqueError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique") || strings.Contains(message, "duplicate")
}

func isBusyError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database is locked") || strings.Contains(message, "sqlite_busy") || strings.Contains(message, "database table is locked")
}

func (s *Store) Issue(spec credentials.Spec, ttl time.Duration) (credentials.Issued, error) {
	return s.IssueContext(context.Background(), spec, ttl)
}

func (s *Store) IssueContext(ctx context.Context, spec credentials.Spec, ttl time.Duration) (credentials.Issued, error) {
	return s.issueContextAt(ctx, spec, ttl, time.Now())
}

func (s *Store) IssueAt(spec credentials.Spec, ttl time.Duration, now time.Time) (credentials.Issued, error) {
	return s.issueContextAt(context.Background(), spec, ttl, now)
}

func (s *Store) issueContextAt(ctx context.Context, spec credentials.Spec, ttl time.Duration, now time.Time) (credentials.Issued, error) {
	if err := ctx.Err(); err != nil {
		return credentials.Issued{}, err
	}
	normalized, err := credentials.NormalizeSpec(spec)
	if err != nil {
		return credentials.Issued{}, err
	}
	if ttl <= 0 || ttl > credentials.MaxTTL {
		return credentials.Issued{}, fmt.Errorf("storage: ttl must be greater than zero and no longer than %s", credentials.MaxTTL)
	}
	now = now.UTC()
	if now.IsZero() {
		return credentials.Issued{}, errors.New("storage: issue time is required")
	}
	for attempt := 0; attempt < 3; attempt++ {
		id, err := randomID()
		if err != nil {
			return credentials.Issued{}, err
		}
		token, err := credentials.NewToken(id)
		if err != nil {
			return credentials.Issued{}, err
		}
		credential := credentials.Credential{
			ID:         id,
			Kind:       normalized.Kind,
			Subdomain:  normalized.Subdomain,
			RemotePort: normalized.RemotePort,
			OwnerID:    normalized.OwnerID,
			CreatedAt:  now,
			ExpiresAt:  now.Add(ttl),
		}
		_, err = s.exec(ctx, `INSERT INTO credentials(id, kind, subdomain, remote_port, owner_id, token_hash, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, credential.ID, credential.Kind, credential.Subdomain, credential.RemotePort, credential.OwnerID, credentials.TokenHashHex(token), nowString(credential.CreatedAt), nowString(credential.ExpiresAt))
		if err == nil {
			return credentials.Issued{Credential: credential, Token: token}, nil
		}
		if !isUniqueError(err) {
			return credentials.Issued{}, fmt.Errorf("storage: issue credential: %w", err)
		}
	}
	return credentials.Issued{}, errors.New("storage: could not allocate credential id")
}

func (s *Store) Validate(token string, now time.Time) (credentials.Credential, error) {
	return s.ValidateContext(context.Background(), token, now)
}

func (s *Store) ValidateContext(ctx context.Context, token string, now time.Time) (credentials.Credential, error) {
	id, err := credentials.ParseTokenID(token)
	if err != nil {
		return credentials.Credential{}, err
	}
	var credential credentials.Credential
	var tokenHash, createdAt, expiresAt, revokedAt string
	err = s.db.QueryRowContext(ctx, s.bind(`SELECT id, kind, subdomain, remote_port, owner_id, token_hash, created_at, expires_at, COALESCE(revoked_at, '') FROM credentials WHERE id = $1`), id).Scan(&credential.ID, &credential.Kind, &credential.Subdomain, &credential.RemotePort, &credential.OwnerID, &tokenHash, &createdAt, &expiresAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return credentials.Credential{}, credentials.ErrInvalid
	}
	if err != nil {
		return credentials.Credential{}, fmt.Errorf("storage: validate credential: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(credentials.TokenHashHex(token)), []byte(tokenHash)) != 1 {
		return credentials.Credential{}, credentials.ErrInvalid
	}
	credential.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return credentials.Credential{}, credentials.ErrInvalid
	}
	credential.ExpiresAt, err = parseTime(expiresAt)
	if err != nil {
		return credentials.Credential{}, credentials.ErrInvalid
	}
	if revokedAt != "" {
		revoked, parseErr := parseTime(revokedAt)
		if parseErr != nil {
			return credentials.Credential{}, credentials.ErrInvalid
		}
		credential.RevokedAt = &revoked
		return credentials.Credential{}, credentials.ErrRevoked
	}
	if !now.Before(credential.ExpiresAt) {
		return credentials.Credential{}, credentials.ErrExpired
	}
	return credential, nil
}

func (s *Store) Active(id string, now time.Time) (bool, error) {
	return s.ActiveContext(context.Background(), id, now)
}

func (s *Store) ActiveContext(ctx context.Context, id string, now time.Time) (bool, error) {
	var expiresAt, revokedAt string
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT expires_at, COALESCE(revoked_at, '') FROM credentials WHERE id = $1`), id).Scan(&expiresAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, credentials.ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("storage: inspect credential: %w", err)
	}
	expires, err := parseTime(expiresAt)
	if err != nil {
		return false, fmt.Errorf("storage: parse credential expiry: %w", err)
	}
	return revokedAt == "" && now.Before(expires), nil
}

func (s *Store) Revoke(id string) error {
	return s.RevokeContext(context.Background(), id)
}

func (s *Store) RevokeContext(ctx context.Context, id string) error {
	result, err := s.exec(ctx, `UPDATE credentials SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL`, nowString(time.Now()), id)
	if err != nil {
		return fmt.Errorf("storage: revoke credential: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("storage: revoke credential: %w", err)
	}
	if rows == 0 {
		var exists int
		if err := s.db.QueryRowContext(ctx, s.bind(`SELECT 1 FROM credentials WHERE id = $1`), id).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
			return credentials.ErrNotFound
		} else if err != nil {
			return fmt.Errorf("storage: inspect credential: %w", err)
		}
	}
	return nil
}

func (s *Store) RevokeForOwner(id, ownerID string) error {
	return s.RevokeForOwnerContext(context.Background(), id, ownerID)
}

func (s *Store) RevokeForOwnerContext(ctx context.Context, id, ownerID string) error {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == credentials.GlobalOwnerID {
		return s.RevokeContext(ctx, id)
	}
	result, err := s.exec(ctx, `UPDATE credentials SET revoked_at = $1 WHERE id = $2 AND owner_id = $3 AND revoked_at IS NULL`, nowString(time.Now()), id, ownerID)
	if err != nil {
		return fmt.Errorf("storage: revoke credential: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("storage: revoke credential: %w", err)
	}
	if rows == 0 {
		return credentials.ErrNotFound
	}
	return nil
}

func (s *Store) List() ([]credentials.Credential, error) {
	return s.ListContext(context.Background())
}

func (s *Store) ListContext(ctx context.Context) ([]credentials.Credential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, subdomain, remote_port, owner_id, created_at, expires_at, COALESCE(revoked_at, '') FROM credentials ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("storage: list credentials: %w", err)
	}
	defer rows.Close()
	var out []credentials.Credential
	for rows.Next() {
		var credential credentials.Credential
		var createdAt, expiresAt, revokedAt string
		if err := rows.Scan(&credential.ID, &credential.Kind, &credential.Subdomain, &credential.RemotePort, &credential.OwnerID, &createdAt, &expiresAt, &revokedAt); err != nil {
			return nil, fmt.Errorf("storage: scan credential: %w", err)
		}
		credential.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, err
		}
		credential.ExpiresAt, err = parseTime(expiresAt)
		if err != nil {
			return nil, err
		}
		if revokedAt != "" {
			revoked, parseErr := parseTime(revokedAt)
			if parseErr != nil {
				return nil, parseErr
			}
			credential.RevokedAt = &revoked
		}
		out = append(out, credential)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: list credentials: %w", err)
	}
	return out, nil
}

func (s *Store) ListForOwner(ownerID string) ([]credentials.Credential, error) {
	return s.ListForOwnerContext(context.Background(), ownerID)
}

func (s *Store) ListForOwnerContext(ctx context.Context, ownerID string) ([]credentials.Credential, error) {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == credentials.GlobalOwnerID {
		return s.ListContext(ctx)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, subdomain, remote_port, owner_id, created_at, expires_at, COALESCE(revoked_at, '') FROM credentials WHERE owner_id = $1 ORDER BY created_at, id`, ownerID)
	if err != nil {
		return nil, fmt.Errorf("storage: list credentials: %w", err)
	}
	defer rows.Close()
	var out []credentials.Credential
	for rows.Next() {
		var credential credentials.Credential
		var createdAt, expiresAt, revokedAt string
		if err := rows.Scan(&credential.ID, &credential.Kind, &credential.Subdomain, &credential.RemotePort, &credential.OwnerID, &createdAt, &expiresAt, &revokedAt); err != nil {
			return nil, fmt.Errorf("storage: scan credential: %w", err)
		}
		credential.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, err
		}
		credential.ExpiresAt, err = parseTime(expiresAt)
		if err != nil {
			return nil, err
		}
		if revokedAt != "" {
			revoked, parseErr := parseTime(revokedAt)
			if parseErr != nil {
				return nil, parseErr
			}
			credential.RevokedAt = &revoked
		}
		out = append(out, credential)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: list credentials: %w", err)
	}
	return out, nil
}

type storedTunnel struct {
	ID                   string
	Name                 string
	Hostname             string
	Kind                 string
	RemotePort           int
	OwnerID              string
	Status               string
	EdgeID               string
	InstanceID           string
	SessionID            string
	HTTP2                int
	MultiConnector       int
	ConnectorTokenDigest string
	AllowCIDRsJSON       string
	AccessJSON           string
	PolicyID             sql.NullString
	PolicyDigest         string
	CreatedAt            string
	UpdatedAt            string
	ExpiresAt            sql.NullString
}

func (s *Store) AcquireLease(ctx context.Context, request LeaseRequest) (Lease, error) {
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		lease, err := s.acquireLeaseOnce(ctx, request)
		if err == nil || !isBusyError(err) {
			return lease, err
		}
		lastErr = err
		delay := time.Duration(10*(1<<attempt)) * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Lease{}, ctx.Err()
		case <-timer.C:
		}
	}
	return Lease{}, lastErr
}

func (s *Store) acquireLeaseOnce(ctx context.Context, request LeaseRequest) (Lease, error) {
	request.Name = strings.TrimSpace(request.Name)
	request.Hostname = strings.ToLower(strings.TrimSpace(request.Hostname))
	request.Kind = strings.ToLower(strings.TrimSpace(request.Kind))
	request.OwnerID = strings.TrimSpace(request.OwnerID)
	request.InstanceID = strings.TrimSpace(request.InstanceID)
	request.SessionID = strings.TrimSpace(request.SessionID)
	request.EdgeID = strings.TrimSpace(request.EdgeID)
	if request.EdgeID == "" {
		request.EdgeID = s.edgeID
	}
	if request.Name == "" {
		request.Name = request.Hostname
	}
	if request.Hostname == "" || request.Kind == "" || request.OwnerID == "" || request.InstanceID == "" || request.SessionID == "" || request.EdgeID == "" {
		return Lease{}, ErrInvalid
	}
	if request.Kind != "http" && request.Kind != "tcp" {
		return Lease{}, ErrInvalid
	}
	if request.Kind == "tcp" && (request.RemotePort < 1 || request.RemotePort > 65535) {
		return Lease{}, ErrInvalid
	}
	if request.Kind == "http" && request.RemotePort != 0 {
		return Lease{}, ErrInvalid
	}
	if request.MultiConnector && request.ConnectorTokenDigest == "" {
		return Lease{}, ErrInvalid
	}
	if request.AllowCIDRsJSON == "" {
		request.AllowCIDRsJSON = "[]"
	}
	if request.AccessJSON == "" {
		request.AccessJSON = "{}"
	}
	var err error
	request.AccessJSON, err = access.CanonicalJSON(request.AccessJSON)
	if err != nil {
		return Lease{}, err
	}
	request.AllowCIDRsJSON, err = access.CanonicalCIDRsJSON(request.AllowCIDRsJSON)
	if err != nil {
		return Lease{}, err
	}
	now := time.Now().UTC()
	if request.ExpiresAt.IsZero() {
		request.ExpiresAt = now.Add(s.leaseTTL)
	}
	request.ExpiresAt = request.ExpiresAt.UTC()
	if !request.ExpiresAt.After(now) {
		return Lease{}, ErrInvalid
	}
	policyID, policyDigest, err := s.policyForLease(ctx, request)
	if err != nil {
		return Lease{}, err
	}
	if request.Policy != nil {
		request.PolicyDigest = policyDigest
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Lease{}, fmt.Errorf("storage: begin lease: %w", err)
	}
	defer tx.Rollback()
	query := `SELECT id, name, hostname, kind, remote_port, owner_id, status, edge_id, instance_id, session_id, http2, multi_connector, connector_token_digest, allow_cidrs_json, access_json, policy_id, policy_digest, created_at, updated_at, expires_at FROM tunnels WHERE hostname = $1 AND kind = $2 AND remote_port = $3`
	if s.driver == DriverPostgres {
		query += ` FOR UPDATE`
	}
	var existing storedTunnel
	err = tx.QueryRowContext(ctx, s.bind(query), request.Hostname, request.Kind, request.RemotePort).Scan(
		&existing.ID, &existing.Name, &existing.Hostname, &existing.Kind, &existing.RemotePort, &existing.OwnerID, &existing.Status, &existing.EdgeID, &existing.InstanceID, &existing.SessionID, &existing.HTTP2, &existing.MultiConnector, &existing.ConnectorTokenDigest, &existing.AllowCIDRsJSON, &existing.AccessJSON, &existing.PolicyID, &existing.PolicyDigest, &existing.CreatedAt, &existing.UpdatedAt, &existing.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		existing = storedTunnel{}
	} else if err != nil {
		return Lease{}, fmt.Errorf("storage: inspect tunnel: %w", err)
	}
	var tunnelID string
	reconnected := false
	if existing.ID == "" {
		tunnelID, err = randomID()
		if err != nil {
			return Lease{}, err
		}
		if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO tunnels(id, name, hostname, kind, remote_port, owner_id, status, edge_id, instance_id, session_id, http2, multi_connector, connector_token_digest, allow_cidrs_json, access_json, policy_id, policy_digest, created_at, updated_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`), tunnelID, request.Name, request.Hostname, request.Kind, request.RemotePort, request.OwnerID, request.EdgeID, request.InstanceID, request.SessionID, intBool(request.HTTP2), intBool(request.MultiConnector), request.ConnectorTokenDigest, request.AllowCIDRsJSON, request.AccessJSON, nullableString(policyID), request.PolicyDigest, nowString(now), nowString(now), nowString(request.ExpiresAt)); err != nil {
			if isUniqueError(err) {
				return Lease{}, ErrTunnelConflict
			}
			return Lease{}, fmt.Errorf("storage: create tunnel: %w", err)
		}
	} else {
		tunnelID = existing.ID
		existing.AccessJSON, err = access.CanonicalJSON(existing.AccessJSON)
		if err != nil {
			return Lease{}, err
		}
		existing.AllowCIDRsJSON, err = access.CanonicalCIDRsJSON(existing.AllowCIDRsJSON)
		if err != nil {
			return Lease{}, err
		}
		if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM connector_leases WHERE tunnel_id = $1 AND expires_at <= $2`), tunnelID, nowString(now)); err != nil {
			return Lease{}, fmt.Errorf("storage: remove expired leases: %w", err)
		}
		var active int
		if err := tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM connector_leases WHERE tunnel_id = $1 AND expires_at > $2`), tunnelID, nowString(now)).Scan(&active); err != nil {
			return Lease{}, fmt.Errorf("storage: count tunnel leases: %w", err)
		}
		if active > 0 {
			if existing.OwnerID != request.OwnerID {
				return Lease{}, ErrTunnelConflict
			}
			var sameInstanceLease string
			err := tx.QueryRowContext(ctx, s.bind(`SELECT id FROM connector_leases WHERE tunnel_id = $1 AND instance_id = $2 AND expires_at > $3`), tunnelID, request.InstanceID, nowString(now)).Scan(&sameInstanceLease)
			sameInstance := err == nil
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return Lease{}, fmt.Errorf("storage: inspect connector lease: %w", err)
			}
			if sameInstance {
				reconnected = true
				if (request.MultiConnector || asBool(existing.MultiConnector)) && !leaseConfigMatches(existing, request) {
					return Lease{}, ErrConnectorConfigMismatch
				}
				if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM connector_leases WHERE id = $1`), sameInstanceLease); err != nil {
					return Lease{}, fmt.Errorf("storage: replace connector lease: %w", err)
				}
			} else if !(request.MultiConnector && asBool(existing.MultiConnector) && existing.OwnerID == request.OwnerID && leaseConfigMatches(existing, request)) {
				return Lease{}, ErrTunnelConflict
			}
		}
		if active == 0 {
			reconnected = true
		}
		if _, err := tx.ExecContext(ctx, s.bind(`UPDATE tunnels SET name = $1, owner_id = $2, status = 'active', edge_id = $3, instance_id = $4, session_id = $5, http2 = $6, multi_connector = $7, connector_token_digest = $8, allow_cidrs_json = $9, access_json = $10, policy_id = $11, policy_digest = $12, updated_at = $13, expires_at = $14 WHERE id = $15`), request.Name, request.OwnerID, request.EdgeID, request.InstanceID, request.SessionID, intBool(request.HTTP2), intBool(request.MultiConnector), request.ConnectorTokenDigest, request.AllowCIDRsJSON, request.AccessJSON, nullableString(policyID), request.PolicyDigest, nowString(now), nowString(request.ExpiresAt), tunnelID); err != nil {
			return Lease{}, fmt.Errorf("storage: update tunnel: %w", err)
		}
	}
	leaseID, err := randomID()
	if err != nil {
		return Lease{}, err
	}
	if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO connector_leases(id, tunnel_id, instance_id, session_id, edge_id, owner_id, acquired_at, renewed_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`), leaseID, tunnelID, request.InstanceID, request.SessionID, request.EdgeID, request.OwnerID, nowString(now), nowString(now), nowString(request.ExpiresAt)); err != nil {
		if isUniqueError(err) {
			return Lease{}, ErrTunnelConflict
		}
		return Lease{}, fmt.Errorf("storage: create connector lease: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Lease{}, fmt.Errorf("storage: commit lease: %w", err)
	}
	return Lease{ID: leaseID, TunnelID: tunnelID, Hostname: request.Hostname, Kind: request.Kind, RemotePort: request.RemotePort, InstanceID: request.InstanceID, SessionID: request.SessionID, EdgeID: request.EdgeID, OwnerID: request.OwnerID, AcquiredAt: now, RenewedAt: now, ExpiresAt: request.ExpiresAt, Reconnected: reconnected}, nil
}

func (s *Store) policyForLease(ctx context.Context, request LeaseRequest) (string, string, error) {
	if request.Policy == nil {
		return "", strings.TrimSpace(request.PolicyDigest), nil
	}
	if err := request.Policy.Validate(); err != nil {
		return "", "", fmt.Errorf("storage: validate traffic policy: %w", err)
	}
	var id string
	digest := request.Policy.Digest()
	err := s.db.QueryRowContext(ctx, `SELECT id FROM traffic_policies WHERE owner_id = $1 AND digest = $2`, request.OwnerID, digest).Scan(&id)
	if err == nil {
		return id, digest, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", "", fmt.Errorf("storage: inspect tunnel policy: %w", err)
	}
	encoded, err := json.Marshal(request.Policy)
	if err != nil {
		return "", "", fmt.Errorf("storage: encode tunnel policy: %w", err)
	}
	id, err = randomID()
	if err != nil {
		return "", "", err
	}
	now := nowString(time.Now())
	for _, name := range []string{request.Name, request.Name + "-" + id} {
		if _, err := s.exec(ctx, `INSERT INTO traffic_policies(id, name, owner_id, digest, policy_json, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $6) ON CONFLICT DO NOTHING`, id, name, request.OwnerID, digest, string(encoded), now); err != nil {
			return "", "", fmt.Errorf("storage: create tunnel policy: %w", err)
		}
		err := s.db.QueryRowContext(ctx, `SELECT id FROM traffic_policies WHERE owner_id = $1 AND digest = $2`, request.OwnerID, digest).Scan(&id)
		if err == nil {
			return id, digest, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return "", "", fmt.Errorf("storage: inspect tunnel policy: %w", err)
		}
	}
	return "", "", ErrPolicyConflict
}

func leaseConfigMatches(existing storedTunnel, request LeaseRequest) bool {
	return asBool(existing.HTTP2) == request.HTTP2 && asBool(existing.MultiConnector) == request.MultiConnector && existing.ConnectorTokenDigest == request.ConnectorTokenDigest && existing.AllowCIDRsJSON == request.AllowCIDRsJSON && existing.AccessJSON == request.AccessJSON && existing.PolicyDigest == request.PolicyDigest
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (s *Store) RenewSessionLeases(ctx context.Context, edgeID, sessionID string, now time.Time) (int64, error) {
	edgeID = strings.TrimSpace(edgeID)
	if edgeID == "" {
		edgeID = s.edgeID
	}
	now = now.UTC()
	expiresAt := now.Add(s.leaseTTL)
	result, err := s.exec(ctx, `UPDATE connector_leases SET renewed_at = $1, expires_at = $2 WHERE edge_id = $3 AND session_id = $4 AND expires_at > $1`, nowString(now), nowString(expiresAt), edgeID, sessionID)
	if err != nil {
		return 0, fmt.Errorf("storage: renew connector leases: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("storage: renew connector leases: %w", err)
	}
	if count > 0 {
		_, _ = s.exec(ctx, `UPDATE tunnels SET updated_at = $1, expires_at = $2, status = 'active' WHERE id IN (SELECT tunnel_id FROM connector_leases WHERE edge_id = $3 AND session_id = $4)`, nowString(now), nowString(expiresAt), edgeID, sessionID)
	}
	return count, nil
}

func (s *Store) ReleaseLease(ctx context.Context, leaseID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("storage: begin release: %w", err)
	}
	defer tx.Rollback()
	var tunnelID string
	err = tx.QueryRowContext(ctx, s.bind(`SELECT tunnel_id FROM connector_leases WHERE id = $1`), leaseID).Scan(&tunnelID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("storage: inspect lease: %w", err)
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM connector_leases WHERE id = $1`), leaseID); err != nil {
		return fmt.Errorf("storage: release connector lease: %w", err)
	}
	if err := markTunnelOffline(ctx, tx, s, tunnelID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("storage: commit release: %w", err)
	}
	return nil
}

func (s *Store) ReleaseSession(ctx context.Context, edgeID, sessionID string) error {
	edgeID = strings.TrimSpace(edgeID)
	if edgeID == "" {
		edgeID = s.edgeID
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("storage: begin session release: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, s.bind(`SELECT tunnel_id FROM connector_leases WHERE edge_id = $1 AND session_id = $2`), edgeID, sessionID)
	if err != nil {
		return fmt.Errorf("storage: inspect session leases: %w", err)
	}
	var tunnelIDs []string
	for rows.Next() {
		var tunnelID string
		if err := rows.Scan(&tunnelID); err != nil {
			rows.Close()
			return fmt.Errorf("storage: scan session lease: %w", err)
		}
		tunnelIDs = append(tunnelIDs, tunnelID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("storage: inspect session leases: %w", err)
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM connector_leases WHERE edge_id = $1 AND session_id = $2`), edgeID, sessionID); err != nil {
		return fmt.Errorf("storage: release session leases: %w", err)
	}
	for _, tunnelID := range tunnelIDs {
		if err := markTunnelOffline(ctx, tx, s, tunnelID); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("storage: commit session release: %w", err)
	}
	return nil
}

func markTunnelOffline(ctx context.Context, tx *sql.Tx, s *Store, tunnelID string) error {
	var active int
	if err := tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM connector_leases WHERE tunnel_id = $1 AND expires_at > $2`), tunnelID, nowString(time.Now())).Scan(&active); err != nil {
		return fmt.Errorf("storage: count remaining leases: %w", err)
	}
	if active == 0 {
		if _, err := tx.ExecContext(ctx, s.bind(`UPDATE tunnels SET status = 'offline', updated_at = $1 WHERE id = $2`), nowString(time.Now()), tunnelID); err != nil {
			return fmt.Errorf("storage: mark tunnel offline: %w", err)
		}
	}
	return nil
}

func (s *Store) ListTunnels(ctx context.Context) ([]Tunnel, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, hostname, kind, remote_port, owner_id, status, edge_id, instance_id, session_id, http2, multi_connector, policy_digest, created_at, updated_at, expires_at FROM tunnels ORDER BY hostname, remote_port, id`)
	if err != nil {
		return nil, fmt.Errorf("storage: list tunnels: %w", err)
	}
	var stored []struct {
		tunnel                    Tunnel
		http2Mode, multiConnector int
		createdAt, updatedAt      string
		expiresAt                 sql.NullString
	}
	for rows.Next() {
		var row struct {
			tunnel                    Tunnel
			http2Mode, multiConnector int
			createdAt, updatedAt      string
			expiresAt                 sql.NullString
		}
		if err := rows.Scan(&row.tunnel.ID, &row.tunnel.Name, &row.tunnel.Hostname, &row.tunnel.Kind, &row.tunnel.RemotePort, &row.tunnel.OwnerID, &row.tunnel.Status, &row.tunnel.EdgeID, &row.tunnel.InstanceID, &row.tunnel.SessionID, &row.http2Mode, &row.multiConnector, &row.tunnel.PolicyDigest, &row.createdAt, &row.updatedAt, &row.expiresAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("storage: scan tunnel: %w", err)
		}
		stored = append(stored, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("storage: list tunnels: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("storage: close tunnels: %w", err)
	}
	var out []Tunnel
	for _, row := range stored {
		tunnel := row.tunnel
		tunnel.HTTP2 = asBool(row.http2Mode)
		tunnel.MultiConnector = asBool(row.multiConnector)
		tunnel.CreatedAt, err = parseTime(row.createdAt)
		if err != nil {
			return nil, err
		}
		tunnel.UpdatedAt, err = parseTime(row.updatedAt)
		if err != nil {
			return nil, err
		}
		if row.expiresAt.Valid && row.expiresAt.String != "" {
			expires, parseErr := parseTime(row.expiresAt.String)
			if parseErr != nil {
				return nil, parseErr
			}
			tunnel.ExpiresAt = &expires
		}
		tunnel.Connectors, err = s.listTunnelLeases(ctx, tunnel.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, tunnel)
	}
	return out, nil
}

func (s *Store) listTunnelLeases(ctx context.Context, tunnelID string) ([]LeaseConnector, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id, instance_id, session_id, edge_id, owner_id, acquired_at, renewed_at, expires_at FROM connector_leases WHERE tunnel_id = $1 ORDER BY acquired_at, id`), tunnelID)
	if err != nil {
		return nil, fmt.Errorf("storage: list tunnel connectors: %w", err)
	}
	defer rows.Close()
	var out []LeaseConnector
	for rows.Next() {
		var connector LeaseConnector
		var acquiredAt, renewedAt, expiresAt string
		if err := rows.Scan(&connector.ID, &connector.InstanceID, &connector.SessionID, &connector.EdgeID, &connector.OwnerID, &acquiredAt, &renewedAt, &expiresAt); err != nil {
			return nil, fmt.Errorf("storage: scan tunnel connector: %w", err)
		}
		connector.AcquiredAt, err = parseTime(acquiredAt)
		if err != nil {
			return nil, err
		}
		connector.RenewedAt, err = parseTime(renewedAt)
		if err != nil {
			return nil, err
		}
		connector.ExpiresAt, err = parseTime(expiresAt)
		if err != nil {
			return nil, err
		}
		out = append(out, connector)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: list tunnel connectors: %w", err)
	}
	return out, nil
}

func (s *Store) RecordAudit(ctx context.Context, event AuditEvent) error {
	if strings.TrimSpace(event.EdgeID) == "" {
		event.EdgeID = s.edgeID
	}
	if event.Action == "" || event.ResourceType == "" {
		return ErrInvalid
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	if event.ID == "" {
		var err error
		event.ID, err = randomID()
		if err != nil {
			return err
		}
	}
	metadata := "{}"
	if len(event.Metadata) > 0 {
		encoded, err := json.Marshal(event.Metadata)
		if err != nil {
			return fmt.Errorf("storage: encode audit metadata: %w", err)
		}
		metadata = string(encoded)
	}
	_, err := s.exec(ctx, `INSERT INTO audit_events(id, edge_id, actor_id, action, resource_type, resource_id, metadata_json, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, event.ID, event.EdgeID, event.ActorID, event.Action, event.ResourceType, event.ResourceID, metadata, nowString(event.CreatedAt))
	if err != nil {
		return fmt.Errorf("storage: record audit event: %w", err)
	}
	if _, err := s.exec(ctx, `DELETE FROM audit_events WHERE id NOT IN (SELECT id FROM audit_events ORDER BY created_at DESC, id DESC LIMIT 10000)`); err != nil {
		return fmt.Errorf("storage: prune audit events: %w", err)
	}
	return nil
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id, edge_id, actor_id, action, resource_type, resource_id, metadata_json, created_at FROM audit_events ORDER BY created_at DESC, id DESC LIMIT $1`), limit)
	if err != nil {
		return nil, fmt.Errorf("storage: list audit events: %w", err)
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var event AuditEvent
		var metadata, createdAt string
		if err := rows.Scan(&event.ID, &event.EdgeID, &event.ActorID, &event.Action, &event.ResourceType, &event.ResourceID, &metadata, &createdAt); err != nil {
			return nil, fmt.Errorf("storage: scan audit event: %w", err)
		}
		if metadata != "" && metadata != "{}" {
			if err := json.Unmarshal([]byte(metadata), &event.Metadata); err != nil {
				return nil, fmt.Errorf("storage: decode audit metadata: %w", err)
			}
		}
		event.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: list audit events: %w", err)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) UpsertTrafficPolicy(ctx context.Context, name, ownerID string, value *policy.Policy) (string, string, error) {
	name = strings.TrimSpace(name)
	ownerID = strings.TrimSpace(ownerID)
	if name == "" || ownerID == "" || value == nil {
		return "", "", ErrInvalid
	}
	if err := value.Validate(); err != nil {
		return "", "", err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", "", fmt.Errorf("storage: encode traffic policy: %w", err)
	}
	digest := value.Digest()
	now := nowString(time.Now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", fmt.Errorf("storage: begin traffic policy: %w", err)
	}
	defer tx.Rollback()
	var digestID, nameID string
	err = tx.QueryRowContext(ctx, s.bind(`SELECT id FROM traffic_policies WHERE owner_id = $1 AND digest = $2`), ownerID, digest).Scan(&digestID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", "", fmt.Errorf("storage: inspect traffic policy: %w", err)
	}
	err = tx.QueryRowContext(ctx, s.bind(`SELECT id FROM traffic_policies WHERE owner_id = $1 AND name = $2`), ownerID, name).Scan(&nameID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", "", fmt.Errorf("storage: inspect traffic policy name: %w", err)
	}
	if digestID != "" && nameID != "" && digestID != nameID {
		return "", "", ErrPolicyConflict
	}
	id := nameID
	if id == "" {
		id = digestID
	}
	if id == "" {
		id, err = randomID()
		if err != nil {
			return "", "", err
		}
		if _, err = tx.ExecContext(ctx, s.bind(`INSERT INTO traffic_policies(id, name, owner_id, digest, policy_json, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`), id, name, ownerID, digest, string(encoded), now, now); err != nil {
			if isUniqueError(err) {
				return "", "", ErrPolicyConflict
			}
			return "", "", fmt.Errorf("storage: create traffic policy: %w", err)
		}
	} else if _, err = tx.ExecContext(ctx, s.bind(`UPDATE traffic_policies SET name = $1, digest = $2, policy_json = $3, updated_at = $4 WHERE id = $5`), name, digest, string(encoded), now, id); err != nil {
		return "", "", fmt.Errorf("storage: update traffic policy: %w", err)
	}
	if err := tx.Commit(); err != nil {
		if isUniqueError(err) {
			return "", "", ErrPolicyConflict
		}
		return "", "", fmt.Errorf("storage: commit traffic policy: %w", err)
	}
	return id, digest, nil
}

func (s *Store) ListTrafficPolicies(ctx context.Context, ownerID string) ([]TrafficPolicy, error) {
	query := `SELECT id, name, owner_id, digest, policy_json, created_at, updated_at FROM traffic_policies`
	args := []any{}
	ownerID = strings.TrimSpace(ownerID)
	if ownerID != credentials.GlobalOwnerID {
		query += ` WHERE owner_id = $1`
		args = append(args, ownerID)
	}
	query += ` ORDER BY updated_at DESC, id`
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, fmt.Errorf("storage: list traffic policies: %w", err)
	}
	defer rows.Close()
	var out []TrafficPolicy
	for rows.Next() {
		var value TrafficPolicy
		var createdAt, updatedAt string
		if err := rows.Scan(&value.ID, &value.Name, &value.OwnerID, &value.Digest, &value.PolicyJSON, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("storage: scan traffic policy: %w", err)
		}
		value.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, err
		}
		value.UpdatedAt, err = parseTime(updatedAt)
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: list traffic policies: %w", err)
	}
	return out, nil
}

func (s *Store) DeleteTrafficPolicy(ctx context.Context, id, ownerID string) error {
	ownerID = strings.TrimSpace(ownerID)
	query := `DELETE FROM traffic_policies WHERE id = $1 AND owner_id = $2 AND NOT EXISTS (SELECT 1 FROM tunnels WHERE policy_id = $1)`
	args := []any{id, ownerID}
	if ownerID == credentials.GlobalOwnerID {
		query = `DELETE FROM traffic_policies WHERE id = $1 AND NOT EXISTS (SELECT 1 FROM tunnels WHERE policy_id = $1)`
		args = []any{id}
	}
	result, err := s.exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("storage: delete traffic policy: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("storage: delete traffic policy: %w", err)
	}
	if count == 0 {
		var inUse int
		if err := s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM tunnels WHERE policy_id = $1`), id).Scan(&inUse); err == nil && inUse > 0 {
			return ErrTunnelConflict
		}
		return ErrNotFound
	}
	return nil
}

func (s *Store) CreateCustomDomain(ctx context.Context, spec CustomDomainSpec) (CustomDomain, error) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(spec.Domain), "."))
	if !validCustomDomain(domain) {
		return CustomDomain{}, ErrInvalid
	}
	ownerID := strings.TrimSpace(spec.OwnerID)
	if ownerID == "" {
		return CustomDomain{}, ErrInvalid
	}
	tunnelID := strings.TrimSpace(spec.TunnelID)
	if tunnelID != "" {
		var exists int
		ownerID = strings.TrimSpace(spec.OwnerID)
		query := `SELECT 1 FROM tunnels WHERE id = $1`
		args := []any{tunnelID}
		if ownerID != credentials.GlobalOwnerID {
			query += ` AND owner_id = $2`
			args = append(args, ownerID)
		}
		err := s.db.QueryRowContext(ctx, s.bind(query), args...).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return CustomDomain{}, ErrNotFound
		}
		if err != nil {
			return CustomDomain{}, fmt.Errorf("storage: inspect custom-domain tunnel: %w", err)
		}
	}
	status := strings.TrimSpace(spec.Status)
	if status == "" {
		status = "pending"
	}
	now := time.Now().UTC()
	id, err := randomID()
	if err != nil {
		return CustomDomain{}, err
	}
	_, err = s.exec(ctx, `INSERT INTO custom_domains(id, domain, tunnel_id, owner_id, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, domain, nullableString(tunnelID), ownerID, status, nowString(now), nowString(now))
	if err != nil {
		if isUniqueError(err) {
			return CustomDomain{}, ErrTunnelConflict
		}
		return CustomDomain{}, fmt.Errorf("storage: create custom domain: %w", err)
	}
	return CustomDomain{ID: id, Domain: domain, TunnelID: tunnelID, OwnerID: ownerID, Status: status, CreatedAt: now, UpdatedAt: now}, nil
}

func validCustomDomain(domain string) bool {
	if domain == "" || len(domain) > 253 || strings.Contains(domain, "..") || net.ParseIP(domain) != nil {
		return false
	}
	return domainRE.MatchString(domain)
}

func (s *Store) ListCustomDomains(ctx context.Context, ownerID string) ([]CustomDomain, error) {
	query := `SELECT id, domain, COALESCE(tunnel_id, ''), owner_id, status, created_at, updated_at FROM custom_domains`
	args := []any{}
	ownerID = strings.TrimSpace(ownerID)
	if ownerID != credentials.GlobalOwnerID {
		query += ` WHERE owner_id = $1`
		args = append(args, ownerID)
	}
	query += ` ORDER BY domain, id`
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, fmt.Errorf("storage: list custom domains: %w", err)
	}
	defer rows.Close()
	var out []CustomDomain
	for rows.Next() {
		var value CustomDomain
		var createdAt, updatedAt string
		if err := rows.Scan(&value.ID, &value.Domain, &value.TunnelID, &value.OwnerID, &value.Status, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("storage: scan custom domain: %w", err)
		}
		value.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, err
		}
		value.UpdatedAt, err = parseTime(updatedAt)
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: list custom domains: %w", err)
	}
	return out, nil
}

func (s *Store) DeleteCustomDomain(ctx context.Context, id, ownerID string) error {
	ownerID = strings.TrimSpace(ownerID)
	query := `DELETE FROM custom_domains WHERE id = $1 AND owner_id = $2`
	args := []any{id, ownerID}
	if ownerID == credentials.GlobalOwnerID {
		query = `DELETE FROM custom_domains WHERE id = $1`
		args = []any{id}
	}
	result, err := s.exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("storage: delete custom domain: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("storage: delete custom domain: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}
