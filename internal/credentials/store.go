package credentials

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	FileVersion    = 1
	KindHTTP       = "http"
	KindTCP        = "tcp"
	MaxTTL         = 30 * 24 * time.Hour
	GlobalOwnerID  = "__ngstone_global_admin__"
	InvalidOwnerID = "__ngstone_invalid_owner__"
	tokenTag       = "nst"
	idBytes        = 16
	secretBytes    = 32
)

var (
	ErrInvalid  = errors.New("invalid credential")
	ErrExpired  = errors.New("credential expired")
	ErrRevoked  = errors.New("credential revoked")
	ErrNotFound = errors.New("credential not found")
	subdomainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	denylisted  = map[string]bool{"www": true, "mail": true, "ns1": true, "ns2": true, "admin": true, "dev": true, "api-edge": true}
)

type Spec struct {
	Kind       string
	Subdomain  string
	RemotePort int
	OwnerID    string
}

type Credential struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Subdomain  string     `json:"subdomain,omitempty"`
	RemotePort int        `json:"remote_port,omitempty"`
	OwnerID    string     `json:"owner_id,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

type Issued struct {
	Credential Credential
	Token      string
}

type storedCredential struct {
	Credential
	TokenHash string `json:"token_hash"`
}

type fileData struct {
	Version     int                `json:"version"`
	Credentials []storedCredential `json:"credentials"`
}

type Store struct {
	path string
	mu   sync.Mutex
}

func Open(path string) (*Store, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("credentials: file path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("credentials: creating %s: %w", filepath.Dir(path), err)
	}
	s := &Store{path: path}
	if err := s.initialize(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Path() string {
	return s.path
}

func (s *Store) Issue(spec Spec, ttl time.Duration) (Issued, error) {
	return s.IssueContext(context.Background(), spec, ttl)
}

func (s *Store) IssueContext(ctx context.Context, spec Spec, ttl time.Duration) (Issued, error) {
	if err := ctx.Err(); err != nil {
		return Issued{}, err
	}
	return s.IssueAt(spec, ttl, time.Now())
}

func (s *Store) IssueAt(spec Spec, ttl time.Duration, now time.Time) (Issued, error) {
	normalized, err := normalizeSpec(spec)
	if err != nil {
		return Issued{}, err
	}
	if ttl <= 0 || ttl > MaxTTL {
		return Issued{}, fmt.Errorf("credentials: ttl must be greater than zero and no longer than %s", MaxTTL)
	}
	now = now.UTC()
	if now.IsZero() {
		return Issued{}, errors.New("credentials: issue time is required")
	}

	var issued Issued
	err = s.withFileLock(func() error {
		data, err := s.read()
		if err != nil {
			return err
		}
		var id string
		for {
			id, err = randomHex(idBytes)
			if err != nil {
				return err
			}
			if !hasCredential(data.Credentials, id) {
				break
			}
		}
		token, err := NewToken(id)
		if err != nil {
			return err
		}
		credential := Credential{
			ID:         id,
			Kind:       normalized.Kind,
			Subdomain:  normalized.Subdomain,
			RemotePort: normalized.RemotePort,
			OwnerID:    normalized.OwnerID,
			CreatedAt:  now,
			ExpiresAt:  now.Add(ttl),
		}
		data.Credentials = append(data.Credentials, storedCredential{
			Credential: credential,
			TokenHash:  TokenHashHex(token),
		})
		if err := validateData(data); err != nil {
			return err
		}
		if err := s.write(data); err != nil {
			return err
		}
		issued = Issued{Credential: credential, Token: token}
		return nil
	})
	return issued, err
}

func (s *Store) Validate(token string, now time.Time) (Credential, error) {
	return s.ValidateContext(context.Background(), token, now)
}

func (s *Store) ValidateContext(ctx context.Context, token string, now time.Time) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	id, err := tokenID(token)
	if err != nil {
		return Credential{}, err
	}
	data, err := s.read()
	if err != nil {
		return Credential{}, err
	}
	sum := sha256.Sum256([]byte(token))
	for _, stored := range data.Credentials {
		if stored.ID != id {
			continue
		}
		storedHash, err := hex.DecodeString(stored.TokenHash)
		if err != nil || len(storedHash) != sha256.Size || subtle.ConstantTimeCompare(sum[:], storedHash) != 1 {
			return Credential{}, ErrInvalid
		}
		if stored.RevokedAt != nil {
			return Credential{}, ErrRevoked
		}
		if !now.Before(stored.ExpiresAt) {
			return Credential{}, ErrExpired
		}
		return stored.Credential, nil
	}
	return Credential{}, ErrInvalid
}

func (s *Store) Active(id string, now time.Time) (bool, error) {
	return s.ActiveContext(context.Background(), id, now)
}

func (s *Store) ActiveContext(ctx context.Context, id string, now time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !validID(id) {
		return false, ErrNotFound
	}
	data, err := s.read()
	if err != nil {
		return false, err
	}
	for _, stored := range data.Credentials {
		if stored.ID != id {
			continue
		}
		return stored.RevokedAt == nil && now.Before(stored.ExpiresAt), nil
	}
	return false, ErrNotFound
}

func (s *Store) Revoke(id string) error {
	return s.RevokeAt(id, time.Now())
}

func (s *Store) RevokeForOwner(id, ownerID string) error {
	return s.RevokeForOwnerContext(context.Background(), id, ownerID)
}

func (s *Store) RevokeForOwnerContext(ctx context.Context, id, ownerID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == GlobalOwnerID {
		return s.Revoke(id)
	}
	if !validID(id) {
		return ErrNotFound
	}
	now := time.Now().UTC()
	return s.withFileLock(func() error {
		data, err := s.read()
		if err != nil {
			return err
		}
		for i := range data.Credentials {
			if data.Credentials[i].ID != id || data.Credentials[i].OwnerID != ownerID {
				continue
			}
			if data.Credentials[i].RevokedAt == nil {
				data.Credentials[i].RevokedAt = &now
				if err := s.write(data); err != nil {
					return err
				}
			}
			return nil
		}
		return ErrNotFound
	})
}

func (s *Store) RevokeAt(id string, now time.Time) error {
	if !validID(id) {
		return ErrNotFound
	}
	now = now.UTC()
	return s.withFileLock(func() error {
		data, err := s.read()
		if err != nil {
			return err
		}
		for i := range data.Credentials {
			if data.Credentials[i].ID != id {
				continue
			}
			if data.Credentials[i].RevokedAt == nil {
				data.Credentials[i].RevokedAt = &now
				if err := s.write(data); err != nil {
					return err
				}
			}
			return nil
		}
		return ErrNotFound
	})
}

func (s *Store) List() ([]Credential, error) {
	data, err := s.read()
	if err != nil {
		return nil, err
	}
	out := make([]Credential, 0, len(data.Credentials))
	for _, stored := range data.Credentials {
		out = append(out, stored.Credential)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (s *Store) ListForOwner(ownerID string) ([]Credential, error) {
	return s.ListForOwnerContext(context.Background(), ownerID)
}

func (s *Store) ListForOwnerContext(ctx context.Context, ownerID string) ([]Credential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == GlobalOwnerID {
		return s.List()
	}
	data, err := s.read()
	if err != nil {
		return nil, err
	}
	out := make([]Credential, 0, len(data.Credentials))
	for _, stored := range data.Credentials {
		if stored.OwnerID == ownerID {
			out = append(out, stored.Credential)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func NormalizeSubdomain(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func ValidateSubdomain(name string) bool {
	return !denylisted[name] && subdomainRE.MatchString(name)
}

func NormalizeSpec(spec Spec) (Spec, error) {
	return normalizeSpec(spec)
}

func NewToken(id string) (string, error) {
	if !validID(id) {
		return "", ErrInvalid
	}
	secret, err := randomBytes(secretBytes)
	if err != nil {
		return "", err
	}
	return tokenTag + "_" + id + "_" + base64.RawURLEncoding.EncodeToString(secret), nil
}

func ParseTokenID(token string) (string, error) {
	return tokenID(token)
}

func TokenHashHex(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func normalizeSpec(spec Spec) (Spec, error) {
	spec.Kind = strings.ToLower(strings.TrimSpace(spec.Kind))
	spec.OwnerID = strings.TrimSpace(spec.OwnerID)
	if spec.Kind == "" {
		spec.Kind = KindHTTP
	}
	switch spec.Kind {
	case KindHTTP:
		spec.Subdomain = NormalizeSubdomain(spec.Subdomain)
		if !ValidateSubdomain(spec.Subdomain) {
			return Spec{}, errors.New("credentials: a valid HTTP subdomain is required")
		}
		if spec.RemotePort != 0 {
			return Spec{}, errors.New("credentials: remote port is only valid for TCP credentials")
		}
	case KindTCP:
		if spec.Subdomain != "" {
			return Spec{}, errors.New("credentials: subdomain is only valid for HTTP credentials")
		}
		if spec.RemotePort < 1 || spec.RemotePort > 65535 {
			return Spec{}, errors.New("credentials: TCP credentials require a remote port between 1 and 65535")
		}
	default:
		return Spec{}, fmt.Errorf("credentials: kind must be %q or %q", KindHTTP, KindTCP)
	}
	return spec, nil
}

func (s *Store) initialize() error {
	return s.withFileLock(func() error {
		if _, err := os.Lstat(s.path); err == nil {
			data, err := s.read()
			if err != nil {
				return err
			}
			migrated := false
			for i := range data.Credentials {
				if data.Credentials[i].OwnerID == "admin" {
					data.Credentials[i].OwnerID = GlobalOwnerID
					migrated = true
				}
			}
			if migrated {
				return s.write(data)
			}
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("credentials: inspecting %s: %w", s.path, err)
		}
		if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
			return fmt.Errorf("credentials: creating %s: %w", filepath.Dir(s.path), err)
		}
		return s.write(fileData{Version: FileVersion, Credentials: []storedCredential{}})
	})
}

func (s *Store) read() (fileData, error) {
	info, err := os.Lstat(s.path)
	if err != nil {
		return fileData{}, fmt.Errorf("credentials: reading %s: %w", s.path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fileData{}, fmt.Errorf("credentials: refusing symlink %s", s.path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fileData{}, fmt.Errorf("credentials: %s must not be group or world readable", s.path)
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return fileData{}, fmt.Errorf("credentials: reading %s: %w", s.path, err)
	}
	var data fileData
	if err := json.Unmarshal(raw, &data); err != nil {
		return fileData{}, fmt.Errorf("credentials: parsing %s: %w", s.path, err)
	}
	if err := validateData(data); err != nil {
		return fileData{}, fmt.Errorf("credentials: validating %s: %w", s.path, err)
	}
	return data, nil
}

func (s *Store) write(data fileData) error {
	if err := validateData(data); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("credentials: creating %s: %w", filepath.Dir(s.path), err)
	}
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("credentials: encoding: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".credentials-*.tmp")
	if err != nil {
		return fmt.Errorf("credentials: creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("credentials: securing temp file: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("credentials: writing temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("credentials: syncing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("credentials: closing temp file: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("credentials: replacing %s: %w", s.path, err)
	}
	renamed = true
	return nil
}

func (s *Store) withFileLock(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("credentials: opening lock: %w", err)
	}
	defer lock.Close()
	if err := lock.Chmod(0o600); err != nil {
		return fmt.Errorf("credentials: securing lock: %w", err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("credentials: locking file: %w", err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	return fn()
}

func validateData(data fileData) error {
	if data.Version != FileVersion {
		return fmt.Errorf("unsupported file version %d", data.Version)
	}
	seen := make(map[string]struct{}, len(data.Credentials))
	for _, stored := range data.Credentials {
		if !validID(stored.ID) {
			return errors.New("credential id is invalid")
		}
		if _, ok := seen[stored.ID]; ok {
			return errors.New("credential ids must be unique")
		}
		seen[stored.ID] = struct{}{}
		normalized, err := normalizeSpec(Spec{Kind: stored.Kind, Subdomain: stored.Subdomain, RemotePort: stored.RemotePort})
		if err != nil {
			return err
		}
		if stored.Kind != normalized.Kind || stored.Subdomain != normalized.Subdomain || stored.RemotePort != normalized.RemotePort {
			return errors.New("credential scope is not normalized")
		}
		if len(stored.TokenHash) != sha256.Size*2 {
			return errors.New("credential token hash is invalid")
		}
		if _, err := hex.DecodeString(stored.TokenHash); err != nil {
			return errors.New("credential token hash is invalid")
		}
		if stored.CreatedAt.IsZero() || stored.ExpiresAt.IsZero() || !stored.ExpiresAt.After(stored.CreatedAt) {
			return errors.New("credential timestamps are invalid")
		}
		if stored.ExpiresAt.Sub(stored.CreatedAt) > MaxTTL {
			return errors.New("credential ttl exceeds the maximum")
		}
		if stored.RevokedAt != nil && stored.RevokedAt.Before(stored.CreatedAt) {
			return errors.New("credential revocation time is invalid")
		}
	}
	return nil
}

func tokenID(token string) (string, error) {
	prefix := tokenTag + "_"
	if !strings.HasPrefix(token, prefix) {
		return "", ErrInvalid
	}
	rest := strings.TrimPrefix(token, prefix)
	if len(rest) <= idBytes*2 || rest[idBytes*2] != '_' || !validID(rest[:idBytes*2]) {
		return "", ErrInvalid
	}
	secret, err := base64.RawURLEncoding.DecodeString(rest[idBytes*2+1:])
	if err != nil || len(secret) != secretBytes {
		return "", ErrInvalid
	}
	return rest[:idBytes*2], nil
}

func validID(id string) bool {
	if len(id) != idBytes*2 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func randomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("credentials: generating secret: %w", err)
	}
	return b, nil
}

func randomHex(size int) (string, error) {
	b, err := randomBytes(size)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hasCredential(credentials []storedCredential, id string) bool {
	for _, stored := range credentials {
		if stored.ID == id {
			return true
		}
	}
	return false
}
