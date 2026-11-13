package edge

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"ngstone/internal/storage"
)

const (
	aliasPollInterval      = 5 * time.Second
	maxActiveCustomDomains = 10000
)

type aliasTarget struct {
	Hostname string
	Kind     string
	OwnerID  string
}

type aliasState int

const (
	aliasNone aliasState = iota
	aliasLocal
	aliasRemote
	aliasRefused
)

type customDomainStore interface {
	ActiveCustomDomains(ctx context.Context, limit int) ([]storage.ActiveCustomDomain, error)
}

type aliasResolver struct {
	store    customDomainStore
	reserved func(string) bool
	ttl      func() time.Duration
	limit    int
	snapshot atomic.Pointer[map[string]aliasTarget]
	fresh    atomic.Int64
	mu       sync.Mutex
	overCap  bool
}

func newAliasResolver(store customDomainStore, reserved func(string) bool, ttl func() time.Duration) *aliasResolver {
	return &aliasResolver{store: store, reserved: reserved, ttl: ttl, limit: maxActiveCustomDomains}
}

func (a *aliasResolver) resolve(host string) (aliasTarget, bool) {
	if a == nil {
		return aliasTarget{}, false
	}
	name, ok := storage.NormalizeCustomDomain(host)
	if !ok || a.reserved(name) {
		return aliasTarget{}, false
	}
	snapshot := a.snapshot.Load()
	if snapshot == nil {
		return aliasTarget{}, false
	}
	target, ok := (*snapshot)[name]
	return target, ok
}

func (a *aliasResolver) watch(ctx context.Context) error {
	ticker := time.NewTicker(aliasPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			a.load(ctx, time.Now())
		}
	}
}

func (a *aliasResolver) refresh(ctx context.Context) {
	if a == nil {
		return
	}
	a.load(ctx, time.Now())
}

func (a *aliasResolver) load(ctx context.Context, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	qctx, cancel := context.WithTimeout(ctx, peerLookupTimeout)
	rows, err := a.store.ActiveCustomDomains(qctx, a.limit+1)
	cancel()
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		metricCustomDomainLookupErrors.Add(1)
		slogStorageError("load custom domains", err)
		if last := a.fresh.Load(); last != 0 && now.Sub(time.Unix(0, last)) > a.ttl() {
			a.fresh.Store(0)
			a.replace(map[string]aliasTarget{})
		}
		return
	}
	over := len(rows) > a.limit
	if over {
		rows = rows[:a.limit]
	}
	if over != a.overCap {
		a.overCap = over
		if over {
			slog.Warn("edge: active custom domains exceed the routing cap; the most recently activated domains are not routed", "cap", a.limit)
		} else {
			slog.Info("edge: active custom domains are back within the routing cap", "cap", a.limit)
		}
	}
	snapshot := make(map[string]aliasTarget, len(rows))
	for _, row := range rows {
		snapshot[row.Domain] = aliasTarget{Hostname: row.Hostname, Kind: row.Kind, OwnerID: row.OwnerID}
	}
	a.fresh.Store(now.UnixNano())
	a.replace(snapshot)
}

func (a *aliasResolver) replace(snapshot map[string]aliasTarget) {
	a.snapshot.Store(&snapshot)
	metricCustomDomainsActive.Set(int64(len(snapshot)))
}

func (b *Binding) ownerID() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Sess == nil {
		return ""
	}
	return durableOwnerID(b.Sess)
}

func (s *Server) localAlias(host string) (aliasTarget, *Binding, aliasState) {
	if s.registry == nil {
		return aliasTarget{}, nil, aliasNone
	}
	target, ok := s.aliases.resolve(host)
	if !ok {
		return aliasTarget{}, nil, aliasNone
	}
	var b *Binding
	if target.Kind == "tls" {
		b, ok = s.registry.RouteTLS(target.Hostname)
	} else {
		b, ok = s.registry.Route(target.Hostname)
	}
	if !ok {
		return target, nil, aliasRemote
	}
	if b.ownerID() != target.OwnerID {
		metricCustomDomainOwnerMismatch.Add(1)
		return target, nil, aliasRefused
	}
	return target, b, aliasLocal
}

func (s *Server) autoCertAllowed(name string) bool {
	target, _, state := s.localAlias(name)
	if target.Kind == "tls" {
		return false
	}
	return state == aliasLocal || (state == aliasRemote && s.peers == nil)
}
