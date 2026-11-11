package edge

import (
	"context"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sync/singleflight"

	"ngstone/internal/storage"
)

const (
	aliasHitCacheSize  = 4096
	aliasHitCacheTTL   = 30 * time.Second
	aliasMissCacheSize = 4096
	aliasMissCacheTTL  = 5 * time.Second
	maxAliasLookups    = 8
	aliasLimiterRate   = 2
	aliasLimiterBurst  = 10
	aliasLimiterSize   = 10000
)

type aliasTarget = storage.CustomDomainTarget

type aliasState int

const (
	aliasNone aliasState = iota
	aliasLocal
	aliasRemote
	aliasRefused
)

type customDomainStore interface {
	LookupCustomDomainTarget(ctx context.Context, domain string) (storage.CustomDomainTarget, bool, error)
}

type aliasLookupResult struct {
	target aliasTarget
	found  bool
}

type aliasResolver struct {
	store    customDomainStore
	reserved func(string) bool
	hits     *expirable.LRU[string, aliasTarget]
	misses   *expirable.LRU[string, struct{}]
	flights  singleflight.Group
	sem      *globalSemaphore
	limiter  *perIPLimiter
}

func newAliasResolver(store customDomainStore, reserved func(string) bool) *aliasResolver {
	return &aliasResolver{
		store:    store,
		reserved: reserved,
		hits:     expirable.NewLRU[string, aliasTarget](aliasHitCacheSize, nil, aliasHitCacheTTL),
		misses:   expirable.NewLRU[string, struct{}](aliasMissCacheSize, nil, aliasMissCacheTTL),
		sem:      newGlobalSemaphore(maxAliasLookups),
		limiter:  newPerIPLimiter(aliasLimiterRate, aliasLimiterBurst, aliasLimiterSize),
	}
}

func (a *aliasResolver) cached(name string) (aliasLookupResult, bool) {
	if target, ok := a.hits.Get(name); ok {
		return aliasLookupResult{target: target, found: true}, true
	}
	if _, miss := a.misses.Get(name); miss {
		return aliasLookupResult{}, true
	}
	return aliasLookupResult{}, false
}

func (a *aliasResolver) resolve(host, ip string) (aliasTarget, bool) {
	if a == nil {
		return aliasTarget{}, false
	}
	name, ok := storage.NormalizeCustomDomain(host)
	if !ok || a.reserved(name) {
		return aliasTarget{}, false
	}
	if result, ok := a.cached(name); ok {
		return result.target, result.found
	}
	if !a.limiter.allow(ip) {
		metricCustomDomainRateLimited.Add(1)
		return aliasTarget{}, false
	}
	value, _, _ := a.flights.Do(name, func() (any, error) {
		return a.lookup(name), nil
	})
	result := value.(aliasLookupResult)
	return result.target, result.found
}

func (a *aliasResolver) lookup(name string) aliasLookupResult {
	if result, ok := a.cached(name); ok {
		return result
	}
	if !a.sem.tryAcquire() {
		metricCustomDomainRejectedLookupCap.Add(1)
		return aliasLookupResult{}
	}
	defer a.sem.release()
	metricCustomDomainLookups.Add(1)
	ctx, cancel := context.WithTimeout(context.Background(), peerLookupTimeout)
	defer cancel()
	target, found, err := a.store.LookupCustomDomainTarget(ctx, name)
	if err != nil {
		metricCustomDomainLookupErrors.Add(1)
		slogStorageError("lookup custom domain", err)
		return aliasLookupResult{}
	}
	if !found {
		a.misses.Add(name, struct{}{})
		return aliasLookupResult{}
	}
	a.hits.Add(name, target)
	return aliasLookupResult{target: target, found: true}
}

func (a *aliasResolver) purge() {
	if a == nil {
		return
	}
	a.hits.Purge()
	a.misses.Purge()
}

func (b *Binding) ownerID() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Sess == nil {
		return ""
	}
	return durableOwnerID(b.Sess)
}

func (s *Server) localAlias(host, ip string) (aliasTarget, *Binding, aliasState) {
	if s.registry == nil {
		return aliasTarget{}, nil, aliasNone
	}
	target, ok := s.aliases.resolve(host, ip)
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
