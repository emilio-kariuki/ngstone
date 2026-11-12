package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/time/rate"
)

const (
	acmeTLS1             = "acme-tls/1"
	autoCertNameInterval = 15 * time.Minute
	autoCertBurst        = 20
	autoCertEvery        = 2 * time.Minute
)

var (
	errAutoCertNotAllowed = errors.New("edge: tls: no certificate for this name")
	errAutoCertThrottled  = errors.New("edge: tls: certificate issuance throttled")
)

func (m *TLSManager) publicCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := normalizeHost(hello.ServerName)
	challenge := len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acmeTLS1
	if name == "" || hostMatchesDomain(name, m.edgeDomain) {
		if challenge {
			return nil, errAutoCertNotAllowed
		}
		return m.magic.GetCertificate(hello)
	}
	if !m.allowed(name) {
		if !challenge && m.operatorCovers(name) {
			return m.magic.GetCertificate(hello)
		}
		return nil, errAutoCertNotAllowed
	}
	if !challenge && m.issuance.failedRecently(name) {
		if len(m.cache.AllMatchingCertificates(name)) == 0 {
			return nil, errAutoCertThrottled
		}
		return m.magic.GetCertificate(hello)
	}
	return m.auto.GetCertificate(hello)
}

func (m *TLSManager) operatorCovers(name string) bool {
	return slices.ContainsFunc(m.cache.AllMatchingCertificates(name), func(c certmagic.Certificate) bool {
		return c.HasTag(customCertTag)
	})
}

type issuanceRecord struct{ attempt, failure time.Time }

type issuanceLimiter struct {
	mu     sync.Mutex
	recent *lru.Cache[string, issuanceRecord]
	global *rate.Limiter
	now    func() time.Time
}

func newIssuanceLimiter(now func() time.Time) *issuanceLimiter {
	recent, err := lru.New[string, issuanceRecord](maxActiveCustomDomains)
	if err != nil {
		panic(err)
	}
	return &issuanceLimiter{
		recent: recent,
		global: rate.NewLimiter(rate.Every(autoCertEvery), autoCertBurst),
		now:    now,
	}
}

func (l *issuanceLimiter) onEvent(_ context.Context, event string, data map[string]any) error {
	name, _ := data["identifier"].(string)
	if name == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	rec, _ := l.recent.Get(name)
	switch event {
	case "cert_failed":
		rec.failure = now
		l.recent.Add(name, rec)
		return nil
	case "cert_obtaining":
		renewal, _ := data["renewal"].(bool)
		if !rec.attempt.IsZero() && now.Sub(rec.attempt) < autoCertNameInterval {
			rec.failure = now
			l.recent.Add(name, rec)
			return certmagic.ErrNoRetry{Err: errAutoCertThrottled}
		}
		rec.attempt = now
		if !renewal && !l.global.AllowN(now, 1) {
			rec.failure = now
			l.recent.Add(name, rec)
			return certmagic.ErrNoRetry{Err: errAutoCertThrottled}
		}
		l.recent.Add(name, rec)
		return nil
	default:
		return nil
	}
}

func (l *issuanceLimiter) failedRecently(name string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.recent.Peek(name)
	return ok && !rec.failure.IsZero() && l.now().Sub(rec.failure) < autoCertNameInterval
}
