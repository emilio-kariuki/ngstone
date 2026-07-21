package edge

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/time/rate"
)

const (
	DefaultReadHeaderTimeout     = 10 * time.Second
	DefaultIdleTimeout           = 120 * time.Second
	DefaultMaxHeaderBytes        = 64 << 10
	DefaultMaxBodyBytes          = 256 << 20
	DefaultResponseHeaderTimeout = 30 * time.Second

	DefaultPerIPRate  = 20
	DefaultPerIPBurst = 50
	DefaultPerIPLRU   = 10000

	DefaultGlobalInFlight     = 64
	DefaultPerSessionInFlight = 48

	DefaultHandshakeConcurrency = 16
	DefaultUnauthSessions       = 32
)

type LimitsConfig struct {
	ReadHeaderTimeout     time.Duration
	IdleTimeout           time.Duration
	MaxHeaderBytes        int
	MaxBodyBytes          int64
	ResponseHeaderTimeout time.Duration

	PerIPRate  float64
	PerIPBurst int
	PerIPLRU   int

	GlobalInFlight     int64
	PerSessionInFlight int64

	HandshakeConcurrency int
	UnauthSessions       int
}

func (l LimitsConfig) withDefaults() (LimitsConfig, error) {
	if l.ReadHeaderTimeout < 0 {
		return l, fmt.Errorf("edge: read-header-timeout must not be negative, got %s", l.ReadHeaderTimeout)
	}
	if l.ReadHeaderTimeout == 0 {
		l.ReadHeaderTimeout = DefaultReadHeaderTimeout
	}
	if l.IdleTimeout < 0 {
		return l, fmt.Errorf("edge: idle-timeout must not be negative, got %s", l.IdleTimeout)
	}
	if l.IdleTimeout == 0 {
		l.IdleTimeout = DefaultIdleTimeout
	}
	if l.MaxHeaderBytes < 0 {
		return l, fmt.Errorf("edge: max-header-bytes must not be negative, got %d", l.MaxHeaderBytes)
	}
	if l.MaxHeaderBytes == 0 {
		l.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	if l.MaxBodyBytes < 0 {
		return l, fmt.Errorf("edge: max-body-bytes must not be negative, got %d", l.MaxBodyBytes)
	}
	if l.MaxBodyBytes == 0 {
		l.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if l.ResponseHeaderTimeout < 0 {
		return l, fmt.Errorf("edge: response-header-timeout must not be negative, got %s", l.ResponseHeaderTimeout)
	}
	if l.ResponseHeaderTimeout == 0 {
		l.ResponseHeaderTimeout = DefaultResponseHeaderTimeout
	}
	if l.PerIPRate < 0 {
		return l, fmt.Errorf("edge: per-ip-rate must not be negative, got %v", l.PerIPRate)
	}
	if l.PerIPRate == 0 {
		l.PerIPRate = DefaultPerIPRate
	}
	if l.PerIPBurst < 0 {
		return l, fmt.Errorf("edge: per-ip-burst must not be negative, got %d", l.PerIPBurst)
	}
	if l.PerIPBurst == 0 {
		l.PerIPBurst = DefaultPerIPBurst
	}
	if l.PerIPLRU < 0 {
		return l, fmt.Errorf("edge: per-ip-lru must not be negative, got %d", l.PerIPLRU)
	}
	if l.PerIPLRU == 0 {
		l.PerIPLRU = DefaultPerIPLRU
	}
	if l.GlobalInFlight < 0 {
		return l, fmt.Errorf("edge: global-inflight must not be negative, got %d", l.GlobalInFlight)
	}
	if l.GlobalInFlight == 0 {
		l.GlobalInFlight = DefaultGlobalInFlight
	}
	if l.PerSessionInFlight < 0 {
		return l, fmt.Errorf("edge: per-session-inflight must not be negative, got %d", l.PerSessionInFlight)
	}
	if l.PerSessionInFlight == 0 {
		l.PerSessionInFlight = DefaultPerSessionInFlight
	}
	if l.HandshakeConcurrency < 0 {
		return l, fmt.Errorf("edge: handshake-concurrency must not be negative, got %d", l.HandshakeConcurrency)
	}
	if l.HandshakeConcurrency == 0 {
		l.HandshakeConcurrency = DefaultHandshakeConcurrency
	}
	if l.UnauthSessions < 0 {
		return l, fmt.Errorf("edge: unauth-sessions must not be negative, got %d", l.UnauthSessions)
	}
	if l.UnauthSessions == 0 {
		l.UnauthSessions = DefaultUnauthSessions
	}
	return l, nil
}

type perIPLimiter struct {
	mu       sync.Mutex
	limiters *lru.Cache[string, *rate.Limiter]
	rate     rate.Limit
	burst    int
}

func newPerIPLimiter(ratePerSec float64, burst, size int) *perIPLimiter {
	c, err := lru.New[string, *rate.Limiter](size)
	if err != nil {
		panic(err)
	}
	return &perIPLimiter{limiters: c, rate: rate.Limit(ratePerSec), burst: burst}
}

func (p *perIPLimiter) allow(ip string) bool {
	if p == nil {
		return true
	}
	key := rateLimitKey(ip)
	p.mu.Lock()
	lim, ok := p.limiters.Get(key)
	if !ok {
		lim = rate.NewLimiter(p.rate, p.burst)
		p.limiters.Add(key, lim)
	}
	p.mu.Unlock()
	return lim.Allow()
}

type globalSemaphore struct {
	slots chan struct{}
}

func newGlobalSemaphore(n int64) *globalSemaphore {
	return &globalSemaphore{slots: make(chan struct{}, n)}
}

func (s *globalSemaphore) tryAcquire() bool {
	if s == nil {
		return true
	}
	select {
	case s.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *globalSemaphore) release() {
	if s == nil {
		return
	}
	select {
	case <-s.slots:
	default:
	}
}

func writeTooManyRequests(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	w.WriteHeader(http.StatusTooManyRequests)
}
