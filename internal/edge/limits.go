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

	DefaultUpgradeInFlight           = 256
	DefaultPerSessionUpgradeInFlight = 32

	DefaultHandshakeConcurrency = 16
	DefaultUnauthSessions       = 32

	// DefaultPerIPInFlight caps how many HTTP requests and TCP tunnel
	// connections one client address can have in flight at once, so a
	// single client cannot take every per-session or global slot.
	DefaultPerIPInFlight = 32
	// DefaultClientIdleTimeout bounds how long one read of a request body,
	// or one write of a response, may wait on the public client.
	DefaultClientIdleTimeout = 60 * time.Second
	// DefaultTCPIdleTimeout closes a TCP tunnel connection that has carried
	// no bytes in either direction for this long.
	DefaultTCPIdleTimeout = 30 * time.Minute

	DefaultWebhookMaxBodyBytes = 1 << 20
	DefaultWebhookBufferBytes  = 64 << 20
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

	UpgradeInFlight           int64
	PerSessionUpgradeInFlight int64

	HandshakeConcurrency int
	UnauthSessions       int

	PerIPInFlight     int
	ClientIdleTimeout time.Duration
	TCPIdleTimeout    time.Duration

	WebhookMaxBodyBytes int64
	WebhookBufferBytes  int64
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
	if l.UpgradeInFlight < 0 {
		return l, fmt.Errorf("edge: upgrade-inflight must not be negative, got %d", l.UpgradeInFlight)
	}
	if l.UpgradeInFlight == 0 {
		l.UpgradeInFlight = DefaultUpgradeInFlight
	}
	if l.PerSessionUpgradeInFlight < 0 {
		return l, fmt.Errorf("edge: per-session-upgrade-inflight must not be negative, got %d", l.PerSessionUpgradeInFlight)
	}
	if l.PerSessionUpgradeInFlight == 0 {
		l.PerSessionUpgradeInFlight = DefaultPerSessionUpgradeInFlight
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
	if l.PerIPInFlight < 0 {
		return l, fmt.Errorf("edge: per-ip-inflight must not be negative, got %d", l.PerIPInFlight)
	}
	if l.PerIPInFlight == 0 {
		l.PerIPInFlight = DefaultPerIPInFlight
	}
	if l.ClientIdleTimeout < 0 {
		return l, fmt.Errorf("edge: client-idle-timeout must not be negative, got %s", l.ClientIdleTimeout)
	}
	if l.ClientIdleTimeout == 0 {
		l.ClientIdleTimeout = DefaultClientIdleTimeout
	}
	if l.TCPIdleTimeout < 0 {
		return l, fmt.Errorf("edge: tcp-idle-timeout must not be negative, got %s", l.TCPIdleTimeout)
	}
	if l.TCPIdleTimeout == 0 {
		l.TCPIdleTimeout = DefaultTCPIdleTimeout
	}
	if l.WebhookMaxBodyBytes < 0 {
		return l, fmt.Errorf("edge: webhook-max-body-bytes must not be negative, got %d", l.WebhookMaxBodyBytes)
	}
	if l.WebhookMaxBodyBytes == 0 {
		l.WebhookMaxBodyBytes = DefaultWebhookMaxBodyBytes
	}
	if l.WebhookBufferBytes < 0 {
		return l, fmt.Errorf("edge: webhook-buffer-bytes must not be negative, got %d", l.WebhookBufferBytes)
	}
	if l.WebhookBufferBytes == 0 {
		l.WebhookBufferBytes = DefaultWebhookBufferBytes
	}
	if l.WebhookMaxBodyBytes > l.WebhookBufferBytes {
		return l, fmt.Errorf("edge: webhook-max-body-bytes (%d) must not exceed webhook-buffer-bytes (%d)", l.WebhookMaxBodyBytes, l.WebhookBufferBytes)
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

// perIPInflight caps concurrent HTTP requests and TCP tunnel connections
// per client address. Addresses are keyed like the rate limiter (IPv6 by
// /48), and an entry exists only while that client has something in
// flight, so the map is bounded by the edge's own concurrency.
type perIPInflight struct {
	max int

	mu     sync.Mutex
	counts map[string]int
}

func newPerIPInflight(max int) *perIPInflight {
	return &perIPInflight{max: max, counts: make(map[string]int)}
}

// acquire takes a slot for ip. When ok is true the caller must call
// release exactly once; release is safe to call more than once.
func (p *perIPInflight) acquire(ip string) (release func(), ok bool) {
	if p == nil {
		return func() {}, true
	}
	key := rateLimitKey(ip)
	p.mu.Lock()
	if p.counts[key] >= p.max {
		p.mu.Unlock()
		return nil, false
	}
	p.counts[key]++
	p.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			if p.counts[key] <= 1 {
				delete(p.counts, key)
			} else {
				p.counts[key]--
			}
			p.mu.Unlock()
		})
	}, true
}

func (p *perIPInflight) inUse(ip string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.counts[rateLimitKey(ip)]
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

func semaphoreStats(s *globalSemaphore) (active, capacity int64) {
	if s == nil {
		return 0, 0
	}
	return int64(len(s.slots)), int64(cap(s.slots))
}

type byteBudget struct {
	max int64

	mu   sync.Mutex
	used int64
}

func newByteBudget(max int64) *byteBudget {
	return &byteBudget{max: max}
}

func (b *byteBudget) reserve(n int64) (release func(), ok bool) {
	if b == nil || n <= 0 {
		return func() {}, true
	}
	b.mu.Lock()
	if n > b.max-b.used {
		b.mu.Unlock()
		return nil, false
	}
	b.used += n
	b.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			b.used -= n
			b.mu.Unlock()
		})
	}, true
}

func (b *byteBudget) inUse() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

func writeTooManyRequests(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	w.WriteHeader(http.StatusTooManyRequests)
}
