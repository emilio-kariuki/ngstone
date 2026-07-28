package edge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ngstone/internal/proto"
)

const dialBudget = 5 * time.Second

var ErrSubdomainTaken = errors.New("edge: subdomain_taken")

type dialError struct{ err error }

func (e *dialError) Error() string { return fmt.Sprintf("edge: dial to agent failed: %v", e.err) }
func (e *dialError) Unwrap() error { return e.err }

type Binding struct {
	Hostname   string
	Sess       *AgentSession
	InstanceID string
	BoundAt    time.Time
	transport  *http.Transport
	proxy      *httputil.ReverseProxy
	access     atomic.Pointer[accessControl]
}

type Registry struct {
	mu        sync.RWMutex
	byHost    map[string]*Binding
	bySession map[*AgentSession]map[string]struct{}
	limits    LimitsConfig
}

func NewRegistry() *Registry {
	limits, _ := LimitsConfig{}.withDefaults()
	return &Registry{
		byHost:    make(map[string]*Binding),
		bySession: make(map[*AgentSession]map[string]struct{}),
		limits:    limits,
	}
}

func (r *Registry) SetLimits(limits LimitsConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	resolved, err := limits.withDefaults()
	if err != nil {
		return
	}
	r.limits = resolved
}

func (r *Registry) Route(host string) (*Binding, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.byHost[normalizeHost(host)]
	return b, ok
}

func (r *Registry) Bind(host string, s *AgentSession, takeover bool, ac *accessControl) (*Binding, *AgentSession, error) {
	host = normalizeHost(host)

	r.mu.Lock()
	defer r.mu.Unlock()

	var evicted *AgentSession
	if existing, ok := r.byHost[host]; ok {
		switch {
		case existing.Sess == s:
			existing.BoundAt = time.Now()
			existing.access.Store(ac)
			return existing, nil, nil
		case existing.InstanceID == s.InstanceID:
			evicted = existing.Sess
		case !takeover:
			return nil, nil, ErrSubdomainTaken
		case isSessionDead(existing.Sess):
			evicted = existing.Sess
		default:
			return nil, nil, ErrSubdomainTaken
		}

		if hostSet, ok := r.bySession[existing.Sess]; ok {
			delete(hostSet, host)
		}
		delete(r.byHost, host)
	}

	transport := newBindingTransport(host, s, r.limits)
	b := &Binding{
		Hostname:   host,
		Sess:       s,
		InstanceID: s.InstanceID,
		BoundAt:    time.Now(),
		transport:  transport,
		proxy:      newBindingProxy(transport),
	}
	b.access.Store(ac)
	r.byHost[host] = b
	if r.bySession[s] == nil {
		r.bySession[s] = make(map[string]struct{})
	}
	r.bySession[s][host] = struct{}{}

	return b, evicted, nil
}

func (r *Registry) Unbind(host string, s *AgentSession) bool {
	host = normalizeHost(host)

	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.byHost[host]
	if !ok || b.Sess != s {
		return false
	}
	delete(r.byHost, host)
	if hostSet, ok := r.bySession[s]; ok {
		delete(hostSet, host)
	}
	return true
}

func (r *Registry) ReleaseSession(s *AgentSession) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for h := range r.bySession[s] {
		if b, ok := r.byHost[h]; ok && b.Sess == s {
			delete(r.byHost, h)
		}
	}
	delete(r.bySession, s)
}

func normalizeHost(host string) string {
	return strings.ToLower(host)
}

func isSessionDead(s *AgentSession) bool {
	select {
	case <-s.Done():
		return true
	default:
		return false
	}
}

func newBindingTransport(host string, s *AgentSession, limits LimitsConfig) *http.Transport {
	return &http.Transport{
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: limits.ResponseHeaderTimeout,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			clientAddr, _ := ctx.Value(ctxKeyClientAddr).(string)
			reqID, _ := ctx.Value(ctxKeyReqID).(string)

			dialCtx, cancel := context.WithTimeout(ctx, dialBudget)
			defer cancel()

			s.inflight.Add(1)
			conn, err := s.Sess.OpenStream(dialCtx, proto.StreamOpen{
				Kind:       proto.KindHTTP,
				Host:       host,
				ReqID:      reqID,
				ClientAddr: clientAddr,
			})
			if err != nil {
				s.inflight.Done()
				return nil, &dialError{err: err}
			}
			return &inflightConn{Conn: conn, wg: &s.inflight}, nil
		},
	}
}

type inflightConn struct {
	net.Conn
	wg   *sync.WaitGroup
	once sync.Once
}

func (c *inflightConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.wg.Done)
	return err
}
