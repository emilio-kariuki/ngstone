package edge

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"ngstone/internal/policy"
	"ngstone/internal/proto"
)

const dialBudget = 5 * time.Second

var ErrSubdomainTaken = errors.New("edge: subdomain_taken")
var ErrConnectorConfigMismatch = errors.New("edge: connector_config_mismatch")
var ErrConnectorTokenRequired = errors.New("edge: connector_token_required")

type dialError struct{ err error }

func (e *dialError) Error() string { return fmt.Sprintf("edge: dial to agent failed: %v", e.err) }
func (e *dialError) Unwrap() error { return e.err }

type Binding struct {
	Hostname    string
	durableID   string
	Sess        *AgentSession
	InstanceID  string
	BoundAt     time.Time
	transport   *http.Transport
	proxy       *httputil.ReverseProxy
	h2Transport *http2.Transport
	h2Proxy     *httputil.ReverseProxy
	access      atomic.Pointer[accessControl]
	snapshot    atomic.Pointer[bindingSnapshot]

	mu         sync.Mutex
	connectors map[*AgentSession]*bindingConnector
	order      []*bindingConnector
	next       uint64
}

type bindingSnapshot struct {
	access               *accessControl
	trafficPolicy        *policy.Policy
	http2                bool
	multiConnector       bool
	connectorTokenDigest string
	proxy                *httputil.ReverseProxy
}

type bindingConnector struct {
	sess        *AgentSession
	instanceID  string
	boundAt     time.Time
	http2       bool
	transport   *http.Transport
	proxy       *httputil.ReverseProxy
	h2Transport *http2.Transport
	h2Proxy     *httputil.ReverseProxy
}

func newBindingConnector(host string, s *AgentSession, limits LimitsConfig, http2Mode bool) *bindingConnector {
	c := &bindingConnector{sess: s, instanceID: s.InstanceID, boundAt: time.Now(), http2: http2Mode}
	if http2Mode {
		c.h2Transport = newBindingHTTP2Transport(host, s, limits)
		c.h2Proxy = newBindingHTTP2Proxy(c.h2Transport)
	} else {
		c.transport = newBindingTransport(host, s, limits)
		c.proxy = newBindingProxy(c.transport)
	}
	return c
}

func (c *bindingConnector) proxyFor(http2Mode bool) *httputil.ReverseProxy {
	if c == nil || c.http2 != http2Mode {
		return nil
	}
	if http2Mode {
		return c.h2Proxy
	}
	return c.proxy
}

func (c *bindingConnector) close() {
	if c == nil {
		return
	}
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	if c.h2Transport != nil {
		c.h2Transport.CloseIdleConnections()
	}
}

type Registry struct {
	mu        sync.RWMutex
	byHost    map[string]*Binding
	bySession map[*AgentSession]map[string]struct{}
	limits    LimitsConfig
}

type BindOptions struct {
	Host                 string
	Session              *AgentSession
	Takeover             bool
	Access               *accessControl
	TrafficPolicy        *policy.Policy
	HTTP2                bool
	MultiConnector       bool
	ConnectorTokenDigest string
}

type registryConnectorInfo struct {
	SessionID      string    `json:"session_id"`
	InstanceID     string    `json:"instance_id"`
	Remote         string    `json:"remote,omitempty"`
	BoundAt        time.Time `json:"bound_at"`
	Alive          bool      `json:"alive"`
	Healthy        bool      `json:"healthy"`
	ActiveStreams  int64     `json:"active_streams"`
	StreamCapacity int64     `json:"stream_capacity"`
}

type registryBindingInfo struct {
	Hostname         string                  `json:"hostname"`
	BoundAt          time.Time               `json:"bound_at"`
	HTTP2            bool                    `json:"http2"`
	MultiConnector   bool                    `json:"multi_connector"`
	AccessRestricted bool                    `json:"access_restricted"`
	PolicyEnabled    bool                    `json:"policy_enabled"`
	Connectors       []registryConnectorInfo `json:"connectors"`
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

func (r *Registry) dashboardSnapshot() []registryBindingInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	bindings := make([]registryBindingInfo, 0, len(r.byHost))
	for _, b := range r.byHost {
		binding := registryBindingInfo{Hostname: b.Hostname}
		snapshot := b.snapshot.Load()
		if snapshot != nil {
			binding.HTTP2 = snapshot.http2
			binding.MultiConnector = snapshot.multiConnector
			binding.PolicyEnabled = snapshot.trafficPolicy != nil
		}
		access := b.access.Load()
		binding.AccessRestricted = access != nil && (len(access.basicDigests) > 0 || len(access.allow) > 0)

		b.mu.Lock()
		binding.BoundAt = b.BoundAt
		binding.Connectors = make([]registryConnectorInfo, 0, len(b.order))
		for _, connector := range b.order {
			if connector == nil || connector.sess == nil {
				continue
			}
			active, capacity := semaphoreStats(connector.sess.streamSem)
			remote := ""
			if connector.sess.Remote.IsValid() {
				remote = connector.sess.Remote.String()
			}
			binding.Connectors = append(binding.Connectors, registryConnectorInfo{
				SessionID:      connector.sess.ID,
				InstanceID:     connector.instanceID,
				Remote:         remote,
				BoundAt:        connector.boundAt,
				Alive:          !isSessionDead(connector.sess),
				Healthy:        connector.sess.healthy(time.Now()),
				ActiveStreams:  active,
				StreamCapacity: capacity,
			})
		}
		b.mu.Unlock()
		bindings = append(bindings, binding)
	}

	sort.Slice(bindings, func(i, j int) bool { return bindings[i].Hostname < bindings[j].Hostname })
	return bindings
}

func (r *Registry) sessionsForHost(host string) []*AgentSession {
	host = normalizeHost(host)
	r.mu.RLock()
	binding, ok := r.byHost[host]
	if !ok {
		r.mu.RUnlock()
		return nil
	}
	binding.mu.Lock()
	sessions := make([]*AgentSession, 0, len(binding.order))
	for _, connector := range binding.order {
		if connector != nil && connector.sess != nil {
			sessions = append(sessions, connector.sess)
		}
	}
	binding.mu.Unlock()
	r.mu.RUnlock()
	return sessions
}

func (r *Registry) observabilityTargetsForSession(as *AgentSession) []observabilityTarget {
	if r == nil || as == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := make(map[string]struct{})
	var targets []observabilityTarget
	for host := range r.bySession[as] {
		binding := r.byHost[host]
		if binding == nil {
			continue
		}
		target := observabilityTarget{TunnelID: binding.durableTunnelID(), Hostname: binding.Hostname}
		key := metricKey(target.TunnelID, target.Hostname)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
	}
	return targets
}

func (r *Registry) sessionsForCredential(id string) []*AgentSession {
	if r == nil || strings.TrimSpace(id) == "" {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*AgentSession
	for session := range r.bySession {
		if session != nil && session.Credential != nil && session.Credential.ID == id {
			out = append(out, session)
		}
	}
	return out
}

func (r *Registry) Route(host string) (*Binding, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.byHost[normalizeHost(host)]
	return b, ok
}

func (r *Registry) Bind(host string, s *AgentSession, takeover bool, ac *accessControl) (*Binding, *AgentSession, error) {
	return r.BindWithOptions(BindOptions{Host: host, Session: s, Takeover: takeover, Access: ac})
}

func (r *Registry) BindWithOptions(opts BindOptions) (*Binding, *AgentSession, error) {
	if opts.Session == nil {
		return nil, nil, errors.New("edge: bind session is required")
	}
	if opts.MultiConnector && opts.ConnectorTokenDigest == "" {
		return nil, nil, ErrConnectorTokenRequired
	}
	if !opts.MultiConnector && opts.ConnectorTokenDigest != "" {
		return nil, nil, ErrConnectorConfigMismatch
	}
	opts.Host = normalizeHost(opts.Host)

	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.byHost[opts.Host]; ok {
		return r.bindExistingLocked(existing, opts)
	}

	b := newBinding(opts, r.limits)
	r.byHost[opts.Host] = b
	r.addSessionHostLocked(opts.Session, opts.Host)
	return b, nil, nil
}

func (r *Registry) Unbind(host string, s *AgentSession) bool {
	host = normalizeHost(host)

	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.byHost[host]
	if !ok {
		return false
	}
	connector := b.detachConnector(s)
	if connector == nil {
		if b.Sess != s {
			return false
		}
		delete(r.byHost, host)
		r.removeSessionHostLocked(s, host)
		closeBindingResources(b)
		return true
	}
	connector.close()
	r.removeSessionHostLocked(s, host)
	if b.connectorCount() == 0 {
		delete(r.byHost, host)
		closeBindingResources(b)
	}
	return true
}

func (r *Registry) ReleaseSession(s *AgentSession) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for h := range r.bySession[s] {
		if b, ok := r.byHost[h]; ok {
			connector := b.detachConnector(s)
			if connector != nil {
				connector.close()
				if b.connectorCount() == 0 {
					delete(r.byHost, h)
					closeBindingResources(b)
				}
			} else if b.Sess == s {
				delete(r.byHost, h)
				closeBindingResources(b)
			}
		}
	}
	delete(r.bySession, s)
}

func newBinding(opts BindOptions, limits LimitsConfig) *Binding {
	connector := newBindingConnector(opts.Host, opts.Session, limits, opts.HTTP2)
	b := &Binding{
		Hostname:   opts.Host,
		Sess:       opts.Session,
		InstanceID: opts.Session.InstanceID,
		BoundAt:    connector.boundAt,
		connectors: map[*AgentSession]*bindingConnector{opts.Session: connector},
		order:      []*bindingConnector{connector},
	}
	b.transport = connector.transport
	b.proxy = connector.proxy
	b.h2Transport = connector.h2Transport
	b.h2Proxy = connector.h2Proxy
	b.access.Store(opts.Access)
	b.snapshot.Store(&bindingSnapshot{
		access:               opts.Access,
		trafficPolicy:        opts.TrafficPolicy,
		http2:                opts.HTTP2,
		multiConnector:       opts.MultiConnector,
		connectorTokenDigest: opts.ConnectorTokenDigest,
		proxy:                connector.proxyFor(opts.HTTP2),
	})
	return b
}

func (r *Registry) bindExistingLocked(existing *Binding, opts BindOptions) (*Binding, *AgentSession, error) {
	if !sameSessionOwner(existing.Sess, opts.Session) {
		return nil, nil, ErrSubdomainTaken
	}
	if existing.connectorForSession(opts.Session) != nil {
		if existing.multiConnectorMode() && !bindingConfigMatches(existing.snapshot.Load(), opts.Access, opts.TrafficPolicy, opts.HTTP2, opts.MultiConnector, opts.ConnectorTokenDigest) {
			return nil, nil, ErrConnectorConfigMismatch
		}
		old := existing.replaceConnector(opts.Host, opts.Session, r.limits, opts.HTTP2)
		if old != nil {
			old.close()
		}
		existing.BoundAt = time.Now()
		existing.access.Store(opts.Access)
		existing.snapshot.Store(&bindingSnapshot{
			access:               opts.Access,
			trafficPolicy:        opts.TrafficPolicy,
			http2:                opts.HTTP2,
			multiConnector:       opts.MultiConnector,
			connectorTokenDigest: opts.ConnectorTokenDigest,
			proxy:                existing.primaryProxy(opts.HTTP2),
		})
		return existing, nil, nil
	}

	if existing.multiConnectorMode() {
		if !opts.MultiConnector || !bindingConfigMatches(existing.snapshot.Load(), opts.Access, opts.TrafficPolicy, opts.HTTP2, opts.MultiConnector, opts.ConnectorTokenDigest) {
			return nil, nil, ErrConnectorConfigMismatch
		}
		if old := existing.connectorForInstance(opts.Session.InstanceID); old != nil {
			oldSession := old.sess
			r.removeSessionHostLocked(oldSession, opts.Host)
			existing.removeConnector(oldSession)
			old.close()
			existing.addConnector(opts.Host, opts.Session, r.limits, opts.HTTP2)
			r.addSessionHostLocked(opts.Session, opts.Host)
			existing.snapshot.Store(&bindingSnapshot{
				access:               opts.Access,
				trafficPolicy:        opts.TrafficPolicy,
				http2:                opts.HTTP2,
				multiConnector:       opts.MultiConnector,
				connectorTokenDigest: opts.ConnectorTokenDigest,
				proxy:                existing.primaryProxy(opts.HTTP2),
			})
			return existing, oldSession, nil
		}
		existing.addConnector(opts.Host, opts.Session, r.limits, opts.HTTP2)
		r.addSessionHostLocked(opts.Session, opts.Host)
		return existing, nil, nil
	}

	if opts.MultiConnector {
		return nil, nil, ErrConnectorConfigMismatch
	}

	if existing.InstanceID == opts.Session.InstanceID {
		evicted := existing.Sess
		r.removeBindingLocked(opts.Host, existing)
		b := newBinding(opts, r.limits)
		r.byHost[opts.Host] = b
		r.addSessionHostLocked(opts.Session, opts.Host)
		return b, evicted, nil
	}
	if !opts.Takeover || !isSessionDead(existing.Sess) {
		return nil, nil, ErrSubdomainTaken
	}
	evicted := existing.Sess
	r.removeBindingLocked(opts.Host, existing)
	b := newBinding(opts, r.limits)
	r.byHost[opts.Host] = b
	r.addSessionHostLocked(opts.Session, opts.Host)
	return b, evicted, nil
}

func sameSessionOwner(a, b *AgentSession) bool {
	if a == nil || b == nil {
		return false
	}
	if a.Credential == nil || b.Credential == nil {
		return a.Credential == nil && b.Credential == nil
	}
	return durableOwnerID(a) == durableOwnerID(b)
}

func bindingConfigMatches(snapshot *bindingSnapshot, ac *accessControl, trafficPolicy *policy.Policy, http2Mode, multiConnector bool, connectorTokenDigest string) bool {
	if snapshot == nil || snapshot.http2 != http2Mode || snapshot.multiConnector != multiConnector || !connectorTokenDigestEqual(snapshot.connectorTokenDigest, connectorTokenDigest) || !accessControlEqual(snapshot.access, ac) {
		return false
	}
	if snapshot.trafficPolicy == nil || trafficPolicy == nil {
		return snapshot.trafficPolicy == nil && trafficPolicy == nil
	}
	return snapshot.trafficPolicy.Digest() == trafficPolicy.Digest()
}

func connectorTokenDigestEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func accessControlEqual(a, b *accessControl) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.realm != b.realm || len(a.basicDigests) != len(b.basicDigests) || len(a.allow) != len(b.allow) {
		return false
	}
	for i := range a.basicDigests {
		if subtle.ConstantTimeCompare(a.basicDigests[i][:], b.basicDigests[i][:]) != 1 {
			return false
		}
	}
	for i := range a.allow {
		if a.allow[i] != b.allow[i] {
			return false
		}
	}
	return true
}

func (r *Registry) addSessionHostLocked(s *AgentSession, host string) {
	if r.bySession[s] == nil {
		r.bySession[s] = make(map[string]struct{})
	}
	r.bySession[s][host] = struct{}{}
}

func (r *Registry) removeSessionHostLocked(s *AgentSession, host string) {
	if hostSet, ok := r.bySession[s]; ok {
		delete(hostSet, host)
		if len(hostSet) == 0 {
			delete(r.bySession, s)
		}
	}
}

func (r *Registry) removeBindingLocked(host string, b *Binding) {
	delete(r.byHost, host)
	connectors := b.detachAllConnectors()
	for _, connector := range connectors {
		r.removeSessionHostLocked(connector.sess, host)
		connector.close()
	}
	closeBindingResources(b)
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
			return &inflightConn{Conn: conn, inflight: &s.inflight}, nil
		},
	}
}

func newBindingHTTP2Transport(host string, s *AgentSession, limits LimitsConfig) *http2.Transport {
	return &http2.Transport{
		AllowHTTP:                  true,
		StrictMaxConcurrentStreams: true,
		IdleConnTimeout:            limits.IdleTimeout,
		ReadIdleTimeout:            limits.IdleTimeout,
		PingTimeout:                15 * time.Second,
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			clientAddr, _ := ctx.Value(ctxKeyClientAddr).(string)
			reqID, _ := ctx.Value(ctxKeyReqID).(string)

			dialCtx, cancel := context.WithTimeout(ctx, dialBudget)
			defer cancel()

			s.inflight.Add(1)
			conn, err := s.Sess.OpenStream(dialCtx, proto.StreamOpen{
				Kind:       proto.KindHTTP2,
				Host:       host,
				ReqID:      reqID,
				ClientAddr: clientAddr,
			})
			if err != nil {
				s.inflight.Done()
				return nil, &dialError{err: err}
			}
			return &inflightConn{Conn: conn, inflight: &s.inflight}, nil
		},
	}
}

func (b *Binding) http2Mode() bool {
	snapshot := b.snapshot.Load()
	return snapshot != nil && snapshot.http2
}

func (b *Binding) multiConnectorMode() bool {
	snapshot := b.snapshot.Load()
	return snapshot != nil && snapshot.multiConnector
}

func (b *Binding) connectorForSession(s *AgentSession) *bindingConnector {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.connectors[s]
}

func (b *Binding) setDurableID(id string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.durableID = id
	b.mu.Unlock()
}

func (b *Binding) durableTunnelID() string {
	if b == nil {
		return ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.durableID
}

func (b *Binding) connectorForInstance(instanceID string) *bindingConnector {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, connector := range b.order {
		if connector.instanceID == instanceID {
			return connector
		}
	}
	return nil
}

func (b *Binding) addConnector(host string, s *AgentSession, limits LimitsConfig, http2Mode bool) *bindingConnector {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.connectors == nil {
		b.connectors = make(map[*AgentSession]*bindingConnector)
	}
	connector := newBindingConnector(host, s, limits, http2Mode)
	b.connectors[s] = connector
	b.order = append(b.order, connector)
	b.refreshPrimaryLocked()
	return connector
}

func (b *Binding) replaceConnector(host string, s *AgentSession, limits LimitsConfig, http2Mode bool) *bindingConnector {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.connectors == nil {
		b.connectors = make(map[*AgentSession]*bindingConnector)
	}
	old := b.connectors[s]
	connector := newBindingConnector(host, s, limits, http2Mode)
	b.connectors[s] = connector
	for i, current := range b.order {
		if current == old {
			b.order[i] = connector
			break
		}
	}
	b.refreshPrimaryLocked()
	return old
}

func (b *Binding) removeConnector(s *AgentSession) *bindingConnector {
	b.mu.Lock()
	defer b.mu.Unlock()
	connector := b.connectors[s]
	if connector == nil {
		return nil
	}
	delete(b.connectors, s)
	for i, current := range b.order {
		if current == connector {
			b.order = append(b.order[:i], b.order[i+1:]...)
			break
		}
	}
	b.refreshPrimaryLocked()
	return connector
}

func (b *Binding) detachConnector(s *AgentSession) *bindingConnector {
	return b.removeConnector(s)
}

func (b *Binding) detachAllConnectors() []*bindingConnector {
	b.mu.Lock()
	defer b.mu.Unlock()
	connectors := append([]*bindingConnector(nil), b.order...)
	b.connectors = nil
	b.order = nil
	b.refreshPrimaryLocked()
	return connectors
}

func (b *Binding) connectorCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.order)
}

func (b *Binding) primaryProxy(http2Mode bool) *httputil.ReverseProxy {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.order) == 0 {
		return nil
	}
	return b.order[0].proxyFor(http2Mode)
}

func (b *Binding) refreshPrimaryLocked() {
	if len(b.order) == 0 {
		b.Sess = nil
		b.InstanceID = ""
		b.transport = nil
		b.proxy = nil
		b.h2Transport = nil
		b.h2Proxy = nil
		return
	}
	connector := b.order[0]
	b.Sess = connector.sess
	b.InstanceID = connector.instanceID
	b.BoundAt = connector.boundAt
	b.transport = connector.transport
	b.proxy = connector.proxy
	b.h2Transport = connector.h2Transport
	b.h2Proxy = connector.h2Proxy
}

func (b *Binding) selectConnector(http2Mode bool) (*bindingConnector, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.order) == 0 {
		return nil, false
	}
	start := b.next % uint64(len(b.order))
	b.next++
	for i := 0; i < len(b.order); i++ {
		connector := b.order[(int(start)+i)%len(b.order)]
		if connector == nil || connector.http2 != http2Mode || !connector.sess.healthy(time.Now()) {
			continue
		}
		if !connector.sess.tryAcquireStream() {
			continue
		}
		return connector, true
	}
	return nil, false
}

func closeBindingResources(b *Binding) {
	if b.transport != nil {
		b.transport.CloseIdleConnections()
	}
	if b.h2Transport != nil {
		b.h2Transport.CloseIdleConnections()
	}
}

type inflightConn struct {
	net.Conn
	inflight *inflightTracker
	once     sync.Once
}

func (c *inflightConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.inflight.Done)
	return err
}
