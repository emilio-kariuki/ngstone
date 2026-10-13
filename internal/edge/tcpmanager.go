package edge

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"ngstone/internal/proto"
)

const (
	maxGlobalTCPConns  = 256
	maxBindsPerSession = 8
)

var errPortUnavailable = errors.New("edge: port_unavailable")
var errTooManyBinds = errors.New("edge: too_many_binds")

var (
	metricTCPRejectedGlobalCap     = expvar.NewInt("ngstoned_tcp_rejected_global_cap_total")
	metricTCPRejectedBindCap       = expvar.NewInt("ngstoned_tcp_rejected_bind_cap_total")
	metricTCPRejectedRateLimited   = expvar.NewInt("ngstoned_tcp_rejected_rate_limited_total")
	metricTCPRejectedForbiddenCIDR = expvar.NewInt("ngstoned_tcp_rejected_forbidden_cidr_total")
)

type tcpConn struct {
	client net.Conn
	stream net.Conn
}

type tcpTunnel struct {
	port int
	ln   net.Listener

	// session, hostname and allow are guarded by tcpManager.mu: a takeover
	// hands the tunnel (listener and all) to a new session while its accept
	// loop keeps running, so the loop reads them per accepted connection.
	session  *AgentSession
	hostname string
	allow    []netip.Prefix

	acceptDone chan struct{}
	closed     chan struct{}
}

type tcpManager struct {
	lo, hi   int
	bindAddr string
	limiter  *perIPLimiter

	forceCloseGrace time.Duration
	globalSem       *globalSemaphore

	mu        sync.Mutex
	allocated map[int]struct{}
	byPort    map[int]*tcpTunnel
	bySession map[*AgentSession]map[int]struct{}
	conns     map[*AgentSession]map[*tcpConn]struct{}
	releasing map[*AgentSession]struct{}
}

func parseTCPPortRange(s string) (int, int, error) {
	parts := strings.SplitN(strings.TrimSpace(s), "-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("edge: tcp port range must be \"min-max\", got %q", s)
	}
	lo, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("edge: tcp port range min: %w", err)
	}
	hi, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("edge: tcp port range max: %w", err)
	}
	if lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, fmt.Errorf("edge: invalid tcp port range %d-%d", lo, hi)
	}
	return lo, hi, nil
}

func newTCPManager(lo, hi int, bindAddr string, limiter *perIPLimiter) *tcpManager {
	return &tcpManager{
		lo:              lo,
		hi:              hi,
		bindAddr:        bindAddr,
		limiter:         limiter,
		forceCloseGrace: 2 * time.Second,
		globalSem:       newGlobalSemaphore(maxGlobalTCPConns),
		allocated:       make(map[int]struct{}),
		byPort:          make(map[int]*tcpTunnel),
		bySession:       make(map[*AgentSession]map[int]struct{}),
		conns:           make(map[*AgentSession]map[*tcpConn]struct{}),
		releasing:       make(map[*AgentSession]struct{}),
	}
}

func (tm *tcpManager) registerLocked(as *AgentSession, tc *tcpConn) {
	if tm.conns[as] == nil {
		tm.conns[as] = make(map[*tcpConn]struct{})
	}
	tm.conns[as][tc] = struct{}{}
}

func (tm *tcpManager) deregister(as *AgentSession, tc *tcpConn) {
	tm.mu.Lock()
	if set, ok := tm.conns[as]; ok {
		delete(set, tc)
		if len(set) == 0 {
			delete(tm.conns, as)
		}
	}
	tm.mu.Unlock()
}

func (tm *tcpManager) reserveLocked(requested int) (int, error) {
	if requested != 0 {
		if requested < tm.lo || requested > tm.hi {
			return 0, errPortUnavailable
		}
		if _, taken := tm.allocated[requested]; taken {
			return 0, errPortUnavailable
		}
		tm.allocated[requested] = struct{}{}
		return requested, nil
	}
	for p := tm.lo; p <= tm.hi; p++ {
		if _, taken := tm.allocated[p]; !taken {
			tm.allocated[p] = struct{}{}
			return p, nil
		}
	}
	return 0, errPortUnavailable
}

func (tm *tcpManager) registerTunnelLocked(as *AgentSession, port int, hostname string, ln net.Listener, allow []netip.Prefix) *tcpTunnel {
	tt := &tcpTunnel{
		port:       port,
		hostname:   hostname,
		ln:         ln,
		session:    as,
		allow:      allow,
		acceptDone: make(chan struct{}),
		closed:     make(chan struct{}),
	}
	tm.byPort[port] = tt
	if tm.bySession[as] == nil {
		tm.bySession[as] = make(map[int]struct{})
	}
	tm.bySession[as][port] = struct{}{}
	return tt
}

// claimHeldLocked resolves a bind for a port that a registered tunnel already
// holds, using the same identity rules as Registry.Bind (ARCHITECTURE §3):
// the holder's own session rebinding is idempotent; (a) the same non-empty
// InstanceID takes the port over immediately, whether or not the holder
// still looks alive; (b) a different InstanceID takes it over only when
// takeover is requested and the holder's session is dead; (c) anything else
// is errPortUnavailable. It returns the evicted session, if any.
//
// A takeover hands the existing listener and accept loop to the new session
// instead of closing and re-listening, so no other process can grab the port
// in between. Connections already relayed stay accounted to the old session
// and are torn down when that session is released; the port no longer
// appears under the old session, so releasing it leaves the port alone.
func (tm *tcpManager) claimHeldLocked(as *AgentSession, tt *tcpTunnel, hostname string, allow []netip.Prefix, takeover bool) (*AgentSession, error) {
	old := tt.session
	switch {
	case old == as:
		tt.hostname = hostname
		tt.allow = allow
		return nil, nil
	case as.InstanceID != "" && old.InstanceID == as.InstanceID:
	case takeover && isSessionDead(old):
	default:
		return nil, errPortUnavailable
	}

	if len(tm.bySession[as]) >= maxBindsPerSession {
		metricTCPRejectedBindCap.Add(1)
		return nil, errTooManyBinds
	}

	if ports, ok := tm.bySession[old]; ok {
		delete(ports, tt.port)
	}
	if tm.bySession[as] == nil {
		tm.bySession[as] = make(map[int]struct{})
	}
	tm.bySession[as][tt.port] = struct{}{}
	tt.session = as
	tt.hostname = hostname
	tt.allow = allow
	return old, nil
}

// bind allocates a public port for as and starts accepting on it. requested
// == 0 picks the first free port in range; otherwise that exact port is used,
// and if a tunnel already holds it, claimHeldLocked decides whether as may
// take it over. The returned session, when non-nil, lost the port to as and
// should be told it was evicted.
func (tm *tcpManager) bind(as *AgentSession, requested int, hostname string, allow []netip.Prefix, takeover bool) (int, *AgentSession, error) {
	tm.mu.Lock()
	if tt, held := tm.byPort[requested]; held && requested != 0 {
		evicted, err := tm.claimHeldLocked(as, tt, hostname, allow, takeover)
		tm.mu.Unlock()
		if err != nil {
			return 0, nil, err
		}
		return requested, evicted, nil
	}

	if len(tm.bySession[as]) >= maxBindsPerSession {
		tm.mu.Unlock()
		metricTCPRejectedBindCap.Add(1)
		return 0, nil, errTooManyBinds
	}

	if requested != 0 {
		port, err := tm.reserveLocked(requested)
		if err != nil {
			tm.mu.Unlock()
			return 0, nil, err
		}

		ln, err := net.Listen("tcp", net.JoinHostPort(tm.bindAddr, strconv.Itoa(port)))
		if err != nil {
			delete(tm.allocated, port)
			tm.mu.Unlock()
			return 0, nil, err
		}

		tt := tm.registerTunnelLocked(as, port, hostname, ln, allow)
		tm.mu.Unlock()

		go tm.acceptLoop(tt)
		return port, nil, nil
	}
	tm.mu.Unlock()

	var tried []int
	var port int
	var ln net.Listener
	found := false

	p := tm.lo
	for {
		tm.mu.Lock()
		candidate := 0
		for ; p <= tm.hi; p++ {
			if _, taken := tm.allocated[p]; !taken {
				candidate = p
				break
			}
		}
		if candidate == 0 {
			tm.mu.Unlock()
			break
		}
		tm.allocated[candidate] = struct{}{}
		tm.mu.Unlock()

		l, err := net.Listen("tcp", net.JoinHostPort(tm.bindAddr, strconv.Itoa(candidate)))
		if err != nil {
			tried = append(tried, candidate)
			p = candidate + 1
			continue
		}
		port, ln = candidate, l
		found = true
		break
	}

	tm.mu.Lock()
	for _, p := range tried {
		delete(tm.allocated, p)
	}
	if !found {
		tm.mu.Unlock()
		return 0, nil, errPortUnavailable
	}
	if len(tm.bySession[as]) >= maxBindsPerSession {
		delete(tm.allocated, port)
		tm.mu.Unlock()
		ln.Close()
		metricTCPRejectedBindCap.Add(1)
		return 0, nil, errTooManyBinds
	}
	tt := tm.registerTunnelLocked(as, port, hostname, ln, allow)
	tm.mu.Unlock()

	go tm.acceptLoop(tt)
	return port, nil, nil
}

func (tm *tcpManager) acceptLoop(tt *tcpTunnel) {
	defer close(tt.acceptDone)
	backoff := 5 * time.Millisecond
	for {
		c, err := tt.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Warn("tcp accept error", "port", tt.port, "err", err, "backoff", backoff)
			t := time.NewTimer(backoff)
			select {
			case <-t.C:
			case <-tt.closed:
				t.Stop()
				return
			}
			if backoff < time.Second {
				backoff *= 2
				if backoff > time.Second {
					backoff = time.Second
				}
			}
			continue
		}
		backoff = 5 * time.Millisecond

		// Read the owner and account the connection to it in one critical
		// section: a takeover may have moved the tunnel to a new session, and
		// a connection registered to the old one before the move is drained
		// by the old session's releaseSession.
		tc := &tcpConn{client: c}
		tm.mu.Lock()
		as, hostname, allow := tt.session, tt.hostname, tt.allow
		as.inflight.Add(1)
		tm.registerLocked(as, tc)
		tm.mu.Unlock()
		go tm.handleConn(as, hostname, allow, tc)
	}
}

func (tm *tcpManager) handleConn(as *AgentSession, hostname string, allow []netip.Prefix, tc *tcpConn) {
	client := tc.client

	if tm.limiter != nil && !tm.limiter.allow(remoteIP(client)) {
		metricTCPRejectedRateLimited.Add(1)
		client.Close()
		as.inflight.Done()
		tm.deregister(as, tc)
		return
	}

	if len(allow) > 0 {
		addr, err := netip.ParseAddr(remoteIP(client))
		if err != nil || !prefixesContain(allow, addr) {
			metricTCPRejectedForbiddenCIDR.Add(1)
			client.Close()
			as.inflight.Done()
			tm.deregister(as, tc)
			return
		}
	}

	if !tm.globalSem.tryAcquire() {
		metricTCPRejectedGlobalCap.Add(1)
		client.Close()
		as.inflight.Done()
		tm.deregister(as, tc)
		return
	}

	if !as.tryAcquireStream() {
		metricRejectedSessionCap.Add(1)
		tm.globalSem.release()
		client.Close()
		as.inflight.Done()
		tm.deregister(as, tc)
		return
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), dialBudget)
	stream, err := as.Sess.OpenStream(dialCtx, proto.StreamOpen{
		Kind:       proto.KindTCP,
		Host:       hostname,
		ClientAddr: client.RemoteAddr().String(),
		ReqID:      randomHex(8),
	})
	cancel()
	if err != nil {
		tm.globalSem.release()
		as.releaseStream()
		as.inflight.Done()
		client.Close()
		tm.deregister(as, tc)
		return
	}

	tm.mu.Lock()
	tc.stream = stream
	_, releasing := tm.releasing[as]
	tm.mu.Unlock()
	if releasing {
		stream.SetDeadline(time.Now())
		client.Close()
		as.inflight.Done()
		as.releaseStream()
		tm.globalSem.release()
		tm.deregister(as, tc)
		stream.Close()
		return
	}

	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			as.inflight.Done()
			as.releaseStream()
			tm.globalSem.release()
			tm.deregister(as, tc)
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		io.Copy(stream, client)
		wg.Done()
		closeWrite(stream)
	}()

	go func() {
		io.Copy(client, stream)
		wg.Done()
		closeWrite(client)
	}()

	wg.Wait()
	release()
	stream.Close()
	client.Close()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}

func (tm *tcpManager) releaseSession(as *AgentSession) {
	tm.mu.Lock()
	tm.releasing[as] = struct{}{}
	ports := tm.bySession[as]
	tunnels := make([]*tcpTunnel, 0, len(ports))
	for p := range ports {
		if tt, ok := tm.byPort[p]; ok {
			tunnels = append(tunnels, tt)
		}
		delete(tm.byPort, p)
	}
	delete(tm.bySession, as)
	for _, tt := range tunnels {
		select {
		case <-tt.closed:
		default:
			close(tt.closed)
		}
	}
	tm.mu.Unlock()

	for _, tt := range tunnels {
		tt.ln.Close()
		<-tt.acceptDone
	}

	tm.mu.Lock()
	for _, tt := range tunnels {
		delete(tm.allocated, tt.port)
	}
	tm.mu.Unlock()

	deadline := time.Now().Add(tm.forceCloseGrace)
	for {
		tm.mu.Lock()
		remaining := len(tm.conns[as])
		tm.mu.Unlock()
		if remaining == 0 {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	tm.mu.Lock()
	survivors := make([]tcpConn, 0, len(tm.conns[as]))
	for tc := range tm.conns[as] {
		survivors = append(survivors, *tc)
	}
	tm.mu.Unlock()

	for i := range survivors {
		if survivors[i].stream != nil {
			survivors[i].stream.SetDeadline(time.Now())
		}
		if survivors[i].client != nil {
			survivors[i].client.Close()
		}
	}

	start := time.Now()
	for {
		tm.mu.Lock()
		remaining := len(tm.conns[as])
		tm.mu.Unlock()
		if remaining == 0 {
			break
		}
		if time.Now().After(start.Add(dialBudget + tm.forceCloseGrace)) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	tm.mu.Lock()
	delete(tm.releasing, as)
	tm.mu.Unlock()
}
