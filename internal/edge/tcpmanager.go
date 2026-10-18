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
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	metricTCPRejectedUnhealthy     = expvar.NewInt("ngstoned_tcp_rejected_unhealthy_total")
)

type tcpConn struct {
	client net.Conn
	stream net.Conn
}

type tcpTunnel struct {
	port      int
	hostname  string
	durableID atomic.Value
	boundAt   time.Time
	ln        net.Listener
	session   *AgentSession
	allow     []netip.Prefix

	acceptDone chan struct{}
	closed     chan struct{}
}

type tcpManager struct {
	lo, hi   int
	bindAddr string
	limiter  *perIPLimiter

	forceCloseGrace time.Duration
	globalSem       *globalSemaphore

	// perIP is shared with the public HTTP handler, so one client has one
	// budget across requests and TCP connections. nil disables the cap.
	perIP *perIPInflight
	// idleTimeout closes a relayed connection that has carried no bytes in
	// either direction for this long. 0 disables it.
	idleTimeout time.Duration

	mu        sync.Mutex
	allocated map[int]struct{}
	byPort    map[int]*tcpTunnel
	bySession map[*AgentSession]map[int]struct{}
	conns     map[*AgentSession]map[*tcpConn]struct{}
	releasing map[*AgentSession]struct{}
	observe   func(string, string, time.Duration, int64, int64)
}

type tcpTunnelInfo struct {
	Hostname         string
	Port             int
	BoundAt          time.Time
	SessionID        string
	InstanceID       string
	Remote           string
	Alive            bool
	Healthy          bool
	AccessRestricted bool
	ActiveStreams    int64
	StreamCapacity   int64
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

func (tm *tcpManager) register(as *AgentSession, tc *tcpConn) {
	tm.mu.Lock()
	if tm.conns[as] == nil {
		tm.conns[as] = make(map[*tcpConn]struct{})
	}
	tm.conns[as][tc] = struct{}{}
	tm.mu.Unlock()
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
		boundAt:    time.Now(),
		ln:         ln,
		session:    as,
		allow:      allow,
		acceptDone: make(chan struct{}),
		closed:     make(chan struct{}),
	}
	tt.durableID.Store("")
	tm.byPort[port] = tt
	if tm.bySession[as] == nil {
		tm.bySession[as] = make(map[int]struct{})
	}
	tm.bySession[as][port] = struct{}{}
	return tt
}

func (tm *tcpManager) dashboardSnapshot() []tcpTunnelInfo {
	if tm == nil {
		return nil
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()

	out := make([]tcpTunnelInfo, 0, len(tm.byPort))
	for _, tunnel := range tm.byPort {
		if tunnel == nil || tunnel.session == nil {
			continue
		}
		active, capacity := semaphoreStats(tunnel.session.streamSem)
		remote := ""
		if tunnel.session.Remote.IsValid() {
			remote = tunnel.session.Remote.String()
		}
		out = append(out, tcpTunnelInfo{
			Hostname:         tunnel.hostname,
			Port:             tunnel.port,
			BoundAt:          tunnel.boundAt,
			SessionID:        tunnel.session.ID,
			InstanceID:       tunnel.session.InstanceID,
			Remote:           remote,
			Alive:            !isSessionDead(tunnel.session),
			Healthy:          tunnel.session.healthy(time.Now()),
			AccessRestricted: len(tunnel.allow) > 0,
			ActiveStreams:    active,
			StreamCapacity:   capacity,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

func (tm *tcpManager) sessionsForHostname(host string) []*AgentSession {
	if tm == nil {
		return nil
	}
	host = normalizeHost(host)
	tm.mu.Lock()
	defer tm.mu.Unlock()
	seen := make(map[*AgentSession]struct{})
	var sessions []*AgentSession
	for _, tunnel := range tm.byPort {
		if tunnel == nil || tunnel.session == nil || normalizeHost(tunnel.hostname) != host {
			continue
		}
		if _, ok := seen[tunnel.session]; ok {
			continue
		}
		seen[tunnel.session] = struct{}{}
		sessions = append(sessions, tunnel.session)
	}
	return sessions
}

func (tm *tcpManager) setTunnelID(as *AgentSession, port int, tunnelID string) {
	if tm == nil {
		return
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if tunnel := tm.byPort[port]; tunnel != nil && tunnel.session == as {
		tunnel.durableID.Store(tunnelID)
	}
}

func (tm *tcpManager) setObserver(observer func(string, string, time.Duration, int64, int64)) {
	if tm == nil {
		return
	}
	tm.mu.Lock()
	tm.observe = observer
	tm.mu.Unlock()
}

func (tm *tcpManager) observabilityTargetsForSession(as *AgentSession) []observabilityTarget {
	if tm == nil || as == nil {
		return nil
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()
	seen := make(map[string]struct{})
	var targets []observabilityTarget
	for port := range tm.bySession[as] {
		tunnel := tm.byPort[port]
		if tunnel == nil {
			continue
		}
		durableID, _ := tunnel.durableID.Load().(string)
		target := observabilityTarget{TunnelID: durableID, Hostname: tunnel.hostname}
		key := metricKey(target.TunnelID, target.Hostname+":"+strconv.Itoa(port))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
	}
	return targets
}

func (tm *tcpManager) bind(as *AgentSession, requested int, hostname string, allow []netip.Prefix) (int, error) {
	tm.mu.Lock()
	if len(tm.bySession[as]) >= maxBindsPerSession {
		tm.mu.Unlock()
		metricTCPRejectedBindCap.Add(1)
		return 0, errTooManyBinds
	}

	if requested != 0 {
		port, err := tm.reserveLocked(requested)
		if err != nil {
			tm.mu.Unlock()
			return 0, err
		}

		ln, err := net.Listen("tcp", net.JoinHostPort(tm.bindAddr, strconv.Itoa(port)))
		if err != nil {
			delete(tm.allocated, port)
			tm.mu.Unlock()
			return 0, err
		}

		tt := tm.registerTunnelLocked(as, port, hostname, ln, allow)
		tm.mu.Unlock()

		go tm.acceptLoop(tt)
		return port, nil
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
		return 0, errPortUnavailable
	}
	if len(tm.bySession[as]) >= maxBindsPerSession {
		delete(tm.allocated, port)
		tm.mu.Unlock()
		ln.Close()
		metricTCPRejectedBindCap.Add(1)
		return 0, errTooManyBinds
	}
	tt := tm.registerTunnelLocked(as, port, hostname, ln, allow)
	tm.mu.Unlock()

	go tm.acceptLoop(tt)
	return port, nil
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

		tc := &tcpConn{client: c}
		tt.session.inflight.Add(1)
		tm.register(tt.session, tc)
		durableID, _ := tt.durableID.Load().(string)
		go tm.handleConn(tt.session, tt.hostname, durableID, tt.allow, tc)
	}
}

func (tm *tcpManager) handleConn(as *AgentSession, hostname, durableID string, allow []netip.Prefix, tc *tcpConn) {
	client := tc.client
	started := time.Now()
	if !as.healthy(started) {
		metricTCPRejectedUnhealthy.Add(1)
		client.Close()
		as.inflight.Done()
		tm.deregister(as, tc)
		return
	}

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

	releaseIP, ok := tm.perIP.acquire(remoteIP(client))
	if !ok {
		metricRejectedPerIPCap.Add(1)
		client.Close()
		as.inflight.Done()
		tm.deregister(as, tc)
		return
	}
	defer releaseIP()

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

	idle := newIdleDeadline(tm.idleTimeout, client, stream)

	var wg sync.WaitGroup
	wg.Add(2)

	var bytesIn, bytesOut int64
	go func() {
		bytesIn, _ = io.Copy(stream, idle.reader(client))
		wg.Done()
		closeWrite(stream)
	}()

	go func() {
		bytesOut, _ = io.Copy(client, idle.reader(stream))
		wg.Done()
		closeWrite(client)
	}()

	wg.Wait()
	release()
	tm.mu.Lock()
	observer := tm.observe
	tm.mu.Unlock()
	if observer != nil {
		observer(durableID, hostname, time.Since(started), bytesIn, bytesOut)
	}
	stream.Close()
	client.Close()
}

// idleDeadline closes a relayed TCP connection once neither direction has
// carried a byte for timeout. Every successful read on either side pushes
// the read deadline of both sides forward, so a connection that is busy in
// only one direction, such as a download, stays open.
type idleDeadline struct {
	timeout  time.Duration
	conns    []net.Conn
	last     atomic.Int64
	timedOut sync.Once
}

// idleExtendEvery throttles deadline updates on busy connections; it is
// capped at a quarter of the timeout so a busy connection never lapses.
const idleExtendEvery = time.Second

func newIdleDeadline(timeout time.Duration, conns ...net.Conn) *idleDeadline {
	d := &idleDeadline{timeout: timeout, conns: conns}
	d.extend(time.Now(), true)
	return d
}

func (d *idleDeadline) extend(now time.Time, force bool) {
	if d.timeout <= 0 {
		return
	}
	if !force && now.Sub(time.Unix(0, d.last.Load())) < min(idleExtendEvery, d.timeout/4) {
		return
	}
	d.last.Store(now.UnixNano())
	for _, c := range d.conns {
		_ = c.SetReadDeadline(now.Add(d.timeout))
	}
}

func (d *idleDeadline) reader(c net.Conn) io.Reader {
	if d.timeout <= 0 {
		return c
	}
	return &idleReader{conn: c, d: d}
}

type idleReader struct {
	conn net.Conn
	d    *idleDeadline
}

func (r *idleReader) Read(p []byte) (int, error) {
	n, err := r.conn.Read(p)
	if n > 0 {
		r.d.extend(time.Now(), false)
	}
	if err != nil && errors.Is(err, os.ErrDeadlineExceeded) {
		r.d.timedOut.Do(func() { metricTCPClosedIdle.Add(1) })
	}
	return n, err
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

func (tm *tcpManager) releasePort(as *AgentSession, port int) {
	tm.mu.Lock()
	ports, ok := tm.bySession[as]
	if !ok {
		tm.mu.Unlock()
		return
	}
	tunnel, ok := tm.byPort[port]
	if !ok || tunnel.session != as {
		tm.mu.Unlock()
		return
	}
	delete(tm.byPort, port)
	delete(ports, port)
	if len(ports) == 0 {
		delete(tm.bySession, as)
	}
	select {
	case <-tunnel.closed:
	default:
		close(tunnel.closed)
	}
	tm.mu.Unlock()

	tunnel.ln.Close()
	<-tunnel.acceptDone
	tm.mu.Lock()
	delete(tm.allocated, port)
	tm.mu.Unlock()
}
