package edge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"ngstone/internal/proto"
)

var errPortUnavailable = errors.New("edge: port_unavailable")

type tcpTunnel struct {
	port     int
	hostname string
	ln       net.Listener
	session  *AgentSession
}

type tcpManager struct {
	lo, hi   int
	bindAddr string
	limiter  *perIPLimiter

	mu        sync.Mutex
	allocated map[int]struct{}
	byPort    map[int]*tcpTunnel
	bySession map[*AgentSession]map[int]struct{}
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
		lo:        lo,
		hi:        hi,
		bindAddr:  bindAddr,
		limiter:   limiter,
		allocated: make(map[int]struct{}),
		byPort:    make(map[int]*tcpTunnel),
		bySession: make(map[*AgentSession]map[int]struct{}),
	}
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

func (tm *tcpManager) bind(as *AgentSession, requested int, hostname string) (int, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	port, err := tm.reserveLocked(requested)
	if err != nil {
		return 0, err
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(tm.bindAddr, strconv.Itoa(port)))
	if err != nil {
		delete(tm.allocated, port)
		return 0, err
	}

	tt := &tcpTunnel{port: port, hostname: hostname, ln: ln, session: as}
	tm.byPort[port] = tt
	if tm.bySession[as] == nil {
		tm.bySession[as] = make(map[int]struct{})
	}
	tm.bySession[as][port] = struct{}{}

	go tm.acceptLoop(tt)
	return port, nil
}

func (tm *tcpManager) acceptLoop(tt *tcpTunnel) {
	for {
		c, err := tt.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		go tm.handleConn(tt.session, tt.hostname, c)
	}
}

func (tm *tcpManager) handleConn(as *AgentSession, hostname string, client net.Conn) {
	if tm.limiter != nil && !tm.limiter.allow(remoteIP(client)) {
		client.Close()
		return
	}

	if !as.tryAcquireStream() {
		client.Close()
		return
	}

	as.inflight.Add(1)
	dialCtx, cancel := context.WithTimeout(context.Background(), dialBudget)
	stream, err := as.Sess.OpenStream(dialCtx, proto.StreamOpen{
		Kind:       proto.KindTCP,
		Host:       hostname,
		ClientAddr: client.RemoteAddr().String(),
		ReqID:      randomHex(8),
	})
	cancel()
	if err != nil {
		as.inflight.Done()
		as.releaseStream()
		client.Close()
		return
	}

	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			as.inflight.Done()
			as.releaseStream()
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(stream, client)
		closeWrite(stream)
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, stream)
		closeWrite(client)
	}()

	wg.Wait()
	stream.Close()
	client.Close()
	release()
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
	ports := tm.bySession[as]
	listeners := make([]net.Listener, 0, len(ports))
	for p := range ports {
		if tt, ok := tm.byPort[p]; ok {
			listeners = append(listeners, tt.ln)
		}
		delete(tm.allocated, p)
		delete(tm.byPort, p)
	}
	delete(tm.bySession, as)
	tm.mu.Unlock()

	for _, ln := range listeners {
		ln.Close()
	}
}
