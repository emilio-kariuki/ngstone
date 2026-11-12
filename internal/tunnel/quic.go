package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	QUICALPN = "ngstone-quic-1"

	quicInitialWindow              = 64 << 10
	quicMaxWindow                  = 1 << 20
	quicHandshakeIdleTimeout       = 5 * time.Second
	quicServerHandshakeIdleTimeout = 2500 * time.Millisecond
	quicMaxIdleTimeout             = 15 * time.Second
	quicKeepAlivePeriod            = 5 * time.Second
	quicStreamAcceptTimeout        = 5 * time.Second
	quicCloseLinger                = 3 * time.Second
)

func quicBaseConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:                 quicMaxIdleTimeout,
		KeepAlivePeriod:                quicKeepAlivePeriod,
		InitialStreamReceiveWindow:     quicInitialWindow,
		MaxStreamReceiveWindow:         quicMaxWindow,
		InitialConnectionReceiveWindow: quicInitialWindow,
		MaxConnectionReceiveWindow:     quicMaxWindow,
		MaxIncomingStreams:             -1,
		MaxIncomingUniStreams:          -1,
		Allow0RTT:                      false,
		EnableDatagrams:                false,
	}
}

func quicClientConfig() *quic.Config {
	cfg := quicBaseConfig()
	cfg.HandshakeIdleTimeout = quicHandshakeIdleTimeout
	return cfg
}

func QUICServerConfig(gate func(*quic.Conn, uint64) bool) *quic.Config {
	cfg := quicBaseConfig()
	cfg.HandshakeIdleTimeout = quicServerHandshakeIdleTimeout
	cfg.MaxIncomingStreams = 1
	cfg.AllowConnectionWindowIncrease = gate
	return cfg
}

type quicConn struct {
	*quic.Stream
	conn      *quic.Conn
	wait      bool
	wmu       sync.Mutex
	closed    atomic.Bool
	eof       chan struct{}
	eofOnce   sync.Once
	closeOnce sync.Once
}

func newQUICConn(st *quic.Stream, qc *quic.Conn, wait bool) *quicConn {
	return &quicConn{Stream: st, conn: qc, wait: wait, eof: make(chan struct{})}
}

func (c *quicConn) Read(p []byte) (int, error) {
	n, err := c.Stream.Read(p)
	if errors.Is(err, io.EOF) {
		c.eofOnce.Do(func() { close(c.eof) })
	}
	return n, err
}

func (c *quicConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.Stream.Write(p)
}

func (c *quicConn) Close() error {
	c.closeOnce.Do(func() {
		now := time.Now()
		c.Stream.SetWriteDeadline(now)
		c.Stream.SetReadDeadline(now)
		c.wmu.Lock()
		c.closed.Store(true)
		c.Stream.Close()
		c.wmu.Unlock()
		if c.wait {
			c.linger()
		} else {
			go c.linger()
		}
	})
	return nil
}

func (c *quicConn) linger() {
	t := time.NewTimer(quicCloseLinger)
	defer t.Stop()
	select {
	case <-c.eof:
	case <-c.conn.Context().Done():
	case <-t.C:
	}
	c.conn.CloseWithError(0, "")
}

func (c *quicConn) SetDeadline(t time.Time) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	return c.Stream.SetDeadline(t)
}

func (c *quicConn) SetReadDeadline(t time.Time) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	return c.Stream.SetReadDeadline(t)
}

func (c *quicConn) SetWriteDeadline(t time.Time) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	return c.Stream.SetWriteDeadline(t)
}

func (c *quicConn) LocalAddr() net.Addr {
	return unmapUDPAddr(c.conn.LocalAddr())
}

func (c *quicConn) RemoteAddr() net.Addr {
	return unmapUDPAddr(c.conn.RemoteAddr())
}

func unmapUDPAddr(a net.Addr) net.Addr {
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		return a
	}
	ip := ua.IP
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return &net.UDPAddr{IP: ip, Port: ua.Port, Zone: ua.Zone}
}

func orderQUICCandidates(ips []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip = ip.Unmap(); ip.Is4() {
			out = append(out, ip)
		}
	}
	for _, ip := range ips {
		if ip = ip.Unmap(); !ip.Is4() {
			out = append(out, ip)
		}
	}
	return out
}

func DialQUIC(ctx context.Context, addr string, tlsConf *tls.Config) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	portNum, err := net.DefaultResolver.LookupPort(ctx, "udp", port)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if lit, perr := netip.ParseAddr(host); perr == nil {
		ips = []netip.Addr{lit}
	} else {
		ips, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	candidates := orderQUICCandidates(ips)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("tunnel: no addresses for %q", host)
	}
	var lastErr error
	for _, ip := range candidates {
		conn, err := dialQUICAddr(ctx, net.JoinHostPort(ip.String(), strconv.Itoa(portNum)), tlsConf)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

func dialQUICAddr(ctx context.Context, addr string, tlsConf *tls.Config) (net.Conn, error) {
	qc, err := quic.DialAddr(ctx, addr, tlsConf, quicClientConfig())
	if err != nil {
		return nil, err
	}
	st, err := qc.OpenStreamSync(ctx)
	if err != nil {
		qc.CloseWithError(0, "")
		return nil, err
	}
	return newQUICConn(st, qc, true), nil
}

func AcceptQUIC(ctx context.Context, qc *quic.Conn) (net.Conn, error) {
	actx, cancel := context.WithTimeout(ctx, quicStreamAcceptTimeout)
	defer cancel()
	st, err := qc.AcceptStream(actx)
	if err != nil {
		qc.CloseWithError(0, "")
		return nil, err
	}
	return newQUICConn(st, qc, false), nil
}
