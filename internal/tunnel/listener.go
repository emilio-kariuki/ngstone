package tunnel

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"ngstone/internal/proto"
)

type placeholderAddr struct {
	network string
	addr    string
}

func (a placeholderAddr) Network() string { return a.network }
func (a placeholderAddr) String() string  { return a.addr }

type streamConn struct {
	net.Conn
	pre  proto.StreamOpen
	addr net.Addr
}

func (c *streamConn) RemoteAddr() net.Addr {
	return c.addr
}

func (c *streamConn) Preamble() proto.StreamOpen {
	return c.pre
}

func resolveClientAddr(clientAddr string) net.Addr {
	if clientAddr != "" {
		if ap, err := netip.ParseAddrPort(clientAddr); err == nil {
			return net.TCPAddrFromAddrPort(ap)
		}
	}
	return placeholderAddr{network: "tunnel", addr: "unknown-client"}
}

type Listener struct {
	sess      Session
	ready     chan net.Conn
	closeCh   chan struct{}
	closeOnce sync.Once
	addr      net.Addr
}

func NewListener(sess Session) (*Listener, error) {
	l := &Listener{
		sess:    sess,
		ready:   make(chan net.Conn),
		closeCh: make(chan struct{}),
		addr:    placeholderAddr{network: "tunnel", addr: "tunnel-listener"},
	}
	go l.acceptLoop()
	return l, nil
}

func (l *Listener) acceptLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-l.closeCh:
		case <-l.sess.Done():
		}
		cancel()
	}()
	for {
		stream, err := l.sess.AcceptRaw(ctx)
		if err != nil {
			return
		}
		go l.handleStream(stream)
	}
}

func (l *Listener) handleStream(stream net.Conn) {
	pre, err := readPreamble(stream)
	if err != nil {
		stream.Close()
		return
	}
	sc := &streamConn{Conn: stream, pre: pre, addr: resolveClientAddr(pre.ClientAddr)}
	select {
	case l.ready <- sc:
	case <-l.closeCh:
		stream.Close()
	case <-l.sess.Done():
		stream.Close()
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case <-l.closeCh:
		return nil, net.ErrClosed
	case <-l.sess.Done():
		return nil, net.ErrClosed
	}
}

func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closeCh)
	})
	return nil
}

func (l *Listener) Addr() net.Addr {
	return l.addr
}
