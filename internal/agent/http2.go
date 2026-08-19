package agent

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"

	"golang.org/x/net/http2"

	"ngstone/internal/inspect"
	"ngstone/internal/proto"
)

type queuedConnListener struct {
	mu     sync.Mutex
	queue  []net.Conn
	notify chan struct{}
	closed bool
	addr   net.Addr
}

func newQueuedConnListener() *queuedConnListener {
	return &queuedConnListener{
		notify: make(chan struct{}, 1),
		addr:   queuedConnAddr{},
	}
}

func (l *queuedConnListener) Accept() (net.Conn, error) {
	for {
		l.mu.Lock()
		if len(l.queue) > 0 {
			c := l.queue[0]
			l.queue = l.queue[1:]
			l.mu.Unlock()
			return c, nil
		}
		if l.closed {
			l.mu.Unlock()
			return nil, net.ErrClosed
		}
		l.mu.Unlock()
		<-l.notify
	}
}

func (l *queuedConnListener) push(c net.Conn) bool {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		c.Close()
		return false
	}
	l.queue = append(l.queue, c)
	l.mu.Unlock()
	select {
	case l.notify <- struct{}{}:
	default:
	}
	return true
}

func (l *queuedConnListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	queued := l.queue
	l.queue = nil
	l.mu.Unlock()
	for _, c := range queued {
		c.Close()
	}
	select {
	case l.notify <- struct{}{}:
	default:
	}
	return nil
}

func (l *queuedConnListener) Addr() net.Addr { return l.addr }

type queuedConnAddr struct{}

func (queuedConnAddr) Network() string { return "tunnel" }
func (queuedConnAddr) String() string  { return "http-stream-listener" }

type http2TunnelServer struct {
	h1         *http.Server
	h2         *http2.Server
	h2Handler  http.Handler
	baseConfig *http.Server

	mu      sync.Mutex
	source  net.Listener
	h1ln    *queuedConnListener
	closed  bool
	h2Conns map[net.Conn]struct{}
	h2WG    sync.WaitGroup
}

func newHTTP2TunnelServer(h1Handler, h2Handler http.Handler) *http2TunnelServer {
	h2Handler = withHTTP2RequestMetadata(h2Handler)
	baseConfig := &http.Server{Handler: h2Handler, ConnContext: streamConnContext}
	return &http2TunnelServer{
		h1:         &http.Server{Handler: h1Handler, ConnContext: streamConnContext},
		h2:         &http2.Server{},
		h2Handler:  h2Handler,
		baseConfig: baseConfig,
		h2Conns:    make(map[net.Conn]struct{}),
	}
}

func withHTTP2RequestMetadata(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := inspect.StreamInfoFrom(r.Context())
		if reqID := r.Header.Get(inspect.RequestIDHeader); reqID != "" {
			info.ReqID = reqID
		}
		if clientAddr := r.Header.Get(inspect.ClientAddrHeader); clientAddr != "" {
			info.ClientAddr = clientAddr
		}
		r.Header.Del(inspect.RequestIDHeader)
		r.Header.Del(inspect.ClientAddrHeader)
		next.ServeHTTP(w, r.WithContext(inspect.WithStreamInfo(r.Context(), info)))
	})
}

func (s *http2TunnelServer) Serve(ln net.Listener) error {
	h1ln := newQueuedConnListener()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		ln.Close()
		return http.ErrServerClosed
	}
	s.source = ln
	s.h1ln = h1ln
	s.mu.Unlock()

	h1Done := make(chan error, 1)
	go func() { h1Done <- s.h1.Serve(h1ln) }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			h1ln.Close()
			s.closeHTTP2Connections()
			h1Err := <-h1Done
			if h1Err != nil && !errors.Is(h1Err, http.ErrServerClosed) && !errors.Is(h1Err, net.ErrClosed) {
				return h1Err
			}
			s.h2WG.Wait()
			if s.isClosed() {
				return http.ErrServerClosed
			}
			return err
		}

		pre, ok := conn.(preambleConn)
		if !ok {
			conn.Close()
			continue
		}
		switch pre.Preamble().Kind {
		case proto.KindHTTP:
			if !h1ln.push(conn) {
				conn.Close()
			}
		case proto.KindHTTP2:
			s.trackHTTP2Connection(conn)
		default:
			conn.Close()
		}
	}
}

func (s *http2TunnelServer) trackHTTP2Connection(conn net.Conn) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		conn.Close()
		return
	}
	s.h2Conns[conn] = struct{}{}
	s.h2WG.Add(1)
	s.mu.Unlock()

	go func() {
		defer s.h2WG.Done()
		defer conn.Close()
		defer func() {
			s.mu.Lock()
			delete(s.h2Conns, conn)
			s.mu.Unlock()
		}()
		s.h2.ServeConn(conn, &http2.ServeConnOpts{
			Context:    streamConnContext(context.Background(), conn),
			BaseConfig: s.baseConfig,
			Handler:    s.h2Handler,
		})
	}()
}

func (s *http2TunnelServer) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	source := s.source
	h1ln := s.h1ln
	s.mu.Unlock()

	if source != nil {
		source.Close()
	}
	if h1ln != nil {
		h1ln.Close()
	}
	if err := s.h1.Shutdown(ctx); err != nil {
		s.closeHTTP2Connections()
		return err
	}

	done := make(chan struct{})
	go func() {
		s.h2WG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		s.closeHTTP2Connections()
		return ctx.Err()
	}
}

func (s *http2TunnelServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	source := s.source
	h1ln := s.h1ln
	s.mu.Unlock()

	if source != nil {
		source.Close()
	}
	if h1ln != nil {
		h1ln.Close()
	}
	s.closeHTTP2Connections()
	return s.h1.Close()
}

func (s *http2TunnelServer) closeHTTP2Connections() {
	s.mu.Lock()
	connections := make([]net.Conn, 0, len(s.h2Conns))
	for conn := range s.h2Conns {
		connections = append(connections, conn)
	}
	s.mu.Unlock()
	for _, conn := range connections {
		conn.Close()
	}
}

func (s *http2TunnelServer) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}
