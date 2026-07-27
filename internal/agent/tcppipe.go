package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

const tcpDialTimeout = 10 * time.Second

var errTCPServerClosed = errors.New("agent: tcp server closed")

type closeWriter interface {
	CloseWrite() error
}

type tcpConnPair struct {
	stream net.Conn
	local  net.Conn
}

type tcpServer struct {
	target string
	dialer net.Dialer

	mu     sync.Mutex
	ln     net.Listener
	closed bool
	conns  map[*tcpConnPair]struct{}

	wg sync.WaitGroup

	ctx    context.Context
	cancel context.CancelFunc
}

func newTCPServer(target string) *tcpServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &tcpServer{
		target: target,
		dialer: net.Dialer{Timeout: tcpDialTimeout},
		conns:  make(map[*tcpConnPair]struct{}),
		ctx:    ctx,
		cancel: cancel,
	}
}

func (s *tcpServer) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		ln.Close()
		return errTCPServerClosed
	}
	s.ln = ln
	s.mu.Unlock()

	for {
		c, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return errTCPServerClosed
			}
			return err
		}
		pair := &tcpConnPair{stream: c}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			return errTCPServerClosed
		}
		s.conns[pair] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			s.handle(pair)
		}()
	}
}

func (s *tcpServer) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	s.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	s.cancel()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		s.forceCloseConns()
		return ctx.Err()
	}
}

func (s *tcpServer) Close() error {
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	s.mu.Unlock()
	s.cancel()
	s.forceCloseConns()
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (s *tcpServer) forceCloseConns() {
	s.mu.Lock()
	type closeTarget struct{ stream, local net.Conn }
	targets := make([]closeTarget, 0, len(s.conns))
	for pair := range s.conns {
		targets = append(targets, closeTarget{stream: pair.stream, local: pair.local})
	}
	s.mu.Unlock()
	for _, t := range targets {
		if t.stream != nil {
			t.stream.SetDeadline(time.Now())
		}
		if t.local != nil {
			t.local.Close()
		}
	}
}

func (s *tcpServer) handle(pair *tcpConnPair) {
	stream := pair.stream
	defer stream.Close()
	defer func() {
		s.mu.Lock()
		delete(s.conns, pair)
		s.mu.Unlock()
	}()

	local, err := s.dialer.DialContext(s.ctx, "tcp", s.target)
	if err != nil {
		slog.Warn("agent: tcp dial failed", "target", s.target, "err", err)
		return
	}
	defer local.Close()

	s.mu.Lock()
	pair.local = local
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		io.Copy(local, stream)
		wg.Done()
		halfCloseWrite(local)
	}()
	go func() {
		io.Copy(stream, local)
		wg.Done()
		halfCloseWrite(stream)
	}()
	wg.Wait()
}

func halfCloseWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}
