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

type tcpServer struct {
	target string
	dialer net.Dialer

	mu     sync.Mutex
	ln     net.Listener
	closed bool

	wg sync.WaitGroup
}

func newTCPServer(target string) *tcpServer {
	return &tcpServer{
		target: target,
		dialer: net.Dialer{Timeout: tcpDialTimeout},
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
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(c)
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

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *tcpServer) Close() error {
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	s.mu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (s *tcpServer) handle(stream net.Conn) {
	defer stream.Close()

	local, err := s.dialer.Dial("tcp", s.target)
	if err != nil {
		slog.Warn("agent: tcp dial failed", "target", s.target, "err", err)
		return
	}
	defer local.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(local, stream)
		halfCloseWrite(local)
	}()
	go func() {
		defer wg.Done()
		io.Copy(stream, local)
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
