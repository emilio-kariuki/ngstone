package agent

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"ngstone/internal/tunnel"
)

// startSilentEdge accepts control connections, completes the yamux setup, and
// then never answers on the control stream: the shape of a wedged edge whose
// transport layer is alive but whose control goroutine is stuck.
func startSilentEdge(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var sessions []tunnel.Session
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				s, err := tunnel.Server(c)
				if err != nil {
					c.Close()
					return
				}
				mu.Lock()
				sessions = append(sessions, s)
				mu.Unlock()
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, s := range sessions {
			s.Close("test done")
		}
	})
	return ln.Addr().String()
}

func TestVerifyTimesOutWhenEdgeNeverAnswers(t *testing.T) {
	prev := handshakeTimeout
	handshakeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { handshakeTimeout = prev })

	addr := startSilentEdge(t)

	errCh := make(chan error, 1)
	go func() {
		errCh <- Verify(context.Background(), Config{ControlAddr: addr, Token: "t", Insecure: true})
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Verify succeeded against an edge that never replied")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Verify still blocked 5s after a 200ms handshake timeout; the control read has no deadline")
	}
}

func TestVerifyReturnsPromptlyOnContextCancel(t *testing.T) {
	prev := handshakeTimeout
	handshakeTimeout = time.Minute
	t.Cleanup(func() { handshakeTimeout = prev })

	addr := startSilentEdge(t)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- Verify(ctx, Config{ControlAddr: addr, Token: "t", Insecure: true})
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Verify succeeded against an edge that never replied")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Verify ignored context cancellation while waiting for the auth reply")
	}
}

func TestRunReturnsPromptlyOnContextCancelDuringHandshake(t *testing.T) {
	prev := handshakeTimeout
	handshakeTimeout = time.Minute
	t.Cleanup(func() { handshakeTimeout = prev })

	addr := startSilentEdge(t)

	a := New(Config{ControlAddr: addr, Token: "t", Insecure: true, TargetURL: "http://127.0.0.1:1"})
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- a.Run(ctx) }()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned %v after cancellation, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation; SIGTERM/Ctrl-C is dead during the handshake")
	}
}
