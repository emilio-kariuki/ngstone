package agent

import (
	"net"
	"runtime"
	"testing"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

func newTestSessionPair(t *testing.T) (agentSide, edgeSide tunnel.Session, cleanup func()) {
	t.Helper()
	c1, c2 := net.Pipe()

	type result struct {
		sess tunnel.Session
		err  error
	}
	clientCh := make(chan result, 1)
	serverCh := make(chan result, 1)
	go func() {
		s, err := tunnel.Client(c1)
		clientCh <- result{s, err}
	}()
	go func() {
		s, err := tunnel.Server(c2)
		serverCh <- result{s, err}
	}()

	cr := <-clientCh
	if cr.err != nil {
		t.Fatalf("client session: %v", cr.err)
	}
	sr := <-serverCh
	if sr.err != nil {
		t.Fatalf("server session: %v", sr.err)
	}

	return cr.sess, sr.sess, func() {
		cr.sess.Close("test done")
		sr.sess.Close("test done")
	}
}

func TestControlLoopEvictedDoesNotLeakReaderGoroutine(t *testing.T) {
	const n = 30

	runtime.GC()
	before := runtime.NumGoroutine()

	for i := 0; i < n; i++ {
		agentSess, edgeSess, cleanup := newTestSessionPair(t)
		a := New(Config{})
		idgen := proto.NewAgentIDGen()

		done := make(chan struct{})
		go func() {
			a.controlLoop(agentSess, idgen)
			close(done)
		}()

		if err := edgeSess.Control().Write(proto.TypeEvicted, 2, proto.Evicted{
			Hostname: "x.example.com",
			Reason:   "takeover",
		}); err != nil {
			t.Fatalf("write evicted: %v", err)
		}

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("controlLoop did not exit after evicted (iteration %d)", i)
		}
		cleanup()
	}

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	after := runtime.NumGoroutine()

	t.Logf("goroutines before=%d after=%d (ran %d session teardowns through the evicted path)", before, after, n)
	if after > before+5 {
		t.Fatalf("goroutine leak: before=%d after=%d (ran %d session teardowns through the evicted path)", before, after, n)
	}
}
