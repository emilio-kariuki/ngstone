package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

func startTarget(t *testing.T, handler func(net.Conn)) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(c)
		}
	}()
	return ln.Addr().String(), func() {
		ln.Close()
		<-done
	}
}

func startTCPServer(t *testing.T, target string) (streamAddr string, srv *tcpServer, serveErr chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen stream: %v", err)
	}
	srv = newTCPServer(target)
	serveErr = make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	return ln.Addr().String(), srv, serveErr
}

func shutdownServer(srv *tcpServer) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

func echoHandler(c net.Conn) {
	io.Copy(c, c)
	c.Close()
}

func dialStream(t *testing.T, streamAddr string) *net.TCPConn {
	t.Helper()
	cc, err := net.Dial("tcp", streamAddr)
	if err != nil {
		t.Fatalf("dial stream: %v", err)
	}
	if err := cc.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	return cc.(*net.TCPConn)
}

func TestTCPServerEchoesAcrossConnections(t *testing.T) {
	targetAddr, stopTarget := startTarget(t, echoHandler)
	defer stopTarget()
	streamAddr, srv, _ := startTCPServer(t, targetAddr)
	defer shutdownServer(srv)

	for i := 0; i < 5; i++ {
		payload := fmt.Sprintf("ping-%d", i)
		cc := dialStream(t, streamAddr)
		if _, err := cc.Write([]byte(payload)); err != nil {
			t.Fatalf("conn %d write: %v", i, err)
		}
		if err := cc.CloseWrite(); err != nil {
			t.Fatalf("conn %d close write: %v", i, err)
		}
		got, err := io.ReadAll(cc)
		if err != nil {
			t.Fatalf("conn %d read echo: %v", i, err)
		}
		if string(got) != payload {
			t.Fatalf("conn %d echo = %q, want %q", i, got, payload)
		}
		cc.Close()
	}
}

func TestTCPServerPropagatesClientHalfCloseToTarget(t *testing.T) {
	targetAddr, stopTarget := startTarget(t, func(c net.Conn) {
		data, _ := io.ReadAll(c)
		c.Write(append([]byte("reply:"), data...))
		c.Close()
	})
	defer stopTarget()
	streamAddr, srv, _ := startTCPServer(t, targetAddr)
	defer shutdownServer(srv)

	cc := dialStream(t, streamAddr)
	if _, err := cc.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := cc.CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}
	got, err := io.ReadAll(cc)
	if err != nil {
		t.Fatalf("read reply: %v (target likely never saw EOF: stream->local half-close not propagated)", err)
	}
	if string(got) != "reply:hello" {
		t.Fatalf("reply = %q, want %q; the target only replies after EOF, so this proves the client half-close reached it", got, "reply:hello")
	}
	cc.Close()
}

func TestTCPServerHalfCloseReverseDirectionReachesClient(t *testing.T) {
	targetAddr, stopTarget := startTarget(t, func(c net.Conn) {
		c.Write([]byte("push-data"))
		c.Close()
	})
	defer stopTarget()
	streamAddr, srv, _ := startTCPServer(t, targetAddr)
	defer shutdownServer(srv)

	cc := dialStream(t, streamAddr)
	got, err := io.ReadAll(cc)
	if err != nil {
		t.Fatalf("read push: %v; the client kept its write side open, so only a stream write half-close can deliver EOF", err)
	}
	if string(got) != "push-data" {
		t.Fatalf("pushed payload = %q, want %q", got, "push-data")
	}
	cc.Close()
}

func realConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen carrier: %v", err)
	}
	defer ln.Close()

	type res struct {
		c   net.Conn
		err error
	}
	accepted := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- res{c, err}
	}()

	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial carrier: %v", err)
	}
	ar := <-accepted
	if ar.err != nil {
		t.Fatalf("accept carrier: %v", ar.err)
	}
	return dialed, ar.c
}

func newRealTCPSessionPair(t *testing.T) (agentSess, remoteSess tunnel.Session, cleanup func()) {
	t.Helper()
	agentCarrier, remoteCarrier := realConnPair(t)

	type res struct {
		sess tunnel.Session
		err  error
	}
	agentCh := make(chan res, 1)
	remoteCh := make(chan res, 1)
	go func() {
		s, err := tunnel.Client(agentCarrier)
		agentCh <- res{s, err}
	}()
	go func() {
		s, err := tunnel.Server(remoteCarrier)
		remoteCh <- res{s, err}
	}()

	ar := <-agentCh
	if ar.err != nil {
		t.Fatalf("agent session: %v", ar.err)
	}
	rr := <-remoteCh
	if rr.err != nil {
		t.Fatalf("remote session: %v", rr.err)
	}

	return ar.sess, rr.sess, func() {
		ar.sess.Close("test done")
		rr.sess.Close("test done")
		agentCarrier.Close()
		remoteCarrier.Close()
	}
}

func TestTCPServerHalfCloseOverYamuxStreamReachesClient(t *testing.T) {
	targetAddr, stopTarget := startTarget(t, func(c net.Conn) {
		c.Write([]byte("srv-bytes"))
		c.Close()
	})
	defer stopTarget()

	agentSess, remoteSess, cleanup := newRealTCPSessionPair(t)
	defer cleanup()

	ln, err := tunnel.NewListener(agentSess)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	srv := newTCPServer(targetAddr)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	defer shutdownServer(srv)

	openCtx, cancelOpen := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelOpen()
	stream, err := remoteSess.OpenStream(openCtx, proto.StreamOpen{
		Kind:       proto.KindTCP,
		Host:       "tcp-target",
		ReqID:      "r-halfclose",
		ClientAddr: "198.51.100.7:5555",
	})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer stream.Close()

	if _, err := stream.Write([]byte("x")); err != nil {
		t.Fatalf("write initial byte: %v", err)
	}

	if err := stream.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("read from stream: %v; expected a clean EOF from the server-first close within the deadline (bug: stream-side half-close is a silent no-op, so the FIN never propagates and the read hangs until yamux StreamCloseTimeout)", err)
	}
	if string(got) != "srv-bytes" {
		t.Fatalf("stream payload = %q, want %q", got, "srv-bytes")
	}
}

func TestTCPServerDialFailureClosesStream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve dead port: %v", err)
	}
	deadAddr := ln.Addr().String()
	ln.Close()

	streamAddr, srv, _ := startTCPServer(t, deadAddr)
	defer shutdownServer(srv)

	cc := dialStream(t, streamAddr)
	got, err := io.ReadAll(cc)
	if err != nil {
		t.Fatalf("read after dial failure: %v, want a clean EOF", err)
	}
	if len(got) != 0 {
		t.Fatalf("read after dial failure returned %q, want no data", got)
	}
	cc.Close()
}

func TestTCPServerDialFailureDeregistersConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve dead port: %v", err)
	}
	deadAddr := ln.Addr().String()
	ln.Close()

	streamAddr, srv, _ := startTCPServer(t, deadAddr)
	defer shutdownServer(srv)

	cc := dialStream(t, streamAddr)
	io.ReadAll(cc)
	cc.Close()

	deadline := time.Now().Add(2 * time.Second)
	for {
		srv.mu.Lock()
		n := len(srv.conns)
		srv.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("s.conns retained %d pair(s) after dial failure, want 0 (map leak)", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTCPServerHandleAbortsWhenClosedWhileDialInFlight(t *testing.T) {
	blockCh := make(chan struct{})
	defer close(blockCh)

	targetAccepted := make(chan net.Conn, 1)
	targetAddr, stopTarget := startTarget(t, func(c net.Conn) {
		select {
		case targetAccepted <- c:
		default:
			c.Close()
		}
		<-blockCh
	})
	defer stopTarget()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen stream: %v", err)
	}
	srv := newTCPServer(targetAddr)

	const dialDelay = 300 * time.Millisecond
	srv.dialer.Control = func(_, _ string, _ syscall.RawConn) error {
		time.Sleep(dialDelay)
		return nil
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	cc := dialStream(t, ln.Addr().String())
	defer cc.Close()

	registerDeadline := time.Now().Add(2 * time.Second)
	for {
		srv.mu.Lock()
		n := len(srv.conns)
		srv.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(registerDeadline) {
			t.Fatalf("dialed conn never registered in srv.conns before the delayed dial completed")
		}
		time.Sleep(5 * time.Millisecond)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	shutdownErr := srv.Shutdown(shutdownCtx)
	cancel()
	if shutdownErr == nil {
		t.Fatalf("Shutdown should have timed out while the dial was still in flight")
	}

	select {
	case tc := <-targetAccepted:
		defer tc.Close()
	case <-time.After(dialDelay + 2*time.Second):
		t.Fatalf("target never accepted the delayed dial")
	}

	drainDeadline := time.Now().Add(2 * time.Second)
	for {
		srv.mu.Lock()
		n := len(srv.conns)
		srv.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(drainDeadline) {
			t.Fatalf("srv.conns retained the pair after the dial finished post-shutdown; handle() should have aborted instead of copying on an already-closed server (fix D.1 regression: it blocks forever reading from the still-open target conn)")
		}
		time.Sleep(10 * time.Millisecond)
	}

	select {
	case <-serveErr:
	default:
	}
}

func TestTCPServerShutdownDrainsActiveConnsNoLeak(t *testing.T) {
	runtime.GC()
	before := runtime.NumGoroutine()

	const rounds = 8
	for i := 0; i < rounds; i++ {
		accepted := make(chan struct{}, 1)
		targetAddr, stopTarget := startTarget(t, func(c net.Conn) {
			select {
			case accepted <- struct{}{}:
			default:
			}
			io.Copy(c, c)
			c.Close()
		})

		streamAddr, srv, serveErr := startTCPServer(t, targetAddr)

		cc := dialStream(t, streamAddr)

		select {
		case <-accepted:
		case <-time.After(2 * time.Second):
			t.Fatalf("round %d: target never accepted the tunneled conn", i)
		}

		cc.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := cc.Write([]byte("ping")); err != nil {
			t.Fatalf("round %d: write to tunneled conn: %v", i, err)
		}
		echo := make([]byte, 4)
		if _, err := io.ReadFull(cc, echo); err != nil {
			t.Fatalf("round %d: conn not actively pumping before shutdown: %v", i, err)
		}
		cc.SetDeadline(time.Time{})

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		err := srv.Shutdown(shutdownCtx)
		cancel()
		if err == nil {
			t.Fatalf("round %d: Shutdown returned nil while a conn was still active; it did not wait for the connection to drain", i)
		}

		cc.Close()

		drainCtx, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
		if err := srv.Shutdown(drainCtx); err != nil {
			t.Fatalf("round %d: Shutdown after releasing the conn = %v, want a clean drain", i, err)
		}
		cancel2()

		select {
		case <-serveErr:
		case <-time.After(2 * time.Second):
			t.Fatalf("round %d: Serve did not return after Shutdown", i)
		}
		stopTarget()
	}

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	after := runtime.NumGoroutine()

	t.Logf("goroutines before=%d after=%d (ran %d serve/traffic/shutdown cycles)", before, after, rounds)
	if after > before+5 {
		t.Fatalf("goroutine leak: before=%d after=%d", before, after)
	}
}

func TestTCPServerCloseForceClosesActiveConnWithHoldingTarget(t *testing.T) {
	runtime.GC()
	before := runtime.NumGoroutine()

	holdCh := make(chan struct{})
	defer close(holdCh)

	received := make(chan struct{}, 1)
	targetAddr, stopTarget := startTarget(t, func(c net.Conn) {
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		received <- struct{}{}
		<-holdCh
		c.Close()
	})
	defer stopTarget()

	streamAddr, srv, serveErr := startTCPServer(t, targetAddr)

	cc := dialStream(t, streamAddr)
	cc.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := cc.Write([]byte("ping")); err != nil {
		t.Fatalf("write to tunneled conn: %v", err)
	}

	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatalf("target never received the tunneled bytes")
	}

	drainDeadline := time.Now().Add(2 * time.Second)
	for {
		srv.mu.Lock()
		n := len(srv.conns)
		srv.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(drainDeadline) {
			t.Fatalf("dialed conn never registered in srv.conns before Close")
		}
		time.Sleep(5 * time.Millisecond)
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- srv.Close() }()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Close did not return promptly")
	}

	cc.Close()

	connsDeadline := time.Now().Add(3 * time.Second)
	for {
		srv.mu.Lock()
		n := len(srv.conns)
		srv.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(connsDeadline) {
			t.Fatalf("s.conns retained %d pair(s) after Close, want 0 (handler leaked because local conn was never force-closed)", n)
		}
		time.Sleep(10 * time.Millisecond)
	}

	select {
	case <-serveErr:
	case <-time.After(2 * time.Second):
		t.Fatalf("Serve did not return after Close")
	}

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	after := runtime.NumGoroutine()

	t.Logf("goroutines before=%d after=%d", before, after)
	if after > before+5 {
		t.Fatalf("goroutine leak: before=%d after=%d", before, after)
	}
}
