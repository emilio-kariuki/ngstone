package edge

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPerIPInflightAcquireRelease(t *testing.T) {
	p := newPerIPInflight(2)

	r1, ok1 := p.acquire("203.0.113.7")
	r2, ok2 := p.acquire("203.0.113.7")
	if !ok1 || !ok2 {
		t.Fatal("first two acquisitions from one address must succeed")
	}
	if _, ok := p.acquire("203.0.113.7"); ok {
		t.Fatal("third acquisition from the same address must be refused")
	}
	rOther, ok := p.acquire("198.51.100.9")
	if !ok {
		t.Fatal("a different address has its own budget")
	}

	r1()
	r1() // double release must not free a second slot
	if got := p.inUse("203.0.113.7"); got != 1 {
		t.Fatalf("in use after one release = %d, want 1", got)
	}
	r3, ok := p.acquire("203.0.113.7")
	if !ok {
		t.Fatal("a released slot must be reusable")
	}
	r2()
	r3()
	rOther()

	p.mu.Lock()
	n := len(p.counts)
	p.mu.Unlock()
	if n != 0 {
		t.Fatalf("map keeps %d idle entries; it must only hold addresses with work in flight", n)
	}
}

func TestPerIPInflightGroupsIPv6By48(t *testing.T) {
	p := newPerIPInflight(1)
	release, ok := p.acquire("2001:db8:1:aaaa::1")
	if !ok {
		t.Fatal("first IPv6 acquisition must succeed")
	}
	defer release()
	if _, ok := p.acquire("2001:db8:1:bbbb::2"); ok {
		t.Fatal("addresses in the same /48 must share a budget")
	}
	if r, ok := p.acquire("2001:db8:2::1"); !ok {
		t.Fatal("a different /48 has its own budget")
	} else {
		r()
	}
}

func TestLimitsDefaultsAndValidationForClientLimits(t *testing.T) {
	l, err := LimitsConfig{}.withDefaults()
	if err != nil {
		t.Fatalf("withDefaults: %v", err)
	}
	if l.PerIPInFlight != DefaultPerIPInFlight || l.ClientIdleTimeout != DefaultClientIdleTimeout || l.TCPIdleTimeout != DefaultTCPIdleTimeout {
		t.Fatalf("defaults not applied: %+v", l)
	}
	for _, bad := range []LimitsConfig{{PerIPInFlight: -1}, {ClientIdleTimeout: -time.Second}, {TCPIdleTimeout: -time.Second}} {
		if _, err := bad.withDefaults(); err == nil {
			t.Fatalf("withDefaults(%+v) accepted a negative value", bad)
		}
	}
}

func newClientLimitsServer(t *testing.T, limits LimitsConfig) *Server {
	t.Helper()
	limits.PerIPRate = 100000
	limits.PerIPBurst = 100000
	s, err := New(Config{
		ControlAddr:  freeTCPAddr(t),
		PublicAddr:   freeTCPAddr(t),
		Domain:       "example.com",
		TokenSHA256:  sumToken("tok"),
		PublicScheme: "http",
		Insecure:     true,
		Limits:       limits,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func runServer(t *testing.T, s *Server) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	waitTCPUp(t, s.cfg.PublicAddr)
}

// One address cannot take more than its share; other addresses are still
// served while it is at its cap.
func TestHandlePublicPerIPCap(t *testing.T) {
	s := newClientLimitsServer(t, LimitsConfig{PerIPInFlight: 2})

	hold := make(chan struct{})
	entered := make(chan struct{}, 8)
	as := newFakeAgentSession(t, "inst-perip", func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-hold
		io.WriteString(w, "ok")
	})
	if _, _, err := s.registry.Bind("svc.example.com", as, true, nil); err != nil {
		t.Fatalf("bind: %v", err)
	}

	serve := func(remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		s.handlePublic(rec, req)
		return rec
	}

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rec := serve("203.0.113.7:4000"); rec.Code != http.StatusOK {
				t.Errorf("held request finished with %d, want 200", rec.Code)
			}
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("held requests never reached the agent")
		}
	}

	if rec := serve("203.0.113.7:4001"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third concurrent request from one address = %d, want 429", rec.Code)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if rec := serve("198.51.100.9:4000"); rec.Code != http.StatusOK {
			t.Errorf("request from another address = %d, want 200", rec.Code)
		}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("a different address was blocked by the first address's cap")
	}

	close(hold)
	wg.Wait()
	if n := s.perIP.inUse("203.0.113.7"); n != 0 {
		t.Fatalf("per-IP slots still held after requests finished: %d", n)
	}
}

// A client that sends headers and then stops sending its body gets a 408
// after the idle timeout, and its slot is free again.
func TestStalledRequestBodyGets408AndFreesSlot(t *testing.T) {
	s := newClientLimitsServer(t, LimitsConfig{PerIPInFlight: 1, ClientIdleTimeout: 300 * time.Millisecond})
	if _, _, err := s.registry.Bind("svc.example.com", newEchoAgentSession(t, "inst-stall"), true, nil); err != nil {
		t.Fatalf("bind: %v", err)
	}
	runServer(t, s)

	conn, err := net.Dial("tcp", s.cfg.PublicAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	io.WriteString(conn, "POST / HTTP/1.1\r\nHost: svc.example.com\r\nContent-Length: 100\r\n\r\n0123456789")
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no response to a stalled upload within 5s: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("stalled upload got %d, want 408", resp.StatusCode)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("stalled upload took %v to be cut off with a 300ms idle timeout", elapsed)
	}

	// The per-IP cap is 1, so this only succeeds if the stalled request
	// released its slot.
	status, _, err := publicGet(s.cfg.PublicAddr, "svc.example.com", "/")
	if err != nil || status != http.StatusOK {
		t.Fatalf("follow-up request status=%d err=%v; the stalled request kept its slot", status, err)
	}
}

// A client that stops reading its response is cut off after the idle
// timeout instead of holding its request slot forever.
func TestStalledResponseReaderIsCutOff(t *testing.T) {
	s := newClientLimitsServer(t, LimitsConfig{ClientIdleTimeout: 300 * time.Millisecond})

	as := newFakeAgentSession(t, "inst-slowread", func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 64<<10)
		for {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			http.NewResponseController(w).Flush()
		}
	})
	if _, _, err := s.registry.Bind("svc.example.com", as, true, nil); err != nil {
		t.Fatalf("bind: %v", err)
	}
	runServer(t, s)

	conn, err := net.Dial("tcp", s.cfg.PublicAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET /big HTTP/1.1\r\nHost: svc.example.com\r\n\r\n")
	// Never read the response.

	waitInUse := func(want int, within time.Duration, msg string) {
		t.Helper()
		deadline := time.Now().Add(within)
		for s.perIP.inUse("127.0.0.1") != want {
			if time.Now().After(deadline) {
				t.Fatal(msg)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitInUse(1, 5*time.Second, "request never became in flight")
	waitInUse(0, 10*time.Second, "edge kept the request slot for a client that stopped reading its response")
}

// Quiet streams such as SSE must survive the idle timeout: the write
// deadline only applies while a write is blocked.
func TestQuietStreamOutlivesClientIdleTimeout(t *testing.T) {
	s := newClientLimitsServer(t, LimitsConfig{ClientIdleTimeout: 200 * time.Millisecond})
	as := newFakeAgentSession(t, "inst-sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < 3; i++ {
			io.WriteString(w, "data: tick\n\n")
			http.NewResponseController(w).Flush()
			time.Sleep(500 * time.Millisecond)
		}
	})
	if _, _, err := s.registry.Bind("svc.example.com", as, true, nil); err != nil {
		t.Fatalf("bind: %v", err)
	}
	runServer(t, s)

	status, body, err := publicGet(s.cfg.PublicAddr, "svc.example.com", "/events")
	if err != nil || status != http.StatusOK {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if got := strings.Count(body, "data: tick"); got != 3 {
		t.Fatalf("got %d events, want 3; a quiet stream was cut by the idle timeout", got)
	}
}

func TestTCPIdleTimeoutClosesQuietConnections(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()
	fx.mgr.idleTimeout = 300 * time.Millisecond

	port, err := fx.mgr.bind(fx.as, 0, "example.com", nil)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	busy := dialPort(t, port)
	defer busy.Close()
	quiet := dialPort(t, port)
	defer quiet.Close()

	busyErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		for i := 0; i < 12; i++ {
			busy.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := busy.Write([]byte("x")); err != nil {
				busyErr <- err
				return
			}
			if _, err := io.ReadFull(busy, buf); err != nil {
				busyErr <- err
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		busyErr <- nil
	}()

	quiet.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := quiet.Read(make([]byte, 1)); err == nil {
		t.Fatal("quiet connection received data")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("quiet connection was not closed by the edge within 5s")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("quiet connection closed after %v with a 300ms idle timeout", elapsed)
	}

	if err := <-busyErr; err != nil {
		t.Fatalf("busy connection was cut off: %v", err)
	}
}

func TestTCPPerIPCap(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()
	fx.mgr.perIP = newPerIPInflight(1)

	port, err := fx.mgr.bind(fx.as, 0, "example.com", nil)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	first := dialPort(t, port)
	defer first.Close()
	first.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(first, "a")
	if _, err := io.ReadFull(first, make([]byte, 1)); err != nil {
		t.Fatalf("first connection did not echo: %v", err)
	}

	second := dialPort(t, port)
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("second connection from the same address was served past the cap")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("second connection was neither served nor closed")
	}

	io.WriteString(first, "b")
	if _, err := io.ReadFull(first, make([]byte, 1)); err != nil {
		t.Fatalf("first connection broke when the second was refused: %v", err)
	}
}

func publicGet(addr, host, path string) (int, string, error) {
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+path, nil)
	if err != nil {
		return 0, "", err
	}
	req.Host = host
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), err
}
