package edge

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

func sumToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeTCPAddr: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitTCPUp(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", addr)
}

func newFakeAgentSession(t *testing.T, instanceID string, handler http.HandlerFunc) *AgentSession {
	t.Helper()
	c1, c2 := net.Pipe()

	type result struct {
		sess tunnel.Session
		err  error
	}
	agentCh := make(chan result, 1)
	edgeCh := make(chan result, 1)
	go func() {
		s, err := tunnel.Client(c1)
		agentCh <- result{s, err}
	}()
	go func() {
		s, err := tunnel.Server(c2)
		edgeCh <- result{s, err}
	}()

	ar := <-agentCh
	if ar.err != nil {
		t.Fatalf("agent-side session: %v", ar.err)
	}
	er := <-edgeCh
	if er.err != nil {
		t.Fatalf("edge-side session: %v", er.err)
	}

	ln, err := tunnel.NewListener(ar.sess)
	if err != nil {
		t.Fatalf("tunnel.NewListener: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)

	t.Cleanup(func() {
		srv.Close()
		ln.Close()
		ar.sess.Close("test done")
		er.sess.Close("test done")
	})

	return &AgentSession{
		ID:         randomHex(4),
		InstanceID: instanceID,
		Sess:       er.sess,
		IDGen:      proto.NewEdgeIDGen(),
	}
}

func newEchoAgentSession(t *testing.T, instanceID string) *AgentSession {
	return newFakeAgentSession(t, instanceID, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, "ok\n")
	})
}

func newSlowAgentSession(t *testing.T, instanceID string, hold time.Duration) *AgentSession {
	return newFakeAgentSession(t, instanceID, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(hold)
		io.WriteString(w, "slow-ok\n")
	})
}

func newServerForTest(limits LimitsConfig) *Server {
	s, err := New(Config{
		ControlAddr:  "127.0.0.1:0",
		PublicAddr:   "127.0.0.1:0",
		Domain:       "example.com",
		TokenSHA256:  sumToken("tok"),
		PublicScheme: "http",
		Insecure:     true,
		Limits:       limits,
	})
	if err != nil {
		panic(err)
	}
	return s
}

func TestPerIPLimiterTripsAtBurstAndIsPerIP(t *testing.T) {
	l := newPerIPLimiter(1000, 3, 100)
	ip := "1.2.3.4"
	for i := 0; i < 3; i++ {
		if !l.allow(ip) {
			t.Fatalf("attempt %d within burst should be allowed", i+1)
		}
	}
	if l.allow(ip) {
		t.Fatalf("request past the burst should be limited")
	}

	other := "5.6.7.8"
	if !l.allow(other) {
		t.Fatalf("a different IP must not be affected by another IP's usage")
	}
}

func TestPerIPLimiterMasksIPv6ToSlash48(t *testing.T) {
	l := newPerIPLimiter(0, 1, 10000)

	allowed := 0
	for i := 0; i < 200; i++ {
		ip := fmt.Sprintf("2001:db8:1234:%x::1", i)
		if l.allow(ip) {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatalf("200 addresses spread across 200 distinct /64s within the same /48 got %d allowed, want exactly 1 (they must share one bucket)", allowed)
	}

	other := "2001:db8:9999::1"
	if !l.allow(other) {
		t.Fatalf("an address in a distinct /48 allocation must not be limited by another /48's usage")
	}
}

func TestHandlePublicPerIPLimiterReturns429PastBurst(t *testing.T) {
	s := newServerForTest(LimitsConfig{PerIPBurst: 2, PerIPRate: 1})
	as := newEchoAgentSession(t, "inst-a")
	if _, _, err := s.registry.Bind("svc.example.com", as, true); err != nil {
		t.Fatalf("bind: %v", err)
	}

	get := func() int {
		req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/", nil)
		req.Host = "svc.example.com"
		req.RemoteAddr = "9.9.9.9:5555"
		rec := httptest.NewRecorder()
		s.handlePublic(rec, req)
		return rec.Code
	}

	for i := 0; i < 2; i++ {
		if code := get(); code != http.StatusOK {
			t.Fatalf("request %d within burst = %d, want 200", i+1, code)
		}
	}
	if code := get(); code != http.StatusTooManyRequests {
		t.Fatalf("request past burst = %d, want 429", code)
	}

	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/", nil)
	req.Host = "svc.example.com"
	req.RemoteAddr = "1.1.1.1:5555"
	rec := httptest.NewRecorder()
	s.handlePublic(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Fatalf("a distinct client IP was rejected by another IP's rate limit")
	}
}

func TestHandlePublicUnknownHostReturns404WithoutTouchingLimiter(t *testing.T) {
	s := newServerForTest(LimitsConfig{PerIPBurst: 1, PerIPRate: 1})

	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://nobody-home.example.com/", nil)
		req.Host = "nobody-home.example.com"
		req.RemoteAddr = "2.2.2.2:1"
		rec := httptest.NewRecorder()
		s.handlePublic(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("request %d for an unbound host = %d, want 404 (limiter burst is 1; a 429 here would mean the limiter ran before the host-miss check)", i+1, rec.Code)
		}
	}
}

func TestHandlePublicGlobalInFlightCapReturns429(t *testing.T) {
	s := newServerForTest(LimitsConfig{
		GlobalInFlight:     1,
		PerSessionInFlight: 10,
		PerIPBurst:         100,
		PerIPRate:          1000,
	})
	as := newSlowAgentSession(t, "inst-a", 400*time.Millisecond)
	if _, _, err := s.registry.Bind("svc.example.com", as, true); err != nil {
		t.Fatalf("bind: %v", err)
	}

	const n = 3
	start := make(chan struct{})
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/", nil)
			req.Host = "svc.example.com"
			req.RemoteAddr = fmt.Sprintf("10.0.0.%d:1", i+1)
			rec := httptest.NewRecorder()
			<-start
			s.handlePublic(rec, req)
			codes[i] = rec.Code
		}(i)
	}
	close(start)
	wg.Wait()

	var ok, tooMany int
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			tooMany++
		default:
			t.Fatalf("unexpected status %d among %v", c, codes)
		}
	}
	if ok != 1 || tooMany != n-1 {
		t.Fatalf("codes=%v, want exactly one 200 and %d 429s (global in-flight cap is 1)", codes, n-1)
	}
}

func TestHandlePublicGlobalInFlightCapReleasesBetweenSequentialRequests(t *testing.T) {
	s := newServerForTest(LimitsConfig{
		GlobalInFlight:     2,
		PerSessionInFlight: 1000,
		PerIPBurst:         100000,
		PerIPRate:          1e6,
	})
	as := newEchoAgentSession(t, "inst-a")
	if _, _, err := s.registry.Bind("svc.example.com", as, true); err != nil {
		t.Fatalf("bind: %v", err)
	}

	const n = 50
	for i := 0; i < n; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/", nil)
		req.Host = "svc.example.com"
		req.RemoteAddr = "10.9.0.1:1"
		rec := httptest.NewRecorder()
		s.handlePublic(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("sequential request %d/%d got %d, want 200 — a leaking global in-flight semaphore would eventually exhaust the cap of 2 even though requests run one at a time", i+1, n, rec.Code)
		}
	}
}

func TestHandlePublicPerSessionCapReleasesBetweenSequentialRequests(t *testing.T) {
	s := newServerForTest(LimitsConfig{
		GlobalInFlight:     1000,
		PerSessionInFlight: 1000,
		PerIPBurst:         100000,
		PerIPRate:          1e6,
	})
	as := newEchoAgentSession(t, "inst-a")
	as.streamSem = newGlobalSemaphore(2)
	if _, _, err := s.registry.Bind("svc.example.com", as, true); err != nil {
		t.Fatalf("bind: %v", err)
	}

	const n = 50
	for i := 0; i < n; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/", nil)
		req.Host = "svc.example.com"
		req.RemoteAddr = "10.9.0.2:1"
		rec := httptest.NewRecorder()
		s.handlePublic(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("sequential request %d/%d got %d, want 200 — a leaking per-session stream semaphore would eventually exhaust the cap of 2 even though requests run one at a time", i+1, n, rec.Code)
		}
	}
}

func TestHandlePublicPerSessionCapReturns429(t *testing.T) {
	s := newServerForTest(LimitsConfig{
		GlobalInFlight:     100,
		PerSessionInFlight: 1,
		PerIPBurst:         100,
		PerIPRate:          1000,
	})
	as := newSlowAgentSession(t, "inst-a", 400*time.Millisecond)
	as.streamSem = newGlobalSemaphore(1)
	if _, _, err := s.registry.Bind("svc.example.com", as, true); err != nil {
		t.Fatalf("bind: %v", err)
	}

	const n = 3
	start := make(chan struct{})
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/", nil)
			req.Host = "svc.example.com"
			req.RemoteAddr = fmt.Sprintf("10.0.1.%d:1", i+1)
			rec := httptest.NewRecorder()
			<-start
			s.handlePublic(rec, req)
			codes[i] = rec.Code
		}(i)
	}
	close(start)
	wg.Wait()

	var ok, tooMany int
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			tooMany++
		default:
			t.Fatalf("unexpected status %d among %v", c, codes)
		}
	}
	if ok != 1 || tooMany != n-1 {
		t.Fatalf("codes=%v, want exactly one 200 and %d 429s (per-session cap is 1, global cap is 100)", codes, n-1)
	}
}

func TestHandlePublicDeclaredOversizeBodyReturns413(t *testing.T) {
	s := newServerForTest(LimitsConfig{MaxBodyBytes: 1024})
	as := newEchoAgentSession(t, "inst-a")
	if _, _, err := s.registry.Bind("svc.example.com", as, true); err != nil {
		t.Fatalf("bind: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://svc.example.com/", strings.NewReader("small body"))
	req.Host = "svc.example.com"
	req.ContentLength = 10 * 1024 * 1024
	rec := httptest.NewRecorder()
	s.handlePublic(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 for a declared Content-Length over the cap", rec.Code)
	}
}

type repeatReader struct {
	remaining int
	b         byte
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	for i := range p {
		p[i] = r.b
	}
	r.remaining -= len(p)
	return len(p), nil
}

func TestHandlePublicChunkedOversizeBodyReturns413ViaErrorHandler(t *testing.T) {
	s := newServerForTest(LimitsConfig{MaxBodyBytes: 16})
	as := newEchoAgentSession(t, "inst-a")
	if _, _, err := s.registry.Bind("svc.example.com", as, true); err != nil {
		t.Fatalf("bind: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://svc.example.com/", &repeatReader{remaining: 4096, b: 'x'})
	req.Host = "svc.example.com"
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	s.handlePublic(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 for a chunked body that exceeds the cap (a naive implementation surfaces this as 502)", rec.Code)
	}
}

func TestHandlePublicChunkedOversizeBodyClosesConnection(t *testing.T) {
	s := newServerForTest(LimitsConfig{MaxBodyBytes: 16})
	as := newEchoAgentSession(t, "inst-a")
	if _, _, err := s.registry.Bind("svc.example.com", as, true); err != nil {
		t.Fatalf("bind: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(s.handlePublic))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/", &repeatReader{remaining: 4096, b: 'x'})
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "svc.example.com"
	req.ContentLength = -1

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}
	if !resp.Close {
		t.Fatalf("resp.Close = false, want true — the un-drained oversize body must not be left to poison a reused keep-alive connection")
	}
}

func TestReadHeaderTimeoutEvictsSlowlorisClient(t *testing.T) {
	publicAddr := freeTCPAddr(t)
	controlAddr := freeTCPAddr(t)

	s, err := New(Config{
		ControlAddr:  controlAddr,
		PublicAddr:   publicAddr,
		Domain:       "example.com",
		TokenSHA256:  sumToken("tok"),
		PublicScheme: "http",
		Insecure:     true,
		Limits:       LimitsConfig{ReadHeaderTimeout: 300 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-runErrCh
	})

	waitTCPUp(t, publicAddr)

	conn, err := net.Dial("tcp", publicAddr)
	if err != nil {
		t.Fatalf("dial public listener: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: svc.example.com\r\n")); err != nil {
		t.Fatalf("write partial headers: %v", err)
	}

	start := time.Now()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	_, readErr := conn.Read(buf)
	elapsed := time.Since(start)

	if readErr == nil {
		t.Fatalf("expected the connection to be closed by ReadHeaderTimeout, got a successful read")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("slowloris client was evicted after %s, want close to the 300ms ReadHeaderTimeout", elapsed)
	}
	if elapsed < 250*time.Millisecond {
		t.Fatalf("connection closed suspiciously fast (%s); ReadHeaderTimeout may not be wired to the public listener", elapsed)
	}
	t.Logf("slowloris client evicted after %s (ReadHeaderTimeout=300ms)", elapsed)
}

func TestRedirectToHTTPSPreservesHostAndPath(t *testing.T) {
	s := &Server{cfg: Config{Domain: "ngstone.site"}}
	req := httptest.NewRequest(http.MethodGet, "http://svc.ngstone.site/foo/bar?x=1", nil)
	req.Host = "svc.ngstone.site"
	rec := httptest.NewRecorder()

	s.redirectToHTTPS(rec, req)

	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMovedPermanently)
	}
	want := "https://svc.ngstone.site/foo/bar?x=1"
	if got := rec.Header().Get("Location"); got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
}

func TestRedirectToHTTPSRejectsUnrelatedHost(t *testing.T) {
	s := &Server{cfg: Config{Domain: "ngstone.site"}}
	req := httptest.NewRequest(http.MethodGet, "http://evil.com/", nil)
	req.Host = "evil.com"
	rec := httptest.NewRecorder()

	s.redirectToHTTPS(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d for a Host that does not match the configured domain (open-redirect guard)", rec.Code, http.StatusNotFound)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("Location = %q, want empty; must not echo an unvalidated Host header into a redirect", loc)
	}
}
