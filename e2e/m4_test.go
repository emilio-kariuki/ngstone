package e2e

import (
	"bufio"
	"context"
	"expvar"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ngstone/internal/agent"
	"ngstone/internal/edge"
	"ngstone/internal/inspect"
)

type inProc struct {
	publicAddr string
	hostname   string
	store      *inspect.Store
}

func startInProcess(t *testing.T, subdomain, targetURL string, maxBody int64) inProc {
	t.Helper()
	return startInProcessWithAccess(t, subdomain, targetURL, maxBody, inProcAccess{})
}

type inProcAccess struct {
	basicAuthSHA256 []string
	basicAuthRealm  string
	allowCIDRs      []string
	limits          edge.LimitsConfig
}

func startInProcessWithAccess(t *testing.T, subdomain, targetURL string, maxBody int64, access inProcAccess) inProc {
	t.Helper()

	token := "e2e-inproc-token"
	domain := "tun.example.com"
	hostname := subdomain + "." + domain
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)

	limits := access.limits
	if maxBody > 0 {
		limits.MaxBodyBytes = maxBody
	}

	edgeSrv, err := edge.New(edge.Config{
		ControlAddr:  controlAddr,
		PublicAddr:   publicAddr,
		Domain:       domain,
		TokenSHA256:  mustSHA256(token),
		PublicScheme: "http",
		Insecure:     true,
		Limits:       limits,
	})
	if err != nil {
		t.Fatalf("edge.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go edgeSrv.Run(ctx)
	waitForPort(t, controlAddr)

	store := inspect.NewStore()
	agt := agent.New(agent.Config{
		ControlAddr:     controlAddr,
		Token:           token,
		Subdomain:       subdomain,
		TargetURL:       targetURL,
		Insecure:        true,
		Store:           store,
		BasicAuthSHA256: access.basicAuthSHA256,
		BasicAuthRealm:  access.basicAuthRealm,
		AllowCIDRs:      access.allowCIDRs,
	})
	go agt.Run(ctx)
	if len(access.basicAuthSHA256) == 0 && access.basicAuthRealm == "" && len(access.allowCIDRs) == 0 {
		waitBound(t, publicAddr, hostname)
	} else {
		waitBoundAny(t, publicAddr, hostname, "/", 10*time.Second)
	}

	return inProc{publicAddr: publicAddr, hostname: hostname, store: store}
}

func writeReady(w http.ResponseWriter) bool {
	w.WriteHeader(http.StatusOK)
	return true
}

func TestWebSocketEchoSession(t *testing.T) {
	const upgradeProto = "websocket"

	serverGone := make(chan struct{}, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/__ngstone_ready", func(w http.ResponseWriter, r *http.Request) {
		writeReady(w)
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), upgradeProto) {
			http.Error(w, "expected upgrade", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() {
			conn.Close()
			select {
			case serverGone <- struct{}{}:
			default:
			}
		}()
		if _, err := brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
			return
		}
		if err := brw.Flush(); err != nil {
			return
		}
		io.Copy(conn, brw)
	})

	origin := httptest.NewServer(mux)
	defer origin.Close()

	h := startInProcess(t, "ws", origin.URL, 0)

	conn, err := net.DialTimeout("tcp", h.publicAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial edge: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	handshake := "GET /ws HTTP/1.1\r\n" +
		"Host: " + h.hostname + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	if _, err := io.WriteString(conn, handshake); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("handshake status = %q, want 101 Switching Protocols", strings.TrimSpace(statusLine))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read handshake headers: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	roundTrip := func(payload string) {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(conn, payload); err != nil {
			t.Fatalf("write %q: %v", payload, err)
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(br, buf); err != nil {
			t.Fatalf("read echo of %q: %v", payload, err)
		}
		if string(buf) != payload {
			t.Fatalf("echo = %q, want %q", buf, payload)
		}
	}

	for i := 0; i < 5; i++ {
		roundTrip(fmt.Sprintf("frame-%d-abcdefghij\n", i))
	}

	deadline := time.Now().Add(3 * time.Second)
	var entry *inspect.Exchange
	for time.Now().Before(deadline) {
		for _, e := range h.store.List() {
			if e.Kind == inspect.KindUpgrade {
				entry = e
			}
		}
		if entry != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if entry == nil {
		t.Fatal("no upgrade exchange appeared in the inspector while the socket was still open")
	}
	if entry.Resp.Status != http.StatusSwitchingProtocols {
		t.Fatalf("captured upgrade status = %d, want 101", entry.Resp.Status)
	}

	idle := 2 * time.Second
	if testing.Short() {
		idle = 750 * time.Millisecond
	}
	time.Sleep(idle)

	for i := 0; i < 5; i++ {
		roundTrip(fmt.Sprintf("after-idle-%d-klmnopqrst\n", i))
	}

	conn.Close()

	select {
	case <-serverGone:
	case <-time.After(5 * time.Second):
		t.Fatal("local app's socket did not tear down within 5s of client close; teardown did not propagate through the tunnel")
	}
}

func TestSSEStream(t *testing.T) {
	seconds := 3
	if testing.Short() {
		seconds = 2
	}
	if v := os.Getenv("NGSTONE_E2E_SSE_SECONDS"); v != "" {
		if testing.Short() {
			t.Skip("skipping env-configured SSE duration in -short mode")
		}
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			t.Fatalf("NGSTONE_E2E_SSE_SECONDS=%q must be a positive integer", v)
		}
		seconds = n
	}

	const cadence = 100 * time.Millisecond
	wantEvents := int(time.Duration(seconds) * time.Second / cadence)

	mux := http.NewServeMux()
	mux.HandleFunc("/__ngstone_ready", func(w http.ResponseWriter, r *http.Request) {
		writeReady(w)
	})
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}
		flusher.Flush()
		ticker := time.NewTicker(cadence)
		defer ticker.Stop()
		for i := 0; i < wantEvents; i++ {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
			fmt.Fprintf(w, "data: event-%d\n\n", i)
			flusher.Flush()
		}
	})

	origin := httptest.NewServer(mux)
	defer origin.Close()

	h := startInProcess(t, "sse", origin.URL, 0)

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, "http://"+h.publicAddr+"/sse", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = h.hostname

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /sse: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}

	arrivals := make(chan time.Duration, wantEvents+4)
	readErr := make(chan error, 1)
	go func() {
		br := bufio.NewReader(resp.Body)
		for {
			line, err := br.ReadString('\n')
			if strings.HasPrefix(line, "data:") {
				arrivals <- time.Since(start)
			}
			if err != nil {
				readErr <- err
				return
			}
		}
	}()

	overall := time.Duration(seconds+15) * time.Second
	hardDeadline := time.After(overall)

	var firstAt, lastAt time.Duration
	got := 0
	for got < wantEvents {
		select {
		case at := <-arrivals:
			if got == 0 {
				firstAt = at
			}
			lastAt = at
			got++
		case err := <-readErr:
			t.Fatalf("SSE read ended after %d/%d events: %v", got, wantEvents, err)
		case <-hardDeadline:
			t.Fatalf("only received %d/%d SSE events within %s; stream stalled or was buffered", got, wantEvents, overall)
		}
	}

	t.Logf("SSE: %d events over %s, first at %s, last at %s", got, time.Duration(seconds)*time.Second, firstAt, lastAt)

	if firstAt > 750*time.Millisecond {
		t.Fatalf("first SSE event arrived after %s; a streaming pipe should deliver it in well under a second (response is being buffered)", firstAt)
	}

	minSpread := time.Duration(seconds) * time.Second / 2
	if lastAt-firstAt < minSpread {
		t.Fatalf("all events arrived within %s of each other (first=%s last=%s); expected incremental delivery spread over ~%s, so the stream was buffered and flushed at the end", lastAt-firstAt, firstAt, lastAt, time.Duration(seconds)*time.Second)
	}
}

func rawRequestStatus(t *testing.T, publicAddr, hostname string, header, body string) int {
	t.Helper()

	conn, err := net.DialTimeout("tcp", publicAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial edge: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(15 * time.Second))

	statusCh := make(chan int, 1)
	errCh := make(chan error, 1)
	go func() {
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			errCh <- err
			return
		}
		resp.Body.Close()
		statusCh <- resp.StatusCode
	}()

	full := header + body
	if _, err := io.WriteString(conn, full); err != nil {
		select {
		case status := <-statusCh:
			return status
		default:
		}
	}

	select {
	case status := <-statusCh:
		return status
	case err := <-errCh:
		t.Fatalf("read response: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatalf("timed out waiting for a response status")
	}
	return 0
}

func TestOversizedBodyReturns413(t *testing.T) {
	const bodyCap = 64 << 10

	mux := http.NewServeMux()
	mux.HandleFunc("/__ngstone_ready", func(w http.ResponseWriter, r *http.Request) {
		writeReady(w)
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})

	origin := httptest.NewServer(mux)
	defer origin.Close()

	h := startInProcess(t, "big", origin.URL, bodyCap)

	t.Run("declared_length", func(t *testing.T) {
		declared := int64(bodyCap) * 8
		header := "POST /upload HTTP/1.1\r\n" +
			"Host: " + h.hostname + "\r\n" +
			"Content-Length: " + strconv.FormatInt(declared, 10) + "\r\n" +
			"Content-Type: application/octet-stream\r\n" +
			"\r\n"
		body := strings.Repeat("x", 4096)
		status := rawRequestStatus(t, h.publicAddr, h.hostname, header, body)
		if status != http.StatusRequestEntityTooLarge {
			t.Fatalf("declared-length oversize body: status = %d, want 413", status)
		}
	})

	t.Run("chunked_unknown_length", func(t *testing.T) {
		header := "POST /upload HTTP/1.1\r\n" +
			"Host: " + h.hostname + "\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Content-Type: application/octet-stream\r\n" +
			"\r\n"

		var b strings.Builder
		const chunkSize = 8192
		chunk := strings.Repeat("y", chunkSize)
		total := 0
		for total < bodyCap*4 {
			fmt.Fprintf(&b, "%x\r\n%s\r\n", chunkSize, chunk)
			total += chunkSize
		}
		b.WriteString("0\r\n\r\n")

		status := rawRequestStatus(t, h.publicAddr, h.hostname, header, b.String())
		if status == http.StatusBadGateway {
			t.Fatalf("chunked oversize body: status = 502, want 413 (the MaxBytesReader trip is surfacing as a proxy error instead of a real 413)")
		}
		if status != http.StatusRequestEntityTooLarge {
			t.Fatalf("chunked oversize body: status = %d, want 413", status)
		}
	})
}

func activeUpgradesGauge() int64 {
	v := expvar.Get("ngstoned_active_upgrades")
	if v == nil {
		return 0
	}
	iv, ok := v.(*expvar.Int)
	if !ok {
		return 0
	}
	return iv.Value()
}

func rejectedUpgradeCapCounter() int64 {
	v := expvar.Get("ngstoned_rejected_upgrade_cap_total")
	if v == nil {
		return 0
	}
	iv, ok := v.(*expvar.Int)
	if !ok {
		return 0
	}
	return iv.Value()
}

func waitForActiveUpgradesDelta(t *testing.T, baseline, want int64, timeout time.Duration, context string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for {
		if got := activeUpgradesGauge() - baseline; got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: ngstoned_active_upgrades delta = %d within %s, want %d (streams were not genuinely established)",
				context, activeUpgradesGauge()-baseline, timeout, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func waitForActiveUpgradesBaseline(t *testing.T, baseline int64, timeout time.Duration, context string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for {
		if activeUpgradesGauge() == baseline {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: ngstoned_active_upgrades did not return to baseline %d within %s; got %d",
				context, baseline, timeout, activeUpgradesGauge())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func openIdleWebSocket(t *testing.T, publicAddr, hostname, path string) (net.Conn, bool) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", publicAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial edge: %v", err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	handshake := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + hostname + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	if _, err := io.WriteString(conn, handshake); err != nil {
		conn.Close()
		t.Fatalf("write handshake: %v", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		t.Fatalf("read status line: %v", err)
	}
	ok := strings.Contains(statusLine, "101")
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, false
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	conn.SetDeadline(time.Time{})
	return conn, ok
}

func idleWebSocketHijackHandler(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err := brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		return
	}
	if err := brw.Flush(); err != nil {
		return
	}
	io.Copy(io.Discard, brw)
}

func TestIdleWebSocketsDoNotStarveNormalHTTP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/__ngstone_ready", func(w http.ResponseWriter, r *http.Request) {
		writeReady(w)
	})
	mux.HandleFunc("/ws-idle", idleWebSocketHijackHandler)
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	origin := httptest.NewServer(mux)
	defer origin.Close()

	h := startInProcessWithAccess(t, "ws-starve", origin.URL, 0, inProcAccess{
		limits: edge.LimitsConfig{
			GlobalInFlight:     4,
			PerSessionInFlight: 4,
		},
	})

	const n = 8
	conns := make([]net.Conn, 0, n)
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	baseline := activeUpgradesGauge()

	for i := 0; i < n; i++ {
		conn, ok := openIdleWebSocket(t, h.publicAddr, h.hostname, "/ws-idle")
		if conn != nil {
			conns = append(conns, conn)
		}
		if !ok {
			t.Fatalf("websocket %d/%d did not receive a 101 handshake", i+1, n)
		}
	}

	waitForActiveUpgradesDelta(t, baseline, n, 5*time.Second, "opening the idle websockets")

	status, _, err := doGet(h.publicAddr, h.hostname, "/ping")
	if err != nil {
		t.Fatalf("GET /ping: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("GET /ping while %d/%d websockets are open and idle = %d, want 200 (idle upgraded connections must not hold the request-scoped in-flight budget)", n, n, status)
	}

	for _, c := range conns {
		c.Close()
	}
	conns = nil

	waitForActiveUpgradesBaseline(t, baseline, 5*time.Second, "closing the idle websockets")
}

func TestIdleSSEDoesNotStarveNormalHTTP(t *testing.T) {
	holdCh := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("/__ngstone_ready", func(w http.ResponseWriter, r *http.Request) {
		writeReady(w)
	})
	mux.HandleFunc("/sse-idle", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-holdCh:
		case <-r.Context().Done():
		}
	})
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	origin := httptest.NewServer(mux)
	defer origin.Close()
	defer close(holdCh)

	h := startInProcessWithAccess(t, "sse-starve", origin.URL, 0, inProcAccess{
		limits: edge.LimitsConfig{
			GlobalInFlight:     4,
			PerSessionInFlight: 4,
		},
	})

	const n = 8
	client := &http.Client{Timeout: 10 * time.Second}
	resps := make([]*http.Response, 0, n)
	defer func() {
		for _, r := range resps {
			r.Body.Close()
		}
	}()

	baseline := activeUpgradesGauge()

	for i := 0; i < n; i++ {
		req, err := http.NewRequest(http.MethodGet, "http://"+h.publicAddr+"/sse-idle", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Host = h.hostname
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /sse-idle attempt %d: %v", i+1, err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("GET /sse-idle attempt %d: status = %d, want 200", i+1, resp.StatusCode)
		}
		resps = append(resps, resp)
	}

	waitForActiveUpgradesDelta(t, baseline, n, 5*time.Second, "opening the idle SSE streams")

	status, _, err := doGet(h.publicAddr, h.hostname, "/ping")
	if err != nil {
		t.Fatalf("GET /ping: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("GET /ping while %d/%d SSE streams are open and idle = %d, want 200 (idle SSE streams must not hold the request-scoped in-flight budget)", n, n, status)
	}

	for _, r := range resps {
		r.Body.Close()
	}
	resps = nil

	waitForActiveUpgradesBaseline(t, baseline, 5*time.Second, "closing the idle SSE streams")
}

func TestUpgradeCapRejectsExcessWithServiceUnavailable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/__ngstone_ready", func(w http.ResponseWriter, r *http.Request) {
		writeReady(w)
	})
	mux.HandleFunc("/ws-idle", idleWebSocketHijackHandler)
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	origin := httptest.NewServer(mux)
	defer origin.Close()

	h := startInProcessWithAccess(t, "ws-cap", origin.URL, 0, inProcAccess{
		limits: edge.LimitsConfig{
			UpgradeInFlight: 2,
		},
	})

	baseline := activeUpgradesGauge()
	rejectedBaseline := rejectedUpgradeCapCounter()

	const n = 2
	conns := make([]net.Conn, 0, n)
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	for i := 0; i < n; i++ {
		conn, ok := openIdleWebSocket(t, h.publicAddr, h.hostname, "/ws-idle")
		if conn != nil {
			conns = append(conns, conn)
		}
		if !ok {
			t.Fatalf("websocket %d/%d did not receive a 101 handshake", i+1, n)
		}
	}

	waitForActiveUpgradesDelta(t, baseline, n, 5*time.Second, "opening the 2 websockets under the upgrade cap")

	handshake := "GET /ws-idle HTTP/1.1\r\n" +
		"Host: " + h.hostname + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	status := rawRequestStatus(t, h.publicAddr, h.hostname, handshake, "")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("3rd websocket upgrade beyond the cap: status = %d, want 503 (a full upgrade budget must reject the connection, not fall back to holding its request slot)", status)
	}

	if got, want := rejectedUpgradeCapCounter()-rejectedBaseline, int64(1); got != want {
		t.Fatalf("ngstoned_rejected_upgrade_cap_total delta = %d, want %d", got, want)
	}

	if got := activeUpgradesGauge() - baseline; got != n {
		t.Fatalf("ngstoned_active_upgrades delta = %d, want %d (the rejected 3rd upgrade must not be counted as active)", got, n)
	}

	pingStatus, _, err := doGet(h.publicAddr, h.hostname, "/ping")
	if err != nil {
		t.Fatalf("GET /ping: %v", err)
	}
	if pingStatus != http.StatusOK {
		t.Fatalf("GET /ping after a rejected upgrade = %d, want 200 (the rejected connection must not have held its request-scoped slot)", pingStatus)
	}

	for _, c := range conns {
		c.Close()
	}
	conns = nil

	waitForActiveUpgradesBaseline(t, baseline, 5*time.Second, "closing the 2 accepted websockets")
}

func TestActiveUpgradesGaugeTracksOpenWebSockets(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/__ngstone_ready", func(w http.ResponseWriter, r *http.Request) {
		writeReady(w)
	})
	mux.HandleFunc("/ws-idle", idleWebSocketHijackHandler)

	origin := httptest.NewServer(mux)
	defer origin.Close()

	h := startInProcess(t, "ws-gauge", origin.URL, 0)

	baseline := activeUpgradesGauge()

	const k = 5
	conns := make([]net.Conn, 0, k)
	for i := 0; i < k; i++ {
		conn, ok := openIdleWebSocket(t, h.publicAddr, h.hostname, "/ws-idle")
		if !ok {
			if conn != nil {
				conn.Close()
			}
			t.Fatalf("websocket %d/%d did not receive a 101 handshake", i+1, k)
		}
		conns = append(conns, conn)
	}

	if got, want := activeUpgradesGauge(), baseline+k; got != want {
		for _, c := range conns {
			c.Close()
		}
		t.Fatalf("ngstoned_active_upgrades = %d, want baseline+%d = %d", got, k, want)
	}

	for _, c := range conns {
		c.Close()
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if activeUpgradesGauge() == baseline {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("ngstoned_active_upgrades did not return to baseline %d within 5s after closing %d websockets; got %d", baseline, k, activeUpgradesGauge())
}

func TestChunkedNonSSEResponseNotReclassified(t *testing.T) {
	proceedCh := make(chan struct{})
	inHandlerCh := make(chan struct{})
	var proceedOnce sync.Once
	releaseHandler := func() { proceedOnce.Do(func() { close(proceedCh) }) }

	mux := http.NewServeMux()
	mux.HandleFunc("/__ngstone_ready", func(w http.ResponseWriter, r *http.Request) {
		writeReady(w)
	})
	mux.HandleFunc("/chunked", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "start\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		close(inHandlerCh)
		<-proceedCh
		io.WriteString(w, "end\n")
	})

	origin := httptest.NewServer(mux)
	defer origin.Close()
	defer releaseHandler()

	h := startInProcess(t, "chunked-noreclass", origin.URL, 0)

	baseline := activeUpgradesGauge()

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://"+h.publicAddr+"/chunked", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = h.hostname

	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	select {
	case <-inHandlerCh:
	case <-time.After(5 * time.Second):
		t.Fatal("origin handler did not start within 5s")
	}

	time.Sleep(250 * time.Millisecond)

	if got := activeUpgradesGauge(); got != baseline {
		t.Fatalf("ngstoned_active_upgrades = %d while a plain chunked 200 response is in flight, want unchanged baseline %d (a non-SSE, non-101 response must not be reclassified)", got, baseline)
	}

	releaseHandler()
	select {
	case <-doneCh:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not complete within 5s")
	}
}
