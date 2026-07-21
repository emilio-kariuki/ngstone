package e2e

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
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

	token := "e2e-inproc-token"
	domain := "tun.example.com"
	hostname := subdomain + "." + domain
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)

	var limits edge.LimitsConfig
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
		ControlAddr: controlAddr,
		Token:       token,
		Subdomain:   subdomain,
		TargetURL:   targetURL,
		Insecure:    true,
		Store:       store,
	})
	go agt.Run(ctx)
	waitBound(t, publicAddr, hostname)

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
