package inspect

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func proxyTo(t *testing.T, c *Capturer, target string) http.Handler {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	p := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = u.Scheme
			pr.Out.URL.Host = u.Host
		},
		FlushInterval: -1,
	}
	c.Install(p)
	return c.Middleware(p)
}

func recvExchange(t *testing.T, ch <-chan *Exchange, d time.Duration) *Exchange {
	t.Helper()
	select {
	case e, ok := <-ch:
		if !ok {
			t.Fatal("subscriber channel closed")
		}
		return e
	case <-time.After(d):
		t.Fatal("timed out waiting for an exchange")
		return nil
	}
}

func echoUpgradeBackend(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "expected upgrade", http.StatusBadRequest)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		if _, err := brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Backend: yes\r\n\r\n"); err != nil {
			t.Error(err)
			return
		}
		if err := brw.Flush(); err != nil {
			t.Error(err)
			return
		}
		io.Copy(conn, brw)
	}))
}

func TestUpgradeIsRecordedAtConnectTime(t *testing.T) {
	backend := echoUpgradeBackend(t)
	defer backend.Close()

	store := NewStore()
	capr := NewCapturer(store)
	front := httptest.NewServer(proxyTo(t, capr, backend.URL))
	defer front.Close()

	ch, cancel := store.Subscribe()
	defer cancel()

	conn, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := "GET /socket?x=1 HTTP/1.1\r\nHost: tunnel.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Client: abc\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "101") {
		t.Fatalf("status line = %q, want 101", line)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if l == "\r\n" {
			break
		}
	}

	ex := recvExchange(t, ch, 3*time.Second)
	if ex.Kind != KindUpgrade {
		t.Fatalf("Kind = %q, want %q", ex.Kind, KindUpgrade)
	}
	if ex.Resp.Status != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101 (recorded before the socket closed)", ex.Resp.Status)
	}
	if got := ex.Resp.Header.Get("X-Backend"); got != "yes" {
		t.Fatalf("response header not captured: %v", ex.Resp.Header)
	}
	if got := ex.Req.Header.Get("X-Client"); got != "abc" {
		t.Fatalf("request header not captured: %v", ex.Req.Header)
	}
	if !strings.Contains(ex.Req.URL, "/socket?x=1") {
		t.Fatalf("Req.URL = %q", ex.Req.URL)
	}
	if len(ex.Resp.Body) != 0 {
		t.Fatalf("upgrade response body should never be buffered, got %d bytes", len(ex.Resp.Body))
	}

	payload := []byte("hello-socket")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}

	if len(store.List()) != 1 {
		t.Fatalf("expected exactly one exchange, got %d", len(store.List()))
	}

	conn.Close()

	deadline := time.After(3 * time.Second)
	for {
		cur, ok := store.Get(ex.ID)
		if ok && cur.BytesClientToApp == int64(len(payload)) && cur.BytesAppToClient == int64(len(payload)) {
			break
		}
		select {
		case <-deadline:
			cur, _ := store.Get(ex.ID)
			t.Fatalf("byte counters never updated: c2a=%d a2c=%d", cur.BytesClientToApp, cur.BytesAppToClient)
		case <-time.After(10 * time.Millisecond):
		}
	}

	if n := len(store.List()); n != 1 {
		t.Fatalf("upgrade was finalized twice: %d entries", n)
	}
	final, _ := store.Get(ex.ID)
	if len(final.Resp.Body) != 0 || final.Resp.Truncated {
		t.Fatalf("socket frames were teed into the body buffer: %d bytes", len(final.Resp.Body))
	}
	if len(final.Req.Body) != 0 {
		t.Fatalf("socket frames were teed into the request body buffer: %d bytes", len(final.Req.Body))
	}
	if final.Duration <= 0 {
		t.Fatal("upgrade duration never updated")
	}
}

func TestPlainHTTPExchangeIsCaptured(t *testing.T) {
	store := NewStore()
	h := Capture(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Answer", "42")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, "got:%s", b)
	}))
	inject := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithStreamInfo(r.Context(), StreamInfo{ReqID: "req-7"})))
	})

	srv := httptest.NewServer(inject)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/a/b?c=d", "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	list := store.List()
	if len(list) != 1 {
		t.Fatalf("want 1 exchange, got %d", len(list))
	}
	ex := list[0]
	if ex.Kind != KindHTTP {
		t.Fatalf("Kind = %q", ex.Kind)
	}
	if ex.ReqID != "req-7" {
		t.Fatalf("ReqID = %q, want req-7", ex.ReqID)
	}
	if ex.Req.Method != http.MethodPost {
		t.Fatalf("method = %q", ex.Req.Method)
	}
	if !strings.HasSuffix(ex.Req.URL, "/a/b?c=d") {
		t.Fatalf("URL = %q", ex.Req.URL)
	}
	if string(ex.Req.Body) != "payload" {
		t.Fatalf("req body = %q", ex.Req.Body)
	}
	if ex.Req.BodySize != 7 {
		t.Fatalf("req body size = %d", ex.Req.BodySize)
	}
	if ex.Resp.Status != http.StatusCreated {
		t.Fatalf("status = %d", ex.Resp.Status)
	}
	if ex.Resp.Header.Get("X-Answer") != "42" {
		t.Fatalf("resp header = %v", ex.Resp.Header)
	}
	if string(ex.Resp.Body) != "got:payload" {
		t.Fatalf("resp body = %q", ex.Resp.Body)
	}
	if ex.Duration <= 0 {
		t.Fatal("duration not recorded")
	}
}

func TestCappedTeeTruncatesAtExactBoundary(t *testing.T) {
	cases := []struct {
		name string
		size int
		want bool
	}{
		{"one below cap", BodyCap - 1, false},
		{"exactly cap", BodyCap, false},
		{"one over cap", BodyCap + 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := make([]byte, tc.size)
			for i := range payload {
				payload[i] = byte(i % 251)
			}
			want := sha256.Sum256(payload)

			store := NewStore()
			var seen [32]byte
			h := Capture(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sum := sha256.New()
				if _, err := io.Copy(sum, r.Body); err != nil {
					t.Error(err)
				}
				copy(seen[:], sum.Sum(nil))
				w.Write(payload)
			}))
			srv := httptest.NewServer(h)
			defer srv.Close()

			resp, err := http.Post(srv.URL, "application/octet-stream", bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			down := sha256.New()
			io.Copy(down, resp.Body)
			resp.Body.Close()

			if seen != want {
				t.Fatal("handler did not receive the request bytes unmodified")
			}
			if !bytes.Equal(down.Sum(nil), want[:]) {
				t.Fatal("client did not receive the response bytes unmodified")
			}

			list := store.List()
			if len(list) != 1 {
				t.Fatalf("want 1 exchange, got %d", len(list))
			}
			ex := list[0]

			if ex.Req.Truncated != tc.want {
				t.Fatalf("req truncated = %v, want %v (size %d)", ex.Req.Truncated, tc.want, tc.size)
			}
			if ex.Resp.Truncated != tc.want {
				t.Fatalf("resp truncated = %v, want %v (size %d)", ex.Resp.Truncated, tc.want, tc.size)
			}
			if ex.Req.BodySize != int64(tc.size) || ex.Resp.BodySize != int64(tc.size) {
				t.Fatalf("body sizes = %d/%d, want %d", ex.Req.BodySize, ex.Resp.BodySize, tc.size)
			}

			keep := tc.size
			if keep > BodyCap {
				keep = BodyCap
			}
			if len(ex.Req.Body) != keep {
				t.Fatalf("kept req bytes = %d, want %d", len(ex.Req.Body), keep)
			}
			if !bytes.Equal(ex.Req.Body, payload[:keep]) {
				t.Fatal("captured request prefix does not match the payload")
			}
			if !bytes.Equal(ex.Resp.Body, payload[:keep]) {
				t.Fatal("captured response prefix does not match the payload")
			}
			if cap(ex.Req.Body) > BodyCap {
				t.Fatalf("capture buffer exceeded the cap: %d", cap(ex.Req.Body))
			}
		})
	}
}

func TestFlushReachesUnderlyingWriter(t *testing.T) {
	store := NewStore()
	release := make(chan struct{})
	h := Capture(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Error(err)
		}
		<-release
		io.WriteString(w, "data: second\n\n")
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancelReq := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelReq()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	var resp *http.Response
	select {
	case resp = <-respCh:
	case err := <-errCh:
		close(release)
		t.Fatalf("flushed response headers never reached the client: %v", err)
	}
	defer resp.Body.Close()

	got := make(chan string, 1)
	go func() {
		buf := make([]byte, len("data: first\n\n"))
		if _, err := io.ReadFull(resp.Body, buf); err != nil {
			got <- "err:" + err.Error()
			return
		}
		got <- string(buf)
	}()

	select {
	case s := <-got:
		if s != "data: first\n\n" {
			close(release)
			t.Fatalf("first chunk = %q", s)
		}
	case <-ctx.Done():
		close(release)
		t.Fatal("flushed bytes never reached the client before the handler returned")
	}
	close(release)

	io.Copy(io.Discard, resp.Body)
	list := store.List()
	if len(list) != 1 {
		t.Fatalf("want 1 exchange, got %d", len(list))
	}
	if string(list[0].Resp.Body) != "data: first\n\ndata: second\n\n" {
		t.Fatalf("captured body = %q", list[0].Resp.Body)
	}
}

func TestResponseControllerReachesTheRealWriter(t *testing.T) {
	store := NewStore()

	type ctlResult struct {
		setWrite     error
		setRead      error
		fullDuplex   error
		wroteAndRead bool
	}
	results := make(chan ctlResult, 1)

	h := Capture(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		var res ctlResult
		res.fullDuplex = rc.EnableFullDuplex()
		res.setWrite = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
		res.setRead = rc.SetReadDeadline(time.Now().Add(30 * time.Second))

		body, err := io.ReadAll(r.Body)
		res.wroteAndRead = err == nil && string(body) == "ping"
		results <- res

		io.WriteString(w, "pong")
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL, "text/plain", strings.NewReader("ping"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "pong" {
		t.Fatalf("body = %q, want pong", got)
	}

	res := <-results
	if errors.Is(res.setWrite, http.ErrNotSupported) {
		t.Fatal("SetWriteDeadline did not reach the real writer: the capture wrapper must expose Unwrap() http.ResponseWriter")
	}
	if res.setWrite != nil {
		t.Fatalf("SetWriteDeadline = %v", res.setWrite)
	}
	if errors.Is(res.setRead, http.ErrNotSupported) {
		t.Fatal("SetReadDeadline did not reach the real writer: the capture wrapper must expose Unwrap() http.ResponseWriter")
	}
	if res.setRead != nil {
		t.Fatalf("SetReadDeadline = %v", res.setRead)
	}
	if errors.Is(res.fullDuplex, http.ErrNotSupported) {
		t.Fatal("EnableFullDuplex did not reach the real writer: the capture wrapper must expose Unwrap() http.ResponseWriter")
	}
	if res.fullDuplex != nil {
		t.Fatalf("EnableFullDuplex = %v", res.fullDuplex)
	}
	if !res.wroteAndRead {
		t.Fatal("handler did not observe the request body after taking deadlines")
	}

	if n := store.Len(); n != 1 {
		t.Fatalf("want 1 exchange, got %d", n)
	}
	if s := store.List()[0].Resp.Status; s != http.StatusOK {
		t.Fatalf("status = %d", s)
	}
}

func TestUnwrapReturnsTheUnderlyingWriter(t *testing.T) {
	inner := httptest.NewRecorder()
	rec := &recorder{ResponseWriter: inner, state: &exchangeState{body: &capBuf{}}, body: &capBuf{}}

	var w http.ResponseWriter = rec
	u, ok := w.(interface{ Unwrap() http.ResponseWriter })
	if !ok {
		t.Fatal("recorder does not implement Unwrap() http.ResponseWriter")
	}
	if u.Unwrap() != http.ResponseWriter(inner) {
		t.Fatal("Unwrap did not return the underlying writer")
	}
}

func TestSlowSubscriberDoesNotBlockCapturePath(t *testing.T) {
	store := NewStore()
	h := Capture(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, "ok")
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()

	_, cancel := store.Subscribe()
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 25; j++ {
					resp, err := http.Post(srv.URL, "text/plain", strings.NewReader("x"))
					if err != nil {
						t.Error(err)
						return
					}
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()
		}
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("capture path stalled behind a wedged subscriber")
	}
	if store.Len() != 100 {
		t.Fatalf("expected 100 captured exchanges, got %d", store.Len())
	}
}

func TestGzippedBodyStaysRawAndDecodesForDisplay(t *testing.T) {
	const jsonBody = `{"hello":"wörld","n":3}`

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(jsonBody))
	zw.Close()
	raw := gz.Bytes()

	store := NewStore()
	h := Capture(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(raw)
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	ex := store.List()[0]
	if !bytes.Equal(ex.Resp.Body, raw) {
		t.Fatal("stored response body is not the raw gzip bytes")
	}
	dec := Decode(ex.Resp.Header, ex.Resp.Body)
	if !dec.Decoded || dec.Err != "" {
		t.Fatalf("decode failed: %+v", dec.Err)
	}
	if string(dec.Data) != jsonBody {
		t.Fatalf("decoded = %q, want %q", dec.Data, jsonBody)
	}
	if dec.Binary {
		t.Fatal("decoded JSON reported as binary")
	}
}

func TestHijackWithoutUpgradeIsNotDoubleFinalized(t *testing.T) {
	store := NewStore()
	h := Capture(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		brw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
		brw.Flush()
		conn.Close()
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	deadline := time.After(2 * time.Second)
	for store.Len() == 0 {
		select {
		case <-deadline:
			t.Fatal("hijacked exchange never recorded")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if n := store.Len(); n != 1 {
		t.Fatalf("expected exactly 1 entry, got %d", n)
	}
	if k := store.List()[0].Kind; k != KindUpgrade {
		t.Fatalf("Kind = %q, want %q", k, KindUpgrade)
	}
}

func TestNoBodyRequestIsNotChunked(t *testing.T) {
	store := NewStore()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TransferEncoding) != 0 {
			t.Errorf("bodyless GET became %v", r.TransferEncoding)
		}
		io.WriteString(w, "ok")
	}))
	defer backend.Close()

	front := httptest.NewServer(proxyTo(t, NewCapturer(store), backend.URL))
	defer front.Close()

	resp, err := http.Get(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func TestCaptureSurvivesContextCancellation(t *testing.T) {
	store := NewStore()
	started := make(chan struct{})
	h := Capture(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	go func() {
		<-started
		cancel()
	}()
	if _, err := http.DefaultClient.Do(req); err == nil {
		t.Fatal("expected the request to be cancelled")
	}

	deadline := time.After(2 * time.Second)
	for store.Len() == 0 {
		select {
		case <-deadline:
			t.Fatal("cancelled exchange never recorded")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if e := store.List()[0]; e.Err == "" {
		t.Fatal("cancelled exchange has no Err")
	}
}
