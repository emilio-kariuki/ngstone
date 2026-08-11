package agent

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"ngstone/internal/inspect"
	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

type fakeEdge struct {
	t  *testing.T
	ln net.Listener

	sessions chan tunnel.Session

	mu     sync.Mutex
	closed bool
	conns  []net.Conn
}

func newFakeEdge(t *testing.T) *fakeEdge {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	e := &fakeEdge{t: t, ln: ln, sessions: make(chan tunnel.Session, 8)}
	go e.acceptLoop()
	t.Cleanup(e.Close)
	return e
}

func (e *fakeEdge) addr() string { return e.ln.Addr().String() }

func (e *fakeEdge) acceptLoop() {
	for {
		c, err := e.ln.Accept()
		if err != nil {
			return
		}
		e.mu.Lock()
		e.conns = append(e.conns, c)
		e.mu.Unlock()
		go e.serve(c)
	}
}

func (e *fakeEdge) serve(c net.Conn) {
	sess, err := tunnel.Server(c)
	if err != nil {
		c.Close()
		return
	}
	ctrl := sess.Control()

	authMsg, err := ctrl.Read()
	if err != nil {
		sess.Close("read auth")
		return
	}
	if authMsg.Type != proto.TypeAuth {
		sess.Close("expected auth")
		return
	}
	if err := ctrl.Write(proto.TypeAuthOK, authMsg.ID, proto.AuthOK{
		ProtoVersion: proto.ProtoVersion,
		SessionID:    "test-session",
	}); err != nil {
		sess.Close("write auth_ok")
		return
	}

	bindMsg, err := ctrl.Read()
	if err != nil {
		sess.Close("read bind")
		return
	}
	if bindMsg.Type != proto.TypeBind {
		sess.Close("expected bind")
		return
	}
	if err := ctrl.Write(proto.TypeBindOK, bindMsg.ID, proto.BindOK{
		Hostname: "test.ngstone.site",
		URL:      "https://test.ngstone.site",
	}); err != nil {
		sess.Close("write bind_ok")
		return
	}

	go func() {
		for {
			m, err := ctrl.Read()
			if err != nil {
				return
			}
			if m.Type == proto.TypePing {
				p, derr := proto.Decode[proto.Ping](m)
				if derr != nil {
					return
				}
				if werr := ctrl.Write(proto.TypePong, m.ID, proto.Pong{TS: p.TS}); werr != nil {
					return
				}
			}
		}
	}()

	select {
	case e.sessions <- sess:
	default:
	}
}

func (e *fakeEdge) waitSession(timeout time.Duration) tunnel.Session {
	e.t.Helper()
	select {
	case s := <-e.sessions:
		return s
	case <-time.After(timeout):
		e.t.Fatalf("no edge session within %v", timeout)
		return nil
	}
}

func (e *fakeEdge) Close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	conns := e.conns
	e.mu.Unlock()
	e.ln.Close()
	for _, c := range conns {
		c.Close()
	}
}

type edgeRequest struct {
	reqID   string
	method  string
	path    string
	headers []string
}

func (e *fakeEdge) do(sess tunnel.Session, req edgeRequest) (*http.Response, error) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := sess.OpenStream(ctx, proto.StreamOpen{
		Kind:       proto.KindHTTP,
		Host:       "test.ngstone.site",
		ReqID:      req.reqID,
		ClientAddr: "203.0.113.7:44321",
	})
	if err != nil {
		return nil, err
	}

	method := req.method
	if method == "" {
		method = http.MethodGet
	}
	path := req.path
	if path == "" {
		path = "/"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\nHost: test.ngstone.site\r\n", method, path)
	for _, h := range req.headers {
		sb.WriteString(h)
		sb.WriteString("\r\n")
	}
	sb.WriteString("Connection: close\r\n\r\n")

	stream.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := stream.Write([]byte(sb.String())); err != nil {
		stream.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(stream), nil)
	if err != nil {
		stream.Close()
		return nil, err
	}
	return resp, nil
}

func (e *fakeEdge) openUpgrade(sess tunnel.Session, reqID, path string) (net.Conn, *bufio.Reader, *http.Response) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := sess.OpenStream(ctx, proto.StreamOpen{
		Kind:       proto.KindHTTP,
		Host:       "test.ngstone.site",
		ReqID:      reqID,
		ClientAddr: "203.0.113.7:44321",
	})
	if err != nil {
		e.t.Fatalf("open upgrade stream: %v", err)
	}

	req := "GET " + path + " HTTP/1.1\r\nHost: test.ngstone.site\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n"
	stream.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := stream.Write([]byte(req)); err != nil {
		stream.Close()
		e.t.Fatalf("write upgrade request: %v", err)
	}

	br := bufio.NewReader(stream)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		stream.Close()
		e.t.Fatalf("read upgrade response: %v", err)
	}
	return stream, br, resp
}

type localApp struct {
	srv       *httptest.Server
	mu        sync.Mutex
	seen      []http.Header
	seenHosts []string
}

func serveEchoUpgrade(w http.ResponseWriter, r *http.Request) {
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\nX-Echo-App: yes\r\n\r\n"
	if _, err := brw.WriteString(resp); err != nil {
		return
	}
	if err := brw.Flush(); err != nil {
		return
	}

	buf := make([]byte, 512)
	for {
		n, rerr := brw.Read(buf)
		if n > 0 {
			if _, werr := brw.Write(buf[:n]); werr != nil {
				return
			}
			if ferr := brw.Flush(); ferr != nil {
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}

func newLocalApp(t *testing.T) *localApp {
	t.Helper()
	app := &localApp{}
	app.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app.mu.Lock()
		app.seen = append(app.seen, r.Header.Clone())
		app.seenHosts = append(app.seenHosts, r.Host)
		app.mu.Unlock()
		if r.URL.Path == "/echo" {
			serveEchoUpgrade(w, r)
			return
		}
		if r.URL.Path == "/teapot" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	}))
	t.Cleanup(app.srv.Close)
	return app
}

func (l *localApp) lastHeader() http.Header {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.seen) == 0 {
		return nil
	}
	return l.seen[len(l.seen)-1]
}

func (l *localApp) lastHost() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.seenHosts) == 0 {
		return ""
	}
	return l.seenHosts[len(l.seenHosts)-1]
}

func TestHostHeaderOverride(t *testing.T) {
	app := newLocalApp(t)
	a := New(Config{TargetURL: app.srv.URL, HostHeader: "demo.localhost:3000"})
	target := a.Target()
	if target == nil {
		t.Fatal("Target() = nil, want parsed URL")
	}

	req := httptest.NewRequest(http.MethodGet, "http://demo.ngstone.site/", nil)
	req.Host = "demo.ngstone.site"
	rec := httptest.NewRecorder()
	a.buildProxy(target).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := app.lastHost(); got != "demo.localhost:3000" {
		t.Fatalf("local app Host = %q, want %q", got, "demo.localhost:3000")
	}
}

func TestHostHeaderDefaultsToIncomingHost(t *testing.T) {
	app := newLocalApp(t)
	a := New(Config{TargetURL: app.srv.URL})
	target := a.Target()
	if target == nil {
		t.Fatal("Target() = nil, want parsed URL")
	}

	req := httptest.NewRequest(http.MethodGet, "http://demo.ngstone.site/", nil)
	req.Host = "demo.ngstone.site:3000"
	rec := httptest.NewRecorder()
	a.buildProxy(target).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := app.lastHost(); got != "demo.ngstone.site:3000" {
		t.Fatalf("local app Host = %q, want %q", got, "demo.ngstone.site:3000")
	}
}

func startAgent(t *testing.T, cfg Config) (*Agent, context.CancelFunc, chan error) {
	t.Helper()
	a := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
	return a, cancel, done
}

func waitBound(t *testing.T, a *Agent, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if a.Status().Hostname != "" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("agent did not bind within %v", timeout)
}

func TestCaptureRecordsExchangeWithReqID(t *testing.T) {
	app := newLocalApp(t)
	edge := newFakeEdge(t)
	store := inspect.NewStore()

	a, _, _ := startAgent(t, Config{
		ControlAddr: edge.addr(),
		TargetURL:   app.srv.URL,
		Insecure:    true,
		Store:       store,
	})

	sess := edge.waitSession(5 * time.Second)
	waitBound(t, a, 5*time.Second)

	resp, err := edge.do(sess, edgeRequest{reqID: "req-abc123", method: http.MethodPost, path: "/teapot"})
	if err != nil {
		t.Fatalf("edge request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", resp.StatusCode)
	}

	ex := waitForExchange(t, store, 1, 5*time.Second)[0]
	if ex.Req.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", ex.Req.Method)
	}
	if ex.Resp.Status != http.StatusTeapot {
		t.Errorf("captured status = %d, want 418", ex.Resp.Status)
	}
	if ex.ReqID != "req-abc123" {
		t.Errorf("ReqID = %q, want %q", ex.ReqID, "req-abc123")
	}
	if a.Store() != store {
		t.Errorf("Store() did not return the configured store")
	}
	if a.Transport() == nil {
		t.Errorf("Transport() returned nil")
	}
}

func waitForExchange(t *testing.T, store *inspect.Store, n int, timeout time.Duration) []*inspect.Exchange {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		list := store.List()
		if len(list) >= n {
			return list
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("store had %d exchanges, want %d, after %v", store.Len(), n, timeout)
	return nil
}

func TestNilStoreAgentStillProxies(t *testing.T) {
	app := newLocalApp(t)
	edge := newFakeEdge(t)

	a, _, _ := startAgent(t, Config{
		ControlAddr: edge.addr(),
		TargetURL:   app.srv.URL,
		Insecure:    true,
	})

	sess := edge.waitSession(5 * time.Second)
	waitBound(t, a, 5*time.Second)

	resp, err := edge.do(sess, edgeRequest{reqID: "req-nil"})
	if err != nil {
		t.Fatalf("edge request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if a.Store() != nil {
		t.Errorf("Store() = %v, want nil", a.Store())
	}
}

func TestStoreSurvivesReconnect(t *testing.T) {
	app := newLocalApp(t)
	edge := newFakeEdge(t)
	store := inspect.NewStore()

	a, _, _ := startAgent(t, Config{
		ControlAddr: edge.addr(),
		TargetURL:   app.srv.URL,
		Insecure:    true,
		Store:       store,
	})

	sess1 := edge.waitSession(5 * time.Second)
	waitBound(t, a, 5*time.Second)

	resp, err := edge.do(sess1, edgeRequest{reqID: "before-reconnect", path: "/one"})
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	resp.Body.Close()
	waitForExchange(t, store, 1, 5*time.Second)

	sess1.Close("forced reconnect")

	sess2 := edge.waitSession(15 * time.Second)

	resp2, err := edge.do(sess2, edgeRequest{reqID: "after-reconnect", path: "/two"})
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	resp2.Body.Close()

	list := waitForExchange(t, store, 2, 10*time.Second)

	var sawBefore, sawAfter bool
	for _, ex := range list {
		if strings.HasSuffix(ex.Req.URL, "/one") {
			sawBefore = true
		}
		if strings.HasSuffix(ex.Req.URL, "/two") {
			sawAfter = true
		}
	}
	if !sawBefore {
		t.Errorf("pre-reconnect exchange missing from store after reconnect: %+v", list)
	}
	if !sawAfter {
		t.Errorf("post-reconnect exchange missing from store: %+v", list)
	}
}

func TestStatusEventsDoNotBlockReconnect(t *testing.T) {
	app := newLocalApp(t)
	edge := newFakeEdge(t)

	events := make(chan StatusEvent)

	a, _, _ := startAgent(t, Config{
		ControlAddr: edge.addr(),
		TargetURL:   app.srv.URL,
		Insecure:    true,
		Events:      events,
	})

	sess1 := edge.waitSession(5 * time.Second)
	waitBound(t, a, 5*time.Second)

	sess1.Close("forced reconnect")

	sess2 := edge.waitSession(10 * time.Second)

	resp, err := edge.do(sess2, edgeRequest{reqID: "after-reconnect"})
	if err != nil {
		t.Fatalf("request after reconnect: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestStatusEventsDelivered(t *testing.T) {
	app := newLocalApp(t)
	edge := newFakeEdge(t)

	events := make(chan StatusEvent, 32)

	_, _, _ = startAgent(t, Config{
		ControlAddr: edge.addr(),
		TargetURL:   app.srv.URL,
		Insecure:    true,
		Events:      events,
	})

	edge.waitSession(5 * time.Second)

	deadline := time.After(5 * time.Second)
	seen := map[string]StatusEvent{}
	for {
		if _, ok := seen[StateOnline]; ok {
			break
		}
		select {
		case ev := <-events:
			seen[ev.State] = ev
		case <-deadline:
			t.Fatalf("did not observe online event, saw %v", seen)
		}
	}
	if _, ok := seen[StateConnecting]; !ok {
		t.Errorf("did not observe connecting event, saw %v", seen)
	}
	if ev := seen[StateOnline]; ev.Hostname != "test.ngstone.site" || ev.URL != "https://test.ngstone.site" {
		t.Errorf("online event = %+v, want hostname/url from bind_ok", ev)
	}
}

func waitForUpgradeExchange(t *testing.T, store *inspect.Store, timeout time.Duration) *inspect.Exchange {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, ex := range store.List() {
			if ex.Kind == inspect.KindUpgrade {
				return ex
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no upgrade exchange in store after %v (store has %d entries)", timeout, store.Len())
	return nil
}

func TestUpgradeRecordedWhileSocketOpen(t *testing.T) {
	app := newLocalApp(t)
	edge := newFakeEdge(t)
	store := inspect.NewStore()

	a, _, _ := startAgent(t, Config{
		ControlAddr: edge.addr(),
		TargetURL:   app.srv.URL,
		Insecure:    true,
		Store:       store,
	})

	sess := edge.waitSession(5 * time.Second)
	waitBound(t, a, 5*time.Second)

	stream, br, resp := edge.openUpgrade(sess, "req-upgrade-1", "/echo")
	defer stream.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	ex := waitForUpgradeExchange(t, store, 5*time.Second)
	if ex.Resp.Status != http.StatusSwitchingProtocols {
		t.Errorf("captured status = %d, want 101", ex.Resp.Status)
	}
	if got := ex.Resp.Header.Get("X-Echo-App"); got != "yes" {
		t.Errorf("captured response header X-Echo-App = %q, want %q", got, "yes")
	}
	if ex.ReqID != "req-upgrade-1" {
		t.Errorf("ReqID = %q, want %q", ex.ReqID, "req-upgrade-1")
	}
	if ex.Req.Method != http.MethodGet {
		t.Errorf("method = %q, want GET", ex.Req.Method)
	}

	for _, payload := range []string{"ping one", "ping two"} {
		stream.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := stream.Write([]byte(payload)); err != nil {
			t.Fatalf("write %q: %v", payload, err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(br, got); err != nil {
			t.Fatalf("read echo of %q: %v", payload, err)
		}
		if string(got) != payload {
			t.Fatalf("echo = %q, want %q", got, payload)
		}
	}

	stream.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cur, ok := store.Get(ex.ID)
		if ok && cur.BytesClientToApp > 0 && cur.BytesAppToClient > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	cur, _ := store.Get(ex.ID)
	t.Fatalf("upgrade byte counters not published: %+v", cur)
}

func TestForwardingHeadersArriveVerbatim(t *testing.T) {
	app := newLocalApp(t)
	edge := newFakeEdge(t)
	store := inspect.NewStore()

	a, _, _ := startAgent(t, Config{
		ControlAddr: edge.addr(),
		TargetURL:   app.srv.URL,
		Insecure:    true,
		Store:       store,
	})

	sess := edge.waitSession(5 * time.Second)
	waitBound(t, a, 5*time.Second)

	resp, err := edge.do(sess, edgeRequest{
		reqID: "hdr-1",
		headers: []string{
			"X-Forwarded-For: 198.51.100.9, 203.0.113.7",
			"X-Forwarded-Host: test.ngstone.site",
			"X-Forwarded-Proto: https",
			"Forwarded: for=203.0.113.7;host=test.ngstone.site;proto=https",
		},
	})
	if err != nil {
		t.Fatalf("edge request: %v", err)
	}
	resp.Body.Close()

	waitForExchange(t, store, 1, 5*time.Second)

	got := app.lastHeader()
	if got == nil {
		t.Fatalf("local app saw no request")
	}
	checks := map[string]string{
		"X-Forwarded-For":   "198.51.100.9, 203.0.113.7",
		"X-Forwarded-Host":  "test.ngstone.site",
		"X-Forwarded-Proto": "https",
		"Forwarded":         "for=203.0.113.7;host=test.ngstone.site;proto=https",
	}
	for k, want := range checks {
		vals := got.Values(k)
		if len(vals) != 1 {
			t.Fatalf("%s = %v, want exactly one value", k, vals)
		}
		if vals[0] != want {
			t.Errorf("%s = %q, want %q", k, vals[0], want)
		}
	}
	if n := strings.Count(got.Get("X-Forwarded-For"), "203.0.113.7"); n != 1 {
		t.Errorf("client IP appears %d times in X-Forwarded-For %q, want exactly once", n, got.Get("X-Forwarded-For"))
	}
	_ = a
}

func TestTargetAccessor(t *testing.T) {
	a := New(Config{TargetURL: "http://127.0.0.1:3000/base"})
	got := a.Target()
	if got == nil {
		t.Fatalf("Target() = nil, want parsed url")
	}
	if got.Scheme != "http" || got.Host != "127.0.0.1:3000" || got.Path != "/base" {
		t.Fatalf("Target() = %#v", got)
	}

	got.Host = "evil.example.com"
	if a.Target().Host != "127.0.0.1:3000" {
		t.Errorf("caller mutated the agent's target: %v", a.Target())
	}

	bad := New(Config{TargetURL: "http://[::1"})
	if bad.Target() != nil {
		t.Errorf("Target() = %v for an unparseable url, want nil", bad.Target())
	}
}
