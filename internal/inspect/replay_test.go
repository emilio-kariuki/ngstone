package inspect

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type recordedRequest struct {
	method string
	uri    string
	host   string
	header http.Header
	body   []byte
}

type requestRecorder struct {
	mu   sync.Mutex
	seen []recordedRequest
}

func (rr *requestRecorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rr.mu.Lock()
		rr.seen = append(rr.seen, recordedRequest{
			method: r.Method,
			uri:    r.URL.RequestURI(),
			host:   r.Host,
			header: r.Header.Clone(),
			body:   body,
		})
		rr.mu.Unlock()
		w.Header().Set("X-Echo", "1")
		w.Write([]byte("echoed:" + string(body)))
	})
}

func (rr *requestRecorder) get(i int) recordedRequest {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	return rr.seen[i]
}

func (rr *requestRecorder) count() int {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	return len(rr.seen)
}

func TestReplayReproducesRequestByteIdentically(t *testing.T) {
	rr := &requestRecorder{}
	app := httptest.NewServer(rr.handler())
	defer app.Close()

	store := NewStore()
	front := httptest.NewServer(proxyTo(t, NewCapturer(store), app.URL))
	defer front.Close()

	req, err := http.NewRequest(http.MethodPost, front.URL+"/api/items?page=2", strings.NewReader(`{"name":"thing"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custom", "keep-me")
	req.Header.Set("Connection", "keep-alive")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if rr.count() != 1 {
		t.Fatalf("app saw %d requests, want 1", rr.count())
	}
	original := rr.get(0)

	ex := store.List()[0]
	target, _ := url.Parse(app.URL)

	replayed, err := store.Replay(context.Background(), ex.ID, target, http.DefaultTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Replayed {
		t.Fatal("replayed exchange not flagged")
	}
	if replayed.ReplayOf != ex.ID {
		t.Fatalf("replay source = %q, want %q", replayed.ReplayOf, ex.ID)
	}
	if rr.count() != 2 {
		t.Fatalf("app saw %d requests after replay, want 2", rr.count())
	}
	got := rr.get(1)

	if got.method != original.method {
		t.Fatalf("method %q != %q", got.method, original.method)
	}
	if got.uri != original.uri {
		t.Fatalf("uri %q != %q", got.uri, original.uri)
	}
	if got.host != original.host {
		t.Fatalf("host %q != %q", got.host, original.host)
	}
	if !bytes.Equal(got.body, original.body) {
		t.Fatalf("body %q != %q", got.body, original.body)
	}
	if !reflect.DeepEqual(got.header, original.header) {
		t.Fatalf("headers differ:\nreplay:   %v\noriginal: %v", got.header, original.header)
	}
	if replayed.Resp.Status != http.StatusOK {
		t.Fatalf("replay status = %d", replayed.Resp.Status)
	}
	if string(replayed.Resp.Body) != `echoed:{"name":"thing"}` {
		t.Fatalf("replay response body = %q", replayed.Resp.Body)
	}
	if _, ok := store.Get(replayed.ID); !ok {
		t.Fatal("replayed exchange not added to the store")
	}
}

func TestReplayRejectsTruncatedBody(t *testing.T) {
	ex := &Exchange{
		ID:   newID(),
		Kind: KindHTTP,
		Req: CapturedReq{
			Method:    http.MethodPost,
			URL:       "http://app.local/upload",
			Header:    hdr("Content-Type", "application/octet-stream"),
			Body:      bytes.Repeat([]byte("x"), BodyCap),
			BodySize:  BodyCap + 1,
			Truncated: true,
		},
	}
	target, _ := url.Parse("http://127.0.0.1:1")
	if _, err := Replay(context.Background(), ex, target, http.DefaultTransport, nil); !errors.Is(err, ErrTruncatedBody) {
		t.Fatalf("err = %v, want ErrTruncatedBody", err)
	}
}

func TestReplayTruncatedAllowedWithBodyOverride(t *testing.T) {
	rr := &requestRecorder{}
	app := httptest.NewServer(rr.handler())
	defer app.Close()
	target, _ := url.Parse(app.URL)

	ex := &Exchange{
		ID:   newID(),
		Kind: KindHTTP,
		Req: CapturedReq{
			Method:    http.MethodPost,
			URL:       "http://app.local/upload",
			Header:    hdr("Content-Type", "text/plain"),
			Truncated: true,
		},
	}
	out, err := Replay(context.Background(), ex, target, http.DefaultTransport, &Overrides{Body: []byte("replacement")})
	if err != nil {
		t.Fatal(err)
	}
	if string(rr.get(0).body) != "replacement" {
		t.Fatalf("body = %q", rr.get(0).body)
	}
	if out.Resp.Status != http.StatusOK {
		t.Fatalf("status = %d", out.Resp.Status)
	}
}

func TestReplayOverrides(t *testing.T) {
	rr := &requestRecorder{}
	app := httptest.NewServer(rr.handler())
	defer app.Close()
	target, _ := url.Parse(app.URL)

	ex := &Exchange{
		ID:   newID(),
		Kind: KindHTTP,
		Req: CapturedReq{
			Method: http.MethodGet,
			URL:    "http://app.local/original",
			Header: hdr("X-Old", "1"),
		},
	}
	ov := &Overrides{
		Method: http.MethodPut,
		URL:    "http://app.local/changed?q=9",
		Header: hdr("X-New", "2"),
		Body:   []byte("new-body"),
	}
	if _, err := Replay(context.Background(), ex, target, http.DefaultTransport, ov); err != nil {
		t.Fatal(err)
	}
	got := rr.get(0)
	if got.method != http.MethodPut {
		t.Fatalf("method = %q", got.method)
	}
	if got.uri != "/changed?q=9" {
		t.Fatalf("uri = %q", got.uri)
	}
	if got.header.Get("X-New") != "2" || got.header.Get("X-Old") != "" {
		t.Fatalf("headers = %v", got.header)
	}
	if string(got.body) != "new-body" {
		t.Fatalf("body = %q", got.body)
	}
}

func TestReplayStripsHopByHopHeaders(t *testing.T) {
	h := hdr(
		"Connection", "keep-alive, X-Custom-Hop",
		"X-Custom-Hop", "drop-me",
		"Keep-Alive", "timeout=5",
		"Transfer-Encoding", "chunked",
		"Upgrade", "websocket",
		"X-Keep", "yes",
	)
	got := sanitizeHeader(h)
	for _, k := range []string{"Connection", "X-Custom-Hop", "Keep-Alive", "Transfer-Encoding", "Upgrade", "Content-Length", "Host"} {
		if got.Get(k) != "" {
			t.Fatalf("header %q survived: %v", k, got)
		}
	}
	if got.Get("X-Keep") != "yes" {
		t.Fatalf("X-Keep dropped: %v", got)
	}
	if h.Get("Connection") == "" {
		t.Fatal("sanitizeHeader mutated the source header")
	}
}

func TestReplayRejectsUpgrade(t *testing.T) {
	ex := &Exchange{ID: newID(), Kind: KindUpgrade}
	target, _ := url.Parse("http://127.0.0.1:1")
	if _, err := Replay(context.Background(), ex, target, http.DefaultTransport, nil); !errors.Is(err, ErrNotReplayable) {
		t.Fatalf("err = %v, want ErrNotReplayable", err)
	}
}

func TestReplayNeverUsesTheTunnel(t *testing.T) {
	rr := &requestRecorder{}
	app := httptest.NewServer(rr.handler())
	defer app.Close()

	var tunnelHit atomic.Bool
	tunnelSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tunnelHit.Store(true)
		w.WriteHeader(http.StatusTeapot)
	}))
	defer tunnelSrv.Close()

	ex := &Exchange{
		ID:   newID(),
		Kind: KindHTTP,
		Req: CapturedReq{
			Method: http.MethodGet,
			URL:    tunnelSrv.URL + "/via-tunnel",
			Header: make(http.Header),
		},
	}
	target, _ := url.Parse(app.URL)
	out, err := Replay(context.Background(), ex, target, http.DefaultTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tunnelHit.Load() {
		t.Fatal("replay went back through the tunnel origin")
	}
	if rr.count() != 1 {
		t.Fatalf("local app saw %d requests", rr.count())
	}
	if rr.get(0).uri != "/via-tunnel" {
		t.Fatalf("uri = %q", rr.get(0).uri)
	}
	if out.Resp.Status != http.StatusOK {
		t.Fatalf("status = %d", out.Resp.Status)
	}
}

func TestReplayTransportErrorRecorded(t *testing.T) {
	ex := &Exchange{
		ID:   newID(),
		Kind: KindHTTP,
		Req: CapturedReq{
			Method: http.MethodGet,
			URL:    "http://127.0.0.1:1/dead",
			Header: make(http.Header),
		},
	}
	target, _ := url.Parse("http://127.0.0.1:1")
	out, err := Replay(context.Background(), ex, target, http.DefaultTransport, nil)
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if out == nil || out.Err == "" {
		t.Fatal("failed replay should still produce an exchange with Err set")
	}
}
