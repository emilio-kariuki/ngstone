package inspect

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"sync/atomic"
	"time"
)

const BodyCap = 256 << 10

const (
	RequestIDHeader  = "X-Ngstone-Request-ID"
	ClientAddrHeader = "X-Ngstone-Client-Addr"
)

var upgradePublishInterval = 250 * time.Millisecond

type ctxKey int

const (
	ctxKeyStream ctxKey = iota
	ctxKeyState
)

type StreamInfo struct {
	ReqID      string
	Host       string
	ClientAddr string
}

func WithStreamInfo(ctx context.Context, info StreamInfo) context.Context {
	return context.WithValue(ctx, ctxKeyStream, info)
}

func StreamInfoFrom(ctx context.Context) StreamInfo {
	if ctx == nil {
		return StreamInfo{}
	}
	info, _ := ctx.Value(ctxKeyStream).(StreamInfo)
	return info
}

func ReqIDFrom(ctx context.Context) string {
	return StreamInfoFrom(ctx).ReqID
}

type capBuf struct {
	mu        sync.Mutex
	buf       []byte
	size      int64
	truncated bool
}

func (c *capBuf) add(b []byte) {
	if len(b) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.size += int64(len(b))

	room := BodyCap - len(c.buf)
	if room <= 0 {
		c.truncated = true
		return
	}
	if len(b) > room {
		b = b[:room]
		c.truncated = true
	}
	c.grow(len(b))
	c.buf = append(c.buf, b...)
}

func (c *capBuf) grow(n int) {
	if cap(c.buf)-len(c.buf) >= n {
		return
	}
	next := cap(c.buf) * 2
	if next < 512 {
		next = 512
	}
	for next < len(c.buf)+n {
		next *= 2
	}
	if next > BodyCap {
		next = BodyCap
	}
	nb := make([]byte, len(c.buf), next)
	copy(nb, c.buf)
	c.buf = nb
}

func (c *capBuf) snapshot() ([]byte, int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]byte, len(c.buf))
	copy(out, c.buf)
	return out, c.size, c.truncated
}

type cappedTee struct {
	r  io.Reader
	cb *capBuf
}

func (t *cappedTee) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		t.cb.add(p[:n])
	}
	return n, err
}

type teeBody struct {
	io.Reader
	c io.Closer
}

func (b *teeBody) Close() error { return b.c.Close() }

type upgradeCounters struct {
	store *Store
	id    string
	start time.Time

	c2a atomic.Int64
	a2c atomic.Int64

	mu      sync.Mutex
	lastPub time.Time

	done sync.Once
}

func (u *upgradeCounters) addClientToApp(n int64) {
	u.c2a.Add(n)
	u.maybePublish()
}

func (u *upgradeCounters) addAppToClient(n int64) {
	u.a2c.Add(n)
	u.maybePublish()
}

func (u *upgradeCounters) maybePublish() {
	u.mu.Lock()
	if time.Since(u.lastPub) < upgradePublishInterval {
		u.mu.Unlock()
		return
	}
	u.lastPub = time.Now()
	u.mu.Unlock()
	u.publish()
}

func (u *upgradeCounters) publish() {
	u.store.Update(u.id, func(e *Exchange) {
		e.BytesClientToApp = u.c2a.Load()
		e.BytesAppToClient = u.a2c.Load()
		e.Duration = time.Since(u.start)
	})
}

func (u *upgradeCounters) finish() {
	u.done.Do(func() {
		u.mu.Lock()
		u.lastPub = time.Now()
		u.mu.Unlock()
		u.publish()
	})
}

type closeWriter interface {
	CloseWrite() error
}

type countingConn struct {
	net.Conn
	ctr *upgradeCounters
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.ctr.addClientToApp(int64(n))
	}
	return n, err
}

func (c *countingConn) Close() error {
	c.ctr.finish()
	return c.Conn.Close()
}

type countingConnCW struct {
	countingConn
}

func (c *countingConnCW) CloseWrite() error {
	return c.Conn.(closeWriter).CloseWrite()
}

func wrapConn(conn net.Conn, ctr *upgradeCounters) net.Conn {
	base := countingConn{Conn: conn, ctr: ctr}
	if _, ok := conn.(closeWriter); ok {
		return &countingConnCW{countingConn: base}
	}
	return &base
}

type countingRWC struct {
	rwc io.ReadWriteCloser
	ctr *upgradeCounters
}

func (c *countingRWC) Read(p []byte) (int, error) {
	n, err := c.rwc.Read(p)
	if n > 0 {
		c.ctr.addAppToClient(int64(n))
	}
	return n, err
}

func (c *countingRWC) Write(p []byte) (int, error) { return c.rwc.Write(p) }

func (c *countingRWC) Close() error {
	c.ctr.finish()
	return c.rwc.Close()
}

type countingRWCCW struct {
	countingRWC
}

func (c *countingRWCCW) CloseWrite() error {
	return c.rwc.(closeWriter).CloseWrite()
}

func wrapRWC(rwc io.ReadWriteCloser, ctr *upgradeCounters) io.ReadWriteCloser {
	base := countingRWC{rwc: rwc, ctr: ctr}
	if _, ok := rwc.(closeWriter); ok {
		return &countingRWCCW{countingRWC: base}
	}
	return &base
}

type exchangeState struct {
	store *Store
	id    string
	reqID string
	start time.Time

	method string
	url    string
	proto  string
	header http.Header
	body   *capBuf

	mu        sync.Mutex
	hijacked  bool
	finalized bool
	ctr       *upgradeCounters
}

func (s *exchangeState) capturedReq() CapturedReq {
	body, size, trunc := s.body.snapshot()
	return CapturedReq{
		Method:    s.method,
		URL:       s.url,
		Proto:     s.proto,
		Header:    s.header,
		Body:      body,
		BodySize:  size,
		Truncated: trunc,
	}
}

func (s *exchangeState) markHijacked(ctr *upgradeCounters) {
	s.mu.Lock()
	s.hijacked = true
	if ctr != nil {
		s.ctr = ctr
	}
	s.mu.Unlock()
}

func (s *exchangeState) counters() *upgradeCounters {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctr
}

func (s *exchangeState) claimFinalize() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finalized {
		return false
	}
	s.finalized = true
	return true
}

func (s *exchangeState) finalizeUpgrade(resp *http.Response) *upgradeCounters {
	if !s.claimFinalize() {
		return nil
	}
	ctr := &upgradeCounters{store: s.store, id: s.id, start: s.start}
	ex := &Exchange{
		ID:       s.id,
		ReqID:    s.reqID,
		Kind:     KindUpgrade,
		Start:    s.start,
		Duration: time.Since(s.start),
		Req:      s.capturedReq(),
		Resp: CapturedResp{
			Status: resp.StatusCode,
			Proto:  resp.Proto,
			Header: resp.Header.Clone(),
		},
	}
	s.mu.Lock()
	s.ctr = ctr
	s.mu.Unlock()
	s.store.Add(ex)
	return ctr
}

func (s *exchangeState) finalizeHTTP(rec *recorder, errText string) {
	if !s.claimFinalize() {
		return
	}
	status, header := rec.result()
	body, size, trunc := rec.body.snapshot()

	kind := KindHTTP
	s.mu.Lock()
	if s.hijacked {
		kind = KindUpgrade
	}
	s.mu.Unlock()

	s.store.Add(&Exchange{
		ID:       s.id,
		ReqID:    s.reqID,
		Kind:     kind,
		Start:    s.start,
		Duration: time.Since(s.start),
		Req:      s.capturedReq(),
		Resp: CapturedResp{
			Status:    status,
			Proto:     s.proto,
			Header:    header,
			Body:      body,
			BodySize:  size,
			Truncated: trunc,
		},
		Err: errText,
	})
}

type recorder struct {
	http.ResponseWriter
	state *exchangeState
	body  *capBuf

	mu          sync.Mutex
	status      int
	header      http.Header
	wroteHeader bool
}

func (w *recorder) WriteHeader(code int) {
	w.mu.Lock()
	if !w.wroteHeader {
		w.wroteHeader = true
		w.status = code
		w.header = w.ResponseWriter.Header().Clone()
	}
	w.mu.Unlock()
	w.ResponseWriter.WriteHeader(code)
}

func (w *recorder) Write(b []byte) (int, error) {
	w.mu.Lock()
	if !w.wroteHeader {
		w.wroteHeader = true
		w.status = http.StatusOK
		w.header = w.ResponseWriter.Header().Clone()
	}
	w.mu.Unlock()

	n, err := w.ResponseWriter.Write(b)
	if n > 0 {
		w.body.add(b[:n])
	}
	return n, err
}

func (w *recorder) result() (int, http.Header) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.wroteHeader {
		return http.StatusOK, w.ResponseWriter.Header().Clone()
	}
	return w.status, w.header
}

func (w *recorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *recorder) FlushError() error {
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *recorder) Flush() { _ = w.FlushError() }

func (w *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	ctr := w.state.counters()
	w.state.markHijacked(ctr)
	if ctr != nil {
		conn = wrapConn(conn, ctr)
	}
	return conn, brw, nil
}

type Capturer struct {
	store *Store
}

func NewCapturer(store *Store) *Capturer { return &Capturer{store: store} }

func (c *Capturer) Store() *Store { return c.store }

func Capture(store *Store) func(http.Handler) http.Handler {
	return NewCapturer(store).Middleware
}

func (c *Capturer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c == nil || c.store == nil {
			next.ServeHTTP(w, r)
			return
		}

		state := &exchangeState{
			store:  c.store,
			id:     c.store.NextID(),
			reqID:  ReqIDFrom(r.Context()),
			start:  time.Now(),
			method: r.Method,
			url:    requestURL(r),
			proto:  r.Proto,
			header: r.Header.Clone(),
			body:   &capBuf{},
		}

		if r.Body != nil && r.Body != http.NoBody {
			r.Body = &teeBody{Reader: &cappedTee{r: r.Body, cb: state.body}, c: r.Body}
		}

		r = r.WithContext(context.WithValue(r.Context(), ctxKeyState, state))

		rec := &recorder{ResponseWriter: w, state: state, body: &capBuf{}}

		defer func() {
			errText := ""
			if err := r.Context().Err(); err != nil {
				errText = err.Error()
			}
			state.finalizeHTTP(rec, errText)
		}()

		next.ServeHTTP(rec, r)
	})
}

func (c *Capturer) ModifyResponse(resp *http.Response) error {
	if resp == nil || resp.StatusCode != http.StatusSwitchingProtocols {
		return nil
	}
	if resp.Request == nil {
		return nil
	}
	state, _ := resp.Request.Context().Value(ctxKeyState).(*exchangeState)
	if state == nil {
		return nil
	}

	ctr := state.finalizeUpgrade(resp)
	if ctr == nil {
		return nil
	}
	if rwc, ok := resp.Body.(io.ReadWriteCloser); ok {
		resp.Body = wrapRWC(rwc, ctr)
	}
	return nil
}

func (c *Capturer) Install(p *httputil.ReverseProxy) {
	prev := p.ModifyResponse
	p.ModifyResponse = func(resp *http.Response) error {
		if err := c.ModifyResponse(resp); err != nil {
			return err
		}
		if prev != nil {
			return prev(resp)
		}
		return nil
	}
}

func requestURL(r *http.Request) string {
	u := *r.URL
	if u.Host == "" {
		u.Host = r.Host
	}
	if u.Scheme == "" {
		if r.TLS != nil {
			u.Scheme = "https"
		} else {
			u.Scheme = "http"
		}
	}
	return u.String()
}
