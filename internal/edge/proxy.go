package edge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"ngstone/internal/inspect"
	"ngstone/internal/policy"
)

type ctxKey int

const (
	ctxKeyClientAddr ctxKey = iota
	ctxKeyReqID
	ctxKeyReqSlot
	ctxKeyIdleBody
)

// statusRecorder records the response status and size. When idle is set,
// each write and flush to the public client must finish within idle: a
// client that stops reading its response cannot hold a request slot
// forever. The deadline is armed only while a write is blocked, so long
// quiet streams such as SSE are unaffected.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
	idle   time.Duration
}

func (r *statusRecorder) armWrite() {
	if r.idle > 0 {
		_ = http.NewResponseController(r.ResponseWriter).SetWriteDeadline(time.Now().Add(r.idle))
	}
}

func (r *statusRecorder) disarmWrite() {
	if r.idle > 0 {
		_ = http.NewResponseController(r.ResponseWriter).SetWriteDeadline(time.Time{})
	}
}

type countingReadCloser struct {
	io.ReadCloser
	bytes atomic.Int64
}

func (r *countingReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	r.bytes.Add(int64(n))
	return n, err
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	r.armWrite()
	n, err := r.ResponseWriter.Write(b)
	r.disarmWrite()
	r.bytes += int64(n)
	return n, err
}

// FlushError is what http.ResponseController and ReverseProxy call; the
// flush is where a write to a slow client actually blocks.
func (r *statusRecorder) FlushError() error {
	r.armWrite()
	err := http.NewResponseController(r.ResponseWriter).Flush()
	r.disarmWrite()
	return err
}

func (r *statusRecorder) Flush() { _ = r.FlushError() }

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func recordRequestMetrics(rec *statusRecorder) {
	metricRequestsTotal.Add(1)
	metricBytesTotal.Add(rec.bytes)
	switch {
	case rec.status >= 500:
		metricResponses5xx.Add(1)
	case rec.status >= 400:
		metricResponses4xx.Add(1)
	}
}

func (s *Server) handlePublic(w http.ResponseWriter, r *http.Request) {
	limits := s.limitsOrDefault()
	rec := &statusRecorder{ResponseWriter: w, idle: limits.ClientIdleTimeout}
	defer recordRequestMetrics(rec)

	host := stripPort(r.Host)
	b, ok := s.registry.Route(host)
	if !ok {
		writeError(rec, http.StatusNotFound)
		return
	}
	var requestBytes countingReadCloser
	started := time.Now()
	defer func() {
		s.observability.observeRequest(b.durableTunnelID(), host, rec.status, time.Since(started), requestBytes.bytes.Load(), rec.bytes)
	}()

	snapshot := b.snapshot.Load()
	var ac *accessControl
	var trafficPolicy *policy.Policy
	var http2Mode bool
	if snapshot != nil {
		ac = snapshot.access
		trafficPolicy = snapshot.trafficPolicy
		http2Mode = snapshot.http2
	} else {
		ac = b.access.Load()
	}

	ip := stripPort(r.RemoteAddr)
	if addr, err := netip.ParseAddr(ip); err == nil {
		if !ac.allowIP(addr) {
			metricRejectedForbiddenCIDR.Add(1)
			http.Error(rec, "forbidden", http.StatusForbidden)
			return
		}
	} else if len(ac.prefixes()) > 0 {
		metricRejectedForbiddenCIDR.Add(1)
		http.Error(rec, "forbidden", http.StatusForbidden)
		return
	}

	if !s.perIPLimiter.allow(ip) {
		metricRejectedRateLimited.Add(1)
		writeTooManyRequests(rec)
		return
	}

	if !ac.checkBasicAuth(r) {
		metricRejectedUnauthorized.Add(1)
		rec.Header().Set("WWW-Authenticate", `Basic realm="`+ac.authRealm()+`", charset="UTF-8"`)
		http.Error(rec, "unauthorized", http.StatusUnauthorized)
		return
	}
	if trafficPolicy != nil && !trafficPolicy.Decide(r).Allowed {
		metricRejectedTrafficPolicy.Add(1)
		http.Error(rec, "forbidden", http.StatusForbidden)
		return
	}
	if ac.hasBasicAuth() {
		r.Header.Del("Authorization")
	}

	releaseIP, ok := s.perIP.acquire(ip)
	if !ok {
		metricRejectedPerIPCap.Add(1)
		writeTooManyRequests(rec)
		return
	}
	defer releaseIP()

	if !s.globalSem.tryAcquire() {
		metricRejectedGlobalCap.Add(1)
		writeTooManyRequests(rec)
		return
	}

	connector, selected := b.selectConnector(http2Mode)
	if !selected {
		s.globalSem.release()
		metricRejectedSessionCap.Add(1)
		writeTooManyRequests(rec)
		return
	}

	proxy := connector.proxyFor(http2Mode)
	if proxy == nil {
		s.globalSem.release()
		connector.sess.releaseStream()
		proxyErrorHandler(rec, r, errors.New("edge: binding proxy unavailable"))
		return
	}

	slot := newReqSlot(s, connector.sess)
	defer slot.release()

	if r.ContentLength > limits.MaxBodyBytes {
		metricRejected413.Add(1)
		http.Error(rec, "request entity too large", http.StatusRequestEntityTooLarge)
		return
	}
	ctx := r.Context()
	if r.Body != nil && r.Body != http.NoBody {
		requestBytes.ReadCloser = r.Body
		body := &idleBody{
			ReadCloser: http.MaxBytesReader(w, &requestBytes, limits.MaxBodyBytes),
			rc:         http.NewResponseController(w),
			idle:       limits.ClientIdleTimeout,
		}
		r.Body = body
		ctx = context.WithValue(ctx, ctxKeyIdleBody, body)
	}

	reqID := randomHex(8)
	ctx = context.WithValue(ctx, ctxKeyClientAddr, r.RemoteAddr)
	ctx = context.WithValue(ctx, ctxKeyReqID, reqID)
	ctx = context.WithValue(ctx, ctxKeyReqSlot, slot)

	proxy.ServeHTTP(rec, r.WithContext(ctx))
}

// errClientIdle reports that the public client stopped sending its request
// body for longer than the client idle timeout.
var errClientIdle = errors.New("edge: client stopped sending the request body")

// idleBody bounds each read of a request body by idle, so a client that
// sends headers and then trickles or stops the body cannot hold a request
// slot indefinitely. The deadline is armed only for the duration of a Read
// or Close: net/http's background read after the body is consumed must not
// see a stale deadline, or it would cancel the request mid-response.
type idleBody struct {
	io.ReadCloser
	rc      *http.ResponseController
	idle    time.Duration
	stalled atomic.Bool
}

func (b *idleBody) Read(p []byte) (int, error) {
	if b.idle <= 0 {
		return b.ReadCloser.Read(p)
	}
	_ = b.rc.SetReadDeadline(time.Now().Add(b.idle))
	n, err := b.ReadCloser.Read(p)
	if err != nil && errors.Is(err, os.ErrDeadlineExceeded) {
		b.stalled.Store(true)
		return n, fmt.Errorf("%w: %w", errClientIdle, err)
	}
	_ = b.rc.SetReadDeadline(time.Time{})
	return n, err
}

// Close is bounded too: closing an unread body makes net/http drain up to
// 256 KiB from the client, which would block forever on a stalled client.
// Once the client is known to have stalled, the drain fails immediately.
func (b *idleBody) Close() error {
	if b.idle <= 0 {
		return b.ReadCloser.Close()
	}
	deadline := time.Now().Add(b.idle)
	if b.stalled.Load() {
		deadline = time.Now()
	}
	_ = b.rc.SetReadDeadline(deadline)
	err := b.ReadCloser.Close()
	_ = b.rc.SetReadDeadline(time.Time{})
	return err
}

func newBindingProxy(transport http.RoundTripper) *httputil.ReverseProxy {
	return newBindingProxyWithMetadata(transport, false)
}

func newBindingHTTP2Proxy(transport http.RoundTripper) *httputil.ReverseProxy {
	return newBindingProxyWithMetadata(transport, true)
}

func newBindingProxyWithMetadata(transport http.RoundTripper, includeMetadata bool) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: "http", Host: "tunnel-agent"})
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
			pr.Out.Header.Del("X-Real-IP")
			if includeMetadata {
				if reqID, _ := pr.Out.Context().Value(ctxKeyReqID).(string); reqID != "" {
					pr.Out.Header.Set(inspect.RequestIDHeader, reqID)
				}
				if clientAddr, _ := pr.Out.Context().Value(ctxKeyClientAddr).(string); clientAddr != "" {
					pr.Out.Header.Set(inspect.ClientAddrHeader, clientAddr)
				}
			}
		},
		ModifyResponse: modifyResponse,
		ErrorHandler:   proxyErrorHandler,
	}
}

var errUpgradeCapExceeded = errors.New("edge: upgrade capacity exceeded")

func modifyResponse(resp *http.Response) error {
	if body, ok := resp.Request.Context().Value(ctxKeyIdleBody).(*idleBody); ok && body.stalled.Load() {
		return errClientIdle
	}
	slot, ok := resp.Request.Context().Value(ctxKeyReqSlot).(*reqSlot)
	if !ok || slot == nil {
		return nil
	}

	if !isLongLivedResponse(resp) {
		return nil
	}

	if !slot.reclassify() {
		metricRejectedUpgradeCap.Add(1)
		return errUpgradeCapExceeded
	}
	return nil
}

func isLongLivedResponse(resp *http.Response) bool {
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return true
	}
	if resp.StatusCode != http.StatusOK {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return false
	}
	return mediaType == "text/event-stream" || strings.HasPrefix(mediaType, "application/grpc")
}

func proxyErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errUpgradeCapExceeded) {
		writeError(w, http.StatusServiceUnavailable)
		return
	}

	// A stalled body usually surfaces as "context canceled": failing the
	// drain breaks the client connection, which cancels the request, and
	// the transport reports the cancellation in preference to the body
	// error. Ask the body itself.
	body, _ := r.Context().Value(ctxKeyIdleBody).(*idleBody)
	if errors.Is(err, errClientIdle) || (body != nil && body.stalled.Load()) {
		metricRejectedClientIdle.Add(1)
		if r.ProtoMajor == 1 {
			w.Header().Set("Connection", "close")
		}
		writeError(w, http.StatusRequestTimeout)
		return
	}

	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		metricRejected413.Add(1)
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}

	var de *dialError
	if errors.As(err, &de) {
		writeError(w, http.StatusBadGateway)
		return
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		writeError(w, http.StatusGatewayTimeout)
		return
	}

	writeError(w, http.StatusBadGateway)
}

func writeError(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<!doctype html><html><head><title>%d %s</title></head><body><p>%d %s</p></body></html>",
		status, http.StatusText(status), status, http.StatusText(status))
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
