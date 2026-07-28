package edge

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
)

type ctxKey int

const (
	ctxKeyClientAddr ctxKey = iota
	ctxKeyReqID
)

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
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
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

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
	rec := &statusRecorder{ResponseWriter: w}
	defer recordRequestMetrics(rec)

	host := stripPort(r.Host)
	b, ok := s.registry.Route(host)
	if !ok {
		http.NotFound(rec, r)
		return
	}

	ac := b.access.Load()

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
	if ac.hasBasicAuth() {
		r.Header.Del("Authorization")
	}

	if !s.globalSem.tryAcquire() {
		metricRejectedGlobalCap.Add(1)
		writeTooManyRequests(rec)
		return
	}
	defer s.globalSem.release()

	if !b.Sess.tryAcquireStream() {
		metricRejectedSessionCap.Add(1)
		writeTooManyRequests(rec)
		return
	}
	defer b.Sess.releaseStream()

	limits := s.limitsOrDefault()
	if r.ContentLength > limits.MaxBodyBytes {
		metricRejected413.Add(1)
		http.Error(rec, "request entity too large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, limits.MaxBodyBytes)

	reqID := randomHex(8)
	ctx := context.WithValue(r.Context(), ctxKeyClientAddr, r.RemoteAddr)
	ctx = context.WithValue(ctx, ctxKeyReqID, reqID)

	b.proxy.ServeHTTP(rec, r.WithContext(ctx))
}

func newBindingProxy(transport *http.Transport) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: "http", Host: "tunnel-agent"})
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
			pr.Out.Header.Del("X-Real-IP")
		},
		ErrorHandler: proxyErrorHandler,
	}
}

func proxyErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		metricRejected413.Add(1)
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}

	var de *dialError
	if errors.As(err, &de) {
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		w.WriteHeader(http.StatusGatewayTimeout)
		return
	}

	w.WriteHeader(http.StatusBadGateway)
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
