package edge

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
)

type ctxKey int

const (
	ctxKeyClientAddr ctxKey = iota
	ctxKeyReqID
)

func (s *Server) handlePublic(w http.ResponseWriter, r *http.Request) {
	host := stripPort(r.Host)
	b, ok := s.registry.Route(host)
	if !ok {
		http.NotFound(w, r)
		return
	}

	reqID := randomHex(8)
	ctx := context.WithValue(r.Context(), ctxKeyClientAddr, r.RemoteAddr)
	ctx = context.WithValue(ctx, ctxKeyReqID, reqID)

	proxy := &httputil.ReverseProxy{
		Transport:     b.transport,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: "http", Host: "tunnel-agent"})
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
			pr.Out.Header.Del("X-Real-IP")
		},
	}
	proxy.ServeHTTP(w, r.WithContext(ctx))
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
