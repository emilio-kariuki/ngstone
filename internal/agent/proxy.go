package agent

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"ngstone/internal/inspect"
)

func (a *Agent) buildProxy(target *url.URL) http.Handler {
	return a.buildProxyWithTransport(target, a.transport)
}

func (a *Agent) buildHTTP2Proxy(target *url.URL) http.Handler {
	return a.buildProxyWithTransport(target, a.http2Transport)
}

func (a *Agent) buildProxyWithTransport(target *url.URL, transport http.RoundTripper) http.Handler {
	rewrite := func(pr *httputil.ProxyRequest) {
		pr.Out.URL.Scheme = strings.ToLower(target.Scheme)
		pr.Out.URL.Host = target.Host
		pr.Out.Host = pr.In.Host
		if a.cfg.HostHeader != "" {
			pr.Out.Host = a.cfg.HostHeader
		}
		pr.Out.Header["Forwarded"] = pr.In.Header["Forwarded"]
		pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"]
		pr.Out.Header["X-Forwarded-Host"] = pr.In.Header["X-Forwarded-Host"]
		pr.Out.Header["X-Forwarded-Proto"] = pr.In.Header["X-Forwarded-Proto"]
	}

	proxy := &httputil.ReverseProxy{
		Rewrite:       rewrite,
		Transport:     transport,
		FlushInterval: -1,
	}

	if a.store == nil {
		return proxy
	}

	capturer := inspect.NewCapturer(a.store)
	capturer.Install(proxy)
	return capturer.Middleware(proxy)
}

func newHTTP2Transport(target *url.URL) *http2.Transport {
	scheme := strings.ToLower(target.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil
	}
	transport := &http2.Transport{
		IdleConnTimeout: 90 * time.Second,
		ReadIdleTimeout: 30 * time.Second,
		PingTimeout:     15 * time.Second,
	}
	if scheme == "http" {
		transport.AllowHTTP = true
		transport.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
	}
	return transport
}
