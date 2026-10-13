package agent

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"ngstone/internal/inspect"
)

func (a *Agent) buildProxy(target *url.URL) http.Handler {
	rewrite := func(pr *httputil.ProxyRequest) {
		pr.Out.URL.Scheme = target.Scheme
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
		Transport:     a.transport,
		FlushInterval: -1,
	}

	if a.store == nil {
		return proxy
	}

	capturer := inspect.NewCapturer(a.store).WithTunnel(a.cfg.Name)
	capturer.Install(proxy)
	return capturer.Middleware(proxy)
}
