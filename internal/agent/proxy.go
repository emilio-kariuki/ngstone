package agent

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

func (a *Agent) buildProxy(target *url.URL) http.Handler {
	transport := &http.Transport{
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   false,
	}

	rewrite := func(pr *httputil.ProxyRequest) {
		pr.Out.URL.Scheme = target.Scheme
		pr.Out.URL.Host = target.Host
		pr.Out.Header["Forwarded"] = pr.In.Header["Forwarded"]
		pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"]
		pr.Out.Header["X-Forwarded-Host"] = pr.In.Header["X-Forwarded-Host"]
		pr.Out.Header["X-Forwarded-Proto"] = pr.In.Header["X-Forwarded-Proto"]
	}

	return &httputil.ReverseProxy{
		Rewrite:       rewrite,
		Transport:     transport,
		FlushInterval: -1,
	}
}
