package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"expvar"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ngstone/internal/agent"
	"ngstone/internal/credentials"
	"ngstone/internal/edge"
	"ngstone/internal/inspect"
	"ngstone/internal/oidc"
	"ngstone/internal/proto"
	"ngstone/internal/storage"
	"ngstone/internal/storage/storagetest"
)

const (
	fwdDomain      = "tun.example.com"
	fwdReadyPath   = "/__ngstone_ready"
	fwdWaitBudget  = 20 * time.Second
	fwdStopBudget  = 10 * time.Second
	fwdRequestWait = 15 * time.Second
)

type fwdEdge struct {
	id          string
	controlAddr string
	publicAddr  string
	store       *storage.Store
}

type fwdConfig struct {
	proxySrc       string
	idp            *e2eIdP
	separateListen bool
}

type fwdOption func(*fwdConfig)

func withProxyProtocol(src string) fwdOption {
	return func(c *fwdConfig) { c.proxySrc = src }
}

func withSeparatePeerListen() fwdOption {
	return func(c *fwdConfig) { c.separateListen = true }
}

func withVisitorIdP(idp *e2eIdP) fwdOption {
	return func(c *fwdConfig) { c.idp = idp }
}

type fwdPair struct {
	dsn     string
	cfg     fwdConfig
	cert    tls.Certificate
	pool    *x509.CertPool
	aPublic string
	a, b    *fwdEdge
}

type fwdAgent struct {
	store *inspect.Store
	stop  func()
}

func forEachForwardStorage(t *testing.T, fn func(t *testing.T, dsn string)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) {
		fn(t, filepath.Join(t.TempDir(), "control.db"))
	})
	if os.Getenv("NGSTONE_TEST_POSTGRES_URL") != "" {
		t.Run("postgres", func(t *testing.T) {
			fn(t, storagetest.PostgresSchemaDSN(t))
		})
	}
}

func startForwardedPair(t *testing.T, dsn string, opts ...fwdOption) *fwdPair {
	t.Helper()
	p := &fwdPair{dsn: dsn}
	for _, opt := range opts {
		opt(&p.cfg)
	}
	p.cert, p.pool = selfSignedTLSCert(t, fwdDomain, "*."+fwdDomain)
	p.aPublic = freeAddr(t)
	p.a = p.startEdge(t, "edge-a", p.aPublic, p.cfg.proxySrc != "")
	p.b = p.startEdge(t, "edge-b", freeAddr(t), false)
	return p
}

func (p *fwdPair) startEdge(t *testing.T, id, publicAddr string, proxyProtocol bool) *fwdEdge {
	t.Helper()
	store, err := storage.Open(storage.Config{DSN: p.dsn, EdgeID: id})
	if err != nil {
		t.Fatalf("open storage for %s: %v", id, err)
	}
	t.Cleanup(func() { store.Close() })

	e := &fwdEdge{id: id, controlAddr: freeAddr(t), publicAddr: publicAddr, store: store}
	cfg := edge.Config{
		Storage:      store,
		ControlAddr:  e.controlAddr,
		PublicAddr:   e.publicAddr,
		Domain:       fwdDomain,
		PublicScheme: "https",
		PeerAddr:     freeAddr(t),
		PublicTLSConfig: &tls.Config{
			Certificates: []tls.Certificate{p.cert},
			MinVersion:   tls.VersionTLS12,
		},
	}
	if p.cfg.separateListen {
		cfg.PeerListen = freeAddr(t)
		cfg.PeerAddr = portMap(t, cfg.PeerListen)
	}
	if proxyProtocol {
		cfg.ProxyProtocol = true
		cfg.ProxyProtocolTrusted = []string{"127.0.0.1/32"}
	}
	if p.cfg.idp != nil {
		_, aPort, _ := net.SplitHostPort(p.aPublic)
		cfg.VisitorOIDC = &oidc.Config{
			Issuer:        p.cfg.idp.server.URL,
			ClientID:      "e2e-client",
			ClientSecret:  "e2e-secret",
			RedirectURL:   "https://" + fwdDomain + ":" + aPort + "/.ngstone/auth/callback",
			CookieSecret:  bytes.Repeat([]byte("e"), 32),
			AllowInsecure: true,
		}
	}
	srv, err := edge.New(cfg)
	if err != nil {
		t.Fatalf("edge.New %s: %v", id, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(fwdStopBudget):
			t.Errorf("edge %s did not stop within %s", id, fwdStopBudget)
		}
	})
	waitForPort(t, e.controlAddr)
	waitForPort(t, e.publicAddr)
	return e
}

func portMap(t *testing.T, to string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("portMap listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				up, err := net.DialTimeout("tcp", to, 2*time.Second)
				if err != nil {
					return
				}
				defer up.Close()
				go func() {
					io.Copy(up, c)
					up.Close()
				}()
				io.Copy(c, up)
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
	})
	return ln.Addr().String()
}

func (p *fwdPair) startAgent(t *testing.T, e *fwdEdge, credKind, subdomain, target string, mutate func(*agent.Config)) *fwdAgent {
	t.Helper()
	issued, err := e.store.Issue(credentials.Spec{Kind: credKind, Subdomain: subdomain, OwnerID: "e2e-owner"}, time.Hour)
	if err != nil {
		t.Fatalf("issue credential for %s: %v", subdomain, err)
	}
	store := inspect.NewStore()
	cfg := agent.Config{
		ControlAddr: e.controlAddr,
		Token:       issued.Token,
		Subdomain:   subdomain,
		TargetURL:   target,
		Insecure:    true,
		Store:       store,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		agent.New(cfg).Run(ctx)
		close(done)
	}()
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(fwdStopBudget):
			t.Errorf("agent %s did not stop within %s", subdomain, fwdStopBudget)
		}
	}
	t.Cleanup(stop)
	return &fwdAgent{store: store, stop: stop}
}

func (p *fwdPair) startWith(t *testing.T, subdomain, targetURL string, wantStatus int, mutate func(*agent.Config)) inProc {
	t.Helper()
	ag := p.startAgent(t, p.b, credentials.KindHTTP, subdomain, targetURL, mutate)
	host := subdomain + "." + fwdDomain
	p.waitStatus(t, p.a, host, fwdReadyPath, wantStatus)
	return inProc{
		publicAddr: p.a.publicAddr,
		hostname:   host,
		store:      ag.store,
		tlsConfig:  &tls.Config{RootCAs: p.pool, ServerName: host},
	}
}

func (p *fwdPair) start(t *testing.T, subdomain, targetURL string) inProc {
	t.Helper()
	return p.startWith(t, subdomain, targetURL, http.StatusOK, nil)
}

func (p *fwdPair) clientTo(e *fwdEdge, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	proxySrc := p.cfg.proxySrc
	viaProxy := proxySrc != "" && e == p.a
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{RootCAs: p.pool},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := dialer.DialContext(ctx, "tcp", e.publicAddr)
				if err != nil || !viaProxy {
					return conn, err
				}
				srcIP, srcPort, _ := net.SplitHostPort(proxySrc)
				conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
				if _, err := fmt.Fprintf(conn, "PROXY TCP4 %s 192.0.2.1 %s 443\r\n", srcIP, srcPort); err != nil {
					conn.Close()
					return nil, err
				}
				conn.SetWriteDeadline(time.Time{})
				return conn, nil
			},
		},
	}
}

func fwdURL(e *fwdEdge, host, path string) string {
	_, port, _ := net.SplitHostPort(e.publicAddr)
	return "https://" + host + ":" + port + path
}

func (p *fwdPair) waitStatus(t *testing.T, e *fwdEdge, host, path string, want int) {
	t.Helper()
	client := p.clientTo(e, 3*time.Second)
	deadline := time.Now().Add(fwdWaitBudget)
	last := ""
	for time.Now().Before(deadline) {
		resp, err := client.Get(fwdURL(e, host, path))
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == want {
				return
			}
			last = resp.Status
		} else {
			last = err.Error()
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %d from %s%s via %s; last: %s", fwdWaitBudget, want, host, path, e.id, last)
}

func (p *fwdPair) waitBody(t *testing.T, e *fwdEdge, host, path, want string) {
	t.Helper()
	client := p.clientTo(e, 3*time.Second)
	deadline := time.Now().Add(fwdWaitBudget)
	last := ""
	for time.Now().Before(deadline) {
		resp, err := client.Get(fwdURL(e, host, path))
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && string(body) == want {
				return
			}
			last = fmt.Sprintf("%d %q", resp.StatusCode, body)
		} else {
			last = err.Error()
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for body %q from %s%s via %s; last: %s", fwdWaitBudget, want, host, path, e.id, last)
}

func (p *fwdPair) browser(t *testing.T) *http.Client {
	t.Helper()
	client := browserClient(t, p.a.publicAddr, fwdDomain)
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: p.pool}
	return client
}

func readyWrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == fwdReadyPath {
			w.WriteHeader(http.StatusOK)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func expvarCount(t *testing.T, name string) int64 {
	t.Helper()
	v, ok := expvar.Get(name).(*expvar.Int)
	if !ok {
		t.Fatalf("expvar %s is not registered", name)
	}
	return v.Value()
}

func forwardedHTTPRequest(t *testing.T, dsn string, opts ...fwdOption) {
	p := startForwardedPair(t, dsn, opts...)
	origin := httptest.NewServer(readyWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %s?%s proto=%s", r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("X-Forwarded-Proto"))
	})))
	defer origin.Close()
	h := p.start(t, "web", origin.URL)

	forwardedBefore := expvarCount(t, "ngstoned_peer_forwarded_conns_total")
	acceptedBefore := expvarCount(t, "ngstoned_peer_accepted_conns_total")
	requestsBefore := expvarCount(t, "ngstoned_requests_total")

	resp, err := p.clientTo(p.a, fwdRequestWait).Get(fwdURL(p.a, h.hostname, "/hello?x=1"))
	if err != nil {
		t.Fatalf("GET via edge-a: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "GET /hello?x=1 proto=https" {
		t.Fatalf("response = %d %q", resp.StatusCode, body)
	}
	if got := expvarCount(t, "ngstoned_peer_forwarded_conns_total") - forwardedBefore; got != 1 {
		t.Fatalf("forwarded connections = %d, want 1", got)
	}
	if got := expvarCount(t, "ngstoned_peer_accepted_conns_total") - acceptedBefore; got != 1 {
		t.Fatalf("accepted peer connections = %d, want 1", got)
	}
	if got := expvarCount(t, "ngstoned_requests_total") - requestsBefore; got != 1 {
		t.Fatalf("requests counted across both edges = %d, want 1 (the owner counts it, the ingress must not)", got)
	}
}

func TestForwardedHTTPRequest(t *testing.T) {
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		forwardedHTTPRequest(t, dsn)
	})
	t.Run("separate peer listen", func(t *testing.T) {
		forEachForwardStorage(t, func(t *testing.T, dsn string) {
			forwardedHTTPRequest(t, dsn, withSeparatePeerListen())
		})
	})
}

func TestForwardedWebSocketEcho(t *testing.T) {
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		p := startForwardedPair(t, dsn)
		testWebSocketEchoSession(t, p.start)
	})
}

func TestForwardedSSEStream(t *testing.T) {
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		p := startForwardedPair(t, dsn)
		testSSEStream(t, p.start)
	})
}

func TestForwardedLargeBody(t *testing.T) {
	const size = 32 << 20
	pattern := func() io.Reader {
		return io.LimitReader(rand.New(rand.NewSource(7)), size)
	}
	want := sha256.New()
	if _, err := io.Copy(want, pattern()); err != nil {
		t.Fatal(err)
	}
	wantSum := hex.EncodeToString(want.Sum(nil))

	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		p := startForwardedPair(t, dsn)
		origin := httptest.NewServer(readyWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := sha256.New()
			n, err := io.Copy(h, r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("X-Upload-SHA256", hex.EncodeToString(h.Sum(nil)))
			w.Header().Set("X-Upload-Bytes", fmt.Sprint(n))
			io.Copy(w, pattern())
		})))
		defer origin.Close()
		h := p.start(t, "big", origin.URL)

		req, err := http.NewRequest(http.MethodPost, fwdURL(p.a, h.hostname, "/upload"), pattern())
		if err != nil {
			t.Fatal(err)
		}
		req.ContentLength = size
		resp, err := p.clientTo(p.a, 2*time.Minute).Do(req)
		if err != nil {
			t.Fatalf("POST via edge-a: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if got := resp.Header.Get("X-Upload-Bytes"); got != fmt.Sprint(size) {
			t.Fatalf("origin received %s bytes, want %d", got, size)
		}
		if got := resp.Header.Get("X-Upload-SHA256"); got != wantSum {
			t.Fatalf("origin received digest %s, want %s", got, wantSum)
		}
		got := sha256.New()
		n, err := io.Copy(got, resp.Body)
		if err != nil {
			t.Fatalf("read response body after %d bytes: %v", n, err)
		}
		if n != size || hex.EncodeToString(got.Sum(nil)) != wantSum {
			t.Fatalf("response body = %d bytes digest %s, want %d bytes digest %s", n, hex.EncodeToString(got.Sum(nil)), size, wantSum)
		}
	})
}

func TestForwardPreservesClientIPBehindProxyProtocol(t *testing.T) {
	const srcIP = "203.0.113.7"
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		p := startForwardedPair(t, dsn, withProxyProtocol(srcIP+":41234"))
		captured := &originCapture{}
		origin := httptest.NewServer(readyWrap(http.HandlerFunc(captured.handler)))
		defer origin.Close()
		h := p.start(t, "web", origin.URL)

		resp, err := p.clientTo(p.a, fwdRequestWait).Get(fwdURL(p.a, h.hostname, "/who"))
		if err != nil {
			t.Fatalf("GET via edge-a: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		seen := captured.snapshot()
		if len(seen) != 1 {
			t.Fatalf("origin saw %d requests, want 1", len(seen))
		}
		if got := seen[0].Values("X-Forwarded-For"); len(got) != 1 || got[0] != srcIP {
			t.Fatalf("origin X-Forwarded-For = %v, want [%s]", got, srcIP)
		}
	})
}

func TestForwardBasicAuthEnforcedOnce(t *testing.T) {
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		p := startForwardedPair(t, dsn)
		hits := new(atomic.Int64)
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != fwdReadyPath {
				hits.Add(1)
			}
			io.WriteString(w, "origin-ok")
		}))
		defer origin.Close()
		h := p.startWith(t, "web", origin.URL, http.StatusUnauthorized, func(c *agent.Config) {
			c.BasicAuthSHA256 = []string{sha256Hex("alice:secret")}
			c.BasicAuthRealm = "fwd"
		})

		do := func(user, pass string) (*http.Response, string) {
			t.Helper()
			req, err := http.NewRequest(http.MethodGet, fwdURL(p.a, h.hostname, "/private"), nil)
			if err != nil {
				t.Fatal(err)
			}
			if user != "" {
				req.SetBasicAuth(user, pass)
			}
			resp, err := p.clientTo(p.a, fwdRequestWait).Do(req)
			if err != nil {
				t.Fatalf("GET via edge-a: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return resp, string(body)
		}

		for _, tc := range []struct{ name, user, pass string }{
			{"no credentials", "", ""},
			{"wrong password", "alice", "wrong"},
		} {
			before := expvarCount(t, "ngstoned_rejected_unauthorized_total")
			resp, _ := do(tc.user, tc.pass)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("%s: status = %d, want 401", tc.name, resp.StatusCode)
			}
			if got := resp.Header.Values("WWW-Authenticate"); len(got) != 1 || !strings.Contains(got[0], `realm="fwd"`) {
				t.Fatalf("%s: WWW-Authenticate = %v, want exactly one challenge for realm fwd", tc.name, got)
			}
			if got := expvarCount(t, "ngstoned_rejected_unauthorized_total") - before; got != 1 {
				t.Fatalf("%s: unauthorized rejections = %d, want 1 (enforced by the owner only)", tc.name, got)
			}
		}
		if got := hits.Load(); got != 0 {
			t.Fatalf("origin reached %d times by rejected requests", got)
		}

		resp, body := do("alice", "secret")
		if resp.StatusCode != http.StatusOK || body != "origin-ok" {
			t.Fatalf("authenticated response = %d %q", resp.StatusCode, body)
		}
		if got := hits.Load(); got != 1 {
			t.Fatalf("origin hits = %d, want 1", got)
		}
	})
}

func TestForwardUnknownHost404(t *testing.T) {
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		p := startForwardedPair(t, dsn)
		origin := httptest.NewServer(readyWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "origin-ok")
		})))
		defer origin.Close()
		p.start(t, "web", origin.URL)

		misdirected := expvarCount(t, "ngstoned_peer_misdirected_421_total")
		resp, err := p.clientTo(p.a, fwdRequestWait).Get(fwdURL(p.a, "nobody."+fwdDomain, "/"))
		if err != nil {
			t.Fatalf("GET via edge-a: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
		if got := expvarCount(t, "ngstoned_peer_misdirected_421_total") - misdirected; got != 0 {
			t.Fatalf("misdirected responses = %d, want 0 for a plain unknown host", got)
		}
	})
}

func TestForwardMisdirected421(t *testing.T) {
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		p := startForwardedPair(t, dsn)
		origin := httptest.NewServer(readyWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "origin-ok")
		})))
		defer origin.Close()
		h := p.start(t, "web", origin.URL)

		send := func(sni, hostHeader string) int {
			t.Helper()
			client := p.clientTo(p.a, fwdRequestWait)
			client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: p.pool, ServerName: sni}
			req, err := http.NewRequest(http.MethodGet, fwdURL(p.a, sni, "/"), nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = hostHeader
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("GET sni=%s host=%s: %v", sni, hostHeader, err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return resp.StatusCode
		}

		t.Run("forwarded connection with an unknown Host header", func(t *testing.T) {
			before := expvarCount(t, "ngstoned_peer_misdirected_421_total")
			if got := send(h.hostname, "nobody."+fwdDomain); got != http.StatusMisdirectedRequest {
				t.Fatalf("status = %d, want 421", got)
			}
			if got := expvarCount(t, "ngstoned_peer_misdirected_421_total") - before; got != 1 {
				t.Fatalf("misdirected counter moved by %d, want 1", got)
			}
		})

		t.Run("SNI differs from the Host header", func(t *testing.T) {
			before := expvarCount(t, "ngstoned_peer_misdirected_421_total")
			if got := send("nobody."+fwdDomain, "other."+fwdDomain); got != http.StatusMisdirectedRequest {
				t.Fatalf("status = %d, want 421", got)
			}
			if got := expvarCount(t, "ngstoned_peer_misdirected_421_total") - before; got != 1 {
				t.Fatalf("misdirected counter moved by %d, want 1", got)
			}
		})
	})
}

func TestForwardKeepAliveMisdirected421AfterUnbind(t *testing.T) {
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		p := startForwardedPair(t, dsn)
		origin := httptest.NewServer(readyWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "origin-ok")
		})))
		defer origin.Close()
		host := "web." + fwdDomain
		ag := p.startAgent(t, p.b, credentials.KindHTTP, "web", origin.URL, nil)
		p.waitBody(t, p.a, host, "/who", "origin-ok")

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: p.pool, ServerName: host},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", p.a.publicAddr)
			},
		}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: fwdRequestWait}
		var reused atomic.Bool
		do := func() int {
			t.Helper()
			trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused.Store(info.Reused) }}
			req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, fwdURL(p.a, host, "/who"), nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("GET %s: %v", host, err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return resp.StatusCode
		}

		if got := do(); got != http.StatusOK {
			t.Fatalf("first request status = %d, want 200", got)
		}
		ag.stop()
		p.waitStatus(t, p.b, host, fwdReadyPath, http.StatusNotFound)

		before := expvarCount(t, "ngstoned_peer_misdirected_421_total")
		if got := do(); got != http.StatusMisdirectedRequest {
			t.Fatalf("second request status = %d, want 421", got)
		}
		if !reused.Load() {
			t.Fatal("second request did not reuse the first connection")
		}
		if got := expvarCount(t, "ngstoned_peer_misdirected_421_total") - before; got != 1 {
			t.Fatalf("misdirected counter moved by %d, want 1", got)
		}
	})
}

func TestForwardStaleOwnerRecovers(t *testing.T) {
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		p := startForwardedPair(t, dsn)
		namedOrigin := func(name string) *httptest.Server {
			return httptest.NewServer(readyWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, name)
			})))
		}
		originB := namedOrigin("from-b")
		defer originB.Close()
		originC := namedOrigin("from-c")
		defer originC.Close()

		host := "web." + fwdDomain
		agentB := p.startAgent(t, p.b, credentials.KindHTTP, "web", originB.URL, nil)
		p.waitBody(t, p.a, host, "/who", "from-b")

		c := p.startEdge(t, "edge-c", freeAddr(t), false)
		agentB.stop()
		p.waitStatus(t, p.b, host, fwdReadyPath, http.StatusNotFound)
		p.startAgent(t, c, credentials.KindHTTP, "web", originC.URL, nil)
		p.waitBody(t, c, host, "/who", "from-c")

		staleBefore := expvarCount(t, "ngstoned_peer_forward_stale_total")
		p.waitBody(t, p.a, host, "/who", "from-c")
		if got := expvarCount(t, "ngstoned_peer_forward_stale_total") - staleBefore; got < 1 {
			t.Fatalf("stale owner refusals = %d, want at least 1 (the cached owner no longer owns the host)", got)
		}
		p.waitBody(t, p.a, host, "/who", "from-c")
	})
}

func TestForwardTLSPassthrough(t *testing.T) {
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		p := startForwardedPair(t, dsn)
		host := "secure." + fwdDomain
		localCert, localPool := selfSignedTLSCert(t, host)
		localAddr, _ := startLocalTLSEcho(t, localCert)

		forwardedBefore := expvarCount(t, "ngstoned_peer_forwarded_conns_total")
		passthroughBefore := expvarCount(t, "ngstoned_tls_passthrough_conns_total")
		p.startAgent(t, p.b, credentials.KindTLS, "secure", localAddr, func(c *agent.Config) {
			c.Kind = proto.KindTLS
			c.Store = nil
		})

		var conn *tls.Conn
		deadline := time.Now().Add(fwdWaitBudget)
		for {
			var err error
			conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", p.a.publicAddr, &tls.Config{RootCAs: localPool, ServerName: host})
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no passthrough connection to the local app within %s: %v", fwdWaitBudget, err)
			}
			time.Sleep(100 * time.Millisecond)
		}
		defer conn.Close()

		if !conn.ConnectionState().PeerCertificates[0].Equal(localCert.Leaf) {
			t.Fatal("client did not receive the local app's certificate")
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		for i := 0; i < 3; i++ {
			msg := fmt.Sprintf("passthrough-%d\n", i)
			if _, err := io.WriteString(conn, msg); err != nil {
				t.Fatalf("write %q: %v", msg, err)
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Fatalf("read echo of %q: %v", msg, err)
			}
			if string(buf) != msg {
				t.Fatalf("echo = %q, want %q", buf, msg)
			}
		}
		if got := expvarCount(t, "ngstoned_peer_forwarded_conns_total") - forwardedBefore; got < 1 {
			t.Fatalf("forwarded connections = %d, want at least 1", got)
		}
		if got := expvarCount(t, "ngstoned_tls_passthrough_conns_total") - passthroughBefore; got < 1 {
			t.Fatalf("passthrough connections = %d, want at least 1", got)
		}
	})
}

func TestForwardVisitorLogin(t *testing.T) {
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		idp := newE2EIdP(t)
		p := startForwardedPair(t, dsn, withVisitorIdP(idp))
		captured := &originCapture{}
		origin := httptest.NewServer(readyWrap(http.HandlerFunc(captured.handler)))
		defer origin.Close()
		h := p.startWith(t, "web", origin.URL, http.StatusUnauthorized, func(c *agent.Config) {
			c.OIDC = &proto.OIDCLogin{AllowEmails: []string{"alice@example.org"}, AllowDomains: []string{"corp.example"}}
		})
		lookupsBefore := expvarCount(t, "ngstoned_peer_apex_rule_lookups_total")

		t.Run("denied email never reaches the app", func(t *testing.T) {
			idp.setEmail("mallory@evil.test")
			before := len(captured.snapshot())
			req, _ := http.NewRequest(http.MethodGet, fwdURL(p.a, h.hostname, "/secret"), nil)
			req.Header.Set("Accept", "text/html")
			resp, err := p.browser(t).Do(req)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", resp.StatusCode)
			}
			if after := len(captured.snapshot()); after != before {
				t.Fatalf("origin reached by denied visitor (%d -> %d)", before, after)
			}
		})

		t.Run("allowed email signs in across edges", func(t *testing.T) {
			idp.setEmail("bob@corp.example")
			req, _ := http.NewRequest(http.MethodGet, fwdURL(p.a, h.hostname, "/welcome?x=1"), nil)
			req.Header.Set("Accept", "text/html")
			resp, err := p.browser(t).Do(req)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK || string(body) != "app:/welcome" {
				t.Fatalf("final response = %d %q", resp.StatusCode, body)
			}
			if resp.Request.URL.String() != fwdURL(p.a, h.hostname, "/welcome?x=1") {
				t.Fatalf("landed on %q, want the original URL", resp.Request.URL)
			}
			seen := captured.snapshot()
			if got := seen[len(seen)-1].Get("X-Ngstone-User-Email"); got != "bob@corp.example" {
				t.Fatalf("origin X-Ngstone-User-Email = %q, want bob@corp.example", got)
			}
		})

		if got := expvarCount(t, "ngstoned_peer_apex_rule_lookups_total") - lookupsBefore; got < 1 {
			t.Fatalf("apex rule lookups from shared storage = %d, want at least 1", got)
		}
	})
}
