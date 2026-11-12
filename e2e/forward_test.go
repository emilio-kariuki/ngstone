package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
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
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ngstone/internal/adminapi/adminapitest"
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
	adminAddr   string
	store       *storage.Store
}

type fwdConfig struct {
	proxySrc       string
	idp            *e2eIdP
	separateListen bool
	tcpLo, tcpHi   int
	customNames    []string
	adminMTLS      bool
}

type fwdOption func(*fwdConfig)

func withProxyProtocol(src string) fwdOption {
	return func(c *fwdConfig) { c.proxySrc = src }
}

func withSeparatePeerListen() fwdOption {
	return func(c *fwdConfig) { c.separateListen = true }
}

func withTCPPorts(lo, hi int) fwdOption {
	return func(c *fwdConfig) { c.tcpLo, c.tcpHi = lo, hi }
}

func withVisitorIdP(idp *e2eIdP) fwdOption {
	return func(c *fwdConfig) { c.idp = idp }
}

func withCustomNames(names ...string) fwdOption {
	return func(c *fwdConfig) { c.customNames = names }
}

func withAdminMTLS() fwdOption {
	return func(c *fwdConfig) { c.adminMTLS = true }
}

type fwdPair struct {
	dsn         string
	cfg         fwdConfig
	cert        tls.Certificate
	pool        *x509.CertPool
	aPublic     string
	a, b        *fwdEdge
	owner       string
	adminCA     *adminapitest.CA
	adminCAFile string
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
	p.cert, p.pool = selfSignedTLSCert(t, fwdDomain, append([]string{"*." + fwdDomain}, p.cfg.customNames...)...)
	if p.cfg.adminMTLS {
		p.adminCA = adminapitest.NewCA(t)
		p.adminCAFile = filepath.Join(t.TempDir(), "admin-ca.pem")
		if err := os.WriteFile(p.adminCAFile, p.adminCA.PEM, 0o600); err != nil {
			t.Fatalf("write admin client CA: %v", err)
		}
	}
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
	if p.cfg.tcpHi != 0 {
		cfg.TCPPortRange = fmt.Sprintf("%d-%d", p.cfg.tcpLo, p.cfg.tcpHi)
		cfg.TCPBindAddr = "127.0.0.1"
		if id != "edge-a" {
			cfg.TCPBindAddr = "::1"
		}
	}
	if p.cfg.adminMTLS {
		e.adminAddr = freeAddr(t)
		cfg.AdminMTLSAddr = e.adminAddr
		cfg.AdminMTLSClientCAFile = p.adminCAFile
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
	if e.adminAddr != "" {
		waitForPort(t, e.adminAddr)
	}
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
	owner := "e2e-owner"
	if p.owner != "" {
		owner = p.owner
	}
	issued, err := e.store.Issue(credentials.Spec{Kind: credKind, Subdomain: subdomain, OwnerID: owner}, time.Hour)
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

func (p *fwdPair) startTCPAgent(t *testing.T, target string, port int, allowCIDR string) func() {
	t.Helper()
	issued, err := p.a.store.Issue(credentials.Spec{Kind: credentials.KindTCP, RemotePort: port, OwnerID: "e2e-owner"}, time.Hour)
	if err != nil {
		t.Fatalf("issue tcp credential for port %d: %v", port, err)
	}
	cfg := agent.Config{
		ControlAddr: p.a.controlAddr,
		Token:       issued.Token,
		Kind:        proto.KindTCP,
		RemotePort:  port,
		TargetURL:   target,
		AllowCIDRs:  []string{allowCIDR},
		Insecure:    true,
		Store:       inspect.NewStore(),
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
			t.Errorf("tcp agent for port %d did not stop within %s", port, fwdStopBudget)
		}
	}
	t.Cleanup(stop)
	return stop
}

func tcpEchoes(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		return false
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		return false
	}
	return string(buf) == "ping"
}

func tcpDialable(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func waitTCPCondition(t *testing.T, budget time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", budget, what)
}

func freePortPair(t *testing.T) int {
	t.Helper()
	for i := 0; i < 50; i++ {
		lo, _ := freeTCPRange(t, 40)
		var held []net.Listener
		ok := true
		for _, host := range []string{"127.0.0.1", "::1"} {
			for port := lo + 39; port <= lo+40; port++ {
				ln, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
				if err != nil {
					ok = false
					break
				}
				held = append(held, ln)
			}
		}
		for _, ln := range held {
			ln.Close()
		}
		if ok {
			return lo
		}
	}
	t.Fatalf("no free adjacent port pair on 127.0.0.1 and ::1")
	return 0
}

func TestForwardRawTCP(t *testing.T) {
	if ln, err := net.Listen("tcp", "[::1]:0"); err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	} else {
		ln.Close()
	}
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		lo := freePortPair(t)
		p := startForwardedPair(t, dsn, withTCPPorts(lo, lo+40))
		echo := startTCPEcho(t)

		portV4, portV6 := lo+39, lo+40
		viaA := func(port int) string { return net.JoinHostPort("127.0.0.1", fmt.Sprint(port)) }
		viaB := func(port int) string { return net.JoinHostPort("::1", fmt.Sprint(port)) }

		stopV4 := p.startTCPAgent(t, echo, portV4, "127.0.0.1/32")
		p.startTCPAgent(t, echo, portV6, "::1/128")

		waitTCPCondition(t, 5*time.Second, "owner to echo for 127.0.0.1/32", func() bool { return tcpEchoes(viaA(portV4)) })
		waitTCPCondition(t, 5*time.Second, "edge B to open the proxied port for the 127.0.0.1/32 tunnel", func() bool { return tcpDialable(viaB(portV4)) })
		if tcpEchoes(viaB(portV4)) {
			t.Fatalf("::1 client reached the 127.0.0.1/32 tunnel through edge B; the owner must enforce allow-CIDR with the real client address")
		}

		waitTCPCondition(t, 5*time.Second, "::1/128 tunnel to echo through edge B", func() bool { return tcpEchoes(viaB(portV6)) })
		if tcpEchoes(viaA(portV6)) {
			t.Fatalf("127.0.0.1 client reached the ::1/128 tunnel directly on the owner")
		}

		stopV4()
		waitTCPCondition(t, 5*time.Second, "edge B to stop serving the disconnected tunnel", func() bool { return !tcpDialable(viaB(portV4)) })
	})
}

func TestForwardShareLink(t *testing.T) {
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		p := startForwardedPair(t, dsn)
		echoAddr := startTCPEcho(t)
		echoPort := tcpPort(t, echoAddr)

		issue := func(owner string) string {
			issued, err := p.a.store.Issue(credentials.Spec{Kind: credentials.KindShare, OwnerID: owner}, time.Hour)
			if err != nil {
				t.Fatalf("issue share credential for %s: %v", owner, err)
			}
			return issued.Token
		}
		operator := func(token string) *agent.Operator {
			return agent.NewOperator(agent.Config{ControlAddr: p.a.controlAddr, Token: token, Insecure: true})
		}

		secret, digest, err := agent.NewShareSecret()
		if err != nil {
			t.Fatal(err)
		}
		spec := &agent.ShareSpec{
			Label: "e2e db",
			Targets: []agent.ShareTargetSpec{{
				ShareTarget: proto.ShareTarget{ID: "t1", Preset: "tcp", Label: "tcp", DefaultPort: echoPort},
				Addr:        echoAddr,
			}},
			SecretSHA256:  digest,
			ExpiresAt:     time.Now().Add(10 * time.Minute),
			MaxConns:      16,
			MaxConnectors: 8,
		}
		sharerEvents := make(chan agent.StatusEvent, 32)
		sharerCtx, stopSharer := context.WithCancel(context.Background())
		sharerDone := make(chan struct{})
		go func() {
			agent.New(agent.Config{
				ControlAddr: p.b.controlAddr,
				Token:       issue("e2e-owner"),
				Kind:        proto.KindTCP,
				TargetURL:   echoAddr,
				InstanceID:  "e2e-sharer",
				Insecure:    true,
				Share:       spec,
				Events:      sharerEvents,
			}).Run(sharerCtx)
			close(sharerDone)
		}()
		t.Cleanup(func() {
			stopSharer()
			select {
			case <-sharerDone:
			case <-time.After(fwdStopBudget):
				t.Errorf("sharer did not stop within %s", fwdStopBudget)
			}
		})
		var shareID string
		for shareID == "" {
			select {
			case ev := <-sharerEvents:
				if ev.State == agent.StateOnline {
					shareID = ev.ShareID
				}
			case <-time.After(fwdWaitBudget):
				t.Fatal("sharer did not register its share on edge-b")
			}
		}

		badSecret, _, err := agent.NewShareSecret()
		if err != nil {
			t.Fatal(err)
		}
		badCtx, badCancel := context.WithTimeout(context.Background(), fwdWaitBudget)
		defer badCancel()
		badErr := agent.NewConnector(agent.ConnectConfig{ControlAddr: p.a.controlAddr, Secret: badSecret, Insecure: true}).Run(badCtx)
		if !errors.Is(badErr, agent.ErrBadToken) {
			t.Fatalf("wrong secret against edge-a: err = %v, want ErrBadToken", badErr)
		}

		connEvents := make(chan agent.ConnectEvent, 32)
		connCtx, stopConn := context.WithCancel(context.Background())
		defer stopConn()
		connDone := make(chan error, 1)
		go func() {
			connDone <- agent.NewConnector(agent.ConnectConfig{
				ControlAddr: p.a.controlAddr,
				Secret:      secret,
				InstanceID:  "e2e-connector",
				Insecure:    true,
				Events:      connEvents,
			}).Run(connCtx)
		}()
		var listenAddr string
		for listenAddr == "" {
			select {
			case ev := <-connEvents:
				if ev.State == agent.StateOnline && len(ev.Targets) > 0 {
					if ev.ShareID != shareID {
						t.Fatalf("connector joined share %q, sharer registered %q", ev.ShareID, shareID)
					}
					listenAddr = ev.Targets[0].ListenAddr
				}
			case err := <-connDone:
				t.Fatalf("connector through edge-a ended before joining: %v", err)
			case <-time.After(fwdWaitBudget):
				t.Fatal("connector through edge-a never joined the share on edge-b")
			}
		}

		conn, err := net.DialTimeout("tcp", listenAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial connector listener %s: %v", listenAddr, err)
		}
		defer conn.Close()
		for i := 0; i < 3; i++ {
			echoRoundTrip(t, conn, "through-a-to-b\n")
		}

		ctx, cancel := context.WithTimeout(context.Background(), fwdWaitBudget)
		defer cancel()
		if err := operator(issue("other-owner")).Unshare(ctx, shareID); !errors.Is(err, agent.ErrShareNotFound) {
			t.Fatalf("unshare by another owner via edge-a: err = %v, want ErrShareNotFound", err)
		}
		echoRoundTrip(t, conn, "still-here\n")

		if err := operator(issue("e2e-owner")).Unshare(ctx, shareID); err != nil {
			t.Fatalf("unshare by the owner via edge-a: %v", err)
		}
		select {
		case err := <-connDone:
			if !errors.Is(err, agent.ErrShareClosed) || agent.CloseReason(err) != proto.ShareReasonRevoked {
				t.Fatalf("connector ended with %v, want a revoked share", err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("connector did not observe the revocation within 20s")
		}
	})
}

func tcpPort(t *testing.T, addr string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return port
}
