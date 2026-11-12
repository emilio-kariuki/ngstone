package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ngstone/internal/adminapi"
	"ngstone/internal/adminapi/adminapitest"
	"ngstone/internal/agent"
	"ngstone/internal/credentials"
	"ngstone/internal/oidc"
	"ngstone/internal/proto"
)

const customDomainName = "app.example.org"

func startCustomDomainPair(t *testing.T, dsn string, names []string, opts ...fwdOption) *fwdPair {
	t.Helper()
	opts = append([]fwdOption{withCustomNames(names...), withAdminMTLS()}, opts...)
	p := startForwardedPair(t, dsn, opts...)
	p.owner = "mtls:alice"
	return p
}

func (p *fwdPair) adminClient(t *testing.T, e *fwdEdge, cn, role string) *adminapi.Client {
	t.Helper()
	cert := p.adminCA.Issue(t, adminapitest.CertOptions{
		CommonName:  cn,
		OUs:         []string{role},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	client, err := adminapi.NewClientTLS("https://"+e.adminAddr, "", &tls.Config{
		ServerName:   fwdDomain,
		RootCAs:      p.pool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("admin client for %s: %v", cn, err)
	}
	return client
}

func (p *fwdPair) tunnelID(t *testing.T, host string) string {
	t.Helper()
	deadline := time.Now().Add(fwdWaitBudget)
	for time.Now().Before(deadline) {
		tunnels, err := p.b.store.ListTunnels(context.Background())
		if err != nil {
			t.Fatalf("list tunnels: %v", err)
		}
		for _, tunnel := range tunnels {
			if tunnel.Hostname == host {
				return tunnel.ID
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no tunnel for %s within %s", host, fwdWaitBudget)
	return ""
}

func postDomain(c *adminapi.Client, domain, tunnelID string) (adminapi.CustomDomain, error) {
	var value adminapi.CustomDomain
	err := c.Post(adminapi.APIPrefix+"/domains", adminapi.CustomDomainRequest{Domain: domain, TunnelID: tunnelID}, &value)
	return value, err
}

func postDomainStatus(c *adminapi.Client, id, status string) (adminapi.CustomDomain, error) {
	var value adminapi.CustomDomain
	err := c.Post(adminapi.APIPrefix+"/domains/"+id+"/status", adminapi.CustomDomainStatusRequest{Status: status}, &value)
	return value, err
}

func apiStatus(err error) int {
	var apiErr *adminapi.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status
	}
	return 0
}

func (p *fwdPair) registerPending(t *testing.T, c *adminapi.Client, domain, tunnelID string) adminapi.CustomDomain {
	t.Helper()
	value, err := postDomain(c, domain, tunnelID)
	if err != nil {
		t.Fatalf("register %s: %v", domain, err)
	}
	if value.Status != "pending" {
		t.Fatalf("registered %s status = %q, want pending", domain, value.Status)
	}
	return value
}

func (p *fwdPair) setStatus(t *testing.T, c *adminapi.Client, id, status string) {
	t.Helper()
	value, err := postDomainStatus(c, id, status)
	if err != nil {
		t.Fatalf("set status %s on %s: %v", status, id, err)
	}
	if value.Status != status {
		t.Fatalf("status after set = %q, want %s", value.Status, status)
	}
}

func (p *fwdPair) statusOf(t *testing.T, e *fwdEdge, host, path string) int {
	t.Helper()
	resp, err := p.clientTo(e, 5*time.Second).Get(fwdURL(e, host, path))
	if err != nil {
		t.Fatalf("GET %s%s via %s: %v", host, path, e.id, err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func startFixedOrigin(t *testing.T, body string) *httptest.Server {
	t.Helper()
	origin := httptest.NewServer(readyWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	})))
	t.Cleanup(origin.Close)
	return origin
}

func TestCustomDomainRoutesHTTPAcrossEdges(t *testing.T) {
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		p := startCustomDomainPair(t, dsn, []string{customDomainName})
		origin := startFixedOrigin(t, "from-origin")
		h := p.start(t, "web", origin.URL)
		id := p.tunnelID(t, h.hostname)
		domain := p.registerPending(t, p.adminClient(t, p.b, "alice", oidc.RoleOperator), customDomainName, id)
		p.setStatus(t, p.adminClient(t, p.b, "root", oidc.RoleAdmin), domain.ID, "active")

		t.Run("own edge", func(t *testing.T) {
			if got := p.statusOf(t, p.b, customDomainName, fwdReadyPath); got != http.StatusOK {
				t.Fatalf("status via the owning edge = %d, want 200", got)
			}
			p.waitBody(t, p.b, customDomainName, "/who", "from-origin")
		})

		t.Run("other edge forwards", func(t *testing.T) {
			forwardedBefore := expvarCount(t, "ngstoned_peer_forwarded_conns_total")
			p.waitBody(t, p.a, customDomainName, "/who", "from-origin")
			if got := expvarCount(t, "ngstoned_peer_forwarded_conns_total") - forwardedBefore; got < 1 {
				t.Fatalf("forwarded connections = %d, want at least 1", got)
			}
		})
	})
}

func TestCustomDomainRoutesTLSPassthroughAcrossEdges(t *testing.T) {
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		p := startCustomDomainPair(t, dsn, []string{customDomainName})
		host := "secure." + fwdDomain
		localCert, localPool := selfSignedTLSCert(t, customDomainName)
		localAddr, _ := startLocalTLSEcho(t, localCert)
		p.startAgent(t, p.b, credentials.KindTLS, "secure", localAddr, func(c *agent.Config) {
			c.Kind = proto.KindTLS
			c.Store = nil
		})
		id := p.tunnelID(t, host)
		domain := p.registerPending(t, p.adminClient(t, p.b, "alice", oidc.RoleOperator), customDomainName, id)
		p.setStatus(t, p.adminClient(t, p.b, "root", oidc.RoleAdmin), domain.ID, "active")

		forwardedBefore := expvarCount(t, "ngstoned_peer_forwarded_conns_total")
		passthroughBefore := expvarCount(t, "ngstoned_tls_passthrough_conns_total")
		var conn *tls.Conn
		deadline := time.Now().Add(fwdWaitBudget)
		for {
			var err error
			conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", p.a.publicAddr, &tls.Config{RootCAs: localPool, ServerName: customDomainName})
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no passthrough connection by custom domain within %s: %v", fwdWaitBudget, err)
			}
			time.Sleep(100 * time.Millisecond)
		}
		defer conn.Close()

		if !conn.ConnectionState().PeerCertificates[0].Equal(localCert.Leaf) {
			t.Fatal("client did not receive the local app's certificate")
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		msg := "custom-passthrough\n"
		if _, err := io.WriteString(conn, msg); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read echo: %v", err)
		}
		if string(buf) != msg {
			t.Fatalf("echo = %q, want %q", buf, msg)
		}
		if got := expvarCount(t, "ngstoned_peer_forwarded_conns_total") - forwardedBefore; got < 1 {
			t.Fatalf("forwarded connections = %d, want at least 1", got)
		}
		if got := expvarCount(t, "ngstoned_tls_passthrough_conns_total") - passthroughBefore; got < 1 {
			t.Fatalf("passthrough connections = %d, want at least 1", got)
		}
	})
}

func TestCustomDomainLifecycle(t *testing.T) {
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		p := startCustomDomainPair(t, dsn, []string{customDomainName})
		origin := startFixedOrigin(t, "from-origin")
		h := p.start(t, "web", origin.URL)
		id := p.tunnelID(t, h.hostname)
		alice := p.adminClient(t, p.b, "alice", oidc.RoleOperator)
		root := p.adminClient(t, p.b, "root", oidc.RoleAdmin)

		domain := p.registerPending(t, alice, customDomainName, id)
		if got := p.statusOf(t, p.b, customDomainName, fwdReadyPath); got != http.StatusNotFound {
			t.Fatalf("pending domain status = %d, want 404", got)
		}
		p.setStatus(t, root, domain.ID, "active")
		if got := p.statusOf(t, p.b, customDomainName, fwdReadyPath); got != http.StatusOK {
			t.Fatalf("active domain status = %d, want 200 immediately after activation", got)
		}
		p.setStatus(t, root, domain.ID, "disabled")
		if got := p.statusOf(t, p.b, customDomainName, fwdReadyPath); got != http.StatusNotFound {
			t.Fatalf("disabled domain status = %d, want 404 immediately after disabling", got)
		}
		p.setStatus(t, root, domain.ID, "active")
		if got := p.statusOf(t, p.b, customDomainName, fwdReadyPath); got != http.StatusOK {
			t.Fatalf("re-activated domain status = %d, want 200", got)
		}
	})
}

func TestCustomDomainOwnership(t *testing.T) {
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		p := startCustomDomainPair(t, dsn, []string{customDomainName, "stolen.example.org"})
		origin := startFixedOrigin(t, "from-origin")
		h := p.start(t, "web", origin.URL)
		id := p.tunnelID(t, h.hostname)
		alice := p.adminClient(t, p.b, "alice", oidc.RoleOperator)
		bob := p.adminClient(t, p.b, "bob", oidc.RoleOperator)
		root := p.adminClient(t, p.b, "root", oidc.RoleAdmin)

		if _, err := postDomain(bob, "stolen.example.org", id); apiStatus(err) != http.StatusNotFound {
			t.Fatalf("second owner registering for another owner's tunnel: error = %v, want API status 404", err)
		}
		if got := p.statusOf(t, p.b, "stolen.example.org", fwdReadyPath); got != http.StatusNotFound {
			t.Fatalf("refused domain status = %d, want 404", got)
		}

		domain := p.registerPending(t, alice, customDomainName, id)
		if _, err := postDomainStatus(alice, domain.ID, "active"); apiStatus(err) != http.StatusForbidden {
			t.Fatalf("operator activation: error = %v, want API status 403", err)
		}
		if got := p.statusOf(t, p.b, customDomainName, fwdReadyPath); got != http.StatusNotFound {
			t.Fatalf("domain after refused activation status = %d, want 404", got)
		}
		p.setStatus(t, root, domain.ID, "active")
		if got := p.statusOf(t, p.b, customDomainName, fwdReadyPath); got != http.StatusOK {
			t.Fatalf("administrator-activated domain status = %d, want 200", got)
		}
	})
}

func TestCustomDomainRandomHostsAreBounded(t *testing.T) {
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		p := startCustomDomainPair(t, dsn, nil)
		const requests = 500
		const workers = 8
		lookupsBefore := expvarCount(t, "ngstoned_custom_domain_lookups_total")
		ownerLookupsBefore := expvarCount(t, "ngstoned_peer_lookups_total")
		client := &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DisableKeepAlives: true,
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", p.a.publicAddr)
				},
			},
		}
		_, port, _ := net.SplitHostPort(p.a.publicAddr)
		var next, routed atomic.Int64
		var wg sync.WaitGroup
		start := time.Now()
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					n := next.Add(1)
					if n > requests {
						return
					}
					resp, err := client.Get(fmt.Sprintf("https://random-%d.attacker.test:%s/", n, port))
					if err != nil {
						continue
					}
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						routed.Add(1)
					}
				}
			}()
		}
		wg.Wait()
		elapsed := time.Since(start)
		if routed.Load() != 0 {
			t.Fatalf("%d random hosts were routed, want 0", routed.Load())
		}
		lookups := expvarCount(t, "ngstoned_custom_domain_lookups_total") - lookupsBefore
		limit := int64(10 + 2*int(elapsed.Seconds()) + 8)
		if lookups < 1 || lookups > limit {
			t.Fatalf("custom domain lookups for %d random hosts over %s = %d, want between 1 and %d", requests, elapsed, lookups, limit)
		}
		if got := expvarCount(t, "ngstoned_peer_lookups_total") - ownerLookupsBefore; got != 0 {
			t.Fatalf("owner lookups caused by random hosts = %d, want 0", got)
		}
	})
}

func TestCustomDomainVisitorLoginTunnelIsForbidden(t *testing.T) {
	forEachForwardStorage(t, func(t *testing.T, dsn string) {
		idp := newE2EIdP(t)
		p := startCustomDomainPair(t, dsn, []string{customDomainName}, withVisitorIdP(idp))
		captured := &originCapture{}
		origin := httptest.NewServer(readyWrap(http.HandlerFunc(captured.handler)))
		defer origin.Close()
		h := p.startWith(t, "web", origin.URL, http.StatusUnauthorized, func(c *agent.Config) {
			c.OIDC = &proto.OIDCLogin{AllowEmails: []string{"alice@example.org"}}
		})
		id := p.tunnelID(t, h.hostname)
		domain := p.registerPending(t, p.adminClient(t, p.b, "alice", oidc.RoleOperator), customDomainName, id)
		p.setStatus(t, p.adminClient(t, p.b, "root", oidc.RoleAdmin), domain.ID, "active")
		rejectedBefore := expvarCount(t, "ngstoned_custom_domain_login_rejected_total")

		for _, e := range []*fwdEdge{p.b, p.a} {
			p.waitStatus(t, e, customDomainName, "/secret", http.StatusForbidden)
		}
		if got := len(captured.snapshot()); got != 0 {
			t.Fatalf("origin reached %d times through a visitor-login tunnel on a custom domain, want 0", got)
		}
		if got := expvarCount(t, "ngstoned_custom_domain_login_rejected_total") - rejectedBefore; got < 1 {
			t.Fatalf("login rejections = %d, want at least 1", got)
		}
	})
}
