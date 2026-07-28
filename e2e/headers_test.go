package e2e

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"ngstone/internal/agent"
	"ngstone/internal/edge"
)

func TestForwardingHeadersEndToEnd(t *testing.T) {
	var mu sync.Mutex
	var gotHeaders http.Header

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotHeaders = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	token := "hdr-test-token"
	domain := "tun.example.com"
	hostname := "hdr." + domain
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)

	edgeSrv, err := edge.New(edge.Config{
		ControlAddr:  controlAddr,
		PublicAddr:   publicAddr,
		Domain:       domain,
		TokenSHA256:  mustSHA256(token),
		PublicScheme: "http",
		Insecure:     true,
	})
	if err != nil {
		t.Fatalf("edge.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go edgeSrv.Run(ctx)

	waitForPort(t, controlAddr)

	agt := agent.New(agent.Config{
		ControlAddr: controlAddr,
		Token:       token,
		Subdomain:   "hdr",
		TargetURL:   origin.URL,
		Insecure:    true,
	})
	go agt.Run(ctx)

	waitBound(t, publicAddr, hostname)

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://"+publicAddr+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = hostname
	req.Header.Set("X-Forwarded-For", "6.6.6.6")
	req.Header.Set("X-Real-IP", "9.9.9.9")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET through tunnel: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	mu.Lock()
	headers := gotHeaders
	mu.Unlock()

	xff := headers.Values("X-Forwarded-For")
	if len(xff) != 1 {
		t.Fatalf("X-Forwarded-For = %v, want exactly one value", xff)
	}
	if xff[0] != "127.0.0.1" {
		t.Fatalf("X-Forwarded-For = %q, want %q", xff[0], "127.0.0.1")
	}

	if v := headers.Values("X-Real-Ip"); len(v) != 0 {
		t.Fatalf("X-Real-Ip leaked to origin: %v", v)
	}

	if got := headers.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("X-Forwarded-Proto = %q, want %q", got, "http")
	}
	if got := headers.Get("X-Forwarded-Host"); got != hostname {
		t.Fatalf("X-Forwarded-Host = %q, want %q", got, hostname)
	}
}

func TestForwardingHeadersEndToEndWithProxyProtocol(t *testing.T) {
	var mu sync.Mutex
	var gotHeaders http.Header

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotHeaders = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	token := "hdr-proxyproto-token"
	domain := "tun.example.com"
	hostname := "hdr-pp." + domain
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)

	edgeSrv, err := edge.New(edge.Config{
		ControlAddr:          controlAddr,
		PublicAddr:           publicAddr,
		Domain:               domain,
		TokenSHA256:          mustSHA256(token),
		PublicScheme:         "http",
		Insecure:             true,
		ProxyProtocol:        true,
		ProxyProtocolTrusted: []string{"127.0.0.1/32"},
	})
	if err != nil {
		t.Fatalf("edge.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go edgeSrv.Run(ctx)

	waitForPort(t, controlAddr)

	agt := agent.New(agent.Config{
		ControlAddr: controlAddr,
		Token:       token,
		Subdomain:   "hdr-pp",
		TargetURL:   origin.URL,
		Insecure:    true,
	})
	go agt.Run(ctx)

	const realClientIP = "203.0.113.42"
	proxyHeader := "PROXY TCP4 " + realClientIP + " 198.51.100.7 51234 443\r\n"

	sendViaProxyProtocol := func(path string) (*http.Response, error) {
		conn, err := net.DialTimeout("tcp", publicAddr, 3*time.Second)
		if err != nil {
			return nil, err
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		request := "GET " + path + " HTTP/1.1\r\n" +
			"Host: " + hostname + "\r\n" +
			"Connection: close\r\n" +
			"\r\n"
		if _, err := io.WriteString(conn, proxyHeader+request); err != nil {
			conn.Close()
			return nil, err
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return resp, nil
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := sendViaProxyProtocol("/__ngstone_ready")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for binding on %s (%s)", publicAddr, hostname)
		}
		time.Sleep(50 * time.Millisecond)
	}

	resp, err := sendViaProxyProtocol("/")
	if err != nil {
		t.Fatalf("GET through tunnel via PROXY protocol: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	mu.Lock()
	headers := gotHeaders
	mu.Unlock()

	xff := headers.Values("X-Forwarded-For")
	if len(xff) != 1 {
		t.Fatalf("X-Forwarded-For = %v, want exactly one value", xff)
	}
	if xff[0] != realClientIP {
		t.Fatalf("X-Forwarded-For = %q, want %q (the PROXY-protocol-advertised client, not the proxy's own TCP peer address)", xff[0], realClientIP)
	}
}
