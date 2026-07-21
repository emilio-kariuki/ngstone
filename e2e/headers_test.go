package e2e

import (
	"context"
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

	edgeSrv := edge.New(edge.Config{
		ControlAddr: controlAddr,
		PublicAddr:  publicAddr,
		Domain:      domain,
		TokenSHA256: mustSHA256(token),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go edgeSrv.Run(ctx)

	waitForPort(t, controlAddr)

	agt := agent.New(agent.Config{
		ControlAddr: controlAddr,
		Token:       token,
		Subdomain:   "hdr",
		TargetURL:   origin.URL,
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
