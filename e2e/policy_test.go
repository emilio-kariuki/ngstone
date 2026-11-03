package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"ngstone/internal/agent"
	"ngstone/internal/edge"
	"ngstone/internal/inspect"
	"ngstone/internal/policy"
)

func TestTrafficPolicyActionsEndToEnd(t *testing.T) {
	var mu sync.Mutex
	var gotHeaders http.Header
	paths := map[string]int{}

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths[r.URL.Path]++
		if r.URL.Path == "/api/items" {
			gotHeaders = r.Header.Clone()
		}
		mu.Unlock()
		w.Header().Set("Server", "local-app")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	trafficPolicy, err := policy.Parse([]byte(`{
  "rules": [
    {"action": "redirect", "path_prefix": "/old", "redirect_url": "/new$path", "redirect_status": 308},
    {"action": "transform", "path_prefix": "/api", "request_headers": {"set": {"X-Env": "prod"}, "remove": ["X-Debug"]}, "response_headers": {"set": {"Cache-Control": "no-store"}, "remove": ["Server"]}}
  ],
  "cors": {"allowed_origins": ["https://app.example"], "allowed_methods": ["GET", "PUT"], "allowed_headers": ["Content-Type"], "max_age": 120}
}`))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}

	token := "policy-e2e-token"
	domain := "tun.example.com"
	hostname := "pol." + domain
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

	store := inspect.NewStore()
	agt := agent.New(agent.Config{
		ControlAddr: controlAddr,
		Token:       token,
		Subdomain:   "pol",
		TargetURL:   origin.URL,
		Insecure:    true,
		Policy:      trafficPolicy,
		Store:       store,
	})
	go agt.Run(ctx)
	waitBound(t, publicAddr, hostname)

	client := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	send := func(method, path string, header http.Header) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, "http://"+publicAddr+path, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Host = hostname
		for name, values := range header {
			req.Header[name] = values
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		resp.Body.Close()
		return resp
	}

	resp := send(http.MethodGet, "/api/items", http.Header{"X-Debug": {"1"}, "Origin": {"https://app.example"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("api status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("Server") != "" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("response headers were not transformed: %v", resp.Header)
	}
	if got := resp.Header.Values("Access-Control-Allow-Origin"); len(got) != 1 || got[0] != "https://app.example" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
	mu.Lock()
	seen := gotHeaders
	mu.Unlock()
	if seen.Get("X-Env") != "prod" || seen.Get("X-Debug") != "" {
		t.Fatalf("local app saw %v", seen)
	}

	var captured *inspect.Exchange
	deadline := time.Now().Add(5 * time.Second)
	for captured == nil && time.Now().Before(deadline) {
		for _, exchange := range store.List() {
			if strings.HasSuffix(exchange.Req.URL, "/api/items") && exchange.Resp.Status != 0 {
				captured = exchange
				break
			}
		}
		if captured == nil {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if captured == nil {
		t.Fatal("inspector did not record the /api/items exchange")
	}
	if captured.Req.Header.Get("X-Env") != "prod" || captured.Req.Header.Get("X-Debug") != "" {
		t.Fatalf("inspector request headers = %v, want what reached the local app", captured.Req.Header)
	}
	if captured.Resp.Header.Get("Server") != "local-app" {
		t.Fatalf("inspector response headers = %v, want what the local app sent", captured.Resp.Header)
	}

	resp = send(http.MethodGet, "/old/page?x=1", nil)
	if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != "/new/page?x=1" {
		t.Fatalf("redirect = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	resp = send(http.MethodOptions, "/api/items", http.Header{"Origin": {"https://app.example"}, "Access-Control-Request-Method": {"PUT"}})
	if resp.StatusCode != http.StatusNoContent || resp.Header.Get("Access-Control-Allow-Methods") != "GET, PUT" || resp.Header.Get("Access-Control-Max-Age") != "120" {
		t.Fatalf("preflight = %d %v", resp.StatusCode, resp.Header)
	}

	mu.Lock()
	defer mu.Unlock()
	if paths["/old/page"] != 0 || paths["/new/page"] != 0 {
		t.Fatalf("redirect reached the local app: %v", paths)
	}
	if paths["/api/items"] != 1 {
		t.Fatalf("local app saw /api/items %d times, want 1 (preflight must stay at the edge)", paths["/api/items"])
	}
	for _, exchange := range store.List() {
		if exchange.Req.Method == http.MethodOptions || strings.Contains(exchange.Req.URL, "/old/") {
			t.Fatalf("inspector recorded an edge-answered request: %s %s", exchange.Req.Method, exchange.Req.URL)
		}
	}
}
