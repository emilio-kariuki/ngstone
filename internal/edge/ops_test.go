package edge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandleHealthzInsecureModeReportsOK(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	s.handleHealthz(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d when no TLS manager is configured (insecure mode)", rec.Code, http.StatusOK)
	}
	var resp healthzResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.OK {
		t.Fatalf("resp.OK = false, want true when no TLS manager is configured")
	}
}

func TestHandleHealthzReportsUnloadableCertsAsUnhealthy(t *testing.T) {
	mgr, err := NewTLSManager(TLSConfig{
		Domain:      "healthz-check.invalid",
		DNSProvider: fakeDNSProvider{},
		ACMEEmail:   "ops@healthz-check.invalid",
		StoragePath: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewTLSManager: %v", err)
	}

	s := &Server{tlsMgr: mgr}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	s.handleHealthz(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d when neither certificate has ever been obtained", rec.Code, http.StatusServiceUnavailable)
	}
	var resp healthzResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.OK {
		t.Fatalf("resp.OK = true, want false when certs are not loadable")
	}
	if resp.Apex.Domain != "healthz-check.invalid" {
		t.Fatalf("resp.Apex.Domain = %q, want %q", resp.Apex.Domain, "healthz-check.invalid")
	}
	if resp.Apex.Error == "" || resp.Wildcard.Error == "" {
		t.Fatalf("expected both apex and wildcard cert errors to be populated, got %+v", resp)
	}
}

func TestDashboardStateIncludesRoutedConnectorsAndEvents(t *testing.T) {
	s := newServerForTest(LimitsConfig{})
	s.cfg.OpsAddr = "127.0.0.1:4041"
	as, cleanup := newTestAgentSession(t, "dashboard-agent")
	if _, _, err := s.registry.Bind("demo.example.com", as, true, nil); err != nil {
		t.Fatalf("bind: %v", err)
	}
	s.recordEvent("info", "test event", map[string]string{"scope": "ops"})
	t.Cleanup(cleanup)
	t.Cleanup(func() { s.registry.ReleaseSession(as) })

	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	rec := httptest.NewRecorder()
	s.handleDashboardState(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var state dashboardState
	if err := json.Unmarshal(rec.Body.Bytes(), &state); err != nil {
		t.Fatalf("decode dashboard state: %v", err)
	}
	if state.Domain != "example.com" || !state.LoopbackOnly {
		t.Fatalf("state server metadata = domain %q loopback=%v", state.Domain, state.LoopbackOnly)
	}
	if state.ActiveTunnels != 1 || state.ActiveConnectors != 1 || len(state.Tunnels) != 1 {
		t.Fatalf("state tunnel counts = tunnels=%d connectors=%d entries=%d", state.ActiveTunnels, state.ActiveConnectors, len(state.Tunnels))
	}
	if state.Tunnels[0].Kind != "http" || state.Tunnels[0].Hostname != "demo.example.com" || len(state.Tunnels[0].Connectors) != 1 {
		t.Fatalf("state tunnel = %+v", state.Tunnels[0])
	}
	if len(state.Events) == 0 || state.Events[len(state.Events)-1].Message != "test event" {
		t.Fatalf("state events = %+v", state.Events)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestDashboardAndMetricsHandlers(t *testing.T) {
	s := newServerForTest(LimitsConfig{})
	mux := s.opsMux()

	page := httptest.NewRecorder()
	mux.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "See the edge breathe.") {
		t.Fatalf("dashboard response = status %d body prefix %q", page.Code, page.Body.String()[:min(len(page.Body.String()), 80)])
	}
	if got := page.Header().Get("Content-Security-Policy"); got == "" {
		t.Fatal("dashboard response is missing Content-Security-Policy")
	}

	metrics := httptest.NewRecorder()
	mux.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metrics.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", metrics.Code)
	}
	if !strings.Contains(metrics.Body.String(), "# TYPE ngstoned_requests_total counter") || !strings.Contains(metrics.Body.String(), "ngstoned_active_tunnels") {
		t.Fatalf("metrics body is missing expected series: %s", metrics.Body.String())
	}

	missing := httptest.NewRecorder()
	mux.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/not-dashboard", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("unknown ops path status = %d, want 404", missing.Code)
	}
}

func TestMetricsIncludesPerTunnelSeries(t *testing.T) {
	s := newServerForTest(LimitsConfig{})
	s.observability.observeRequest("metrics-tunnel", "metrics.example.com", http.StatusOK, 40*time.Millisecond, 10, 20)
	recorder := httptest.NewRecorder()
	s.handleMetrics(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recorder.Body.String()
	if !strings.Contains(body, `ngstoned_tunnel_requests_total{tunnel_id="metrics-tunnel",hostname="metrics.example.com"} 1`) {
		t.Fatalf("per-tunnel request series missing: %s", body)
	}
	if !strings.Contains(body, `ngstoned_tunnel_status_codes_total{tunnel_id="metrics-tunnel",hostname="metrics.example.com",status_code="200"} 1`) {
		t.Fatalf("per-tunnel status series missing: %s", body)
	}
}

func TestIsLoopbackOpsAddr(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{addr: "127.0.0.1:4041", want: true},
		{addr: "[::1]:4041", want: true},
		{addr: ":4041", want: false},
		{addr: "0.0.0.0:4041", want: false},
		{addr: "localhost:4041", want: false},
	} {
		if got := isLoopbackOpsAddr(tc.addr); got != tc.want {
			t.Errorf("isLoopbackOpsAddr(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}
