package edge

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"ngstone/internal/adminapi"
)

type dashboardState struct {
	GeneratedAt      time.Time          `json:"generated_at"`
	StartedAt        time.Time          `json:"started_at,omitempty"`
	UptimeSeconds    int64              `json:"uptime_seconds"`
	Domain           string             `json:"domain"`
	PublicScheme     string             `json:"public_scheme"`
	Listeners        dashboardListeners `json:"listeners"`
	LoopbackOnly     bool               `json:"loopback_only"`
	Health           healthzResponse    `json:"health"`
	Metrics          dashboardMetrics   `json:"metrics"`
	ActiveTunnels    int                `json:"active_tunnels"`
	ActiveConnectors int                `json:"active_connectors"`
	Tunnels          []dashboardTunnel  `json:"tunnels"`
	Events           []opsEvent         `json:"events"`
}

type dashboardTunnel struct {
	ID               string                  `json:"id,omitempty"`
	Name             string                  `json:"name,omitempty"`
	Kind             string                  `json:"kind"`
	Hostname         string                  `json:"hostname"`
	Port             int                     `json:"port,omitempty"`
	OwnerID          string                  `json:"owner_id,omitempty"`
	Status           string                  `json:"status,omitempty"`
	EdgeID           string                  `json:"edge_id,omitempty"`
	Durable          bool                    `json:"durable,omitempty"`
	BoundAt          time.Time               `json:"bound_at"`
	HTTP2            bool                    `json:"http2"`
	MultiConnector   bool                    `json:"multi_connector"`
	AccessRestricted bool                    `json:"access_restricted"`
	PolicyEnabled    bool                    `json:"policy_enabled"`
	Connectors       []registryConnectorInfo `json:"connectors"`
	RequestCount     int64                   `json:"request_count"`
	LatencyP95MS     float64                 `json:"latency_p95_ms"`
	BytesTransferred int64                   `json:"bytes_transferred"`
	Reconnects       int64                   `json:"reconnects"`
	StatusCodes      map[string]int64        `json:"status_codes,omitempty"`
}

type dashboardListeners struct {
	Control string `json:"control"`
	Public  string `json:"public"`
	Ops     string `json:"ops"`
}

type dashboardMetrics struct {
	RequestsTotal            int64 `json:"requests_total"`
	Responses4xx             int64 `json:"responses_4xx"`
	Responses5xx             int64 `json:"responses_5xx"`
	BytesTotal               int64 `json:"bytes_total"`
	ActiveSessions           int64 `json:"active_sessions"`
	ActiveUpgrades           int64 `json:"active_upgrades"`
	RejectedRateLimited      int64 `json:"rejected_rate_limited"`
	RejectedGlobalCap        int64 `json:"rejected_global_cap"`
	RejectedSessionCap       int64 `json:"rejected_session_cap"`
	Rejected413              int64 `json:"rejected_413"`
	RejectedForbiddenCIDR    int64 `json:"rejected_forbidden_cidr"`
	RejectedUnauthorized     int64 `json:"rejected_unauthorized"`
	RejectedTrafficPolicy    int64 `json:"rejected_traffic_policy"`
	RejectedUpgradeCap       int64 `json:"rejected_upgrade_cap"`
	TCPRejectedGlobalCap     int64 `json:"tcp_rejected_global_cap"`
	TCPRejectedBindCap       int64 `json:"tcp_rejected_bind_cap"`
	TCPRejectedRateLimited   int64 `json:"tcp_rejected_rate_limited"`
	TCPRejectedForbiddenCIDR int64 `json:"tcp_rejected_forbidden_cidr"`
}

func (s *Server) dashboardState(r *http.Request) dashboardState {
	now := time.Now().UTC()
	state := dashboardState{
		GeneratedAt:  now,
		Domain:       s.cfg.Domain,
		PublicScheme: s.cfg.PublicScheme,
		Listeners: dashboardListeners{
			Control: s.cfg.ControlAddr,
			Public:  s.cfg.PublicAddr,
			Ops:     s.cfg.OpsAddr,
		},
		LoopbackOnly: isLoopbackOpsAddr(s.cfg.OpsAddr),
		Metrics:      dashboardMetricsSnapshot(),
		Tunnels:      nil,
		Events:       nil,
	}
	if !s.startedAt.IsZero() {
		state.StartedAt = s.startedAt.UTC()
		if now.After(s.startedAt) {
			state.UptimeSeconds = int64(now.Sub(s.startedAt) / time.Second)
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	state.Health = s.healthzSnapshot(ctx)

	state.Tunnels = s.dashboardTunnelsForContext(ctx)
	observability := make(map[string]adminapi.TunnelObservability)
	for _, metric := range s.observabilitySnapshot(ctx) {
		key := metric.TunnelID
		if key == "" {
			key = metricKey("", metric.Hostname)
		}
		observability[key] = metric
	}
	for i := range state.Tunnels {
		key := state.Tunnels[i].ID
		if key == "" {
			key = metricKey("", state.Tunnels[i].Hostname)
		}
		if metric, ok := observability[key]; ok {
			state.Tunnels[i].RequestCount = metric.RequestCount
			state.Tunnels[i].LatencyP95MS = metric.LatencyP95MS
			state.Tunnels[i].BytesTransferred = metric.BytesTransferred
			state.Tunnels[i].Reconnects = metric.Reconnects
			state.Tunnels[i].StatusCodes = metric.StatusCodes
		}
	}
	for _, tunnel := range state.Tunnels {
		tunnelActive := false
		for _, connector := range tunnel.Connectors {
			if connector.Alive && connector.Healthy {
				tunnelActive = true
				state.ActiveConnectors++
			}
		}
		if tunnelActive {
			state.ActiveTunnels++
		}
	}
	state.Events = s.dashboardEvents(ctx)
	cancel()
	return state
}

func (s *Server) dashboardTunnels() []dashboardTunnel {
	var out []dashboardTunnel
	if s.registry != nil {
		for _, binding := range s.registry.dashboardSnapshot() {
			out = append(out, dashboardTunnel{
				Kind:             "http",
				Hostname:         binding.Hostname,
				BoundAt:          binding.BoundAt,
				HTTP2:            binding.HTTP2,
				MultiConnector:   binding.MultiConnector,
				AccessRestricted: binding.AccessRestricted,
				PolicyEnabled:    binding.PolicyEnabled,
				Connectors:       binding.Connectors,
			})
		}
	}
	if s.tcpMgr != nil {
		for _, tunnel := range s.tcpMgr.dashboardSnapshot() {
			out = append(out, dashboardTunnel{
				Kind:             "tcp",
				Hostname:         tunnel.Hostname,
				Port:             tunnel.Port,
				BoundAt:          tunnel.BoundAt,
				AccessRestricted: tunnel.AccessRestricted,
				Connectors: []registryConnectorInfo{{
					SessionID:      tunnel.SessionID,
					InstanceID:     tunnel.InstanceID,
					Remote:         tunnel.Remote,
					BoundAt:        tunnel.BoundAt,
					Alive:          tunnel.Alive,
					Healthy:        tunnel.Healthy,
					ActiveStreams:  tunnel.ActiveStreams,
					StreamCapacity: tunnel.StreamCapacity,
				}},
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hostname == out[j].Hostname {
			return out[i].Port < out[j].Port
		}
		return out[i].Hostname < out[j].Hostname
	})
	return out
}

func (s *Server) dashboardTunnelsForContext(ctx context.Context) []dashboardTunnel {
	local := s.dashboardTunnels()
	if s.storage == nil {
		if local == nil {
			return []dashboardTunnel{}
		}
		return local
	}
	durable, err := s.storage.ListTunnels(ctx)
	if err != nil {
		return local
	}
	localByKey := make(map[string]dashboardTunnel, len(local))
	for _, tunnel := range local {
		localByKey[dashboardTunnelKey(tunnel.Kind, tunnel.Hostname, tunnel.Port)] = tunnel
	}
	now := time.Now()
	out := make([]dashboardTunnel, 0, len(durable))
	for _, tunnel := range durable {
		key := dashboardTunnelKey(tunnel.Kind, tunnel.Hostname, tunnel.RemotePort)
		merged := localByKey[key]
		localConnectors := merged.Connectors
		merged.ID = tunnel.ID
		merged.Name = tunnel.Name
		merged.Kind = tunnel.Kind
		merged.Hostname = tunnel.Hostname
		merged.Port = tunnel.RemotePort
		merged.OwnerID = tunnel.OwnerID
		merged.EdgeID = tunnel.EdgeID
		merged.Durable = true
		merged.BoundAt = tunnel.CreatedAt
		merged.HTTP2 = tunnel.HTTP2
		merged.MultiConnector = tunnel.MultiConnector
		merged.PolicyEnabled = tunnel.PolicyDigest != ""
		merged.Status = tunnel.Status
		merged.Connectors = make([]registryConnectorInfo, 0, len(tunnel.Connectors))
		aliveConnectors := 0
		for _, connector := range tunnel.Connectors {
			alive := connector.ExpiresAt.After(now)
			if alive {
				aliveConnectors++
			}
			localConnector := findDashboardConnector(localConnectors, connector.SessionID)
			if localConnector != nil {
				localConnectorCopy := *localConnector
				localConnectorCopy.Alive = alive
				localConnectorCopy.Healthy = alive
				merged.Connectors = append(merged.Connectors, localConnectorCopy)
				continue
			}
			merged.Connectors = append(merged.Connectors, registryConnectorInfo{
				SessionID:  connector.SessionID,
				InstanceID: connector.InstanceID,
				BoundAt:    connector.AcquiredAt,
				Alive:      alive,
				Healthy:    alive,
			})
		}
		if aliveConnectors == 0 {
			merged.Status = "offline"
		}
		out = append(out, merged)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hostname == out[j].Hostname {
			return out[i].Port < out[j].Port
		}
		return out[i].Hostname < out[j].Hostname
	})
	return out
}

func dashboardTunnelKey(kind, hostname string, port int) string {
	return kind + "|" + hostname + "|" + fmt.Sprintf("%d", port)
}

func findDashboardConnector(connectors []registryConnectorInfo, sessionID string) *registryConnectorInfo {
	for i := range connectors {
		if connectors[i].SessionID == sessionID {
			return &connectors[i]
		}
	}
	return nil
}

func (s *Server) dashboardEvents(ctx context.Context) []opsEvent {
	if s.storage == nil {
		if s.events == nil {
			return nil
		}
		return s.events.snapshot()
	}
	events, err := s.storage.ListAudit(ctx, 200)
	if err != nil {
		if s.events == nil {
			return nil
		}
		return s.events.snapshot()
	}
	out := make([]opsEvent, 0, len(events))
	for _, event := range events {
		out = append(out, opsEvent{At: event.CreatedAt, Level: "info", Message: event.Action, Fields: event.Metadata})
	}
	return out
}

func dashboardMetricsSnapshot() dashboardMetrics {
	return dashboardMetrics{
		RequestsTotal:            metricRequestsTotal.Value(),
		Responses4xx:             metricResponses4xx.Value(),
		Responses5xx:             metricResponses5xx.Value(),
		BytesTotal:               metricBytesTotal.Value(),
		ActiveSessions:           metricActiveSessions.Value(),
		ActiveUpgrades:           metricActiveUpgrades.Value(),
		RejectedRateLimited:      metricRejectedRateLimited.Value(),
		RejectedGlobalCap:        metricRejectedGlobalCap.Value(),
		RejectedSessionCap:       metricRejectedSessionCap.Value(),
		Rejected413:              metricRejected413.Value(),
		RejectedForbiddenCIDR:    metricRejectedForbiddenCIDR.Value(),
		RejectedUnauthorized:     metricRejectedUnauthorized.Value(),
		RejectedTrafficPolicy:    metricRejectedTrafficPolicy.Value(),
		RejectedUpgradeCap:       metricRejectedUpgradeCap.Value(),
		TCPRejectedGlobalCap:     metricTCPRejectedGlobalCap.Value(),
		TCPRejectedBindCap:       metricTCPRejectedBindCap.Value(),
		TCPRejectedRateLimited:   metricTCPRejectedRateLimited.Value(),
		TCPRejectedForbiddenCIDR: metricTCPRejectedForbiddenCIDR.Value(),
	}
}

func (s *Server) handleDashboardState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	setOpsHeaders(w, "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(s.dashboardState(r)); err != nil {
		return
	}
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	setOpsHeaders(w, "text/plain; version=0.0.4; charset=utf-8")
	metrics := dashboardMetricsSnapshot()
	writePrometheusCounter(w, "ngstoned_requests_total", "Total public requests received.", metrics.RequestsTotal)
	writePrometheusCounter(w, "ngstoned_responses_4xx_total", "Total public responses with a 4xx status.", metrics.Responses4xx)
	writePrometheusCounter(w, "ngstoned_responses_5xx_total", "Total public responses with a 5xx status.", metrics.Responses5xx)
	writePrometheusCounter(w, "ngstoned_bytes_total", "Total response bytes sent to public clients.", metrics.BytesTotal)
	writePrometheusGauge(w, "ngstoned_active_sessions", "Currently authenticated agent sessions.", metrics.ActiveSessions)
	writePrometheusGauge(w, "ngstoned_active_upgrades", "Currently active WebSocket, SSE, and gRPC-style upgrades.", metrics.ActiveUpgrades)
	writePrometheusCounter(w, "ngstoned_rejected_rate_limited_total", "Requests rejected by the per-IP rate limiter.", metrics.RejectedRateLimited)
	writePrometheusCounter(w, "ngstoned_rejected_global_cap_total", "Requests rejected by the global concurrency cap.", metrics.RejectedGlobalCap)
	writePrometheusCounter(w, "ngstoned_rejected_session_cap_total", "Requests rejected by the per-session concurrency cap.", metrics.RejectedSessionCap)
	writePrometheusCounter(w, "ngstoned_rejected_413_total", "Requests rejected for exceeding the body limit.", metrics.Rejected413)
	writePrometheusCounter(w, "ngstoned_rejected_forbidden_cidr_total", "Requests rejected by an IP allowlist.", metrics.RejectedForbiddenCIDR)
	writePrometheusCounter(w, "ngstoned_rejected_unauthorized_total", "Requests rejected by HTTP basic authentication.", metrics.RejectedUnauthorized)
	writePrometheusCounter(w, "ngstoned_rejected_traffic_policy_total", "Requests rejected by a traffic policy.", metrics.RejectedTrafficPolicy)
	writePrometheusCounter(w, "ngstoned_rejected_upgrade_cap_total", "Requests rejected by the upgrade concurrency cap.", metrics.RejectedUpgradeCap)
	writePrometheusCounter(w, "ngstoned_tcp_rejected_global_cap_total", "TCP connections rejected by the global concurrency cap.", metrics.TCPRejectedGlobalCap)
	writePrometheusCounter(w, "ngstoned_tcp_rejected_bind_cap_total", "TCP binds rejected by the per-session bind cap.", metrics.TCPRejectedBindCap)
	writePrometheusCounter(w, "ngstoned_tcp_rejected_rate_limited_total", "TCP connections rejected by the per-IP rate limiter.", metrics.TCPRejectedRateLimited)
	writePrometheusCounter(w, "ngstoned_tcp_rejected_forbidden_cidr_total", "TCP connections rejected by an IP allowlist.", metrics.TCPRejectedForbiddenCIDR)
	writePrometheusGauge(w, "ngstoned_active_tunnels", "Currently routed HTTP and TCP tunnels.", int64(len(s.dashboardTunnels())))
	writePrometheusGauge(w, "ngstoned_uptime_seconds", "Seconds since ngstoned started.", uptimeSeconds(s.startedAt))
	fmt.Fprintln(w, "# HELP ngstoned_tunnel_requests_total Requests observed for a tunnel.")
	fmt.Fprintln(w, "# TYPE ngstoned_tunnel_requests_total counter")
	fmt.Fprintln(w, "# HELP ngstoned_tunnel_bytes_in_total Request bytes observed for a tunnel.")
	fmt.Fprintln(w, "# TYPE ngstoned_tunnel_bytes_in_total counter")
	fmt.Fprintln(w, "# HELP ngstoned_tunnel_bytes_out_total Response bytes observed for a tunnel.")
	fmt.Fprintln(w, "# TYPE ngstoned_tunnel_bytes_out_total counter")
	fmt.Fprintln(w, "# HELP ngstoned_tunnel_reconnects_total Connector reconnects observed for a tunnel.")
	fmt.Fprintln(w, "# TYPE ngstoned_tunnel_reconnects_total counter")
	fmt.Fprintln(w, "# HELP ngstoned_tunnel_credential_expired_total Expired credential events observed for a tunnel.")
	fmt.Fprintln(w, "# TYPE ngstoned_tunnel_credential_expired_total counter")
	fmt.Fprintln(w, "# HELP ngstoned_tunnel_credential_revoked_total Revoked credential events observed for a tunnel.")
	fmt.Fprintln(w, "# TYPE ngstoned_tunnel_credential_revoked_total counter")
	fmt.Fprintln(w, "# HELP ngstoned_tunnel_active_connectors Active connectors for a tunnel.")
	fmt.Fprintln(w, "# TYPE ngstoned_tunnel_active_connectors gauge")
	fmt.Fprintln(w, "# HELP ngstoned_tunnel_latency_ms Approximate tunnel request latency percentile in milliseconds.")
	fmt.Fprintln(w, "# TYPE ngstoned_tunnel_latency_ms gauge")
	fmt.Fprintln(w, "# HELP ngstoned_tunnel_status_codes_total Responses by status code for a tunnel.")
	fmt.Fprintln(w, "# TYPE ngstoned_tunnel_status_codes_total counter")
	for _, metric := range s.observabilitySnapshot(r.Context()) {
		labels := fmt.Sprintf("tunnel_id=%q,hostname=%q", metric.TunnelID, metric.Hostname)
		writePrometheusLabeledCounter(w, "ngstoned_tunnel_requests_total", labels, metric.RequestCount)
		writePrometheusLabeledCounter(w, "ngstoned_tunnel_bytes_in_total", labels, metric.BytesIn)
		writePrometheusLabeledCounter(w, "ngstoned_tunnel_bytes_out_total", labels, metric.BytesOut)
		writePrometheusLabeledCounter(w, "ngstoned_tunnel_reconnects_total", labels, metric.Reconnects)
		writePrometheusLabeledCounter(w, "ngstoned_tunnel_credential_expired_total", labels, metric.CredentialExpired)
		writePrometheusLabeledCounter(w, "ngstoned_tunnel_credential_revoked_total", labels, metric.CredentialRevoked)
		writePrometheusLabeledGauge(w, "ngstoned_tunnel_active_connectors", labels, float64(metric.ActiveConnectors))
		writePrometheusLabeledGauge(w, "ngstoned_tunnel_latency_ms", labels+`,quantile="0.5"`, metric.LatencyP50MS)
		writePrometheusLabeledGauge(w, "ngstoned_tunnel_latency_ms", labels+`,quantile="0.95"`, metric.LatencyP95MS)
		writePrometheusLabeledGauge(w, "ngstoned_tunnel_latency_ms", labels+`,quantile="0.99"`, metric.LatencyP99MS)
		statuses := make([]string, 0, len(metric.StatusCodes))
		for status := range metric.StatusCodes {
			statuses = append(statuses, status)
		}
		sort.Strings(statuses)
		for _, status := range statuses {
			writePrometheusLabeledCounter(w, "ngstoned_tunnel_status_codes_total", labels+fmt.Sprintf(",status_code=%q", status), metric.StatusCodes[status])
		}
	}

	health := s.healthzSnapshot(r.Context())
	fmt.Fprintln(w, "# HELP ngstoned_certificate_not_after_seconds Certificate expiration timestamp.")
	fmt.Fprintln(w, "# TYPE ngstoned_certificate_not_after_seconds gauge")
	writeCertNotAfter(w, "apex", health.Apex.NotAfter)
	writeCertNotAfter(w, "wildcard", health.Wildcard.NotAfter)
}

func writePrometheusCounter(w http.ResponseWriter, name, help string, value int64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, value)
}

func writePrometheusGauge(w http.ResponseWriter, name, help string, value int64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, value)
}

func writePrometheusLabeledCounter(w http.ResponseWriter, name, labels string, value int64) {
	fmt.Fprintf(w, "%s{%s} %d\n", name, labels, value)
}

func writePrometheusLabeledGauge(w http.ResponseWriter, name, labels string, value float64) {
	fmt.Fprintf(w, "%s{%s} %g\n", name, labels, value)
}

func writeCertNotAfter(w http.ResponseWriter, name, value string) {
	if value == "" {
		return
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "ngstoned_certificate_not_after_seconds{certificate=%q} %d\n", name, t.Unix())
}

func uptimeSeconds(startedAt time.Time) int64 {
	if startedAt.IsZero() || time.Since(startedAt) < 0 {
		return 0
	}
	return int64(time.Since(startedAt) / time.Second)
}

func isLoopbackOpsAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func setOpsHeaders(w http.ResponseWriter, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.oidcEnabled() {
		if _, ok := s.oidcSessionFromRequest(r); !ok {
			http.Redirect(w, r, "/api/v1/auth/oidc/start", http.StatusFound)
			return
		}
	}
	setOpsHeaders(w, "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
	fmt.Fprint(w, dashboardHTML)
}

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>ngstone / ops</title>
  <style>
    :root {
      --bg: #071011;
      --panel: rgba(14, 27, 27, .88);
      --panel-hi: #132526;
      --line: #1d3938;
      --text: #e1efea;
      --muted: #819a94;
      --lime: #c7f36b;
      --cyan: #7fe2d0;
      --amber: #f2b66d;
      --coral: #ff8c7e;
      --shadow: 0 22px 70px rgba(0, 0, 0, .34);
    }
    * { box-sizing: border-box; }
    html { background: var(--bg); }
    body {
      margin: 0;
      min-width: 320px;
      color: var(--text);
      background:
        radial-gradient(circle at 88% 4%, rgba(127, 226, 208, .12), transparent 28rem),
        radial-gradient(circle at 4% 28%, rgba(199, 243, 107, .08), transparent 24rem),
        linear-gradient(135deg, #071011 0%, #091717 52%, #071011 100%);
      font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
      line-height: 1.45;
    }
    body::before {
      position: fixed;
      inset: 0;
      z-index: -1;
      pointer-events: none;
      content: "";
      opacity: .28;
      background-image: linear-gradient(rgba(127, 226, 208, .035) 1px, transparent 1px), linear-gradient(90deg, rgba(127, 226, 208, .035) 1px, transparent 1px);
      background-size: 42px 42px;
      mask-image: linear-gradient(to bottom, black, transparent 76%);
    }
    a { color: var(--cyan); text-decoration: none; }
    a:hover { color: var(--lime); }
    .shell { width: min(1440px, calc(100% - 44px)); margin: 0 auto; padding: 34px 0 56px; }
    .topbar { display: flex; justify-content: space-between; align-items: flex-start; gap: 22px; margin-bottom: 42px; }
    .brandline { display: flex; align-items: center; gap: 13px; color: var(--muted); font-size: 11px; letter-spacing: .18em; text-transform: uppercase; }
    .mark { display: grid; width: 31px; height: 31px; place-items: center; color: var(--bg); background: var(--lime); font-family: "DM Sans", "Avenir Next", sans-serif; font-size: 16px; font-weight: 900; letter-spacing: -.08em; box-shadow: 5px 5px 0 rgba(127, 226, 208, .32); }
    h1 { max-width: 680px; margin: 17px 0 9px; font-family: "DM Sans", "Avenir Next", sans-serif; font-size: clamp(34px, 5vw, 67px); font-weight: 700; letter-spacing: -.065em; line-height: .96; }
    .lede { max-width: 650px; margin: 0; color: var(--muted); font-size: 13px; }
    .statusbox { min-width: 230px; padding: 15px 17px; border: 1px solid var(--line); background: rgba(8, 19, 19, .6); box-shadow: var(--shadow); }
    .statusline { display: flex; align-items: center; justify-content: space-between; gap: 14px; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .12em; }
    .status { display: inline-flex; align-items: center; gap: 8px; color: var(--lime); }
    .status::before { width: 8px; height: 8px; border-radius: 50%; background: currentColor; box-shadow: 0 0 0 5px rgba(199, 243, 107, .1), 0 0 18px currentColor; content: ""; }
    .status.offline { color: var(--coral); }
    .status.offline::before { box-shadow: 0 0 0 5px rgba(255, 140, 126, .1); }
    .statusbox strong { display: block; margin-top: 13px; color: var(--text); font-size: 13px; font-weight: 500; }
    .statusbox small { display: block; margin-top: 5px; color: var(--muted); font-size: 10px; }
    .metrics { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 18px; }
    .metric { position: relative; min-height: 127px; padding: 17px; overflow: hidden; border: 1px solid var(--line); background: var(--panel); box-shadow: var(--shadow); }
    .metric::after { position: absolute; right: -19px; bottom: -28px; width: 92px; height: 92px; border: 1px solid rgba(127, 226, 208, .16); border-radius: 50%; content: ""; }
    .metric:nth-child(2)::after { border-color: rgba(199, 243, 107, .2); }
    .metric:nth-child(3)::after { border-color: rgba(242, 182, 109, .2); }
    .metric:nth-child(4)::after { border-color: rgba(255, 140, 126, .2); }
    .metric:nth-child(5)::after { border-color: rgba(127, 226, 208, .2); }
    .metric label { display: block; color: var(--muted); font-size: 10px; letter-spacing: .12em; text-transform: uppercase; }
    .metric strong { display: block; margin-top: 13px; color: var(--text); font-family: "DM Sans", "Avenir Next", sans-serif; font-size: 34px; font-weight: 650; letter-spacing: -.06em; line-height: 1; }
    .metric small { display: block; margin-top: 12px; color: var(--muted); font-size: 10px; }
    .layout { display: grid; grid-template-columns: minmax(0, 1.65fr) minmax(290px, .75fr); gap: 18px; align-items: start; }
    .stack { display: grid; gap: 18px; }
    .panel { border: 1px solid var(--line); background: var(--panel); box-shadow: var(--shadow); }
    .panelhead { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; padding: 18px 20px 15px; border-bottom: 1px solid var(--line); }
    .panelhead h2 { margin: 0; color: var(--text); font-family: "DM Sans", "Avenir Next", sans-serif; font-size: 17px; font-weight: 650; letter-spacing: -.035em; }
    .panelhead span { color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: .1em; }
    .tablewrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; min-width: 670px; }
    th { padding: 13px 20px 10px; color: var(--muted); font-size: 9px; font-weight: 500; letter-spacing: .12em; text-align: left; text-transform: uppercase; }
    td { padding: 16px 20px; border-top: 1px solid rgba(29, 57, 56, .66); color: var(--text); font-size: 11px; vertical-align: top; }
    tbody tr { transition: background .18s ease; }
    tbody tr:hover { background: rgba(127, 226, 208, .045); }
    .host { color: var(--cyan); font-size: 12px; }
    .sub { display: block; margin-top: 5px; color: var(--muted); font-size: 10px; }
    .badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 7px; border: 1px solid var(--line); color: var(--muted); font-size: 9px; letter-spacing: .06em; text-transform: uppercase; white-space: nowrap; }
    .badge::before { width: 5px; height: 5px; border-radius: 50%; background: currentColor; content: ""; }
    .badge.live { color: var(--lime); border-color: rgba(199, 243, 107, .28); }
    .badge.warn { color: var(--amber); border-color: rgba(242, 182, 109, .28); }
    .badge.dead { color: var(--coral); border-color: rgba(255, 140, 126, .28); }
    .connector { display: grid; grid-template-columns: auto 1fr; gap: 8px; align-items: start; margin: 0 0 8px; }
    .connector:last-child { margin-bottom: 0; }
    .connector-meta { min-width: 160px; color: var(--text); font-size: 10px; }
    .connector-meta small { display: block; margin-top: 2px; color: var(--muted); font-size: 9px; }
    .chips { display: flex; flex-wrap: wrap; gap: 5px; }
    .chip { padding: 3px 6px; color: var(--muted); background: rgba(127, 226, 208, .05); font-size: 9px; }
    .empty { padding: 34px 20px; color: var(--muted); font-size: 11px; text-align: center; }
    .certs { display: grid; gap: 10px; padding: 14px; }
    .cert { padding: 15px; border: 1px solid var(--line); background: rgba(127, 226, 208, .025); }
    .certline { display: flex; justify-content: space-between; gap: 12px; color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: .1em; }
    .cert strong { display: block; margin-top: 11px; color: var(--text); font-size: 12px; font-weight: 500; }
    .cert small { display: block; margin-top: 5px; color: var(--muted); font-size: 10px; }
    .cert.good .certline { color: var(--lime); }
    .cert.bad .certline { color: var(--coral); }
    .events { max-height: 350px; overflow: auto; padding: 8px 20px 15px; }
    .event { display: grid; grid-template-columns: 70px 1fr; gap: 12px; padding: 10px 0; border-bottom: 1px solid rgba(29, 57, 56, .58); font-size: 10px; }
    .event:last-child { border-bottom: 0; }
    .event time { color: var(--muted); }
    .event strong { color: var(--text); font-weight: 500; }
    .event small { display: block; margin-top: 4px; color: var(--muted); font-size: 9px; word-break: break-word; }
    .event.warn strong { color: var(--amber); }
    .event.error strong { color: var(--coral); }
    .footer { display: flex; justify-content: space-between; gap: 20px; margin-top: 18px; color: var(--muted); font-size: 10px; }
    .links { display: flex; flex-wrap: wrap; gap: 12px; }
    button { border: 1px solid var(--line); padding: 7px 10px; color: var(--cyan); background: transparent; font: inherit; font-size: 10px; cursor: pointer; }
    button:hover { border-color: var(--cyan); color: var(--lime); }
    @media (max-width: 1050px) { .metrics { grid-template-columns: repeat(3, 1fr); } .layout { grid-template-columns: 1fr; } }
    @media (max-width: 620px) { .shell { width: min(100% - 26px, 1440px); padding-top: 22px; } .topbar { display: block; } .statusbox { margin-top: 24px; } .metrics { grid-template-columns: repeat(2, 1fr); } .metric { min-height: 112px; padding: 13px; } .metric strong { font-size: 27px; } .panelhead { padding-left: 14px; padding-right: 14px; } th, td { padding-left: 14px; padding-right: 14px; } .footer { display: block; } .links { margin-top: 12px; } }
  </style>
</head>
<body>
  <main class="shell">
    <header class="topbar">
      <div>
        <div class="brandline"><span class="mark">N</span><span>ngstone / local operations</span></div>
        <h1>See the edge breathe.</h1>
        <p class="lede">A quiet control room for tunnel health, connector capacity, certificate lifetimes, and the traffic moving through your edge.</p>
      </div>
      <aside class="statusbox">
        <div class="statusline"><span>control surface</span><span class="status" id="connectionStatus">connected</span></div>
        <strong id="domain">—</strong>
        <small id="listenerNote">loopback ops endpoint · refreshing every 3s</small>
      </aside>
    </header>

    <section class="metrics" aria-label="Edge metrics">
      <article class="metric"><label>requests</label><strong id="requests">—</strong><small id="requestRate">waiting for sample</small></article>
      <article class="metric"><label>active tunnels</label><strong id="tunnels">—</strong><small id="connectors">— connectors</small></article>
      <article class="metric"><label>agent sessions</label><strong id="sessions">—</strong><small id="uptime">uptime —</small></article>
      <article class="metric"><label>5xx responses</label><strong id="errors">—</strong><small id="errorShare">—</small></article>
      <article class="metric"><label>egress</label><strong id="bytes">—</strong><small id="lastRefresh">last refresh —</small></article>
    </section>

    <section class="layout">
      <div class="stack">
        <section class="panel">
          <div class="panelhead"><h2>Routed tunnels</h2><span id="tunnelSummary">—</span></div>
          <div class="tablewrap">
            <table>
              <thead><tr><th>hostname</th><th>mode</th><th>connectors</th><th>guards</th><th>traffic</th><th>bound</th></tr></thead>
              <tbody id="tunnelRows"><tr><td class="empty" colspan="5">waiting for registry state</td></tr></tbody>
            </table>
          </div>
        </section>
        <section class="panel">
          <div class="panelhead"><h2>Recent edge events</h2><span>in-memory · last 200</span></div>
          <div class="events" id="events"><div class="empty">waiting for events</div></div>
        </section>
      </div>
      <aside class="stack">
        <section class="panel">
          <div class="panelhead"><h2>Certificates</h2><span id="healthLabel">checking</span></div>
          <div class="certs">
            <article class="cert" id="apexCert"><div class="certline"><span>apex</span><span id="apexState">—</span></div><strong id="apexDomain">—</strong><small id="apexExpiry">—</small></article>
            <article class="cert" id="wildcardCert"><div class="certline"><span>wildcard</span><span id="wildcardState">—</span></div><strong id="wildcardDomain">—</strong><small id="wildcardExpiry">—</small></article>
          </div>
        </section>
        <section class="panel">
          <div class="panelhead"><h2>Rejections</h2><span>since process start</span></div>
          <div class="certs">
            <div class="cert"><div class="certline"><span>rate limit</span><strong id="rateRejected">0</strong></div><small>per-IP admission control</small></div>
            <div class="cert"><div class="certline"><span>auth / CIDR</span><strong id="guardRejected">0</strong></div><small>private tunnel guards</small></div>
            <div class="cert"><div class="certline"><span>capacity</span><strong id="capacityRejected">0</strong></div><small>global and connector slots</small></div>
          </div>
        </section>
      </aside>
    </section>

    <footer class="footer">
      <span>read-only by design · keep this listener on loopback</span>
      <nav class="links"><a href="/healthz">healthz</a><a href="/metrics">metrics</a><a href="/debug/vars">expvar</a><a href="/debug/pprof/">pprof</a><button id="refreshButton" type="button">refresh now</button></nav>
    </footer>
  </main>
  <script>
    (function () {
      var previous = null;
      var previousAt = 0;
      var number = new Intl.NumberFormat();
      var date = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      function value(input) { return input === null || input === undefined || input === '' ? '—' : String(input); }
      function set(id, input) { var node = document.getElementById(id); if (node) node.textContent = value(input); }
      function fmtNumber(input) { return number.format(Number(input || 0)); }
      function fmtBytes(input) { var n = Number(input || 0); if (n < 1024) return n + ' B'; if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB'; if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB'; return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB'; }
      function fmtUptime(input) { var n = Number(input || 0); var d = Math.floor(n / 86400); n %= 86400; var h = Math.floor(n / 3600); n %= 3600; var m = Math.floor(n / 60); var s = n % 60; return (d ? d + 'd ' : '') + (h ? h + 'h ' : '') + (m ? m + 'm ' : '') + s + 's'; }
      function fmtDate(input) { if (!input) return '—'; try { return date.format(new Date(input)); } catch (error) { return '—'; } }
      function badge(label, kind) { var node = document.createElement('span'); node.className = 'badge ' + (kind || ''); node.textContent = label; return node; }
      function chip(label) { var node = document.createElement('span'); node.className = 'chip'; node.textContent = label; return node; }
      function cell(text, className) { var node = document.createElement('td'); if (className) node.className = className; node.textContent = value(text); return node; }
      function renderTunnels(tunnels) {
        var root = document.getElementById('tunnelRows'); root.replaceChildren();
        if (!tunnels.length) { var row = document.createElement('tr'); var empty = cell('No active tunnels. Start an agent to see it here.', 'empty'); empty.colSpan = 6; row.appendChild(empty); root.appendChild(row); return; }
        tunnels.forEach(function (tunnel) {
          var row = document.createElement('tr');
          var host = document.createElement('td'); var hostName = document.createElement('div'); hostName.className = 'host'; hostName.textContent = tunnel.hostname; host.appendChild(hostName); var hostSub = document.createElement('small'); hostSub.className = 'sub'; hostSub.textContent = tunnel.kind === 'tcp' ? 'tcp port ' + tunnel.port : (tunnel.multi_connector ? 'shared connector pool' : 'single connector'); host.appendChild(hostSub); row.appendChild(host);
          var mode = document.createElement('td'); mode.appendChild(badge(tunnel.kind === 'tcp' ? 'tcp / raw' : (tunnel.http2 ? 'h2 / grpc' : 'http / 1.1'), tunnel.http2 ? 'live' : '')); row.appendChild(mode);
          var connectors = document.createElement('td'); (tunnel.connectors || []).forEach(function (connector) { var item = document.createElement('div'); item.className = 'connector'; item.appendChild(badge(connector.alive ? 'live' : 'dead', connector.alive ? 'live' : 'dead')); var meta = document.createElement('div'); meta.className = 'connector-meta'; meta.textContent = connector.instance_id || connector.session_id || 'unknown'; var small = document.createElement('small'); small.textContent = fmtNumber(connector.active_streams) + ' / ' + fmtNumber(connector.stream_capacity) + ' streams' + (connector.remote ? ' · ' + connector.remote : ''); meta.appendChild(small); item.appendChild(meta); connectors.appendChild(item); }); row.appendChild(connectors);
          var guards = document.createElement('td'); var guardChips = document.createElement('div'); guardChips.className = 'chips'; guardChips.appendChild(chip(tunnel.access_restricted ? 'access restricted' : 'public')); if (tunnel.policy_enabled) guardChips.appendChild(chip('traffic policy')); guards.appendChild(guardChips); row.appendChild(guards);
          var traffic = document.createElement('td'); var trafficChips = document.createElement('div'); trafficChips.className = 'chips'; trafficChips.appendChild(chip(fmtNumber(tunnel.request_count) + ' req')); trafficChips.appendChild(chip('p95 ' + Number(tunnel.latency_p95_ms || 0).toFixed(1) + ' ms')); trafficChips.appendChild(chip(fmtBytes(tunnel.bytes_transferred) + ' moved')); if (tunnel.reconnects) trafficChips.appendChild(chip(fmtNumber(tunnel.reconnects) + ' reconnects')); traffic.appendChild(trafficChips); row.appendChild(traffic);
          row.appendChild(cell(fmtDate(tunnel.bound_at), 'sub')); root.appendChild(row);
        });
      }
      function renderEvents(events) {
        var root = document.getElementById('events'); root.replaceChildren();
        if (!events || !events.length) { var empty = document.createElement('div'); empty.className = 'empty'; empty.textContent = 'No edge events yet.'; root.appendChild(empty); return; }
        events.slice().reverse().forEach(function (event) { var item = document.createElement('div'); item.className = 'event ' + (event.level || ''); var time = document.createElement('time'); time.textContent = fmtDate(event.at); item.appendChild(time); var body = document.createElement('div'); var message = document.createElement('strong'); message.textContent = event.message; body.appendChild(message); if (event.fields) { var details = Object.keys(event.fields).map(function (key) { return key + '=' + event.fields[key]; }).join(' · '); if (details) { var small = document.createElement('small'); small.textContent = details; body.appendChild(small); } } item.appendChild(body); root.appendChild(item); });
      }
      function renderCert(id, cert, healthy) { var root = document.getElementById(id + 'Cert'); var state = document.getElementById(id + 'State'); if (!cert || !cert.domain) { root.className = 'cert'; state.textContent = 'disabled'; set(id + 'Domain', 'TLS certificate management is off'); set(id + 'Expiry', 'insecure edge mode'); return; } root.className = 'cert ' + (healthy ? 'good' : 'bad'); state.textContent = healthy ? 'ready' : 'attention'; set(id + 'Domain', cert.domain); set(id + 'Expiry', cert.error ? cert.error : (cert.not_after ? 'expires ' + fmtDate(cert.not_after) : 'not available')); }
      function render(state) {
        var metrics = state.metrics || {}; var now = Date.now(); var rate = ''; if (previous && previousAt) { var seconds = (now - previousAt) / 1000; if (seconds > 0) rate = Math.max(0, Math.round((metrics.requests_total - previous.requests_total) / seconds)) + ' req/s since last sample'; } previous = metrics; previousAt = now;
        set('domain', state.domain); set('requests', fmtNumber(metrics.requests_total)); set('tunnels', fmtNumber(state.active_tunnels)); set('connectors', fmtNumber(state.active_connectors) + ' connector' + (state.active_connectors === 1 ? '' : 's')); set('sessions', fmtNumber(metrics.active_sessions)); set('uptime', 'uptime ' + fmtUptime(state.uptime_seconds)); set('errors', fmtNumber(metrics.responses_5xx)); var total = Number(metrics.requests_total || 0); set('errorShare', total ? ((Number(metrics.responses_5xx || 0) / total) * 100).toFixed(2) + '% of requests' : 'no requests yet'); set('bytes', fmtBytes(metrics.bytes_total)); set('requestRate', rate || 'sampling request velocity'); set('lastRefresh', 'last refresh ' + fmtDate(state.generated_at)); set('tunnelSummary', fmtNumber(state.active_tunnels) + ' routed · ' + fmtNumber(state.active_connectors) + ' connectors'); set('listenerNote', (state.loopback_only ? 'loopback ops endpoint' : 'non-loopback ops endpoint') + ' · refreshing every 3s'); set('rateRejected', fmtNumber(metrics.rejected_rate_limited)); set('guardRejected', fmtNumber(Number(metrics.rejected_forbidden_cidr || 0) + Number(metrics.rejected_unauthorized || 0) + Number(metrics.rejected_traffic_policy || 0))); set('capacityRejected', fmtNumber(Number(metrics.rejected_global_cap || 0) + Number(metrics.rejected_session_cap || 0) + Number(metrics.rejected_upgrade_cap || 0))); var healthy = state.health && state.health.ok; set('healthLabel', healthy ? 'healthy' : 'attention'); renderCert('apex', state.health && state.health.apex_cert, healthy && !(state.health && state.health.apex_cert && state.health.apex_cert.error)); renderCert('wildcard', state.health && state.health.wildcard_cert, healthy && !(state.health && state.health.wildcard_cert && state.health.wildcard_cert.error)); renderTunnels(state.tunnels || []); renderEvents(state.events || []); }
      function setConnection(online, error) { var node = document.getElementById('connectionStatus'); node.textContent = online ? 'connected' : 'offline'; node.className = 'status' + (online ? '' : ' offline'); if (error) set('listenerNote', error); }
      function refresh() { fetch('/api/state', { cache: 'no-store', headers: { Accept: 'application/json' } }).then(function (response) { if (response.status === 401) { window.location.href = '/api/v1/auth/oidc/start'; return null; } if (!response.ok) throw new Error('ops API returned ' + response.status); return response.json(); }).then(function (state) { if (state) { setConnection(true); render(state); } }).catch(function (error) { setConnection(false, error.message); }); }
      document.getElementById('refreshButton').addEventListener('click', refresh); refresh(); window.setInterval(refresh, 3000);
    }());
  </script>
</body>
</html>`
