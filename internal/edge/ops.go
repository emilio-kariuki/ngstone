package edge

import (
	"context"
	"encoding/json"
	"expvar"
	"net/http"
	"net/http/pprof"
	"time"
)

var (
	metricRequestsTotal  = expvar.NewInt("ngstoned_requests_total")
	metricResponses4xx   = expvar.NewInt("ngstoned_responses_4xx_total")
	metricResponses5xx   = expvar.NewInt("ngstoned_responses_5xx_total")
	metricBytesTotal     = expvar.NewInt("ngstoned_bytes_total")
	metricActiveSessions = expvar.NewInt("ngstoned_active_sessions")

	metricRejectedRateLimited = expvar.NewInt("ngstoned_rejected_rate_limited_total")
	metricRejectedGlobalCap   = expvar.NewInt("ngstoned_rejected_global_cap_total")
	metricRejectedSessionCap  = expvar.NewInt("ngstoned_rejected_session_cap_total")
	metricRejected413         = expvar.NewInt("ngstoned_rejected_413_total")

	metricRejectedForbiddenCIDR = expvar.NewInt("ngstoned_rejected_forbidden_cidr_total")
	metricRejectedUnauthorized  = expvar.NewInt("ngstoned_rejected_unauthorized_total")
	metricRejectedTrafficPolicy = expvar.NewInt("ngstoned_rejected_traffic_policy_total")
	metricRejectedWebhook       = expvar.NewInt("ngstoned_rejected_webhook_signature_total")
	metricRejectedWebhookBuffer = expvar.NewInt("ngstoned_rejected_webhook_buffer_total")

	metricRejectedUpgradeCap = expvar.NewInt("ngstoned_rejected_upgrade_cap_total")

	metricRejectedPerIPCap   = expvar.NewInt("ngstoned_rejected_per_ip_cap_total")
	metricRejectedClientIdle = expvar.NewInt("ngstoned_rejected_client_idle_total")
	metricTCPClosedIdle      = expvar.NewInt("ngstoned_tcp_closed_idle_total")
	metricActiveUpgrades     = expvar.NewInt("ngstoned_active_upgrades")

	metricPeerForwardedConns     = expvar.NewInt("ngstoned_peer_forwarded_conns_total")
	metricPeerForwardFailed      = expvar.NewInt("ngstoned_peer_forward_failed_total")
	metricPeerForwardStale       = expvar.NewInt("ngstoned_peer_forward_stale_total")
	metricPeerLookups            = expvar.NewInt("ngstoned_peer_lookups_total")
	metricPeerLookupErrors       = expvar.NewInt("ngstoned_peer_lookup_errors_total")
	metricPeerRejectedLookupCap  = expvar.NewInt("ngstoned_peer_rejected_lookup_cap_total")
	metricPeerRejectedForwardCap = expvar.NewInt("ngstoned_peer_rejected_forward_cap_total")
	metricPeerAcceptedConns      = expvar.NewInt("ngstoned_peer_accepted_conns_total")
	metricPeerVersionSkew        = expvar.NewInt("ngstoned_peer_version_skew_total")
	metricPeerRejectedAuth       = expvar.NewInt("ngstoned_peer_rejected_auth_total")
	metricPeerMisdirected        = expvar.NewInt("ngstoned_peer_misdirected_421_total")
	metricPeerApexRuleLookups    = expvar.NewInt("ngstoned_peer_apex_rule_lookups_total")
	metricActivePeerForwards     = expvar.NewInt("ngstoned_active_peer_forwards")
	metricPeerTCPForwarded       = expvar.NewInt("ngstoned_peer_tcp_forwarded_total")
	metricPeerControlForwarded   = expvar.NewInt("ngstoned_peer_control_forwarded_total")
	metricControlForwardFailed   = expvar.NewInt("ngstoned_peer_control_forward_failed_total")
	metricShareDirectoryErrors   = expvar.NewInt("ngstoned_share_directory_errors_total")
	metricPeerTCPBindFailed      = expvar.NewInt("ngstoned_peer_tcp_bind_failed_total")
	metricPeerTCPListeners       = expvar.NewInt("ngstoned_peer_tcp_listeners")

	metricAdminMTLSRejected = expvar.NewInt("ngstoned_admin_mtls_rejected_total")

	metricCustomDomainLookups           = expvar.NewInt("ngstoned_custom_domain_lookups_total")
	metricCustomDomainLookupErrors      = expvar.NewInt("ngstoned_custom_domain_lookup_errors_total")
	metricCustomDomainRejectedLookupCap = expvar.NewInt("ngstoned_custom_domain_rejected_lookup_cap_total")
	metricCustomDomainRateLimited       = expvar.NewInt("ngstoned_custom_domain_rejected_rate_limited_total")
	metricCustomDomainOwnerMismatch     = expvar.NewInt("ngstoned_custom_domain_owner_mismatch_total")
	metricCustomDomainLoginRejected     = expvar.NewInt("ngstoned_custom_domain_login_rejected_total")
)

type certStatusJSON struct {
	Domain   string `json:"domain"`
	NotAfter string `json:"not_after,omitempty"`
	Error    string `json:"error,omitempty"`
}

type healthzResponse struct {
	OK       bool           `json:"ok"`
	Apex     certStatusJSON `json:"apex_cert,omitempty"`
	Wildcard certStatusJSON `json:"wildcard_cert,omitempty"`
}

func (s *Server) opsMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/debug/vars", expvar.Handler())
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/api/state", s.handleProtectedDashboardState)
	mux.HandleFunc("/api/v1", s.handleAdminAPI)
	mux.HandleFunc("/api/v1/", s.handleAdminAPI)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/", s.handleDashboard)
	return mux
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	resp := s.healthzSnapshot(ctx)

	w.Header().Set("Content-Type", "application/json")
	if !resp.OK {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) healthzSnapshot(ctx context.Context) healthzResponse {
	resp := healthzResponse{OK: true}
	if s.tlsMgr == nil {
		return resp
	}

	apex, wildcard := s.tlsMgr.CertStatus(ctx)
	resp.Apex = certInfoJSON(apex)
	resp.Wildcard = certInfoJSON(wildcard)
	resp.OK = apex.Err == nil && wildcard.Err == nil
	return resp
}

func certInfoJSON(c CertInfo) certStatusJSON {
	out := certStatusJSON{Domain: c.Domain}
	if c.Err != nil {
		out.Error = c.Err.Error()
		return out
	}
	out.NotAfter = c.NotAfter.Format(time.RFC3339)
	return out
}
