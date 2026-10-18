package edge

import (
	"context"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ngstone/internal/adminapi"
	"ngstone/internal/storage"
)

const observabilityFlushInterval = 5 * time.Second

var latencyBucketBounds = []struct {
	Key   string
	Upper float64
	Limit time.Duration
}{
	{Key: "1", Upper: 1, Limit: time.Millisecond},
	{Key: "5", Upper: 5, Limit: 5 * time.Millisecond},
	{Key: "10", Upper: 10, Limit: 10 * time.Millisecond},
	{Key: "25", Upper: 25, Limit: 25 * time.Millisecond},
	{Key: "50", Upper: 50, Limit: 50 * time.Millisecond},
	{Key: "100", Upper: 100, Limit: 100 * time.Millisecond},
	{Key: "250", Upper: 250, Limit: 250 * time.Millisecond},
	{Key: "500", Upper: 500, Limit: 500 * time.Millisecond},
	{Key: "1000", Upper: 1000, Limit: time.Second},
	{Key: "2500", Upper: 2500, Limit: 2500 * time.Millisecond},
	{Key: "5000", Upper: 5000, Limit: 5 * time.Second},
	{Key: "10000", Upper: 10000, Limit: 10 * time.Second},
	{Key: "30000", Upper: 30000, Limit: 30 * time.Second},
	{Key: "+Inf", Upper: 30000, Limit: 0},
}

type observabilityRegistry struct {
	mu    sync.Mutex
	byKey map[string]storage.TunnelMetricDelta
}

func newObservabilityRegistry() *observabilityRegistry {
	return &observabilityRegistry{byKey: make(map[string]storage.TunnelMetricDelta)}
}

func metricKey(tunnelID, hostname string) string {
	if strings.TrimSpace(tunnelID) != "" {
		return "id:" + strings.TrimSpace(tunnelID)
	}
	return "host:" + strings.ToLower(strings.TrimSpace(hostname))
}

func (r *observabilityRegistry) metric(tunnelID, hostname string) storage.TunnelMetricDelta {
	key := metricKey(tunnelID, hostname)
	metric, ok := r.byKey[key]
	if !ok {
		metric = storage.TunnelMetricDelta{
			TunnelID:       strings.TrimSpace(tunnelID),
			Hostname:       strings.ToLower(strings.TrimSpace(hostname)),
			StatusCounts:   make(map[string]int64),
			LatencyBuckets: make(map[string]int64),
		}
	}
	return metric
}

func (r *observabilityRegistry) observeRequest(tunnelID, hostname string, status int, latency time.Duration, bytesIn, bytesOut int64) {
	if r == nil {
		return
	}
	if status == 0 {
		status = 200
	}
	if latency < 0 {
		latency = 0
	}
	if bytesIn < 0 {
		bytesIn = 0
	}
	if bytesOut < 0 {
		bytesOut = 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	metric := r.metric(tunnelID, hostname)
	metric.RequestCount++
	metric.BytesIn += bytesIn
	metric.BytesOut += bytesOut
	metric.StatusCounts[strconv.Itoa(status)]++
	metric.LatencyBuckets[latencyBucket(latency)]++
	r.byKey[metricKey(tunnelID, hostname)] = metric
}

func (r *observabilityRegistry) observeTCP(tunnelID, hostname string, latency time.Duration, bytesIn, bytesOut int64) {
	if r == nil {
		return
	}
	if latency < 0 {
		latency = 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	metric := r.metric(tunnelID, hostname)
	metric.RequestCount++
	metric.BytesIn += maxInt64(bytesIn, 0)
	metric.BytesOut += maxInt64(bytesOut, 0)
	metric.StatusCounts["tcp"]++
	metric.LatencyBuckets[latencyBucket(latency)]++
	r.byKey[metricKey(tunnelID, hostname)] = metric
}

func (r *observabilityRegistry) observeReconnect(tunnelID, hostname string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	metric := r.metric(tunnelID, hostname)
	metric.Reconnects++
	r.byKey[metricKey(tunnelID, hostname)] = metric
}

func (r *observabilityRegistry) observeCredentialEvent(tunnelID, hostname, event string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	metric := r.metric(tunnelID, hostname)
	switch event {
	case "credential_expired":
		metric.CredentialExpired++
	case "credential_revoked":
		metric.CredentialRevoked++
	default:
		return
	}
	r.byKey[metricKey(tunnelID, hostname)] = metric
}

func (r *observabilityRegistry) snapshot() []storage.TunnelMetricDelta {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return copyMetricDeltas(r.byKey)
}

func (r *observabilityRegistry) drain() []storage.TunnelMetricDelta {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	deltas := copyMetricDeltas(r.byKey)
	r.byKey = make(map[string]storage.TunnelMetricDelta)
	return deltas
}

func (r *observabilityRegistry) restore(deltas []storage.TunnelMetricDelta) {
	if r == nil || len(deltas) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, delta := range deltas {
		key := metricKey(delta.TunnelID, delta.Hostname)
		current := r.byKey[key]
		if current.TunnelID == "" {
			current.TunnelID = delta.TunnelID
			current.Hostname = delta.Hostname
			current.StatusCounts = make(map[string]int64)
			current.LatencyBuckets = make(map[string]int64)
		}
		mergeMetricDelta(&current, delta)
		r.byKey[key] = current
	}
}

func copyMetricDeltas(source map[string]storage.TunnelMetricDelta) []storage.TunnelMetricDelta {
	out := make([]storage.TunnelMetricDelta, 0, len(source))
	keys := make([]string, 0, len(source))
	for key := range source {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := source[key]
		value.StatusCounts = copyCounts(value.StatusCounts)
		value.LatencyBuckets = copyCounts(value.LatencyBuckets)
		out = append(out, value)
	}
	return out
}

func copyCounts(source map[string]int64) map[string]int64 {
	if len(source) == 0 {
		return make(map[string]int64)
	}
	out := make(map[string]int64, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

func mergeMetricDelta(target *storage.TunnelMetricDelta, delta storage.TunnelMetricDelta) {
	target.RequestCount += delta.RequestCount
	target.BytesIn += delta.BytesIn
	target.BytesOut += delta.BytesOut
	target.Reconnects += delta.Reconnects
	target.CredentialExpired += delta.CredentialExpired
	target.CredentialRevoked += delta.CredentialRevoked
	if target.StatusCounts == nil {
		target.StatusCounts = make(map[string]int64)
	}
	for key, value := range delta.StatusCounts {
		target.StatusCounts[key] += value
	}
	if target.LatencyBuckets == nil {
		target.LatencyBuckets = make(map[string]int64)
	}
	for key, value := range delta.LatencyBuckets {
		target.LatencyBuckets[key] += value
	}
}

func latencyBucket(value time.Duration) string {
	for _, bucket := range latencyBucketBounds {
		if bucket.Limit > 0 && value <= bucket.Limit {
			return bucket.Key
		}
	}
	return "+Inf"
}

func latencyPercentile(buckets map[string]int64, total int64, quantile float64) float64 {
	if total <= 0 {
		return 0
	}
	target := int64(math.Ceil(float64(total) * quantile))
	if target < 1 {
		target = 1
	}
	var seen int64
	for _, bucket := range latencyBucketBounds {
		seen += buckets[bucket.Key]
		if seen >= target {
			return bucket.Upper
		}
	}
	return latencyBucketBounds[len(latencyBucketBounds)-1].Upper
}

type observabilityAggregate struct {
	adminapi.TunnelObservability
	latencyBuckets map[string]int64
}

type observabilityTarget struct {
	TunnelID string
	Hostname string
}

func (s *Server) observabilityTargetsForSession(as *AgentSession) []observabilityTarget {
	if s == nil || as == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var targets []observabilityTarget
	if s.storage != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		tunnels, err := s.storage.ListTunnels(ctx)
		cancel()
		if err == nil {
			for _, tunnel := range tunnels {
				for _, connector := range tunnel.Connectors {
					if connector.SessionID != as.ID {
						continue
					}
					target := observabilityTarget{TunnelID: tunnel.ID, Hostname: tunnel.Hostname}
					key := metricKey(target.TunnelID, target.Hostname)
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					targets = append(targets, target)
				}
			}
		}
	}
	if len(targets) == 0 && s.registry != nil {
		for _, target := range s.registry.observabilityTargetsForSession(as) {
			key := metricKey(target.TunnelID, target.Hostname)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			targets = append(targets, target)
		}
	}
	if len(targets) == 0 && s.tcpMgr != nil {
		for _, target := range s.tcpMgr.observabilityTargetsForSession(as) {
			key := metricKey(target.TunnelID, target.Hostname)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			targets = append(targets, target)
		}
	}
	return targets
}

func (s *Server) emitAlert(eventType string, target observabilityTarget, metadata map[string]string) {
	if s == nil || s.alerts == nil {
		return
	}
	s.alerts.emit(alertEvent{Type: eventType, TunnelID: target.TunnelID, Hostname: target.Hostname, Metadata: metadata})
}

func (s *Server) recordCredentialEvent(as *AgentSession, eventType string) {
	if as == nil || !as.claimObservabilityEvent(eventType) {
		return
	}
	for _, target := range s.observabilityTargetsForSession(as) {
		s.observability.observeCredentialEvent(target.TunnelID, target.Hostname, eventType)
		s.emitAlert(eventType, target, map[string]string{"credential_id": as.Credential.ID})
	}
}

func (s *Server) recordCredentialEventForID(id, eventType string) {
	if s == nil || s.registry == nil {
		return
	}
	for _, as := range s.registry.sessionsForCredential(id) {
		s.recordCredentialEvent(as, eventType)
	}
}

func (s *Server) recordLeaseAcquired(as *AgentSession, lease storage.Lease) {
	if !lease.Reconnected {
		return
	}
	target := observabilityTarget{TunnelID: lease.TunnelID, Hostname: lease.Hostname}
	s.observability.observeReconnect(target.TunnelID, target.Hostname)
	s.emitAlert("connector_reconnected", target, map[string]string{"session_id": lease.SessionID, "instance_id": lease.InstanceID})
}

func (s *Server) recordSessionAlert(as *AgentSession, eventType string, metadata map[string]string) {
	for _, target := range s.observabilityTargetsForSession(as) {
		s.emitAlert(eventType, target, metadata)
	}
}

func (s *Server) observabilitySnapshot(ctx context.Context) []adminapi.TunnelObservability {
	aggregates := make(map[string]*observabilityAggregate)
	if s.storage != nil {
		if metrics, err := s.storage.ListTunnelMetrics(ctx); err == nil {
			for _, metric := range metrics {
				aggregate := observabilityAggregateFor(aggregates, metric.TunnelID, metric.Hostname)
				aggregate.TunnelID = metric.TunnelID
				aggregate.Hostname = metric.Hostname
				aggregate.RequestCount += metric.RequestCount
				aggregate.BytesIn += metric.BytesIn
				aggregate.BytesOut += metric.BytesOut
				aggregate.Reconnects += metric.Reconnects
				aggregate.CredentialExpired += metric.CredentialExpired
				aggregate.CredentialRevoked += metric.CredentialRevoked
				mergeCounts(aggregate.StatusCodes, metric.StatusCounts)
				mergeCounts(aggregate.latencyBuckets, metric.LatencyBuckets)
				if metric.UpdatedAt.After(aggregate.UpdatedAt) {
					aggregate.UpdatedAt = metric.UpdatedAt
				}
			}
		}
		if tunnels, err := s.storage.ListTunnels(ctx); err == nil {
			for _, tunnel := range tunnels {
				aggregate := observabilityAggregateFor(aggregates, tunnel.ID, tunnel.Hostname)
				aggregate.TunnelID = tunnel.ID
				aggregate.Name = tunnel.Name
				aggregate.Hostname = tunnel.Hostname
				aggregate.Kind = tunnel.Kind
				aggregate.Port = tunnel.RemotePort
				aggregate.OwnerID = tunnel.OwnerID
				aggregate.Status = tunnel.Status
				if tunnel.UpdatedAt.After(aggregate.UpdatedAt) {
					aggregate.UpdatedAt = tunnel.UpdatedAt
				}
				for _, connector := range tunnel.Connectors {
					if connector.ExpiresAt.After(time.Now()) {
						aggregate.ActiveConnectors++
					}
				}
			}
		}
	}
	for _, delta := range s.observability.snapshot() {
		aggregate := observabilityAggregateFor(aggregates, delta.TunnelID, delta.Hostname)
		aggregate.TunnelID = firstNonEmpty(aggregate.TunnelID, delta.TunnelID)
		aggregate.Hostname = firstNonEmpty(aggregate.Hostname, delta.Hostname)
		aggregate.RequestCount += delta.RequestCount
		aggregate.BytesIn += delta.BytesIn
		aggregate.BytesOut += delta.BytesOut
		aggregate.Reconnects += delta.Reconnects
		aggregate.CredentialExpired += delta.CredentialExpired
		aggregate.CredentialRevoked += delta.CredentialRevoked
		mergeCounts(aggregate.StatusCodes, delta.StatusCounts)
		mergeCounts(aggregate.latencyBuckets, delta.LatencyBuckets)
	}
	if s.storage == nil {
		for _, tunnel := range s.dashboardTunnels() {
			aggregate := observabilityAggregateFor(aggregates, tunnel.ID, tunnel.Hostname)
			aggregate.TunnelID = firstNonEmpty(aggregate.TunnelID, tunnel.ID)
			aggregate.Name = firstNonEmpty(aggregate.Name, tunnel.Name)
			aggregate.Hostname = firstNonEmpty(aggregate.Hostname, tunnel.Hostname)
			aggregate.Kind = firstNonEmpty(aggregate.Kind, tunnel.Kind)
			if aggregate.Port == 0 {
				aggregate.Port = tunnel.Port
			}
			aggregate.ActiveConnectors = 0
			for _, connector := range tunnel.Connectors {
				if connector.Alive && connector.Healthy {
					aggregate.ActiveConnectors++
				}
			}
		}
	}
	out := make([]adminapi.TunnelObservability, 0, len(aggregates))
	for _, aggregate := range aggregates {
		aggregate.LatencyP50MS = latencyPercentile(aggregate.latencyBuckets, aggregate.RequestCount, 0.50)
		aggregate.LatencyP95MS = latencyPercentile(aggregate.latencyBuckets, aggregate.RequestCount, 0.95)
		aggregate.LatencyP99MS = latencyPercentile(aggregate.latencyBuckets, aggregate.RequestCount, 0.99)
		aggregate.BytesTransferred = aggregate.BytesIn + aggregate.BytesOut
		out = append(out, aggregate.TunnelObservability)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hostname == out[j].Hostname {
			return out[i].Port < out[j].Port
		}
		return out[i].Hostname < out[j].Hostname
	})
	return out
}

func observabilityAggregateFor(aggregates map[string]*observabilityAggregate, tunnelID, hostname string) *observabilityAggregate {
	key := metricKey(tunnelID, hostname)
	if aggregate := aggregates[key]; aggregate != nil {
		return aggregate
	}
	aggregate := &observabilityAggregate{
		TunnelObservability: adminapi.TunnelObservability{
			TunnelID:    tunnelID,
			Hostname:    hostname,
			StatusCodes: make(map[string]int64),
		},
		latencyBuckets: make(map[string]int64),
	}
	aggregates[key] = aggregate
	return aggregate
}

func mergeCounts(target, source map[string]int64) {
	for key, value := range source {
		target[key] += value
	}
}

func firstNonEmpty(current, fallback string) string {
	if current != "" {
		return current
	}
	return fallback
}

func maxInt64(value, floor int64) int64 {
	if value < floor {
		return floor
	}
	return value
}

func (s *Server) flushObservability(ctx context.Context) {
	if s.storage == nil {
		return
	}
	deltas := s.observability.drain()
	if len(deltas) == 0 {
		return
	}
	var failed []storage.TunnelMetricDelta
	for _, delta := range deltas {
		if strings.TrimSpace(delta.TunnelID) == "" {
			continue
		}
		if err := s.storage.UpsertTunnelMetrics(ctx, delta); err != nil {
			failed = append(failed, delta)
		}
	}
	if len(failed) > 0 {
		s.observability.restore(failed)
	}
}

func (s *Server) observabilityLoop(ctx context.Context) error {
	ticker := time.NewTicker(observabilityFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			s.flushObservability(flushCtx)
			cancel()
			return nil
		case <-ticker.C:
			flushCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			s.flushObservability(flushCtx)
			cancel()
		}
	}
}
