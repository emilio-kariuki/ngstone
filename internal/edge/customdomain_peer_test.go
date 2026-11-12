package edge

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"ngstone/internal/credentials"
	"ngstone/internal/storage"
)

func (e *peerEdge) bindTLSAs(t *testing.T, host, leaseOwner, sessionOwner string) string {
	t.Helper()
	e.fx.as.Credential = &credentials.Credential{ID: "cred-" + sessionOwner, OwnerID: sessionOwner}
	if _, _, err := e.srv.registry.BindWithOptions(BindOptions{Host: host, Session: e.fx.as, TLS: true}); err != nil {
		t.Fatalf("bind tls %s: %v", host, err)
	}
	return e.leaseFor(t, host, leaseOwner)
}

func (e *peerEdge) leaseFor(t *testing.T, host, owner string) string {
	t.Helper()
	lease, err := e.store.AcquireLease(context.Background(), storage.LeaseRequest{
		Hostname:   host,
		Kind:       "tls",
		EdgeID:     e.id,
		OwnerID:    owner,
		InstanceID: "inst-" + e.id,
		SessionID:  "sess-" + e.id + "-" + host,
		ExpiresAt:  time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("acquire lease %s on %s: %v", host, e.id, err)
	}
	return lease.TunnelID
}

func activateDomainFor(t *testing.T, store *storage.Store, domain, tunnelID, owner string) {
	t.Helper()
	created, err := store.CreateCustomDomain(context.Background(), storage.CustomDomainSpec{Domain: domain, OwnerID: owner, TunnelID: tunnelID})
	if err != nil {
		t.Fatalf("create domain %s: %v", domain, err)
	}
	if _, err := store.SetCustomDomainStatus(context.Background(), created.ID, "active"); err != nil {
		t.Fatalf("activate domain %s: %v", domain, err)
	}
}

func newCustomDomainCluster(t *testing.T, names ...string) *peerCluster {
	t.Helper()
	pc := newPeerCluster(t)
	pc.cert, pc.pool = passthroughTestCert(t, names...)
	return pc
}

func TestClassifyForwardsCustomDomainToOwner(t *testing.T) {
	pc := newCustomDomainCluster(t, "tls.example.org")
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	tunnelID := b.bindTLSAs(t, peerTestHost, "owner", "owner")
	activateDomainFor(t, b.store, "tls.example.org", tunnelID, "owner")
	forwarded := metricDelta(metricPeerForwardedConns)

	tc, err := dialIngress(t, a, "tls.example.org", pc.pool)
	if err != nil {
		t.Fatalf("handshake through the other edge: %v", err)
	}
	pingEcho(t, tc)
	if b.agentHit.Load() != 1 || a.agentHit.Load() != 0 || forwarded() != 1 {
		t.Fatalf("agentHit b=%d a=%d forwarded=%d, want 1, 0, 1", b.agentHit.Load(), a.agentHit.Load(), forwarded())
	}
	if pre := b.lastPre.Load(); pre == nil || pre.Host != peerTestHost || pre.Kind != "tls" {
		t.Fatalf("agent preamble = %+v, want the canonical host", pre)
	}
}

func TestClassifyForwardedCustomDomainNotOwnerWhenUnbound(t *testing.T) {
	pc := newCustomDomainCluster(t, "tls.example.org")
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	tunnelID := a.leaseFor(t, peerTestHost, "owner")
	activateDomainFor(t, a.store, "tls.example.org", tunnelID, "owner")

	tc, err := dialPeerTLS(t, a.srv.peers.clientTLS(b.pin()), b.peerAddr())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	sendForwarded(t, tc, "203.0.113.9:4000", helloFor(t, "tls.example.org"))
	mustPeerStatus(t, tc, peerStatusNotOwner)
	expectClosed(t, tc)
	if b.agentHit.Load() != 0 {
		t.Fatal("an unbound custom domain reached the agent")
	}
}

func TestClassifyForwardedCustomDomainRefusesOwnerMismatch(t *testing.T) {
	pc := newCustomDomainCluster(t, "tls.example.org")
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	tunnelID := b.bindTLSAs(t, peerTestHost, "owner", "mallory")
	activateDomainFor(t, b.store, "tls.example.org", tunnelID, "owner")
	mismatch := metricDelta(metricCustomDomainOwnerMismatch)

	tc, err := dialPeerTLS(t, a.srv.peers.clientTLS(b.pin()), b.peerAddr())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	sendForwarded(t, tc, "203.0.113.9:4000", helloFor(t, "tls.example.org"))
	mustPeerStatus(t, tc, peerStatusNotOwner)
	expectClosed(t, tc)
	if b.agentHit.Load() != 0 || mismatch() != 1 {
		t.Fatalf("agentHit=%d mismatch=%d, want 0, 1", b.agentHit.Load(), mismatch())
	}
}

func TestCustomDomainFloodDoesNotQueryOwners(t *testing.T) {
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	b.bindTLS(t, peerTestHost)
	ownerLookups := metricDelta(metricPeerLookups)
	customLookups := metricDelta(metricCustomDomainLookups)
	limited := metricDelta(metricCustomDomainRateLimited)
	started := time.Now()

	const flood = 500
	for i := 0; i < flood; i++ {
		sendRawHello(t, a.addr, captureClientHello(t, &tls.Config{ServerName: fmt.Sprintf("rnd-%d.example.org", i), InsecureSkipVerify: true}))
	}
	peerEventually(t, "every flood connection to be classified", func() bool {
		return customLookups()+limited() >= flood
	})
	if got := ownerLookups(); got != 0 {
		t.Fatalf("owner lookups = %d, want 0", got)
	}
	bound := int64(aliasLimiterBurst) + int64(time.Since(started).Seconds()*aliasLimiterRate) + 1
	if got := customLookups(); got > bound {
		t.Fatalf("custom domain lookups = %d, want at most %d", got, bound)
	}
}
