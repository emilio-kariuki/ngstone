package edge

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

const testConnectorTokenDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestMultiConnectorRoutesRequestsAcrossHealthyConnectors(t *testing.T) {
	var countA atomic.Int64
	var countB atomic.Int64
	s := newServerForTest(LimitsConfig{PerIPRate: 1e6, PerIPBurst: 100})
	a := newFakeAgentSession(t, "instance-a", func(w http.ResponseWriter, r *http.Request) {
		countA.Add(1)
		io.WriteString(w, "connector-a")
	})
	b := newFakeAgentSession(t, "instance-b", func(w http.ResponseWriter, r *http.Request) {
		countB.Add(1)
		io.WriteString(w, "connector-b")
	})

	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "svc.example.com", Session: a, Takeover: true, MultiConnector: true, ConnectorTokenDigest: testConnectorTokenDigest}); err != nil {
		t.Fatalf("bind connector a: %v", err)
	}
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "svc.example.com", Session: b, Takeover: true, MultiConnector: true, ConnectorTokenDigest: testConnectorTokenDigest}); err != nil {
		t.Fatalf("bind connector b: %v", err)
	}

	for i := 0; i < 8; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/", nil)
		req.Host = "svc.example.com"
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		s.handlePublic(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d got %d, want 200: %s", i+1, rec.Code, rec.Body.String())
		}
	}

	if countA.Load() == 0 || countB.Load() == 0 {
		t.Fatalf("requests were not distributed across both connectors: a=%d b=%d", countA.Load(), countB.Load())
	}
}

func TestMultiConnectorSkipsUnhealthyConnector(t *testing.T) {
	var staleCount atomic.Int64
	var healthyCount atomic.Int64
	s := newServerForTest(LimitsConfig{PerIPRate: 1e6, PerIPBurst: 100})
	stale := newFakeAgentSession(t, "stale", func(w http.ResponseWriter, r *http.Request) {
		staleCount.Add(1)
		io.WriteString(w, "stale")
	})
	healthy := newFakeAgentSession(t, "healthy", func(w http.ResponseWriter, r *http.Request) {
		healthyCount.Add(1)
		io.WriteString(w, "healthy")
	})
	stale.lastHeartbeat.Store(time.Now().Add(-time.Hour).UnixNano())

	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "svc.example.com", Session: stale, Takeover: true, MultiConnector: true, ConnectorTokenDigest: testConnectorTokenDigest}); err != nil {
		t.Fatalf("bind stale connector: %v", err)
	}
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "svc.example.com", Session: healthy, Takeover: true, MultiConnector: true, ConnectorTokenDigest: testConnectorTokenDigest}); err != nil {
		t.Fatalf("bind healthy connector: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/", nil)
	req.Host = "svc.example.com"
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	s.handlePublic(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "healthy" {
		t.Fatalf("request got status %d body %q, want healthy connector", rec.Code, rec.Body.String())
	}
	if staleCount.Load() != 0 || healthyCount.Load() != 1 {
		t.Fatalf("connector counts = stale=%d healthy=%d", staleCount.Load(), healthyCount.Load())
	}
}

func TestMultiConnectorRejectsMismatchedSettings(t *testing.T) {
	r := NewRegistry()
	a, cleanupA := newTestAgentSession(t, "instance-a")
	defer cleanupA()
	b, cleanupB := newTestAgentSession(t, "instance-b")
	defer cleanupB()

	if _, _, err := r.BindWithOptions(BindOptions{Host: "svc.example.com", Session: a, Takeover: true, MultiConnector: true, ConnectorTokenDigest: testConnectorTokenDigest}); err != nil {
		t.Fatalf("initial bind: %v", err)
	}
	if _, _, err := r.BindWithOptions(BindOptions{Host: "svc.example.com", Session: b, Takeover: true, MultiConnector: true}); err != ErrConnectorTokenRequired {
		t.Fatalf("missing connector token error = %v, want %v", err, ErrConnectorTokenRequired)
	}
	if _, _, err := r.BindWithOptions(BindOptions{Host: "svc.example.com", Session: b, Takeover: true, MultiConnector: true, ConnectorTokenDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}); err != ErrConnectorConfigMismatch {
		t.Fatalf("connector token mismatch error = %v, want %v", err, ErrConnectorConfigMismatch)
	}
	if _, _, err := r.BindWithOptions(BindOptions{Host: "svc.example.com", Session: b, Takeover: true, HTTP2: true, MultiConnector: true, ConnectorTokenDigest: testConnectorTokenDigest}); err != ErrConnectorConfigMismatch {
		t.Fatalf("HTTP/2 mismatch error = %v, want %v", err, ErrConnectorConfigMismatch)
	}
	if _, _, err := r.BindWithOptions(BindOptions{Host: "svc.example.com", Session: b, Takeover: true, Access: &accessControl{realm: "other"}, MultiConnector: true, ConnectorTokenDigest: testConnectorTokenDigest}); err != ErrConnectorConfigMismatch {
		t.Fatalf("access mismatch error = %v, want %v", err, ErrConnectorConfigMismatch)
	}
	if got, ok := r.Route("svc.example.com"); !ok || !gotOkWithConnectorCount(got, 1) {
		t.Fatalf("mismatched connector changed the existing pool: %+v", got)
	}
}

func TestMultiConnectorReconnectReplacesOnlyItsOwnConnector(t *testing.T) {
	r := NewRegistry()
	a, cleanupA := newTestAgentSession(t, "instance-a")
	defer cleanupA()
	b, cleanupB := newTestAgentSession(t, "instance-b")
	defer cleanupB()
	a2, cleanupA2 := newTestAgentSession(t, "instance-a")
	defer cleanupA2()

	if _, _, err := r.BindWithOptions(BindOptions{Host: "svc.example.com", Session: a, Takeover: true, MultiConnector: true, ConnectorTokenDigest: testConnectorTokenDigest}); err != nil {
		t.Fatalf("bind connector a: %v", err)
	}
	if _, _, err := r.BindWithOptions(BindOptions{Host: "svc.example.com", Session: b, Takeover: true, MultiConnector: true, ConnectorTokenDigest: testConnectorTokenDigest}); err != nil {
		t.Fatalf("bind connector b: %v", err)
	}
	bound, evicted, err := r.BindWithOptions(BindOptions{Host: "svc.example.com", Session: a2, Takeover: true, MultiConnector: true, ConnectorTokenDigest: testConnectorTokenDigest})
	if err != nil {
		t.Fatalf("reconnect connector a: %v", err)
	}
	if evicted != a {
		t.Fatalf("reconnect evicted %v, want old connector %v", evicted, a)
	}
	if !gotOkWithConnectorCount(bound, 2) {
		t.Fatalf("reconnect dropped a peer connector: %+v", bound)
	}
	if got, ok := r.Route("svc.example.com"); !ok || got != bound {
		t.Fatalf("route changed after connector reconnect: got=%p want=%p ok=%v", got, bound, ok)
	}
}

func TestMultiConnectorReleaseDrainsOnlyRemovedConnector(t *testing.T) {
	r := NewRegistry()
	started := make(chan struct{})
	release := make(chan struct{})
	a := newFakeAgentSession(t, "instance-a", func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		io.WriteString(w, "drained")
	})
	b := newFakeAgentSession(t, "instance-b", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "peer")
	})

	if _, _, err := r.BindWithOptions(BindOptions{Host: "svc.example.com", Session: a, Takeover: true, MultiConnector: true, ConnectorTokenDigest: testConnectorTokenDigest}); err != nil {
		t.Fatalf("bind connector a: %v", err)
	}
	if _, _, err := r.BindWithOptions(BindOptions{Host: "svc.example.com", Session: b, Takeover: true, MultiConnector: true, ConnectorTokenDigest: testConnectorTokenDigest}); err != nil {
		t.Fatalf("bind connector b: %v", err)
	}

	result := make(chan int, 1)
	go func() {
		req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/", nil)
		req.Host = "svc.example.com"
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		s := &Server{registry: r, globalSem: newGlobalSemaphore(10), upgradeSem: newGlobalSemaphore(10), perIPLimiter: newPerIPLimiter(1e6, 100, 10)}
		s.handlePublic(rec, req)
		result <- rec.Code
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("connector a never received the request")
	}
	r.ReleaseSession(a)
	if got, ok := r.Route("svc.example.com"); !ok || !gotOkWithConnectorCount(got, 1) {
		count := 0
		if got != nil {
			count = got.connectorCount()
		}
		t.Fatalf("removing connector a removed the peer: route=%p ok=%v count=%d", got, ok, count)
	}
	close(release)
	select {
	case code := <-result:
		if code != http.StatusOK {
			t.Fatalf("draining request got %d, want 200", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("draining request did not finish")
	}

	r.ReleaseSession(b)
	if _, ok := r.Route("svc.example.com"); ok {
		t.Fatal("last connector release left the tunnel route registered")
	}
}

func gotOkWithConnectorCount(b *Binding, count int) bool {
	return b != nil && b.connectorCount() == count
}
