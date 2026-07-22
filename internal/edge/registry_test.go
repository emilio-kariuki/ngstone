package edge

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

func newTestAgentSession(t *testing.T, instanceID string) (*AgentSession, func()) {
	t.Helper()
	c1, c2 := net.Pipe()

	type result struct {
		sess tunnel.Session
		err  error
	}
	clientCh := make(chan result, 1)
	serverCh := make(chan result, 1)
	go func() {
		s, err := tunnel.Client(c1)
		clientCh <- result{s, err}
	}()
	go func() {
		s, err := tunnel.Server(c2)
		serverCh <- result{s, err}
	}()

	cr := <-clientCh
	if cr.err != nil {
		t.Fatalf("client session: %v", cr.err)
	}
	sr := <-serverCh
	if sr.err != nil {
		t.Fatalf("server session: %v", sr.err)
	}

	as := &AgentSession{ID: randomHex(4), InstanceID: instanceID, Sess: sr.sess, IDGen: proto.NewEdgeIDGen()}
	cleanup := func() {
		cr.sess.Close("test done")
		sr.sess.Close("test done")
	}
	return as, cleanup
}

func waitDead(t *testing.T, as *AgentSession) {
	t.Helper()
	select {
	case <-as.Done():
	case <-time.After(2 * time.Second):
		t.Fatalf("session %s never became dead", as.ID)
	}
}

func TestBindRuleA_SameInstanceTakeoverSucceedsAgainstLiveHolder(t *testing.T) {
	r := NewRegistry()

	holder, holderCleanup := newTestAgentSession(t, "instance-a")
	defer holderCleanup()
	b, evicted, err := r.Bind("foo.example.com", holder, true)
	if err != nil {
		t.Fatalf("initial bind: %v", err)
	}
	if evicted != nil {
		t.Fatalf("unexpected eviction on first bind")
	}
	if b.Sess != holder {
		t.Fatalf("binding owner mismatch")
	}

	if isSessionDead(holder) {
		t.Fatalf("holder must still be live for this test")
	}

	reconnected, reconnectedCleanup := newTestAgentSession(t, "instance-a")
	defer reconnectedCleanup()

	b2, evicted2, err := r.Bind("foo.example.com", reconnected, true)
	if err != nil {
		t.Fatalf("takeover bind: %v", err)
	}
	if evicted2 != holder {
		t.Fatalf("expected holder to be evicted, got %v", evicted2)
	}
	if b2.Sess != reconnected {
		t.Fatalf("binding did not transfer to reconnected session")
	}

	got, ok := r.Route("foo.example.com")
	if !ok || got.Sess != reconnected {
		t.Fatalf("route does not reflect takeover: %+v ok=%v", got, ok)
	}
}

func TestBindRuleB_DeadHolderTakeoverSucceeds(t *testing.T) {
	r := NewRegistry()

	holder, holderCleanup := newTestAgentSession(t, "instance-a")
	defer holderCleanup()
	if _, _, err := r.Bind("foo.example.com", holder, true); err != nil {
		t.Fatalf("initial bind: %v", err)
	}

	holder.Sess.Close("simulate crash")
	waitDead(t, holder)

	newOwner, newOwnerCleanup := newTestAgentSession(t, "instance-b")
	defer newOwnerCleanup()

	b, evicted, err := r.Bind("foo.example.com", newOwner, true)
	if err != nil {
		t.Fatalf("takeover of dead holder failed: %v", err)
	}
	if evicted != holder {
		t.Fatalf("expected dead holder to be reported evicted, got %v", evicted)
	}
	if b.Sess != newOwner {
		t.Fatalf("binding did not transfer to new owner")
	}
}

func TestBindRuleC_DifferentInstanceLiveHolderSubdomainTaken(t *testing.T) {
	r := NewRegistry()

	holder, holderCleanup := newTestAgentSession(t, "instance-a")
	defer holderCleanup()
	if _, _, err := r.Bind("foo.example.com", holder, true); err != nil {
		t.Fatalf("initial bind: %v", err)
	}

	other, otherCleanup := newTestAgentSession(t, "instance-b")
	defer otherCleanup()

	_, _, err := r.Bind("foo.example.com", other, true)
	if !errors.Is(err, ErrSubdomainTaken) {
		t.Fatalf("got err %v, want ErrSubdomainTaken", err)
	}

	got, ok := r.Route("foo.example.com")
	if !ok || got.Sess != holder {
		t.Fatalf("original holder should remain bound after rejected takeover")
	}
}

func TestReleaseSessionAfterTakeoverDoesNotDeleteNewOwner(t *testing.T) {
	r := NewRegistry()

	victim, victimCleanup := newTestAgentSession(t, "instance-a")
	defer victimCleanup()
	if _, _, err := r.Bind("foo.example.com", victim, true); err != nil {
		t.Fatalf("initial bind: %v", err)
	}

	newOwner, newOwnerCleanup := newTestAgentSession(t, "instance-a")
	defer newOwnerCleanup()

	if _, _, err := r.Bind("foo.example.com", newOwner, true); err != nil {
		t.Fatalf("takeover bind: %v", err)
	}

	r.ReleaseSession(victim)

	got, ok := r.Route("foo.example.com")
	if !ok {
		t.Fatalf("ReleaseSession(victim) deleted the new owner's binding")
	}
	if got.Sess != newOwner {
		t.Fatalf("binding owner changed after releasing evicted session: %+v", got)
	}
}

func TestReleaseSessionIdempotent(t *testing.T) {
	r := NewRegistry()

	as, cleanup := newTestAgentSession(t, "instance-a")
	defer cleanup()
	if _, _, err := r.Bind("foo.example.com", as, true); err != nil {
		t.Fatalf("bind: %v", err)
	}

	r.ReleaseSession(as)
	if _, ok := r.Route("foo.example.com"); ok {
		t.Fatalf("expected binding gone after ReleaseSession")
	}

	r.ReleaseSession(as)
	r.ReleaseSession(as)
}

func TestUnbindCompareAndDelete(t *testing.T) {
	r := NewRegistry()

	as, cleanup := newTestAgentSession(t, "instance-a")
	defer cleanup()
	if _, _, err := r.Bind("foo.example.com", as, true); err != nil {
		t.Fatalf("bind: %v", err)
	}

	other, otherCleanup := newTestAgentSession(t, "instance-b")
	defer otherCleanup()

	if r.Unbind("foo.example.com", other) {
		t.Fatalf("Unbind succeeded for a session that does not own the host")
	}
	if !r.Unbind("foo.example.com", as) {
		t.Fatalf("Unbind failed for the actual owner")
	}
	if _, ok := r.Route("foo.example.com"); ok {
		t.Fatalf("binding still present after Unbind")
	}
}

func TestAssignRandomHostnameRetriesOnCollision(t *testing.T) {
	r := NewRegistry()

	holder, holderCleanup := newTestAgentSession(t, "instance-a")
	defer holderCleanup()
	if _, _, err := r.Bind("taken.example.com", holder, true); err != nil {
		t.Fatalf("pre-bind: %v", err)
	}

	requester, requesterCleanup := newTestAgentSession(t, "instance-b")
	defer requesterCleanup()

	names := []string{"taken", "taken", "free"}
	i := 0
	gen := func() string {
		n := names[i]
		if i < len(names)-1 {
			i++
		}
		return n
	}

	hostname, evicted, err := assignRandomHostname(r, requester, false, "example.com", gen)
	if err != nil {
		t.Fatalf("assignRandomHostname: %v", err)
	}
	if hostname != "free.example.com" {
		t.Fatalf("got hostname %q, want %q", hostname, "free.example.com")
	}
	if evicted != nil {
		t.Fatalf("unexpected eviction")
	}
	if i < 2 {
		t.Fatalf("expected at least 2 collisions to be tried, only tried %d", i)
	}
}

func TestRandomSubdomainFormat(t *testing.T) {
	for i := 0; i < 200; i++ {
		name := randomSubdomain()
		if !subdomainRE.MatchString(name) {
			t.Fatalf("randomSubdomain() = %q does not match subdomain regex", name)
		}
	}
}

func TestValidSubdomain(t *testing.T) {
	valid := []string{"a", "foo", "foo-bar", "foo123", "a-b-c-1-2-3"}
	for _, v := range valid {
		if !validSubdomain(v) {
			t.Fatalf("validSubdomain(%q) = false, want true", v)
		}
	}
	invalid := []string{"", "-foo", "foo-", "Foo", "foo_bar", "foo.bar", "www", "mail", "ns1", "ns2", "admin", "dev", "api-edge"}
	for _, v := range invalid {
		if validSubdomain(v) {
			t.Fatalf("validSubdomain(%q) = true, want false", v)
		}
	}
}

func TestRegistryConcurrentBindRouteRelease(t *testing.T) {
	r := NewRegistry()

	const n = 20
	sessions := make([]*AgentSession, n)
	cleanups := make([]func(), n)
	for i := 0; i < n; i++ {
		sessions[i], cleanups[i] = newTestAgentSession(t, randomHex(4))
	}
	defer func() {
		for _, c := range cleanups {
			c()
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(3)
		as := sessions[i]
		host := "host" + string(rune('a'+i)) + ".example.com"
		go func() {
			defer wg.Done()
			r.Bind(host, as, true)
		}()
		go func() {
			defer wg.Done()
			r.Route(host)
		}()
		go func() {
			defer wg.Done()
			r.ReleaseSession(as)
		}()
	}
	wg.Wait()
}

func TestReleaseSessionCompareAndDeleteAgainstDirectlyConstructedStaleState(t *testing.T) {
	r := NewRegistry()

	victim, victimCleanup := newTestAgentSession(t, "instance-a")
	defer victimCleanup()
	winner, winnerCleanup := newTestAgentSession(t, "instance-a")
	defer winnerCleanup()

	r.byHost["foo.example.com"] = &Binding{
		Hostname:   "foo.example.com",
		Sess:       winner,
		InstanceID: winner.InstanceID,
		BoundAt:    time.Now(),
	}
	r.bySession[victim] = map[string]struct{}{"foo.example.com": {}}

	r.ReleaseSession(victim)

	got, ok := r.Route("foo.example.com")
	if !ok {
		t.Fatalf("ReleaseSession(victim) deleted the winner's binding even though byHost still pointed at winner — the compare-and-delete guard in ReleaseSession is not doing its job")
	}
	if got.Sess != winner {
		t.Fatalf("winner's binding was replaced: got %+v", got)
	}
}

func TestBindRuleA_SameInstanceSucceedsAgainstLiveHolderEvenWithTakeoverFalse(t *testing.T) {
	r := NewRegistry()

	holder, holderCleanup := newTestAgentSession(t, "instance-a")
	defer holderCleanup()
	if _, _, err := r.Bind("foo.example.com", holder, true); err != nil {
		t.Fatalf("initial bind: %v", err)
	}

	if isSessionDead(holder) {
		t.Fatalf("holder must still be live for this test")
	}

	reconnected, reconnectedCleanup := newTestAgentSession(t, "instance-a")
	defer reconnectedCleanup()

	b, evicted, err := r.Bind("foo.example.com", reconnected, false)
	if err != nil {
		t.Fatalf("same-instance rebind against a live holder must succeed even with takeover=false, got err: %v", err)
	}
	if evicted != holder {
		t.Fatalf("expected holder to be evicted, got %v", evicted)
	}
	if b.Sess != reconnected {
		t.Fatalf("binding did not transfer to reconnected session")
	}

	got, ok := r.Route("foo.example.com")
	if !ok || got.Sess != reconnected {
		t.Fatalf("route does not reflect takeover: %+v ok=%v", got, ok)
	}
}
