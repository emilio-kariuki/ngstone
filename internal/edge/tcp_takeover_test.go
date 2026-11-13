package edge

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"ngstone/internal/credentials"
	"ngstone/internal/proto"
	"ngstone/internal/storage"
)

func tagEchoHandler(tag string) func(net.Conn, proto.StreamOpen) {
	return func(conn net.Conn, _ proto.StreamOpen) {
		defer conn.Close()
		if _, err := io.WriteString(conn, tag+"\n"); err != nil {
			return
		}
		io.Copy(conn, conn)
	}
}

func dialOwner(t *testing.T, port int) (string, net.Conn, *bufio.Reader) {
	t.Helper()
	c := dialPort(t, port)
	c.SetDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil {
		c.Close()
		t.Fatalf("read owner tag on port %d: %v", port, err)
	}
	return line[:len(line)-1], c, r
}

func expectOwner(t *testing.T, port int, want string) {
	t.Helper()
	got, c, r := dialOwner(t, port)
	defer c.Close()
	if got != want {
		t.Fatalf("port %d answered by %q, want %q", port, got, want)
	}
	echoOnce(t, c, r, "ping")
}

func echoOnce(t *testing.T, c net.Conn, r *bufio.Reader, msg string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

func newTakeoverManager(t *testing.T) *tcpManager {
	t.Helper()
	return newTCPManager(20000, 20009, "127.0.0.1", nil)
}

func assertOwnedBy(t *testing.T, mgr *tcpManager, port int, owner, former *AgentSession) {
	t.Helper()
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	tt, ok := mgr.byPort[port]
	if !ok {
		t.Fatalf("port %d not bound", port)
	}
	if tt.session != owner {
		t.Fatalf("port %d owned by session %s, want %s", port, tt.session.ID, owner.ID)
	}
	if _, ok := mgr.bySession[owner][port]; !ok {
		t.Fatalf("bySession[new owner] missing port %d", port)
	}
	if _, ok := mgr.bySession[former][port]; ok {
		t.Fatalf("bySession[former owner] still lists port %d", port)
	}
	if _, ok := mgr.allocated[port]; !ok {
		t.Fatalf("port %d no longer marked allocated", port)
	}
}

func releaseAll(mgr *tcpManager, peers ...*tcpPeer) {
	for _, p := range peers {
		mgr.releaseSession(p.as)
	}
	for _, p := range peers {
		p.close()
	}
}

func inflightCount(as *AgentSession) int {
	as.inflight.mu.Lock()
	defer as.inflight.mu.Unlock()
	return as.inflight.n
}

func tunnelFor(t *testing.T, mgr *tcpManager, port int) *tcpTunnel {
	t.Helper()
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	tt := mgr.byPort[port]
	if tt == nil {
		t.Fatalf("port %d not bound", port)
	}
	return tt
}

func bindTCPVia(t *testing.T, s *Server, peer *tcpPeer, id uint64, b proto.Bind) proto.Msg {
	t.Helper()
	handled := make(chan struct{})
	go func() {
		s.handleBindTCP(peer.as, peer.as.Sess.Control(), id, b)
		close(handled)
	}()
	peer.agent.Control().SetReadDeadline(time.Now().Add(3 * time.Second))
	reply, err := peer.agent.Control().Read()
	if err != nil {
		t.Fatalf("read bind reply: %v", err)
	}
	<-handled
	return reply
}

func TestTCPTakeoverSameInstanceTransfersLivePort(t *testing.T) {
	mgr := newTakeoverManager(t)
	oldPeer := newTCPPeer(t, "inst-x", tagEchoHandler("old"))
	newPeer := newTCPPeer(t, "inst-x", tagEchoHandler("new"))
	defer releaseAll(mgr, oldPeer, newPeer)

	port, _, err := mgr.bind(oldPeer.as, 0, "example.com", nil, true)
	if err != nil {
		t.Fatalf("old bind: %v", err)
	}
	expectOwner(t, port, "old")

	tag, before, beforeR := dialOwner(t, port)
	defer before.Close()
	if tag != "old" {
		t.Fatalf("pre-takeover conn answered by %q, want old", tag)
	}

	got, evicted, err := mgr.bind(newPeer.as, port, "example.com", nil, true)
	if err != nil {
		t.Fatalf("same-instance takeover of a live holder: %v", err)
	}
	if got != port {
		t.Fatalf("takeover port = %d, want %d", got, port)
	}
	if evicted != oldPeer.as {
		t.Fatalf("evicted = %v, want the old session", evicted)
	}
	if isSessionDead(oldPeer.as) {
		t.Fatal("test precondition: old session must still look alive at takeover time")
	}
	assertOwnedBy(t, mgr, port, newPeer.as, oldPeer.as)

	expectOwner(t, port, "new")
	echoOnce(t, before, beforeR, "still-old")

	mgr.mu.Lock()
	oldConns := len(mgr.conns[oldPeer.as])
	mgr.mu.Unlock()
	if oldConns != 1 {
		t.Fatalf("old session conns = %d, want 1 (the pre-takeover connection)", oldConns)
	}
}

func TestTCPTakeoverSameInstanceIgnoresTakeoverFlag(t *testing.T) {
	mgr := newTakeoverManager(t)
	oldPeer := newTCPPeer(t, "inst-x", tagEchoHandler("old"))
	newPeer := newTCPPeer(t, "inst-x", tagEchoHandler("new"))
	defer releaseAll(mgr, oldPeer, newPeer)

	port, _, err := mgr.bind(oldPeer.as, 0, "example.com", nil, false)
	if err != nil {
		t.Fatalf("old bind: %v", err)
	}
	if _, evicted, err := mgr.bind(newPeer.as, port, "example.com", nil, false); err != nil || evicted != oldPeer.as {
		t.Fatalf("same-instance rebind with takeover=false: evicted=%v err=%v, want old session and nil", evicted, err)
	}
	expectOwner(t, port, "new")
}

func TestTCPTakeoverDifferentInstanceLiveHolderRejected(t *testing.T) {
	mgr := newTakeoverManager(t)
	holder := newTCPPeer(t, "inst-a", tagEchoHandler("holder"))
	requester := newTCPPeer(t, "inst-b", tagEchoHandler("requester"))
	defer releaseAll(mgr, holder, requester)

	port, _, err := mgr.bind(holder.as, 0, "example.com", nil, true)
	if err != nil {
		t.Fatalf("holder bind: %v", err)
	}
	if _, evicted, err := mgr.bind(requester.as, port, "example.com", nil, true); err != errPortUnavailable || evicted != nil {
		t.Fatalf("different instance vs live holder: evicted=%v err=%v, want nil and errPortUnavailable", evicted, err)
	}
	assertOwnedBy(t, mgr, port, holder.as, requester.as)
	expectOwner(t, port, "holder")
}

func TestTCPTakeoverDifferentInstanceDeadHolder(t *testing.T) {
	for _, tc := range []struct {
		name     string
		takeover bool
	}{
		{"with takeover succeeds", true},
		{"without takeover is rejected", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr := newTakeoverManager(t)
			holder := newTCPPeer(t, "inst-a", tagEchoHandler("holder"))
			requester := newTCPPeer(t, "inst-b", tagEchoHandler("requester"))
			defer releaseAll(mgr, holder, requester)

			port, _, err := mgr.bind(holder.as, 0, "example.com", nil, true)
			if err != nil {
				t.Fatalf("holder bind: %v", err)
			}
			holder.close()
			waitDead(t, holder.as)

			got, evicted, err := mgr.bind(requester.as, port, "example.com", nil, tc.takeover)
			if !tc.takeover {
				if err != errPortUnavailable || evicted != nil {
					t.Fatalf("dead holder without takeover: evicted=%v err=%v, want nil and errPortUnavailable", evicted, err)
				}
				assertOwnedBy(t, mgr, port, holder.as, requester.as)
				return
			}
			if err != nil {
				t.Fatalf("dead holder with takeover: %v", err)
			}
			if got != port || evicted != holder.as {
				t.Fatalf("got port %d evicted %v, want port %d and the dead holder", got, evicted, port)
			}
			assertOwnedBy(t, mgr, port, requester.as, holder.as)
			expectOwner(t, port, "requester")
		})
	}
}

func TestTCPTakeoverEmptyInstanceIDsMatchLikeHTTP(t *testing.T) {
	for _, takeover := range []bool{false, true} {
		t.Run("takeover="+strconv.FormatBool(takeover), func(t *testing.T) {
			mgr := newTakeoverManager(t)
			holder := newTCPPeer(t, "", tagEchoHandler("holder"))
			requester := newTCPPeer(t, "", tagEchoHandler("requester"))
			defer releaseAll(mgr, holder, requester)

			port, _, err := mgr.bind(holder.as, 0, "example.com", nil, true)
			if err != nil {
				t.Fatalf("holder bind: %v", err)
			}
			if _, evicted, err := mgr.bind(requester.as, port, "example.com", nil, takeover); err != nil || evicted != holder.as {
				t.Fatalf("empty InstanceIDs: evicted=%v err=%v, want the holder and nil", evicted, err)
			}
			assertOwnedBy(t, mgr, port, requester.as, holder.as)
			expectOwner(t, port, "requester")
		})
	}
}

func TestTCPTakeoverDifferentOwnerSameInstanceRejected(t *testing.T) {
	mgr := newTakeoverManager(t)
	holder := newTCPPeer(t, "inst-x", tagEchoHandler("holder"))
	requester := newTCPPeer(t, "inst-x", tagEchoHandler("requester"))
	holder.as.Credential = &credentials.Credential{ID: "cred-a", Kind: credentials.KindTCP, OwnerID: "alice"}
	requester.as.Credential = &credentials.Credential{ID: "cred-b", Kind: credentials.KindTCP, OwnerID: "bob"}
	defer releaseAll(mgr, holder, requester)

	port, _, err := mgr.bind(holder.as, 0, "example.com", nil, true)
	if err != nil {
		t.Fatalf("holder bind: %v", err)
	}
	if _, evicted, err := mgr.bind(requester.as, port, "example.com", nil, true); err != errPortUnavailable || evicted != nil {
		t.Fatalf("different owner, same instance: evicted=%v err=%v, want nil and errPortUnavailable", evicted, err)
	}
	assertOwnedBy(t, mgr, port, holder.as, requester.as)
	expectOwner(t, port, "holder")
}

func TestTCPTakeoverResetsBoundAt(t *testing.T) {
	mgr := newTakeoverManager(t)
	oldPeer := newTCPPeer(t, "inst-x", tagEchoHandler("old"))
	newPeer := newTCPPeer(t, "inst-x", tagEchoHandler("new"))
	defer releaseAll(mgr, oldPeer, newPeer)

	port, _, err := mgr.bind(oldPeer.as, 0, "example.com", nil, true)
	if err != nil {
		t.Fatalf("old bind: %v", err)
	}
	stale := time.Now().Add(-time.Hour)
	mgr.mu.Lock()
	mgr.byPort[port].boundAt = stale
	mgr.mu.Unlock()

	before := time.Now()
	if _, _, err := mgr.bind(newPeer.as, port, "example.com", nil, true); err != nil {
		t.Fatalf("takeover: %v", err)
	}
	mgr.mu.Lock()
	boundAt := mgr.byPort[port].boundAt
	mgr.mu.Unlock()
	if boundAt.Before(before) {
		t.Fatalf("boundAt = %v after takeover, want a time not before %v", boundAt, before)
	}
}

func TestTCPTakeoverAtBindCapRejected(t *testing.T) {
	mgr := newTakeoverManager(t)
	holder := newTCPPeer(t, "inst-x", tagEchoHandler("holder"))
	requester := newTCPPeer(t, "inst-x", tagEchoHandler("requester"))
	defer releaseAll(mgr, holder, requester)

	port, _, err := mgr.bind(holder.as, 0, "example.com", nil, true)
	if err != nil {
		t.Fatalf("holder bind: %v", err)
	}
	for i := 0; i < maxBindsPerSession; i++ {
		if _, _, err := mgr.bind(requester.as, 0, "example.com", nil, true); err != nil {
			t.Fatalf("requester fill bind %d: %v", i, err)
		}
	}
	if _, evicted, err := mgr.bind(requester.as, port, "example.com", nil, true); err != errTooManyBinds || evicted != nil {
		t.Fatalf("takeover at the bind cap: evicted=%v err=%v, want nil and errTooManyBinds", evicted, err)
	}
	assertOwnedBy(t, mgr, port, holder.as, requester.as)
	mgr.mu.Lock()
	held := len(mgr.bySession[requester.as])
	mgr.mu.Unlock()
	if held != maxBindsPerSession {
		t.Fatalf("requester holds %d ports, want %d", held, maxBindsPerSession)
	}
	expectOwner(t, port, "holder")
}

func TestTCPRebindSameSessionIsIdempotentAndUpdatesAllow(t *testing.T) {
	mgr := newTakeoverManager(t)
	peer := newTCPPeer(t, "inst-x", tagEchoHandler("peer"))
	defer releaseAll(mgr, peer)

	port, _, err := mgr.bind(peer.as, 0, "example.com", nil, true)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	expectOwner(t, port, "peer")

	deny := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	got, evicted, err := mgr.bind(peer.as, port, "example.com", deny, true)
	if err != nil || got != port || evicted != nil {
		t.Fatalf("idempotent rebind: port=%d evicted=%v err=%v, want %d, nil, nil", got, evicted, err, port)
	}
	mgr.mu.Lock()
	nPorts := len(mgr.bySession[peer.as])
	mgr.mu.Unlock()
	if nPorts != 1 {
		t.Fatalf("session holds %d ports after idempotent rebind, want 1", nPorts)
	}

	c := dialPort(t, port)
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection from 127.0.0.1 was relayed although the rebind's allow list excludes it")
	}
}

func TestTCPReleaseOldSessionAfterTakeoverKeepsPort(t *testing.T) {
	mgr := newTakeoverManager(t)
	mgr.forceCloseGrace = 200 * time.Millisecond
	oldPeer := newTCPPeer(t, "inst-x", tagEchoHandler("old"))
	newPeer := newTCPPeer(t, "inst-x", tagEchoHandler("new"))
	defer func() {
		mgr.releaseSession(newPeer.as)
		oldPeer.close()
		newPeer.close()
	}()

	port, _, err := mgr.bind(oldPeer.as, 0, "example.com", nil, true)
	if err != nil {
		t.Fatalf("old bind: %v", err)
	}
	_, before, _ := dialOwner(t, port)
	defer before.Close()

	if _, _, err := mgr.bind(newPeer.as, port, "example.com", nil, true); err != nil {
		t.Fatalf("takeover: %v", err)
	}

	oldPeer.close()
	mgr.releaseSession(oldPeer.as)

	mgr.mu.Lock()
	_, oldListed := mgr.bySession[oldPeer.as]
	oldConns := len(mgr.conns[oldPeer.as])
	mgr.mu.Unlock()
	if oldListed || oldConns != 0 {
		t.Fatalf("old session not fully released: listed=%v conns=%d", oldListed, oldConns)
	}

	before.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.Copy(io.Discard, before); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("pre-takeover conn still open after the old session was released")
		}
	}

	assertOwnedBy(t, mgr, port, newPeer.as, oldPeer.as)
	expectOwner(t, port, "new")
	expectOwner(t, port, "new")
}

func TestTCPConnAdmittedBeforeTakeoverStaysWithOldSession(t *testing.T) {
	mgr := newTakeoverManager(t)
	oldPeer := newTCPPeer(t, "inst-x", tagEchoHandler("old"))
	newPeer := newTCPPeer(t, "inst-x", tagEchoHandler("new"))
	defer releaseAll(mgr, oldPeer, newPeer)

	port, _, err := mgr.bind(oldPeer.as, 0, "example.com", nil, true)
	if err != nil {
		t.Fatalf("old bind: %v", err)
	}
	client, accepted := realConnPair(t)
	defer client.Close()
	tc := mgr.admit(tunnelFor(t, mgr, port), accepted)

	if _, _, err := mgr.bind(newPeer.as, port, "example.com", nil, true); err != nil {
		t.Fatalf("takeover: %v", err)
	}
	go mgr.serveAdmitted(tc)

	client.SetDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatalf("read owner tag: %v", err)
	}
	if line != "old\n" {
		t.Fatalf("pre-takeover connection reached %q, want the old agent", line)
	}
	if got := inflightCount(newPeer.as); got != 0 {
		t.Fatalf("new session inflight = %d, want 0", got)
	}

	client.Close()
	if !oldPeer.as.inflight.waitTimeout(3 * time.Second) {
		t.Fatal("old session inflight never returned to zero")
	}
	if got := inflightCount(newPeer.as); got != 0 {
		t.Fatalf("new session inflight = %d after close, want 0", got)
	}
}

func TestTCPForwardedAbortAfterTakeoverAccountsOldSession(t *testing.T) {
	mgr := newTakeoverManager(t)
	oldPeer := newTCPPeer(t, "inst-x", tagEchoHandler("old"))
	newPeer := newTCPPeer(t, "inst-x", tagEchoHandler("new"))
	defer releaseAll(mgr, oldPeer, newPeer)

	port, _, err := mgr.bind(oldPeer.as, 0, "example.com", nil, true)
	if err != nil {
		t.Fatalf("old bind: %v", err)
	}
	client, accepted := realConnPair(t)
	defer client.Close()
	f, ok := mgr.acceptForwarded(port, accepted)
	if !ok {
		t.Fatal("acceptForwarded refused a bound port")
	}

	if _, _, err := mgr.bind(newPeer.as, port, "example.com", nil, true); err != nil {
		t.Fatalf("takeover: %v", err)
	}
	otherClient, otherAccepted := realConnPair(t)
	defer otherClient.Close()
	other, ok := mgr.acceptForwarded(port, otherAccepted)
	if !ok {
		t.Fatal("acceptForwarded refused the taken-over port")
	}

	f.abort()

	mgr.mu.Lock()
	oldConns := len(mgr.conns[oldPeer.as])
	newConns := len(mgr.conns[newPeer.as])
	mgr.mu.Unlock()
	if oldConns != 0 {
		t.Fatalf("old session conns = %d after abort, want 0", oldConns)
	}
	if newConns != 1 {
		t.Fatalf("new session conns = %d after abort, want 1", newConns)
	}
	if got := inflightCount(oldPeer.as); got != 0 {
		t.Fatalf("old session inflight = %d, want 0", got)
	}
	if got := inflightCount(newPeer.as); got != 1 {
		t.Fatalf("new session inflight = %d, want 1", got)
	}
	other.abort()
}

func TestHandleBindTCPTakeoverEvictsOldSession(t *testing.T) {
	mgr := newTakeoverManager(t)
	oldPeer := newTCPPeer(t, "inst-x", tagEchoHandler("old"))
	newPeer := newTCPPeer(t, "inst-x", tagEchoHandler("new"))
	defer releaseAll(mgr, oldPeer, newPeer)

	s := newTestServer("tok")
	s.tcpMgr = mgr

	first := bindTCPVia(t, s, oldPeer, 1, proto.Bind{Kind: proto.KindTCP, Takeover: true})
	firstOK, err := proto.Decode[proto.BindOK](first)
	if first.Type != proto.TypeBindOK || err != nil {
		t.Fatalf("first bind reply = %+v (%v), want bind_ok", first, err)
	}
	port := firstOK.Port

	second := bindTCPVia(t, s, newPeer, 2, proto.Bind{Kind: proto.KindTCP, RemotePort: port, Takeover: true})
	if second.Type != proto.TypeBindOK || second.ID != 2 {
		t.Fatalf("takeover bind reply = %+v, want bind_ok id=2", second)
	}
	secondOK, err := proto.Decode[proto.BindOK](second)
	if err != nil {
		t.Fatalf("decode bind ok: %v", err)
	}
	wantURL := "tcp://example.com:" + strconv.Itoa(port)
	if secondOK.Port != port || secondOK.URL != wantURL {
		t.Fatalf("takeover bind ok = %+v, want port %d url %s", secondOK, port, wantURL)
	}

	oldPeer.agent.Control().SetReadDeadline(time.Now().Add(3 * time.Second))
	msg, err := oldPeer.agent.Control().Read()
	if err != nil {
		t.Fatalf("old agent read: %v", err)
	}
	if msg.Type != proto.TypeEvicted {
		t.Fatalf("old agent got %q, want %q", msg.Type, proto.TypeEvicted)
	}
	ev, err := proto.Decode[proto.Evicted](msg)
	if err != nil {
		t.Fatalf("decode evicted: %v", err)
	}
	if ev.Hostname != wantURL || ev.Reason != "takeover" {
		t.Fatalf("evicted = %+v, want hostname %s reason takeover", ev, wantURL)
	}
	waitDead(t, oldPeer.as)

	expectOwner(t, port, "new")
}

func TestHandleBindTCPDifferentInstanceLiveHolderPortUnavailable(t *testing.T) {
	mgr := newTakeoverManager(t)
	holder := newTCPPeer(t, "inst-a", tagEchoHandler("holder"))
	requester := newTCPPeer(t, "inst-b", tagEchoHandler("requester"))
	defer releaseAll(mgr, holder, requester)

	s := newTestServer("tok")
	s.tcpMgr = mgr

	port, _, err := mgr.bind(holder.as, 0, "example.com", nil, true)
	if err != nil {
		t.Fatalf("holder bind: %v", err)
	}

	reply := bindTCPVia(t, s, requester, 9, proto.Bind{Kind: proto.KindTCP, RemotePort: port, Takeover: true})
	if reply.Type != proto.TypeBindErr {
		t.Fatalf("reply = %+v, want bind_err", reply)
	}
	e, _ := proto.Decode[proto.BindErr](reply)
	if e.Code != proto.CodePortUnavailable {
		t.Fatalf("code = %q, want %q", e.Code, proto.CodePortUnavailable)
	}
	if isSessionDead(holder.as) {
		t.Fatal("a rejected bind must not touch the live holder's session")
	}
	expectOwner(t, port, "holder")
}

func TestHandleBindTCPStorageSameInstanceTakeover(t *testing.T) {
	store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	mgr := newTakeoverManager(t)
	mgr.forceCloseGrace = 200 * time.Millisecond
	oldPeer := newTCPPeer(t, "inst-x", tagEchoHandler("old"))
	newPeer := newTCPPeer(t, "inst-x", tagEchoHandler("new"))
	defer func() {
		mgr.releaseSession(newPeer.as)
		oldPeer.close()
		newPeer.close()
	}()

	s := newTestServer("tok")
	s.tcpMgr = mgr
	s.storage = store

	const port = 20004
	first := bindTCPVia(t, s, oldPeer, 1, proto.Bind{Kind: proto.KindTCP, RemotePort: port, Takeover: true})
	if first.Type != proto.TypeBindOK {
		t.Fatalf("first bind reply = %+v, want bind_ok", first)
	}
	second := bindTCPVia(t, s, newPeer, 2, proto.Bind{Kind: proto.KindTCP, RemotePort: port, Takeover: true})
	if second.Type != proto.TypeBindOK {
		t.Fatalf("takeover bind reply = %+v, want bind_ok", second)
	}

	oldPeer.agent.Control().SetReadDeadline(time.Now().Add(3 * time.Second))
	msg, err := oldPeer.agent.Control().Read()
	if err != nil || msg.Type != proto.TypeEvicted {
		t.Fatalf("old agent read = %+v, %v, want evicted", msg, err)
	}
	ev, _ := proto.Decode[proto.Evicted](msg)
	if want := "tcp://example.com:" + strconv.Itoa(port); ev.Hostname != want {
		t.Fatalf("evicted hostname = %q, want %q", ev.Hostname, want)
	}

	ctx := context.Background()
	renewed, err := store.RenewSessionLeases(ctx, store.EdgeID(), newPeer.as.ID, time.Now())
	if err != nil || renewed != 1 {
		t.Fatalf("new session renews %d leases (err %v), want 1", renewed, err)
	}

	waitDead(t, oldPeer.as)
	s.releaseDurableSession(oldPeer.as)
	mgr.releaseSession(oldPeer.as)

	renewed, err = store.RenewSessionLeases(ctx, store.EdgeID(), newPeer.as.ID, time.Now())
	if err != nil || renewed != 1 {
		t.Fatalf("new session renews %d leases after the old release (err %v), want 1", renewed, err)
	}
	assertOwnedBy(t, mgr, port, newPeer.as, oldPeer.as)
	expectOwner(t, port, "new")
}

func TestHandleBindTwiceAfterBindErr(t *testing.T) {
	client, server, cleanup := newRawSessionPair(t)
	defer cleanup()
	s := newTestServer("tok")
	holder := &AgentSession{ID: "holder", InstanceID: "inst-holder", Sess: server, IDGen: proto.NewEdgeIDGen(), NegotiatedVersion: proto.ProtoVersion}
	if _, _, err := s.registry.Bind("taken.example.com", holder, false, nil); err != nil {
		t.Fatalf("holder bind: %v", err)
	}
	as := &AgentSession{ID: "requester", InstanceID: "inst-requester", Sess: server, IDGen: proto.NewEdgeIDGen(), NegotiatedVersion: proto.ProtoVersion}
	defer s.registry.ReleaseSession(as)
	defer s.registry.ReleaseSession(holder)

	reply := bindOverWire(t, s, as, client, server, proto.Bind{Kind: proto.KindHTTP, Subdomain: "taken"})
	e, _ := proto.Decode[proto.BindErr](reply)
	if reply.Type != proto.TypeBindErr || e.Code != proto.CodeSubdomainTaken {
		t.Fatalf("first reply = %s %s, want subdomain_taken", reply.Type, reply.Data)
	}
	if isSessionDead(as) {
		t.Fatal("a rejected bind closed the session")
	}

	reply = bindOverWire(t, s, as, client, server, proto.Bind{Kind: proto.KindHTTP})
	if reply.Type != proto.TypeBindOK {
		t.Fatalf("second reply = %s %s, want bind_ok", reply.Type, reply.Data)
	}
}

func TestHandleBindTCPTakeoverLocalBindFailureKeepsReplacedLease(t *testing.T) {
	store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	mgr := newTakeoverManager(t)
	oldPeer := newTCPPeer(t, "inst-x", tagEchoHandler("old"))
	newPeer := newTCPPeer(t, "inst-x", tagEchoHandler("new"))
	defer releaseAll(mgr, oldPeer, newPeer)

	s := newTestServer("tok")
	s.tcpMgr = mgr
	s.storage = store

	const port = 20004
	first := bindTCPVia(t, s, oldPeer, 1, proto.Bind{Kind: proto.KindTCP, RemotePort: port, Takeover: true})
	if first.Type != proto.TypeBindOK {
		t.Fatalf("first bind reply = %+v, want bind_ok", first)
	}
	for i := 0; i < maxBindsPerSession; i++ {
		if _, _, err := mgr.bind(newPeer.as, 0, "example.com", nil, false); err != nil {
			t.Fatalf("fill bind %d: %v", i, err)
		}
	}

	second := bindTCPVia(t, s, newPeer, 2, proto.Bind{Kind: proto.KindTCP, RemotePort: port, Takeover: true})
	if second.Type != proto.TypeBindErr {
		t.Fatalf("takeover reply = %+v, want bind_err", second)
	}
	e, _ := proto.Decode[proto.BindErr](second)
	if e.Code != proto.CodeTooManyBinds {
		t.Fatalf("code = %q, want %q", e.Code, proto.CodeTooManyBinds)
	}
	if isSessionDead(oldPeer.as) {
		t.Fatal("a failed takeover closed the old holder's session")
	}
	assertOwnedBy(t, mgr, port, oldPeer.as, newPeer.as)

	tunnels, err := store.ListTunnels(context.Background())
	if err != nil {
		t.Fatalf("list tunnels: %v", err)
	}
	if len(tunnels) != 1 || tunnels[0].Status != "active" || len(tunnels[0].Connectors) != 1 || tunnels[0].Connectors[0].InstanceID != "inst-x" {
		t.Fatalf("tunnels after the failed takeover = %+v, want one active tunnel with its lease", tunnels)
	}
}

func TestHandleBindTCPLeaseStorageErrorIsInternal(t *testing.T) {
	for _, tc := range []struct {
		name string
		port int
	}{
		{"requested port", 20003},
		{"auto port", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newTCPFixture(t, echoHandler)
			defer fx.cleanup()

			store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db")})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			s := newTestServer("tok")
			s.tcpMgr = fx.mgr
			s.storage = store

			done := make(chan struct{})
			go func() {
				defer close(done)
				s.handleBindTCP(fx.as, fx.as.Sess.Control(), 7, proto.Bind{Kind: proto.KindTCP, RemotePort: tc.port})
			}()
			reply, err := fx.agent.Control().Read()
			if err != nil {
				t.Fatalf("read reply: %v", err)
			}
			<-done
			if reply.Type != proto.TypeBindErr {
				t.Fatalf("reply type = %q, want bind_err", reply.Type)
			}
			be, err := proto.Decode[proto.BindErr](reply)
			if err != nil {
				t.Fatal(err)
			}
			if be.Code != proto.CodeInternal {
				t.Fatalf("code = %q, want %q", be.Code, proto.CodeInternal)
			}
		})
	}
}
