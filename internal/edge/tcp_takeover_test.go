package edge

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"ngstone/internal/proto"
)

// tagEchoHandler announces which agent answered with a "<tag>\n" line, then
// echoes, so a test can tell which session a public connection reached.
func tagEchoHandler(tag string) func(net.Conn, proto.StreamOpen) {
	return func(conn net.Conn, _ proto.StreamOpen) {
		defer conn.Close()
		if _, err := io.WriteString(conn, tag+"\n"); err != nil {
			return
		}
		io.Copy(conn, conn)
	}
}

// dialOwner connects to port and returns the tag of the agent that answered,
// plus the open connection (already past the tag line) for further echoes.
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

// assertOwnedBy checks the manager's bookkeeping says port belongs to owner
// and not to former.
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

func TestTCPTakeoverSameInstanceTransfersLivePort(t *testing.T) {
	mgr := newTakeoverManager(t)
	oldPeer := newTCPPeer(t, "inst-x", tagEchoHandler("old"))
	newPeer := newTCPPeer(t, "inst-x", tagEchoHandler("new"))
	defer func() {
		mgr.releaseSession(oldPeer.as)
		mgr.releaseSession(newPeer.as)
		oldPeer.close()
		newPeer.close()
	}()

	port, _, err := mgr.bind(oldPeer.as, 0, "example.com", nil, true)
	if err != nil {
		t.Fatalf("old bind: %v", err)
	}
	expectOwner(t, port, "old")

	// A connection relayed before the takeover stays with the old session.
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
	defer func() {
		mgr.releaseSession(oldPeer.as)
		mgr.releaseSession(newPeer.as)
		oldPeer.close()
		newPeer.close()
	}()

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
	defer func() {
		mgr.releaseSession(holder.as)
		mgr.releaseSession(requester.as)
		holder.close()
		requester.close()
	}()

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
			defer func() {
				mgr.releaseSession(holder.as)
				mgr.releaseSession(requester.as)
				holder.close()
				requester.close()
			}()

			port, _, err := mgr.bind(holder.as, 0, "example.com", nil, true)
			if err != nil {
				t.Fatalf("holder bind: %v", err)
			}
			// The holder's session dies but nothing has reaped it yet: the
			// half-open window the takeover rules exist for.
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

func TestTCPTakeoverEmptyInstanceIDsNeverMatch(t *testing.T) {
	for _, takeover := range []bool{false, true} {
		t.Run("takeover="+strconv.FormatBool(takeover), func(t *testing.T) {
			mgr := newTakeoverManager(t)
			holder := newTCPPeer(t, "", tagEchoHandler("holder"))
			requester := newTCPPeer(t, "", tagEchoHandler("requester"))
			defer func() {
				mgr.releaseSession(holder.as)
				mgr.releaseSession(requester.as)
				holder.close()
				requester.close()
			}()

			port, _, err := mgr.bind(holder.as, 0, "example.com", nil, true)
			if err != nil {
				t.Fatalf("holder bind: %v", err)
			}
			if _, evicted, err := mgr.bind(requester.as, port, "example.com", nil, takeover); err != errPortUnavailable || evicted != nil {
				t.Fatalf("empty InstanceIDs vs live holder: evicted=%v err=%v, want nil and errPortUnavailable", evicted, err)
			}
			expectOwner(t, port, "holder")
		})
	}
}

func TestTCPRebindSameSessionIsIdempotentAndUpdatesAllow(t *testing.T) {
	mgr := newTakeoverManager(t)
	peer := newTCPPeer(t, "inst-x", tagEchoHandler("peer"))
	defer func() {
		mgr.releaseSession(peer.as)
		peer.close()
	}()

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

	// What the edge's control loop does once the evicted session is closed.
	oldPeer.close()
	mgr.releaseSession(oldPeer.as)

	mgr.mu.Lock()
	_, oldListed := mgr.bySession[oldPeer.as]
	oldConns := len(mgr.conns[oldPeer.as])
	mgr.mu.Unlock()
	if oldListed || oldConns != 0 {
		t.Fatalf("old session not fully released: listed=%v conns=%d", oldListed, oldConns)
	}

	// The pre-takeover connection was relayed by the old session, so it ends
	// with it (EOF or reset, but not left hanging).
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

func TestHandleBindTCPTakeoverEvictsOldSession(t *testing.T) {
	mgr := newTakeoverManager(t)
	oldPeer := newTCPPeer(t, "inst-x", tagEchoHandler("old"))
	newPeer := newTCPPeer(t, "inst-x", tagEchoHandler("new"))
	defer func() {
		mgr.releaseSession(oldPeer.as)
		mgr.releaseSession(newPeer.as)
		oldPeer.close()
		newPeer.close()
	}()

	s := newTestServer("tok")
	s.tcpMgr = mgr

	bindVia := func(peer *tcpPeer, id uint64, b proto.Bind) proto.Msg {
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

	first := bindVia(oldPeer, 1, proto.Bind{Kind: proto.KindTCP, Takeover: true})
	firstOK, err := proto.Decode[proto.BindOK](first)
	if first.Type != proto.TypeBindOK || err != nil {
		t.Fatalf("first bind reply = %+v (%v), want bind_ok", first, err)
	}
	port := firstOK.Port

	second := bindVia(newPeer, 2, proto.Bind{Kind: proto.KindTCP, RemotePort: port, Takeover: true})
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
	defer func() {
		mgr.releaseSession(holder.as)
		mgr.releaseSession(requester.as)
		holder.close()
		requester.close()
	}()

	s := newTestServer("tok")
	s.tcpMgr = mgr

	port, _, err := mgr.bind(holder.as, 0, "example.com", nil, true)
	if err != nil {
		t.Fatalf("holder bind: %v", err)
	}

	go s.handleBindTCP(requester.as, requester.as.Sess.Control(), 9, proto.Bind{Kind: proto.KindTCP, RemotePort: port, Takeover: true})
	requester.agent.Control().SetReadDeadline(time.Now().Add(3 * time.Second))
	reply, err := requester.agent.Control().Read()
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
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
