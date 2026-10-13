package agent

import (
	"errors"
	"testing"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

// bindReply is what the fake edge answers to one Bind: a BindOK, or a
// BindErr when errCode is set.
type bindReply struct {
	port     int
	hostname string // defaults to example.com
	errCode  string
}

// scriptedEdge plays the edge side of one handshake: it accepts Auth with
// protocol v2, then answers each Bind with the next scripted reply and
// records every Bind it saw. It stops once the script runs out.
func scriptedEdge(t *testing.T, edgeSess tunnel.Session, replies []bindReply) <-chan []proto.Bind {
	t.Helper()
	done := make(chan []proto.Bind, 1)
	go func() {
		var binds []proto.Bind
		defer func() { done <- binds }()
		ctrl := edgeSess.Control()
		msg, err := ctrl.Read()
		if err != nil || msg.Type != proto.TypeAuth {
			return
		}
		if err := ctrl.Write(proto.TypeAuthOK, msg.ID, proto.AuthOK{ProtoVersion: 2, SessionID: "fake", ServerVersion: "fake-edge"}); err != nil {
			return
		}
		for _, r := range replies {
			msg, err := ctrl.Read()
			if err != nil || msg.Type != proto.TypeBind {
				return
			}
			b, err := proto.Decode[proto.Bind](msg)
			if err != nil {
				return
			}
			binds = append(binds, b)
			if r.errCode != "" {
				ctrl.Write(proto.TypeBindErr, msg.ID, proto.BindErr{Code: r.errCode, Message: "scripted"})
				continue
			}
			hostname := r.hostname
			if hostname == "" {
				hostname = "example.com"
			}
			ctrl.Write(proto.TypeBindOK, msg.ID, proto.BindOK{
				Hostname: hostname,
				URL:      "https://" + hostname,
				Port:     r.port,
			})
		}
	}()
	return done
}

// handshakeAgainst runs one agent handshake against a scripted edge and
// returns the handshake result plus the Binds the edge received.
func handshakeAgainst(t *testing.T, a *Agent, replies []bindReply) (proto.BindOK, []proto.Bind, error) {
	t.Helper()
	agentSess, edgeSess, cleanup := newTestSessionPair(t)
	defer cleanup()

	binds := scriptedEdge(t, edgeSess, replies)

	type result struct {
		ok  proto.BindOK
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		agentSess.Control().SetDeadline(time.Now().Add(3 * time.Second))
		ok, err := a.handshake(agentSess, proto.NewAgentIDGen())
		resCh <- result{ok, err}
	}()

	var res result
	select {
	case res = <-resCh:
	case <-time.After(5 * time.Second):
		t.Fatal("handshake did not return within 5s")
	}
	// Unblock a fake edge still waiting for a Bind the agent never sent.
	cleanup()
	select {
	case got := <-binds:
		return res.ok, got, res.err
	case <-time.After(5 * time.Second):
		t.Fatal("fake edge did not finish within 5s")
	}
	return res.ok, nil, res.err
}

func TestTCPHandshakeRequestsRememberedPortOnReconnect(t *testing.T) {
	a := New(Config{Kind: proto.KindTCP, TargetURL: "127.0.0.1:1"})

	ok, binds, err := handshakeAgainst(t, a, []bindReply{{port: 20123}})
	if err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	if ok.Port != 20123 {
		t.Fatalf("first bind port = %d, want 20123", ok.Port)
	}
	if len(binds) != 1 || binds[0].RemotePort != 0 || !binds[0].Takeover {
		t.Fatalf("first binds = %+v, want one bind with RemotePort 0 and Takeover", binds)
	}

	ok, binds, err = handshakeAgainst(t, a, []bindReply{{port: 20123}})
	if err != nil {
		t.Fatalf("reconnect handshake: %v", err)
	}
	if ok.Port != 20123 {
		t.Fatalf("reconnect bind port = %d, want 20123", ok.Port)
	}
	if len(binds) != 1 || binds[0].RemotePort != 20123 || !binds[0].Takeover {
		t.Fatalf("reconnect binds = %+v, want one bind for the remembered port 20123 with Takeover", binds)
	}
}

func TestTCPHandshakeFallsBackToAnyPortWhenRememberedPortTaken(t *testing.T) {
	a := New(Config{Kind: proto.KindTCP, TargetURL: "127.0.0.1:1"})

	if _, _, err := handshakeAgainst(t, a, []bindReply{{port: 20123}}); err != nil {
		t.Fatalf("first handshake: %v", err)
	}

	ok, binds, err := handshakeAgainst(t, a, []bindReply{
		{errCode: proto.CodePortUnavailable},
		{port: 20124},
	})
	if err != nil {
		t.Fatalf("reconnect handshake should fall back to a fresh port, got: %v", err)
	}
	if ok.Port != 20124 {
		t.Fatalf("fallback bind port = %d, want 20124", ok.Port)
	}
	if len(binds) != 2 {
		t.Fatalf("edge saw %d binds, want 2 (remembered port, then port 0): %+v", len(binds), binds)
	}
	if binds[0].RemotePort != 20123 || binds[1].RemotePort != 0 {
		t.Fatalf("bind ports = %d then %d, want 20123 then 0", binds[0].RemotePort, binds[1].RemotePort)
	}
	if !binds[1].Takeover {
		t.Fatal("fallback bind must still send Takeover")
	}

	_, binds, err = handshakeAgainst(t, a, []bindReply{{port: 20124}})
	if err != nil {
		t.Fatalf("third handshake: %v", err)
	}
	if len(binds) != 1 || binds[0].RemotePort != 20124 {
		t.Fatalf("third binds = %+v, want the newly remembered port 20124", binds)
	}
}

func TestTCPHandshakeUserRemotePortDoesNotFallBack(t *testing.T) {
	a := New(Config{Kind: proto.KindTCP, TargetURL: "127.0.0.1:1", RemotePort: 15432})

	_, binds, err := handshakeAgainst(t, a, []bindReply{
		{errCode: proto.CodePortUnavailable},
		{port: 20124},
	})
	if err == nil {
		t.Fatal("a user-requested --remote-port that is unavailable must fail the handshake, not silently move")
	}
	if errors.Is(err, errFatalHandshake) {
		t.Fatalf("port_unavailable on --remote-port should stay retryable, got fatal: %v", err)
	}
	if len(binds) != 1 || binds[0].RemotePort != 15432 || !binds[0].Takeover {
		t.Fatalf("binds = %+v, want exactly one bind for 15432 with Takeover", binds)
	}

	ok, binds, err := handshakeAgainst(t, a, []bindReply{{port: 15432}})
	if err != nil {
		t.Fatalf("retry handshake: %v", err)
	}
	if ok.Port != 15432 || len(binds) != 1 || binds[0].RemotePort != 15432 {
		t.Fatalf("retry: port %d binds %+v, want 15432", ok.Port, binds)
	}
}
