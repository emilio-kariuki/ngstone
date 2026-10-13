package edge

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

// connectFakeAgent authenticates and binds an HTTP tunnel over a real control
// connection, so the edge runs its full controlLoop for the session. Every
// data stream the edge opens is answered with a 101 and then held open, like
// a WebSocket the local app keeps alive.
func connectFakeAgent(t *testing.T, controlAddr, subdomain string) (sess tunnel.Session, goodbyeAt *atomic.Int64) {
	t.Helper()
	conn, err := net.Dial("tcp", controlAddr)
	if err != nil {
		t.Fatalf("dial control: %v", err)
	}
	sess, err = tunnel.Client(conn)
	if err != nil {
		t.Fatalf("tunnel client: %v", err)
	}
	t.Cleanup(func() { sess.Close("test done") })

	ctrl := sess.Control()
	if err := ctrl.Write(proto.TypeAuth, 1, proto.Auth{Token: "tok", InstanceID: "inst-shutdown", ProtoVersions: proto.SupportedVersions}); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	if m, err := ctrl.Read(); err != nil || m.Type != proto.TypeAuthOK {
		t.Fatalf("auth reply: %+v %v", m, err)
	}
	if err := ctrl.Write(proto.TypeBind, 3, proto.Bind{Kind: proto.KindHTTP, Subdomain: subdomain}); err != nil {
		t.Fatalf("write bind: %v", err)
	}
	if m, err := ctrl.Read(); err != nil || m.Type != proto.TypeBindOK {
		t.Fatalf("bind reply: %+v %v", m, err)
	}

	goodbyeAt = new(atomic.Int64)
	go func() {
		for {
			m, err := ctrl.Read()
			if err != nil {
				return
			}
			if m.Type == proto.TypeGoodbye {
				goodbyeAt.Store(time.Now().UnixNano())
			}
		}
	}()

	go func() {
		for {
			st, err := sess.AcceptRaw(context.Background())
			if err != nil {
				return
			}
			go func() {
				defer st.Close()
				if _, err := proto.ReadMsg(st); err != nil {
					return
				}
				br := bufio.NewReader(st)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				io.WriteString(st, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: test\r\nConnection: Upgrade\r\n\r\n")
				io.Copy(io.Discard, br)
			}()
		}
	}()
	return sess, goodbyeAt
}

// Run must not return until each agent session has sent Goodbye and drained.
// http.Server.Shutdown does not wait for hijacked (upgraded) connections, so
// before Run tracked control sessions it returned immediately and the process
// exited mid-drain.
func TestRunWaitsForControlSessionsToDrainOnShutdown(t *testing.T) {
	prevDrain := drainTimeout
	drainTimeout = time.Second
	t.Cleanup(func() { drainTimeout = prevDrain })

	publicAddr := freeTCPAddr(t)
	controlAddr := freeTCPAddr(t)
	s, err := New(Config{
		ControlAddr:  controlAddr,
		PublicAddr:   publicAddr,
		Domain:       "example.com",
		TokenSHA256:  sumToken("tok"),
		PublicScheme: "http",
		Insecure:     true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		s.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-runDone
	})
	waitTCPUp(t, controlAddr)
	waitTCPUp(t, publicAddr)

	_, goodbyeAt := connectFakeAgent(t, controlAddr, "ws")

	client, err := net.Dial("tcp", publicAddr)
	if err != nil {
		t.Fatalf("dial public: %v", err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(client, "GET / HTTP/1.1\r\nHost: ws.example.com\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
	status, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("upgrade response: %q %v", status, err)
	}
	client.SetDeadline(time.Time{})

	start := time.Now()
	cancel()
	select {
	case <-runDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return within 10s of shutdown")
	}
	elapsed := time.Since(start)
	t.Logf("Run returned %v after cancel", elapsed)

	if elapsed < drainTimeout-100*time.Millisecond {
		t.Fatalf("Run returned after %v with an upgraded stream still in flight; want it to wait out the %v drain", elapsed, drainTimeout)
	}
	gb := goodbyeAt.Load()
	if gb == 0 {
		t.Fatal("agent never received Goodbye before Run returned")
	}
}
