package e2e

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func startTCPEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start echo listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func startTCPReplyThenClose(t *testing.T, reply string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start reply-then-close listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				c.SetReadDeadline(time.Now().Add(10 * time.Second))
				if _, err := c.Read(buf); err != nil {
					return
				}
				io.WriteString(c, reply)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func dialTunnel(t *testing.T, port int) net.Conn {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial public tcp tunnel %s: %v", addr, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func echoRoundTrip(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, msg); err != nil {
		t.Fatalf("write %q through tunnel: %v", msg, err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo of %q: %v", msg, err)
	}
	if string(got) != msg {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
}

func TestTCPTunnelEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess tcp end-to-end test in -short mode")
	}

	edgeBin, agentBin := buildBinaries(t)

	echoAddr := startTCPEcho(t)

	token := "e2e-tcp-token"
	domain := "tun.example.com"
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)
	tcpLo, tcpHi := freeTCPRange(t, 30)

	startEdgeTCP(t, edgeBin, controlAddr, publicAddr, token, domain, tcpLo, tcpHi)
	_, agentSB := startAgentTCP(t, agentBin, controlAddr, token, echoAddr, 0)

	port := waitTCPAssignedPort(t, agentSB, 15*time.Second)
	if port < tcpLo || port > tcpHi {
		t.Fatalf("assigned tcp port %d is outside the configured range %d-%d", port, tcpLo, tcpHi)
	}
	waitForPort(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))

	t.Run("single_message", func(t *testing.T) {
		conn := dialTunnel(t, port)
		echoRoundTrip(t, conn, "hello-tcp\n")
	})

	t.Run("multiple_messages_same_connection", func(t *testing.T) {
		conn := dialTunnel(t, port)
		for i := 0; i < 5; i++ {
			echoRoundTrip(t, conn, fmt.Sprintf("msg-%d-abcdefghij\n", i))
		}
	})

	t.Run("concurrent_connections", func(t *testing.T) {
		connA := dialTunnel(t, port)
		connB := dialTunnel(t, port)

		var wg sync.WaitGroup
		wg.Add(2)
		errs := make(chan error, 2)
		run := func(conn net.Conn, tag string) {
			defer wg.Done()
			for i := 0; i < 4; i++ {
				msg := fmt.Sprintf("%s-%d-zyxwvutsrq\n", tag, i)
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.WriteString(conn, msg); err != nil {
					errs <- fmt.Errorf("%s write: %w", tag, err)
					return
				}
				got := make([]byte, len(msg))
				if _, err := io.ReadFull(conn, got); err != nil {
					errs <- fmt.Errorf("%s read: %w", tag, err)
					return
				}
				if string(got) != msg {
					errs <- fmt.Errorf("%s echo = %q, want %q", tag, got, msg)
					return
				}
			}
		}
		go run(connA, "connA")
		go run(connB, "connB")
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("concurrent connection failed: %v", err)
		}
	})
}

func TestTCPTunnelSpecificRemotePort(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess tcp end-to-end test in -short mode")
	}

	edgeBin, agentBin := buildBinaries(t)
	echoAddr := startTCPEcho(t)

	token := "e2e-tcp-token"
	domain := "tun.example.com"
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)
	tcpLo, tcpHi := freeTCPRange(t, 30)

	want := tcpLo + 7
	if want > tcpHi {
		want = tcpHi
	}

	startEdgeTCP(t, edgeBin, controlAddr, publicAddr, token, domain, tcpLo, tcpHi)
	_, agentSB := startAgentTCP(t, agentBin, controlAddr, token, echoAddr, want)

	port := waitTCPAssignedPort(t, agentSB, 15*time.Second)
	if port != want {
		t.Fatalf("advertised tcp port = %d, want exactly the requested %d", port, want)
	}
	waitForPort(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))

	conn := dialTunnel(t, port)
	echoRoundTrip(t, conn, "pinned-port\n")
}

func TestTCPTunnelHalfClose(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess tcp end-to-end test in -short mode")
	}

	edgeBin, agentBin := buildBinaries(t)

	const reply = "one-reply-then-close\n"
	targetAddr := startTCPReplyThenClose(t, reply)

	token := "e2e-tcp-token"
	domain := "tun.example.com"
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)
	tcpLo, tcpHi := freeTCPRange(t, 30)

	startEdgeTCP(t, edgeBin, controlAddr, publicAddr, token, domain, tcpLo, tcpHi)
	_, agentSB := startAgentTCP(t, agentBin, controlAddr, token, targetAddr, 0)

	port := waitTCPAssignedPort(t, agentSB, 15*time.Second)
	waitForPort(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))

	conn := dialTunnel(t, port)

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "trigger\n"); err != nil {
		t.Fatalf("write trigger: %v", err)
	}

	got := make([]byte, len(reply))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if string(got) != reply {
		t.Fatalf("reply = %q, want %q", got, reply)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(make([]byte, 16))
	if err == nil {
		t.Fatalf("expected EOF after the target closed, but read %d more bytes", n)
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("read timed out: the target's half-close did not propagate through edge+agent; the client never saw EOF")
	}
}

func TestTCPTunnelNoLocalTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess tcp end-to-end test in -short mode")
	}

	edgeBin, agentBin := buildBinaries(t)

	deadTarget := freeAddr(t)

	token := "e2e-tcp-token"
	domain := "tun.example.com"
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)
	tcpLo, tcpHi := freeTCPRange(t, 30)

	startEdgeTCP(t, edgeBin, controlAddr, publicAddr, token, domain, tcpLo, tcpHi)
	_, agentSB := startAgentTCP(t, agentBin, controlAddr, token, deadTarget, 0)

	port := waitTCPAssignedPort(t, agentSB, 15*time.Second)
	waitForPort(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))

	conn := dialTunnel(t, port)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn, "anybody-home\n")

	n, err := io.ReadFull(conn, make([]byte, 8))
	if err == nil {
		t.Fatalf("expected no echo when nothing is listening on the local target, but read %d bytes", n)
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("read timed out: a tunnel with no reachable local target should close fast, not hang")
	}
}
