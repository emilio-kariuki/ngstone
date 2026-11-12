package e2e

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func requireEdgeLog(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(quicEdgeLog.String(), want) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(quicEdgeLog.String(), want) {
		t.Fatalf("edge log has no %q:\n%s", want, quicEdgeLog.String())
	}
}

func TestQUICShareConnectEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess share end-to-end test in -short mode")
	}
	useQUIC(t)
	_, agentBin, controlAddr, token, echoAddr := shareFixture(t, "-quic")

	sharer, sharerSB := startSharer(t, agentBin, controlAddr, token, echoAddr, "-expires", "5m", "-transport", quicTransport())
	link := waitMatch(t, sharerSB, shareLinkRe, 10*time.Second)[1]
	shareID := waitMatch(t, sharerSB, shareIDRe, 10*time.Second)[1]

	connector, connSB := startConnector(t, agentBin, link, "-as", "alice", "-transport", quicTransport())
	listenAddr := waitMatch(t, connSB, listenAddrRe, 15*time.Second)[1]
	waitMatch(t, sharerSB, connJoinedRe, 10*time.Second)

	conn, err := net.DialTimeout("tcp", listenAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial connector listener %s: %v", listenAddr, err)
	}
	defer conn.Close()
	for i := 0; i < 3; i++ {
		echoRoundTrip(t, conn, "through-the-quic-share\n")
	}
	waitMatch(t, sharerSB, connOpenRe, 10*time.Second)

	out, code := runCLI(t, agentBin, controlAddr, token, "shares", "-transport", quicTransport())
	if code != 0 || !strings.Contains(out, shareID) || !strings.Contains(out, "connector alice") {
		t.Fatalf("shares over quic: code=%d out=%q", code, out)
	}

	if err := sharer.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if code := waitExit(t, sharer, 10*time.Second); code != 0 {
		t.Fatalf("sharer exit code = %d after Ctrl-C, want 0; output:\n%s", code, sharerSB.String())
	}
	if code := waitExit(t, connector, 10*time.Second); code != 3 {
		t.Fatalf("connector exit code = %d after revocation, want 3; output:\n%s", code, connSB.String())
	}
}

func TestQUICConstantMemory100MB(t *testing.T) {
	useQUIC(t)
	TestConstantMemory100MB(t)
}

func TestQUICWebSocketEchoSession(t *testing.T) {
	useQUIC(t)
	TestWebSocketEchoSession(t)
}

func TestQUICSSEStream(t *testing.T) {
	useQUIC(t)
	TestSSEStream(t)
}

func TestQUICTCPTunnelEndToEnd(t *testing.T) {
	useQUIC(t)
	TestTCPTunnelEndToEnd(t)
}

func TestQUICTCPTunnelSpecificRemotePort(t *testing.T) {
	useQUIC(t)
	TestTCPTunnelSpecificRemotePort(t)
}

func TestQUICTCPTunnelHalfClose(t *testing.T) {
	useQUIC(t)
	TestTCPTunnelHalfClose(t)
}

func TestQUICTCPTunnelNoLocalTarget(t *testing.T) {
	useQUIC(t)
	TestTCPTunnelNoLocalTarget(t)
}

func TestQUICTLSPassthroughEndToEnd(t *testing.T) {
	useQUIC(t)
	TestTLSPassthroughEndToEnd(t)
}

func TestQUICPartitionInstantTakeoverPastHalfOpenPeer(t *testing.T) {
	useQUIC(t)
	TestPartitionInstantTakeoverPastHalfOpenPeer(t)
}

func TestQUICPartitionDifferentInstanceRefused(t *testing.T) {
	useQUIC(t)
	TestPartitionDifferentInstanceRefused(t)
}

func TestQUICPartitionTakeoverVictimEvicted(t *testing.T) {
	useQUIC(t)
	TestPartitionTakeoverVictimEvicted(t)
}

func TestQUICPartitionGracefulDrainAgentSIGTERM(t *testing.T) {
	useQUIC(t)
	TestPartitionGracefulDrainAgentSIGTERM(t)
	requireEdgeLog(t, "edge: agent goodbye")
}

func TestQUICPartitionGracefulDrainEdgeSIGTERM(t *testing.T) {
	useQUIC(t)
	TestPartitionGracefulDrainEdgeSIGTERM(t)
}

func TestQUICPartitionKillAgentMidRequest(t *testing.T) {
	useQUIC(t)
	partitionKillAgentMidRequest(t, 30*time.Second, true)
}

func TestQUICPartitionEdgeRestart(t *testing.T) {
	useQUIC(t)
	partitionEdgeRestart(t, 45*time.Second)
}
