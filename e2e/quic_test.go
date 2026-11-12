package e2e

import (
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
