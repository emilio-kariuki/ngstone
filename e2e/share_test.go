package e2e

import (
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

var (
	shareLinkRe   = regexp.MustCompile(`(?m)^link\s+(ngstone://\S+)`)
	listenAddrRe  = regexp.MustCompile(`(?m)^listening\s+(\S+)`)
	shareLiveRe   = regexp.MustCompile(`share live`)
	connJoinedRe  = regexp.MustCompile(`connector joined`)
	connOpenRe    = regexp.MustCompile(`conn #1\s+open`)
	connClosedRe  = regexp.MustCompile(`conn #1\s+closed`)
	shareClosedRe = regexp.MustCompile(`share closed`)
)

func startSharer(t *testing.T, agentBin, controlAddr, token, target string, extra ...string) (*managedProc, *syncBuf) {
	t.Helper()
	args := []string{
		"share", "tcp", target,
		"-server", controlAddr,
		"-token", token,
		"-insecure",
		"-label", "e2e db",
	}
	args = append(args, extra...)
	cmd := exec.Command(agentBin, args...)
	sb := &syncBuf{}
	cmd.Stdout = io.MultiWriter(os.Stderr, sb)
	cmd.Stderr = io.MultiWriter(os.Stderr, sb)
	p := newManagedProc(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ngstone share: %v", err)
	}
	t.Cleanup(p.killAndWait)
	return p, sb
}

func startConnector(t *testing.T, agentBin, link string, extra ...string) (*managedProc, *syncBuf) {
	t.Helper()
	args := []string{"connect", link, "-insecure"}
	args = append(args, extra...)
	cmd := exec.Command(agentBin, args...)
	sb := &syncBuf{}
	cmd.Stdout = io.MultiWriter(os.Stderr, sb)
	cmd.Stderr = io.MultiWriter(os.Stderr, sb)
	p := newManagedProc(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ngstone connect: %v", err)
	}
	t.Cleanup(p.killAndWait)
	return p, sb
}

func waitMatch(t *testing.T, sb *syncBuf, re *regexp.Regexp, max time.Duration) []string {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(sb.String()); m != nil {
			return m
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for output matching %q; got:\n%s", max, re, sb.String())
	return nil
}

func waitExit(t *testing.T, p *managedProc, max time.Duration) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- p.wait() }()
	select {
	case err := <-done:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		if err != nil {
			t.Fatalf("wait: %v", err)
		}
		return 0
	case <-time.After(max):
		t.Fatalf("process did not exit within %s", max)
		return -1
	}
}

func shareFixture(t *testing.T) (edgeBin, agentBin, controlAddr, token, echoAddr string) {
	t.Helper()
	edgeBin, agentBin = buildBinaries(t)
	echoAddr = startTCPEcho(t)
	token = "e2e-share-token"
	controlAddr = freeAddr(t)
	publicAddr := freeAddr(t)
	startEdge(t, edgeBin, controlAddr, publicAddr, token, "tun.example.com")
	return
}

func TestShareConnectEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess share end-to-end test in -short mode")
	}
	_, agentBin, controlAddr, token, echoAddr := shareFixture(t)

	sharer, sharerSB := startSharer(t, agentBin, controlAddr, token, echoAddr, "-expires", "5m")
	link := waitMatch(t, sharerSB, shareLinkRe, 10*time.Second)[1]
	if !strings.HasPrefix(link, "ngstone://"+controlAddr+"/s/") {
		t.Fatalf("link %q does not carry the edge address", link)
	}
	waitMatch(t, sharerSB, shareLiveRe, 10*time.Second)

	// The echo server already owns the share's default port, so the
	// connector must fall back to a free one and say so.
	connector, connSB := startConnector(t, agentBin, link)
	listenAddr := waitMatch(t, connSB, listenAddrRe, 15*time.Second)[1]
	if listenAddr == echoAddr {
		t.Fatalf("connector claims to listen on the echo server's own address %s", listenAddr)
	}
	waitMatch(t, sharerSB, connJoinedRe, 10*time.Second)

	conn, err := net.DialTimeout("tcp", listenAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial connector listener %s: %v", listenAddr, err)
	}
	for i := 0; i < 3; i++ {
		echoRoundTrip(t, conn, "through-the-share\n")
	}
	waitMatch(t, sharerSB, connOpenRe, 10*time.Second)
	conn.Close()
	waitMatch(t, sharerSB, connClosedRe, 10*time.Second)
	if !strings.Contains(sharerSB.String(), "54 B up") {
		t.Fatalf("expected byte accounting in the sharer's audit line; got:\n%s", sharerSB.String())
	}

	// A second client while the first share is live, then revoke with
	// Ctrl-C: the open connection is cut and the connector exits non-zero
	// saying why.
	held, err := net.DialTimeout("tcp", listenAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	echoRoundTrip(t, held, "held\n")

	if err := sharer.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if code := waitExit(t, sharer, 10*time.Second); code != 0 {
		t.Fatalf("sharer exit code = %d after Ctrl-C, want 0; output:\n%s", code, sharerSB.String())
	}
	if !strings.Contains(sharerSB.String(), "share revoked") {
		t.Fatalf("sharer should report the revocation; got:\n%s", sharerSB.String())
	}
	if code := waitExit(t, connector, 10*time.Second); code != 3 {
		t.Fatalf("connector exit code = %d after revocation, want 3; output:\n%s", code, connSB.String())
	}
	if !strings.Contains(connSB.String(), "revoked") {
		t.Fatalf("connector should say the share was revoked; got:\n%s", connSB.String())
	}
	held.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := held.Read(make([]byte, 1)); err == nil {
		t.Fatalf("held connection should be closed after revocation")
	}
}

func TestShareExpires(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess share expiry test in -short mode")
	}
	_, agentBin, controlAddr, token, echoAddr := shareFixture(t)

	sharer, sharerSB := startSharer(t, agentBin, controlAddr, token, echoAddr, "-expires", "4s")
	link := waitMatch(t, sharerSB, shareLinkRe, 10*time.Second)[1]
	connector, connSB := startConnector(t, agentBin, link)
	waitMatch(t, connSB, listenAddrRe, 15*time.Second)

	if code := waitExit(t, connector, 15*time.Second); code != 3 {
		t.Fatalf("connector exit code = %d after expiry, want 3; output:\n%s", code, connSB.String())
	}
	if !strings.Contains(connSB.String(), "expired") {
		t.Fatalf("connector should say the share expired; got:\n%s", connSB.String())
	}
	if code := waitExit(t, sharer, 15*time.Second); code != 0 {
		t.Fatalf("sharer exit code = %d after expiry, want 0; output:\n%s", code, sharerSB.String())
	}
	waitMatch(t, sharerSB, shareClosedRe, time.Second)
	if !strings.Contains(sharerSB.String(), "share expired") {
		t.Fatalf("sharer should say the share expired; got:\n%s", sharerSB.String())
	}

	// The link is dead now: a fresh connector is refused outright.
	late, lateSB := startConnector(t, agentBin, link)
	if code := waitExit(t, late, 15*time.Second); code != 1 {
		t.Fatalf("connector on an expired link exit code = %d, want 1; output:\n%s", code, lateSB.String())
	}
	if !strings.Contains(lateSB.String(), "not valid") {
		t.Fatalf("expected a not-valid message; got:\n%s", lateSB.String())
	}
}

func TestShareSingleUseLocksToFirstConnector(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess share single-use test in -short mode")
	}
	_, agentBin, controlAddr, token, echoAddr := shareFixture(t)

	_, sharerSB := startSharer(t, agentBin, controlAddr, token, echoAddr, "-expires", "5m", "-single-use")
	link := waitMatch(t, sharerSB, shareLinkRe, 10*time.Second)[1]

	_, firstSB := startConnector(t, agentBin, link, "-instance-id", "aaaa")
	waitMatch(t, firstSB, listenAddrRe, 15*time.Second)

	second, secondSB := startConnector(t, agentBin, link, "-instance-id", "bbbb")
	if code := waitExit(t, second, 15*time.Second); code != 1 {
		t.Fatalf("second connector on a single-use link exit code = %d, want 1; output:\n%s", code, secondSB.String())
	}
	if !strings.Contains(secondSB.String(), "share_locked") {
		t.Fatalf("expected share_locked; got:\n%s", secondSB.String())
	}
	waitLogContains(t, sharerSB, "rejected", 5*time.Second)
}

func TestShareAllowCIDRRejectsOutsideAddresses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess share allow-cidr test in -short mode")
	}
	_, agentBin, controlAddr, token, echoAddr := shareFixture(t)

	_, sharerSB := startSharer(t, agentBin, controlAddr, token, echoAddr, "-expires", "5m", "-allow-cidr", "203.0.113.0/24")
	link := waitMatch(t, sharerSB, shareLinkRe, 10*time.Second)[1]

	connector, connSB := startConnector(t, agentBin, link)
	if code := waitExit(t, connector, 15*time.Second); code != 1 {
		t.Fatalf("connector outside the allow list exit code = %d, want 1; output:\n%s", code, connSB.String())
	}
	if !strings.Contains(connSB.String(), "forbidden_cidr") {
		t.Fatalf("expected forbidden_cidr; got:\n%s", connSB.String())
	}
}

func TestShareSurvivesEdgeRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess share edge-restart test in -short mode")
	}
	edgeBin, agentBin := buildBinaries(t)
	echoAddr := startTCPEcho(t)
	token := "e2e-share-token"
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)
	edge, _ := startEdge(t, edgeBin, controlAddr, publicAddr, token, "tun.example.com")

	_, sharerSB := startSharer(t, agentBin, controlAddr, token, echoAddr, "-expires", "5m")
	link := waitMatch(t, sharerSB, shareLinkRe, 10*time.Second)[1]
	_, connSB := startConnector(t, agentBin, link)
	listenAddr := waitMatch(t, connSB, listenAddrRe, 15*time.Second)[1]

	edge.killAndWait()
	startEdge(t, edgeBin, controlAddr, publicAddr, token, "tun.example.com")

	waitLogContains(t, sharerSB, "reconnected", 30*time.Second)
	waitLogContains(t, connSB, "reconnected", 60*time.Second)

	conn, err := net.DialTimeout("tcp", listenAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial connector listener after restart: %v", err)
	}
	defer conn.Close()
	echoRoundTrip(t, conn, "after-restart\n")
}
