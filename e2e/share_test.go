package e2e

import (
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
	p, sb, _ := startSharerTargets(t, agentBin, controlAddr, token, []string{"tcp", target}, extra...)
	return p, sb
}

// startSharerTargets runs `ngstone share <targets...>` and returns the
// process, its output, and a writer for the commands typed into its
// terminal (y/n, kick, extend, q).
func startSharerTargets(t *testing.T, agentBin, controlAddr, token string, targets []string, extra ...string) (*managedProc, *syncBuf, io.WriteCloser) {
	t.Helper()
	args := []string{"share"}
	args = append(args, targets...)
	args = append(args,
		"-server", controlAddr,
		"-token", token,
		"-insecure",
		"-label", "e2e db",
	)
	args = append(args, extra...)
	cmd := exec.Command(agentBin, args...)
	sb := &syncBuf{}
	cmd.Stdout = io.MultiWriter(os.Stderr, sb)
	cmd.Stderr = io.MultiWriter(os.Stderr, sb)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	p := newManagedProc(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ngstone share: %v", err)
	}
	t.Cleanup(p.killAndWait)
	return p, sb, stdin
}

// runCLI runs a one-shot ngstone verb against the edge and returns its
// combined output and exit code.
func runCLI(t *testing.T, agentBin, controlAddr, token string, args ...string) (string, int) {
	t.Helper()
	full := append([]string{}, args...)
	full = append(full, "-server", controlAddr, "-token", token, "-insecure")
	cmd := exec.Command(agentBin, full...)
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	t.Logf("$ ngstone %s\n%s(exit %d)", strings.Join(args, " "), out, code)
	return string(out), code
}

var shareIDRe = regexp.MustCompile(`share live\s+id (sh_[0-9a-f]+)`)

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

func shareFixture(t *testing.T, edgeExtra ...string) (edgeBin, agentBin, controlAddr, token, echoAddr string) {
	t.Helper()
	edgeBin, agentBin = buildBinaries(t)
	echoAddr = startTCPEcho(t)
	token = "e2e-share-token"
	controlAddr = freeAddr(t)
	publicAddr := freeAddr(t)
	startEdgeExtra(t, edgeBin, controlAddr, publicAddr, token, "tun.example.com", edgeExtra...)
	return
}

func startEdgeExtra(t *testing.T, edgeBin, controlAddr, publicAddr, token, domain string, extra ...string) (*managedProc, *syncBuf) {
	t.Helper()
	args := []string{
		"-public", publicAddr,
		"-control", controlAddr,
		"-token-sha256", sha256Hex(token),
		"-domain", domain,
		"-public-scheme", "http",
		"-insecure",
		"-ops", "",
	}
	args = append(args, extra...)
	cmd := exec.Command(edgeBin, args...)
	sb := &syncBuf{}
	cmd.Stdout = io.MultiWriter(os.Stderr, sb)
	cmd.Stderr = io.MultiWriter(os.Stderr, sb)
	p := newManagedProc(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ngstoned: %v", err)
	}
	t.Cleanup(p.killAndWait)
	waitForPort(t, controlAddr)
	return p, sb
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

func TestShareManagementVerbs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess share management test in -short mode")
	}
	_, agentBin, controlAddr, token, echoAddr := shareFixture(t)

	sharer, sharerSB := startSharer(t, agentBin, controlAddr, token, echoAddr, "-expires", "10m", "-max-uses", "3")
	link := waitMatch(t, sharerSB, shareLinkRe, 10*time.Second)[1]
	shareID := waitMatch(t, sharerSB, shareIDRe, 10*time.Second)[1]

	out, code := runCLI(t, agentBin, controlAddr, token, "shares")
	if code != 0 || !strings.Contains(out, shareID) || !strings.Contains(out, "e2e db") || !strings.Contains(out, "0/3 uses") {
		t.Fatalf("shares: code=%d out=%q", code, out)
	}

	connector, connSB := startConnector(t, agentBin, link, "-as", "alice")
	waitMatch(t, connSB, listenAddrRe, 15*time.Second)
	waitLogContains(t, sharerSB, "connector joined", 10*time.Second)
	if !strings.Contains(sharerSB.String(), "alice") {
		t.Fatalf("sharer should see the connector's name; got:\n%s", sharerSB.String())
	}
	out, _ = runCLI(t, agentBin, controlAddr, token, "shares")
	if !strings.Contains(out, "connector alice") || !strings.Contains(out, "1/3 uses") {
		t.Fatalf("shares after join: %q", out)
	}
	out, _ = runCLI(t, agentBin, controlAddr, token, "shares", "--json")
	if !strings.Contains(out, `"connector_id"`) && !strings.Contains(out, `"id": "alice"`) {
		t.Fatalf("shares --json: %q", out)
	}

	out, code = runCLI(t, agentBin, controlAddr, token, "extend", shareID, "2h")
	if code != 0 || !strings.Contains(out, "now expires") {
		t.Fatalf("extend: code=%d out=%q", code, out)
	}
	waitLogContains(t, sharerSB, "extended", 10*time.Second)
	waitLogContains(t, connSB, "share extended", 10*time.Second)

	if _, code := runCLI(t, agentBin, controlAddr, token, "kick", shareID, "nobody"); code != 1 {
		t.Fatalf("kick of an unknown connector should fail, got exit %d", code)
	}
	out, code = runCLI(t, agentBin, controlAddr, token, "kick", shareID, "alice")
	if code != 0 {
		t.Fatalf("kick: code=%d out=%q", code, out)
	}
	if code := waitExit(t, connector, 10*time.Second); code != 3 {
		t.Fatalf("kicked connector exit = %d, want 3; output:\n%s", code, connSB.String())
	}
	if !strings.Contains(connSB.String(), "removed this connector") {
		t.Fatalf("kicked connector should say why; got:\n%s", connSB.String())
	}
	waitLogContains(t, sharerSB, "(kicked)", 10*time.Second)

	out, code = runCLI(t, agentBin, controlAddr, token, "unshare", shareID)
	if code != 0 || !strings.Contains(out, "revoked") {
		t.Fatalf("unshare: code=%d out=%q", code, out)
	}
	if code := waitExit(t, sharer, 10*time.Second); code != 0 {
		t.Fatalf("sharer exit after unshare = %d, want 0; output:\n%s", code, sharerSB.String())
	}
	if !strings.Contains(sharerSB.String(), "by another terminal") {
		t.Fatalf("sharer should attribute the revocation; got:\n%s", sharerSB.String())
	}
	if _, code := runCLI(t, agentBin, controlAddr, token, "unshare", shareID); code != 1 {
		t.Fatalf("second unshare should report not found, got exit %d", code)
	}
	out, _ = runCLI(t, agentBin, controlAddr, token, "shares")
	if !strings.Contains(out, "no live shares") {
		t.Fatalf("shares after unshare: %q", out)
	}
}

func TestShareMultiTargetApprovalAndPassphrase(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess multi-target share test in -short mode")
	}
	_, agentBin, controlAddr, token, echo1 := shareFixture(t)
	echo2 := startTCPEcho(t)

	_, sharerSB, sharerIn := startSharerTargets(t, agentBin, controlAddr, token,
		[]string{"tcp:" + echo1, "redis:" + echo2},
		"-expires", "10m", "-approve", "-passphrase", "open-sesame", "-user", "readonly")
	link := waitMatch(t, sharerSB, shareLinkRe, 10*time.Second)[1]
	waitMatch(t, sharerSB, shareLiveRe, 10*time.Second)

	// Wrong passphrase: refused before approval is even asked, and with
	// stdin not a terminal the connector cannot prompt, so it exits 1.
	bad, badSB := startConnector(t, agentBin, link, "-as", "mallory", "-passphrase", "wrong")
	if code := waitExit(t, bad, 15*time.Second); code != 1 {
		t.Fatalf("wrong passphrase exit = %d, want 1; output:\n%s", code, badSB.String())
	}
	if !strings.Contains(badSB.String(), "needs a passphrase") {
		t.Fatalf("wrong passphrase should be reported; got:\n%s", badSB.String())
	}
	waitLogContains(t, sharerSB, "bad_passphrase", 5*time.Second)

	// Right passphrase: parked until the sharer types y.
	connector, connSB := startConnector(t, agentBin, link, "-as", "alice", "-passphrase", "open-sesame")
	waitLogContains(t, sharerSB, "approve?", 10*time.Second)
	waitLogContains(t, connSB, "waiting for the sharer to approve", 10*time.Second)
	if _, err := io.WriteString(sharerIn, "y alice\n"); err != nil {
		t.Fatal(err)
	}
	waitLogContains(t, sharerSB, "connector joined", 15*time.Second)
	waitLogContains(t, connSB, "connected", 15*time.Second)

	// Two listeners, one per target, each relaying to its own echo server.
	listens := regexp.MustCompile(`(?m)^listening\s+(\S+)\s+(\S+)`).FindAllStringSubmatch(connSB.String(), -1)
	if len(listens) != 2 {
		t.Fatalf("expected two listening lines; got:\n%s", connSB.String())
	}
	for _, m := range listens {
		conn, err := net.DialTimeout("tcp", m[1], 5*time.Second)
		if err != nil {
			t.Fatalf("dial %s: %v", m[1], err)
		}
		echoRoundTrip(t, conn, "target-"+m[2]+"\n")
		conn.Close()
	}
	if !strings.Contains(connSB.String(), "redis-cli") {
		t.Fatalf("redis target should carry its hint; got:\n%s", connSB.String())
	}
	waitLogContains(t, sharerSB, "conn #2", 10*time.Second)

	// A second approval request answered with n.
	denied, deniedSB := startConnector(t, agentBin, link, "-as", "bob", "-passphrase", "open-sesame")
	waitLogContains(t, sharerSB, "bob wants to connect", 10*time.Second)
	if _, err := io.WriteString(sharerIn, "n bob\n"); err != nil {
		t.Fatal(err)
	}
	if code := waitExit(t, denied, 15*time.Second); code != 1 {
		t.Fatalf("declined connector exit = %d, want 1; output:\n%s", code, deniedSB.String())
	}
	if !strings.Contains(deniedSB.String(), "approval_denied") {
		t.Fatalf("declined connector should say so; got:\n%s", deniedSB.String())
	}

	// kick typed into the sharer's terminal.
	if _, err := io.WriteString(sharerIn, "kick alice\n"); err != nil {
		t.Fatal(err)
	}
	if code := waitExit(t, connector, 10*time.Second); code != 3 {
		t.Fatalf("kicked connector exit = %d, want 3; output:\n%s", code, connSB.String())
	}
}

func TestShareWatchAndEdgeAuditLog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess share watch test in -short mode")
	}
	auditPath := filepath.Join(t.TempDir(), "edge-audit.jsonl")
	_, agentBin, controlAddr, token, echoAddr := shareFixture(t, "-share-audit-log", auditPath)

	watch := exec.Command(agentBin, "shares", "--watch", "-server", controlAddr, "-token", token, "-insecure")
	watchSB := &syncBuf{}
	watch.Stdout = io.MultiWriter(os.Stderr, watchSB)
	watch.Stderr = io.MultiWriter(os.Stderr, watchSB)
	watchP := newManagedProc(watch)
	if err := watch.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(watchP.killAndWait)
	waitLogContains(t, watchSB, "watching every share", 10*time.Second)

	_, sharerSB := startSharer(t, agentBin, controlAddr, token, echoAddr, "-expires", "5m")
	link := waitMatch(t, sharerSB, shareLinkRe, 10*time.Second)[1]
	waitLogContains(t, watchSB, "share registered", 10*time.Second)

	_, connSB := startConnector(t, agentBin, link, "-as", "carol")
	listenAddr := waitMatch(t, connSB, listenAddrRe, 15*time.Second)[1]
	conn, err := net.DialTimeout("tcp", listenAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	echoRoundTrip(t, conn, "watched\n")
	conn.Close()

	waitLogContains(t, watchSB, "connector joined", 10*time.Second)
	waitLogContains(t, watchSB, "conn #1   closed", 10*time.Second)
	if !strings.Contains(watchSB.String(), "e2e db") {
		t.Fatalf("watch lines should carry the share label; got:\n%s", watchSB.String())
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		data, _ := os.ReadFile(auditPath)
		if strings.Contains(string(data), `"event":"conn_close"`) && strings.Contains(string(data), `"connector_id":"carol"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("edge audit log lacks the expected events; got:\n%s", data)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestShareSecretFileKeepsTheLink(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess share secret-file test in -short mode")
	}
	_, agentBin, controlAddr, token, echoAddr := shareFixture(t)
	secretFile := filepath.Join(t.TempDir(), "share.secret")

	first, firstSB := startSharer(t, agentBin, controlAddr, token, echoAddr, "-expires", "5m", "-secret-file", secretFile)
	link1 := waitMatch(t, firstSB, shareLinkRe, 10*time.Second)[1]
	waitMatch(t, firstSB, shareLiveRe, 10*time.Second)
	first.killAndWait()

	_, secondSB := startSharer(t, agentBin, controlAddr, token, echoAddr, "-expires", "5m", "-secret-file", secretFile)
	link2 := waitMatch(t, secondSB, shareLinkRe, 10*time.Second)[1]
	waitMatch(t, secondSB, shareLiveRe, 15*time.Second)
	if link1 != link2 {
		t.Fatalf("links differ across runs with the same secret file:\n%s\n%s", link1, link2)
	}
	if !strings.Contains(secondSB.String(), "same link as last time") {
		t.Fatalf("second run should say the secret was reused; got:\n%s", secondSB.String())
	}

	_, connSB := startConnector(t, agentBin, link1)
	listenAddr := waitMatch(t, connSB, listenAddrRe, 15*time.Second)[1]
	conn, err := net.DialTimeout("tcp", listenAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	echoRoundTrip(t, conn, "same-link\n")
}
