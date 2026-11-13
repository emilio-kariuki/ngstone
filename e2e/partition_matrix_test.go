package e2e

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestPartitionKillAgentMidRequest(t *testing.T) {
	partitionKillAgentMidRequest(t, 10*time.Second, false)
}

func partitionKillAgentMidRequest(t *testing.T, detectBound time.Duration, allowBadGateway bool) {
	if testing.Short() {
		t.Skip("skipping partition matrix test in -short mode")
	}

	edgeBin, agentBin := buildBinaries(t)
	origin, _ := newSlowOrigin(3 * time.Second)
	defer origin.Close()

	token := "tok-kill-mid-request"
	domain := "kill.example.com"
	hostname := "app." + domain
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)

	startEdge(t, edgeBin, controlAddr, publicAddr, token, domain)
	agentProc, _ := startAgent(t, agentBin, controlAddr, token, origin.URL, "app", "")
	waitBound(t, publicAddr, hostname)

	type result struct {
		status  int
		body    string
		doErr   error
		bodyErr error
	}
	resCh := make(chan result, 1)
	started := make(chan struct{})
	go func() {
		client := &http.Client{Timeout: 10 * time.Second}
		req, err := http.NewRequest(http.MethodGet, "http://"+publicAddr+"/slow", nil)
		if err != nil {
			resCh <- result{doErr: err}
			return
		}
		req.Host = hostname
		resp, err := client.Do(req)
		if err != nil {
			resCh <- result{doErr: err}
			return
		}
		defer resp.Body.Close()
		close(started)
		b, berr := io.ReadAll(resp.Body)
		resCh <- result{status: resp.StatusCode, body: string(b), bodyErr: berr}
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("client never received response headers for the in-flight request")
	}

	killedAt := time.Now()
	if err := agentProc.cmd.Process.Kill(); err != nil {
		t.Fatalf("kill -9 agent: %v", err)
	}
	agentProc.wait()

	res := <-resCh
	switch {
	case res.doErr != nil:
		t.Logf("in-flight request failed at the transport level (acceptable): %v", res.doErr)
	case res.bodyErr != nil:
		t.Logf("in-flight request got status %d then a body read error (acceptable): %v; partial body=%q", res.status, res.bodyErr, res.body)
	default:
		t.Fatalf("expected the in-flight request to fail after kill -9, but it completed cleanly: status=%d body=%q", res.status, res.body)
	}

	if allowBadGateway {
		waitNotFoundThrough502(t, publicAddr, hostname, "/", detectBound-time.Since(killedAt))
		t.Logf("agent kill detected %s after the kill", time.Since(killedAt))
	} else {
		waitStatus(t, publicAddr, hostname, "/", http.StatusNotFound, detectBound)
	}
	t.Log("confirmed: subsequent request got 404, not 502, after agent death")

	startAgent(t, agentBin, controlAddr, token, origin.URL, "app", "")
	elapsed := waitBoundWithin(t, publicAddr, hostname, 15*time.Second)
	t.Logf("agent restart recovery took %s", elapsed)

	status, body, err := doGet(publicAddr, hostname, "/")
	if err != nil || status != http.StatusOK || body != "ok\n" {
		t.Fatalf("restarted agent should serve 200: status=%d body=%q err=%v", status, body, err)
	}
}

func TestPartitionInstantTakeoverPastHalfOpenPeer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping partition matrix test in -short mode")
	}

	edgeBin, agentBin := buildBinaries(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok\n")
	}))
	defer origin.Close()

	token := "tok-instant-takeover"
	domain := "takeover.example.com"
	hostname := "svc." + domain
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)
	const instanceID = "fixed-instance-half-open"

	startEdge(t, edgeBin, controlAddr, publicAddr, token, domain)

	agentA, _ := startAgent(t, agentBin, controlAddr, token, origin.URL, "svc", instanceID)
	waitBound(t, publicAddr, hostname)

	if err := agentA.cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatalf("SIGSTOP agent A: %v", err)
	}
	t.Cleanup(func() {
		agentA.cmd.Process.Signal(syscall.SIGCONT)
	})

	startAgent(t, agentBin, controlAddr, token, origin.URL, "svc", instanceID)

	const bound = 10 * time.Second
	elapsed := waitBoundWithin(t, publicAddr, hostname, bound)
	t.Logf("instant takeover past half-open peer: rebind took %s (must stay well under the 45s dead-peer window; asserted bound was %s)", elapsed, bound)

	status, body, err := doGet(publicAddr, hostname, "/")
	if err != nil || status != http.StatusOK || body != "ok\n" {
		t.Fatalf("agent B should be serving after instant takeover: status=%d body=%q err=%v", status, body, err)
	}

	agentA.cmd.Process.Signal(syscall.SIGCONT)
}

func TestPartitionInstantTCPTakeoverPastHalfOpenPeer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping partition matrix test in -short mode")
	}

	edgeBin, agentBin := buildBinaries(t)
	echoAddr := startTCPEcho(t)

	token := "tok-instant-tcp-takeover"
	domain := "tcptakeover.example.com"
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)
	tcpLo, tcpHi := freeTCPRange(t, 30)
	const instanceID = "fixed-instance-tcp-half-open"

	startEdgeTCP(t, edgeBin, controlAddr, publicAddr, token, domain, tcpLo, tcpHi)

	agentA, sbA := startAgentTCPWithInstanceID(t, agentBin, controlAddr, token, echoAddr, 0, "", instanceID)
	port := waitTCPAssignedPort(t, sbA, 15*time.Second)
	waitForPort(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	echoRoundTrip(t, dialTunnel(t, port), "before-takeover\n")

	if err := agentA.cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatalf("SIGSTOP agent A: %v", err)
	}
	t.Cleanup(func() {
		agentA.cmd.Process.Signal(syscall.SIGCONT)
	})

	_, sbB := startAgentTCPWithInstanceID(t, agentBin, controlAddr, token, echoAddr, port, "", instanceID)

	const bound = 10 * time.Second
	start := time.Now()
	got := waitTCPAssignedPort(t, sbB, bound)
	t.Logf("instant tcp takeover past half-open peer: rebind took %s (asserted bound was %s)", time.Since(start), bound)
	if got != port {
		t.Fatalf("agent B advertised tcp port %d, want the port agent A held (%d)", got, port)
	}

	echoRoundTrip(t, dialTunnel(t, port), "after-takeover\n")

	agentA.cmd.Process.Signal(syscall.SIGCONT)
}

type controlRelay struct {
	addr      string
	mu        sync.Mutex
	agentSide []net.Conn
	edgeSide  []net.Conn
}

func startControlRelay(t *testing.T, target string) *controlRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	r := &controlRelay{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			r.mu.Lock()
			r.agentSide = append(r.agentSide, c)
			r.edgeSide = append(r.edgeSide, up)
			r.mu.Unlock()
			go io.Copy(up, c)
			go io.Copy(c, up)
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, c := range append(r.agentSide, r.edgeSide...) {
			c.Close()
		}
	})
	return r
}

func (r *controlRelay) dropAgentSides() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.agentSide {
		c.Close()
	}
	r.agentSide = nil
}

func TestPartitionAutoPortTCPRebindsRememberedPortPastHalfOpenSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping partition matrix test in -short mode")
	}

	edgeBin, agentBin := buildBinaries(t)
	echoAddr := startTCPEcho(t)

	token := "tok-auto-port-rebind"
	domain := "autoport.example.com"
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)
	tcpLo, tcpHi := freeTCPRange(t, 30)
	const instanceID = "fixed-instance-auto-port"

	startEdgeTCP(t, edgeBin, controlAddr, publicAddr, token, domain, tcpLo, tcpHi)
	relay := startControlRelay(t, controlAddr)

	_, sb := startAgentTCPWithInstanceID(t, agentBin, relay.addr, token, echoAddr, 0, "", instanceID)
	port := waitTCPAssignedPort(t, sb, 15*time.Second)
	waitForPort(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	echoRoundTrip(t, dialTunnel(t, port), "before-drop\n")

	relay.dropAgentSides()

	const bound = 10 * time.Second
	start := time.Now()
	var adverts [][]string
	for time.Now().Before(start.Add(bound)) {
		if adverts = tcpAdvertRe.FindAllStringSubmatch(sb.String(), -1); len(adverts) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(adverts) < 2 {
		t.Fatalf("agent did not re-advertise a tcp port within %s of the control drop:\n%s", bound, sb.String())
	}
	t.Logf("auto-port rebind past half-open session took %s (asserted bound was %s, the keepalive timeout is 45s)", time.Since(start), bound)
	if got, _ := strconv.Atoi(adverts[len(adverts)-1][1]); got != port {
		t.Fatalf("agent re-advertised tcp port %d, want the remembered port %d", got, port)
	}

	echoRoundTrip(t, dialTunnel(t, port), "after-rebind\n")
}

func TestPartitionDifferentInstanceRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping partition matrix test in -short mode")
	}

	edgeBin, agentBin := buildBinaries(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok\n")
	}))
	defer origin.Close()

	token := "tok-different-instance"
	domain := "refuse.example.com"
	hostname := "svc." + domain
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)

	startEdge(t, edgeBin, controlAddr, publicAddr, token, domain)

	startAgent(t, agentBin, controlAddr, token, origin.URL, "svc", "instance-a")
	waitBound(t, publicAddr, hostname)

	status, body, err := doGet(publicAddr, hostname, "/")
	if err != nil || status != http.StatusOK || body != "ok\n" {
		t.Fatalf("agent A should be serving before the refused takeover attempt: status=%d body=%q err=%v", status, body, err)
	}

	agentB, sbB := startAgent(t, agentBin, controlAddr, token, origin.URL, "svc", "instance-b")
	waitErr := agentB.wait()

	if waitErr == nil {
		t.Fatalf("expected agent B to exit non-zero when a different live instance holds the subdomain")
	}
	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) {
		t.Fatalf("expected agent B to fail with *exec.ExitError, got %T: %v", waitErr, waitErr)
	}
	if exitErr.ExitCode() == 0 {
		t.Fatalf("expected agent B exit code != 0, got 0")
	}
	if !strings.Contains(sbB.String(), "subdomain_taken") {
		t.Fatalf("expected agent B's output to mention subdomain_taken, got:\n%s", sbB.String())
	}
	t.Logf("agent B correctly refused: exit code %d, output mentions subdomain_taken", exitErr.ExitCode())

	status, body, err = doGet(publicAddr, hostname, "/")
	if err != nil || status != http.StatusOK || body != "ok\n" {
		t.Fatalf("agent A must keep serving 200 after the refused takeover attempt: status=%d body=%q err=%v", status, body, err)
	}
}

func TestPartitionTakeoverVictimEvicted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping partition matrix test in -short mode")
	}

	edgeBin, agentBin := buildBinaries(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok\n")
	}))
	defer origin.Close()

	token := "tok-evicted"
	domain := "evict.example.com"
	hostname := "svc." + domain
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)
	const instanceID = "fixed-instance-evict"

	startEdge(t, edgeBin, controlAddr, publicAddr, token, domain)

	agentA, sbA := startAgent(t, agentBin, controlAddr, token, origin.URL, "svc", instanceID)
	waitBound(t, publicAddr, hostname)

	startAgent(t, agentBin, controlAddr, token, origin.URL, "svc", instanceID)
	waitBoundWithin(t, publicAddr, hostname, 10*time.Second)

	waitLogContains(t, sbA, "evicted", 10*time.Second)
	if !strings.Contains(sbA.String(), "no longer advertising") {
		t.Fatalf("expected agent A's log to show it stopped advertising the URL, got:\n%s", sbA.String())
	}
	t.Log("confirmed: evicted agent logged eviction and stopped advertising its URL")

	agentA.killAndWait()

	status, body, err := doGet(publicAddr, hostname, "/")
	if err != nil || status != http.StatusOK || body != "ok\n" {
		t.Fatalf("agent B should be serving after evicting A: status=%d body=%q err=%v", status, body, err)
	}
}

func TestPartitionEdgeRestart(t *testing.T) {
	partitionEdgeRestart(t, 30*time.Second)
}

func partitionEdgeRestart(t *testing.T, rebindBound time.Duration) {
	if testing.Short() {
		t.Skip("skipping partition matrix test in -short mode")
	}

	edgeBin, agentBin := buildBinaries(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok\n")
	}))
	defer origin.Close()

	token := "tok-edge-restart"
	domain := "restart.example.com"
	hostname := "svc." + domain
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)

	edgeProc, _ := startEdge(t, edgeBin, controlAddr, publicAddr, token, domain)
	startAgent(t, agentBin, controlAddr, token, origin.URL, "svc", "")
	waitBound(t, publicAddr, hostname)

	status, body, err := doGet(publicAddr, hostname, "/")
	if err != nil || status != http.StatusOK || body != "ok\n" {
		t.Fatalf("sanity check before restart failed: status=%d body=%q err=%v", status, body, err)
	}

	if err := edgeProc.cmd.Process.Kill(); err != nil {
		t.Fatalf("kill edge: %v", err)
	}
	edgeProc.wait()

	startEdge(t, edgeBin, controlAddr, publicAddr, token, domain)

	elapsed := waitBoundWithin(t, publicAddr, hostname, rebindBound)
	t.Logf("edge restart recovery took %s", elapsed)

	status, body, err = doGet(publicAddr, hostname, "/")
	if err != nil || status != http.StatusOK || body != "ok\n" {
		t.Fatalf("agent should be serving again after edge restart: status=%d body=%q err=%v", status, body, err)
	}
}

func TestPartitionGracefulDrainAgentSIGTERM(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping partition matrix test in -short mode")
	}

	edgeBin, agentBin := buildBinaries(t)
	origin, started := newSlowOrigin(2 * time.Second)
	defer origin.Close()

	token := "tok-drain-agent"
	domain := "drain-agent.example.com"
	hostname := "svc." + domain
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)

	startEdge(t, edgeBin, controlAddr, publicAddr, token, domain)
	agentProc, _ := startAgent(t, agentBin, controlAddr, token, origin.URL, "svc", "")
	waitBound(t, publicAddr, hostname)

	type result struct {
		status  int
		body    string
		doErr   error
		bodyErr error
	}
	resCh := make(chan result, 1)
	go func() {
		client := &http.Client{Timeout: 20 * time.Second}
		req, err := http.NewRequest(http.MethodGet, "http://"+publicAddr+"/slow", nil)
		if err != nil {
			resCh <- result{doErr: err}
			return
		}
		req.Host = hostname
		resp, err := client.Do(req)
		if err != nil {
			resCh <- result{doErr: err}
			return
		}
		defer resp.Body.Close()
		b, berr := io.ReadAll(resp.Body)
		resCh <- result{status: resp.StatusCode, body: string(b), bodyErr: berr}
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("origin never started responding to the in-flight request")
	}

	if err := agentProc.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM agent: %v", err)
	}

	sawUnrouted := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		status, _, err := doGet(publicAddr, hostname, "/")
		if err == nil && status == http.StatusNotFound {
			sawUnrouted = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !sawUnrouted {
		t.Fatalf("expected new requests to stop being routed (404) shortly after agent SIGTERM/goodbye")
	}
	t.Log("confirmed: new requests stopped being routed shortly after agent SIGTERM")

	res := <-resCh
	if res.doErr != nil {
		t.Fatalf("in-flight request during agent drain should complete successfully (drain, not abort), got transport error: %v", res.doErr)
	}
	if res.bodyErr != nil {
		t.Fatalf("in-flight request during agent drain should complete successfully, got body read error: %v (partial body=%q)", res.bodyErr, res.body)
	}
	if res.status != http.StatusOK || res.body != "start\ndone\n" {
		t.Fatalf("in-flight request during agent drain: status=%d body=%q, want 200 and full body %q", res.status, res.body, "start\ndone\n")
	}
	t.Log("confirmed: in-flight request completed successfully through agent SIGTERM drain")

	if err := agentProc.wait(); err != nil {
		t.Logf("agent process exit: %v (informational)", err)
	}
}

func TestPartitionGracefulDrainEdgeSIGTERM(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping partition matrix test in -short mode")
	}

	edgeBin, agentBin := buildBinaries(t)
	origin, started := newSlowOrigin(2 * time.Second)
	defer origin.Close()

	token := "tok-drain-edge"
	domain := "drain-edge.example.com"
	hostname := "svc." + domain
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)

	edgeProc, _ := startEdge(t, edgeBin, controlAddr, publicAddr, token, domain)
	startAgent(t, agentBin, controlAddr, token, origin.URL, "svc", "")
	waitBound(t, publicAddr, hostname)

	type result struct {
		status  int
		body    string
		doErr   error
		bodyErr error
	}
	resCh := make(chan result, 1)
	go func() {
		client := &http.Client{Timeout: 20 * time.Second}
		req, err := http.NewRequest(http.MethodGet, "http://"+publicAddr+"/slow", nil)
		if err != nil {
			resCh <- result{doErr: err}
			return
		}
		req.Host = hostname
		resp, err := client.Do(req)
		if err != nil {
			resCh <- result{doErr: err}
			return
		}
		defer resp.Body.Close()
		b, berr := io.ReadAll(resp.Body)
		resCh <- result{status: resp.StatusCode, body: string(b), bodyErr: berr}
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("origin never started responding to the in-flight request")
	}

	if err := edgeProc.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM edge: %v", err)
	}

	res := <-resCh
	if res.doErr != nil {
		t.Fatalf("in-flight request during edge drain should complete successfully (drain, not abort), got transport error: %v — per ARCHITECTURE.md §3 the edge should mirror the agent's Goodbye+drain on shutdown before closing sessions", res.doErr)
	}
	if res.bodyErr != nil {
		t.Fatalf("in-flight request during edge drain should complete successfully, got body read error: %v (partial body=%q) — per ARCHITECTURE.md §3 the edge should mirror the agent's Goodbye+drain on shutdown before closing sessions", res.bodyErr, res.body)
	}
	if res.status != http.StatusOK || res.body != "start\ndone\n" {
		t.Fatalf("in-flight request during edge drain: status=%d body=%q, want 200 and full body %q", res.status, res.body, "start\ndone\n")
	}
	t.Log("confirmed: in-flight request completed successfully through edge SIGTERM drain")

	if err := edgeProc.wait(); err != nil {
		t.Logf("edge process exit: %v (informational)", err)
	}
}
