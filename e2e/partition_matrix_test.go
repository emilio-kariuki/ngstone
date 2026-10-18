package e2e

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPartitionKillAgentMidRequest(t *testing.T) {
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

	waitStatus(t, publicAddr, hostname, "/", http.StatusNotFound, 10*time.Second)
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

	elapsed := waitBoundWithin(t, publicAddr, hostname, 30*time.Second)
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
