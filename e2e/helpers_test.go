package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func mustSHA256(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeAddr: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitForPort(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to accept connections", addr)
}

func waitBound(t *testing.T, publicAddr, hostname string) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, "http://"+publicAddr+"/__ngstone_ready", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Host = hostname
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for binding on %s (%s)", publicAddr, hostname)
}

func buildBinary(t *testing.T, out, pkg string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", out, pkg)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, output)
	}
}

func buildBinaries(t *testing.T) (edgeBin, agentBin string) {
	t.Helper()
	tmp := t.TempDir()
	edgeBin = filepath.Join(tmp, "ngstoned")
	agentBin = filepath.Join(tmp, "ngstone")
	buildBinary(t, edgeBin, "ngstone/cmd/ngstoned")
	buildBinary(t, agentBin, "ngstone/cmd/ngstone")
	return edgeBin, agentBin
}

type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type managedProc struct {
	cmd  *exec.Cmd
	once sync.Once
	err  error
}

func newManagedProc(cmd *exec.Cmd) *managedProc {
	return &managedProc{cmd: cmd}
}

func (p *managedProc) wait() error {
	p.once.Do(func() { p.err = p.cmd.Wait() })
	return p.err
}

func (p *managedProc) killAndWait() {
	if p.cmd.Process != nil {
		p.cmd.Process.Kill()
	}
	p.wait()
}

func startEdge(t *testing.T, edgeBin, controlAddr, publicAddr, token, domain string) (*managedProc, *syncBuf) {
	t.Helper()
	cmd := exec.Command(edgeBin,
		"-public", publicAddr,
		"-control", controlAddr,
		"-token-sha256", sha256Hex(token),
		"-domain", domain,
		"-public-scheme", "http",
		"-insecure",
		"-ops", "",
	)
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

func startAgent(t *testing.T, agentBin, controlAddr, token, target, subdomain, instanceID string) (*managedProc, *syncBuf) {
	t.Helper()
	args := []string{
		"-control", controlAddr,
		"-token", token,
		"-target", target,
		"-insecure",
	}
	if subdomain != "" {
		args = append(args, "-subdomain", subdomain)
	}
	if instanceID != "" {
		args = append(args, "-instance-id", instanceID)
	}
	cmd := exec.Command(agentBin, args...)
	sb := &syncBuf{}
	cmd.Stdout = io.MultiWriter(os.Stderr, sb)
	cmd.Stderr = io.MultiWriter(os.Stderr, sb)
	p := newManagedProc(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ngstone: %v", err)
	}
	t.Cleanup(p.killAndWait)
	return p, sb
}

func doGet(publicAddr, hostname, path string) (status int, body string, err error) {
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://"+publicAddr+path, nil)
	if err != nil {
		return 0, "", err
	}
	req.Host = hostname
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(b), nil
}

func waitBoundWithin(t *testing.T, publicAddr, hostname string, max time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	deadline := start.Add(max)
	for time.Now().Before(deadline) {
		status, _, err := doGet(publicAddr, hostname, "/")
		if err == nil && status == http.StatusOK {
			return time.Since(start)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s (%s) to bind within %s", publicAddr, hostname, max)
	return 0
}

func waitStatus(t *testing.T, publicAddr, hostname, path string, want int, max time.Duration) {
	t.Helper()
	deadline := time.Now().Add(max)
	var lastStatus int
	var lastErr error
	for time.Now().Before(deadline) {
		status, _, err := doGet(publicAddr, hostname, path)
		lastStatus, lastErr = status, err
		if err == nil && status == want {
			return
		}
		if err == nil && status == http.StatusBadGateway && want != http.StatusBadGateway {
			t.Fatalf("got 502 while waiting for status %d on %s%s; binding was not released", want, hostname, path)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for status %d on %s%s within %s; last status=%d err=%v", want, hostname, path, max, lastStatus, lastErr)
}

func waitLogContains(t *testing.T, sb *syncBuf, substr string, max time.Duration) {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if strings.Contains(sb.String(), substr) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for log output to contain %q; got:\n%s", substr, sb.String())
}

func newSlowOrigin(hold time.Duration) (srv *httptest.Server, started <-chan struct{}) {
	ch := make(chan struct{})
	var once sync.Once

	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "start\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		once.Do(func() { close(ch) })
		time.Sleep(hold)
		io.WriteString(w, "done\n")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok\n")
	})

	return httptest.NewServer(mux), ch
}
