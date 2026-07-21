package e2e

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestEndToEndSubprocesses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess end-to-end test in -short mode")
	}

	tmp := t.TempDir()
	edgeBin := filepath.Join(tmp, "ngstoned")
	agentBin := filepath.Join(tmp, "ngstone")
	buildBinary(t, edgeBin, "ngstone/cmd/ngstoned")
	buildBinary(t, agentBin, "ngstone/cmd/ngstone")

	const wantBody = "hello from origin\n"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, wantBody)
	}))
	defer origin.Close()

	token := "e2e-test-token"
	domain := "tun.example.com"
	hostname := "demo." + domain
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)

	edgeCmd := exec.Command(edgeBin,
		"-public", publicAddr,
		"-control", controlAddr,
		"-token-sha256", sha256Hex(token),
		"-domain", domain,
	)
	edgeCmd.Stdout = os.Stderr
	edgeCmd.Stderr = os.Stderr
	if err := edgeCmd.Start(); err != nil {
		t.Fatalf("start ngstoned: %v", err)
	}
	defer func() {
		edgeCmd.Process.Kill()
		edgeCmd.Wait()
	}()

	waitForPort(t, controlAddr)

	agentCmd := exec.Command(agentBin,
		"-control", controlAddr,
		"-token", token,
		"-target", origin.URL,
		"-subdomain", "demo",
	)
	agentCmd.Stdout = os.Stderr
	agentCmd.Stderr = os.Stderr
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("start ngstone: %v", err)
	}
	defer func() {
		agentCmd.Process.Kill()
		agentCmd.Wait()
	}()

	waitBound(t, publicAddr, hostname)

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://"+publicAddr+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = hostname

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET through tunnel: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", resp.StatusCode, body)
	}
	if string(body) != wantBody {
		t.Fatalf("body = %q, want %q", body, wantBody)
	}
}
