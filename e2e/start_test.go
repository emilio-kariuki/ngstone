package e2e

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// One `ngstone start` process runs every tunnel in the file: two HTTP
// tunnels to different local apps and a TCP tunnel on a fixed port.
func TestStartRunsEveryTunnelInTheFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess end-to-end test in -short mode")
	}
	edgeBin, agentBin := buildBinaries(t)

	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "web\n") }))
	defer web.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "api\n") }))
	defer api.Close()
	echoAddr := startTCPEcho(t)

	token := "e2e-start-token"
	domain := "start.example.com"
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)
	tcpLo, tcpHi := freeTCPRange(t, 10)
	startEdgeTCP(t, edgeBin, controlAddr, publicAddr, token, domain, tcpLo, tcpHi)

	cfg := fmt.Sprintf(`server: %s
tunnels:
  web:
    url: %s
    subdomain: web
  api:
    url: %s
    subdomain: api
  echo:
    kind: tcp
    address: %s
    remote_port: %d
`, controlAddr, web.URL, api.URL, echoAddr, tcpLo)
	path := filepath.Join(t.TempDir(), "ngstone.yml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(agentBin, "start", "--config", path, "--no-tui", "--insecure", "--token", token)
	sb := &syncBuf{}
	cmd.Stdout = io.MultiWriter(os.Stderr, sb)
	cmd.Stderr = io.MultiWriter(os.Stderr, sb)
	p := newManagedProc(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(p.killAndWait)

	waitBound(t, publicAddr, "web."+domain)
	waitBound(t, publicAddr, "api."+domain)
	for host, want := range map[string]string{"web." + domain: "web\n", "api." + domain: "api\n"} {
		status, body, err := doGet(publicAddr, host, "/")
		if err != nil || status != http.StatusOK || body != want {
			t.Fatalf("%s: status=%d body=%q err=%v, want %q", host, status, body, err, want)
		}
	}

	tcpAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpLo))
	waitForPort(t, tcpAddr)
	conn := dialTunnel(t, tcpLo)
	echoRoundTrip(t, conn, "hello-from-start\n")

	waitLogContains(t, sb, "web", 5*time.Second)
	waitLogContains(t, sb, "tcp://", 5*time.Second)
}
