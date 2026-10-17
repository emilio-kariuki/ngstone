package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// `ngstone ps` lists the tunnels of a running `ngstone start` process, and
// shows nothing once it has stopped.
func TestPSListsRunningTunnels(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess end-to-end test in -short mode")
	}
	edgeBin, agentBin := buildBinaries(t)

	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") }))
	defer app.Close()

	token := "e2e-ps-token"
	domain := "ps.example.com"
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)
	startEdge(t, edgeBin, controlAddr, publicAddr, token, domain)

	home := t.TempDir()
	env := append(os.Environ(), "XDG_RUNTIME_DIR="+filepath.Join(home, "run"), "XDG_CONFIG_HOME="+filepath.Join(home, "cfg"))

	cfgPath := filepath.Join(home, "ngstone.yml")
	os.WriteFile(cfgPath, []byte(fmt.Sprintf("server: %s\ntunnels:\n  web:\n    url: %s\n    subdomain: web\n", controlAddr, app.URL)), 0o600)

	cmd := exec.Command(agentBin, "start", "--config", cfgPath, "--no-tui", "--insecure", "--token", token)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	p := newManagedProc(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(p.killAndWait)
	waitBound(t, publicAddr, "web."+domain)

	ps := func(args ...string) string {
		c := exec.Command(agentBin, append([]string{"ps"}, args...)...)
		c.Env = env
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("ngstone ps %v: %v\n%s", args, err, out)
		}
		return string(out)
	}

	out := ps()
	for _, want := range []string{"web", "online", "http://web." + domain, app.URL, "start"} {
		if !strings.Contains(out, want) {
			t.Fatalf("ps output missing %q:\n%s", want, out)
		}
	}

	var snaps []struct {
		PID     int `json:"pid"`
		Tunnels []struct {
			Name, State, URL string
		} `json:"tunnels"`
	}
	if err := json.Unmarshal([]byte(ps("--json")), &snaps); err != nil {
		t.Fatalf("ps --json: %v", err)
	}
	if len(snaps) != 1 || snaps[0].PID != cmd.Process.Pid || len(snaps[0].Tunnels) != 1 || snaps[0].Tunnels[0].State != "online" {
		t.Fatalf("ps --json = %+v, want one process with one online tunnel", snaps)
	}

	p.killAndWait()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if out := ps(); strings.Contains(out, "no running ngstone tunnels") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ps still lists the stopped process:\n%s", ps())
		}
		time.Sleep(100 * time.Millisecond)
	}
}
