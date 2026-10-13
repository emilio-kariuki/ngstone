package e2e

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestServeSharesADirectoryThroughTheTunnel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess end-to-end test in -short mode")
	}
	edgeBin, agentBin := buildBinaries(t)

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>app</h1>"), 0o644)
	os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello from serve"), 0o644)

	token := "e2e-serve-token"
	domain := "serve.example.com"
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)
	startEdge(t, edgeBin, controlAddr, publicAddr, token, domain)

	cmd := exec.Command(agentBin, "serve", dir, "--spa", "--subdomain", "files", "--server", controlAddr, "--token", token, "--insecure", "--no-tui")
	cmd.Stdout = io.MultiWriter(os.Stderr)
	cmd.Stderr = io.MultiWriter(os.Stderr)
	p := newManagedProc(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("serve: %v", err)
	}
	t.Cleanup(p.killAndWait)
	waitBound(t, publicAddr, "files."+domain)

	status, body, err := doGet(publicAddr, "files."+domain, "/hello.txt")
	if err != nil || status != http.StatusOK || body != "hello from serve" {
		t.Fatalf("/hello.txt: status=%d body=%q err=%v", status, body, err)
	}
	status, body, err = doGet(publicAddr, "files."+domain, "/some/client/route")
	if err != nil || status != http.StatusOK || body != "<h1>app</h1>" {
		t.Fatalf("spa route: status=%d body=%q err=%v", status, body, err)
	}
	status, _, _ = doGet(publicAddr, "files."+domain, "/missing.css")
	if status != http.StatusNotFound {
		t.Fatalf("/missing.css status=%d, want 404", status)
	}
}
