package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"ngstone/internal/credentials"
	"ngstone/internal/edge"
	"ngstone/internal/status"
	"ngstone/internal/storage"
)

func TestScopedProjectCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess end-to-end test in -short mode")
	}
	bin := filepath.Join(t.TempDir(), "ngstone")
	buildBinary(t, bin, "ngstone/cmd/ngstone")
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "scoped\n") }))
	defer app.Close()
	for _, tc := range []struct{ command, format string }{{"start", "yml"}, {"start", "json"}, {"up", "json"}} {
		t.Run(tc.command+"-"+tc.format, func(t *testing.T) {
			home := t.TempDir()
			env := append(os.Environ(), "XDG_RUNTIME_DIR="+filepath.Join(home, "run"), "XDG_CONFIG_HOME="+filepath.Join(home, "cfg"), "NGSTONE_TOKEN=")
			store, err := storage.Open(storage.Config{DSN: filepath.Join(home, "control.db")})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			for _, name := range []string{"web", "api"} {
				issued, err := store.Issue(credentials.Spec{Kind: credentials.KindHTTP, Subdomain: name, OwnerID: "alice"}, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(home, name+".token"), []byte(issued.Token), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			control, public := freeAddr(t), freeAddr(t)
			server, err := edge.New(edge.Config{Storage: store, ControlAddr: control, PublicAddr: public, Domain: "project.example.com", PublicScheme: "http", Insecure: true})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- server.Run(ctx) }()
			t.Cleanup(func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Errorf("edge shutdown: %v", err)
					}
				case <-time.After(10 * time.Second):
					t.Error("edge did not stop")
				}
			})
			waitForPort(t, control)
			content := fmt.Sprintf(`{"tunnels":{"web":{"target":%q,"server":%q,"insecure":true,"subdomain":"web","credential_file":"web.token","ttl":"4s"},"api":{"target":%q,"server":%q,"insecure":true,"subdomain":"api","credential_file":"api.token"}}}`, app.URL, control, app.URL, control)
			if tc.format == "yml" {
				content = fmt.Sprintf("server: %s\ntunnels:\n  web:\n    url: %s\n    insecure: true\n    subdomain: web\n    credential_file: web.token\n    ttl: 4s\n  api:\n    url: %s\n    insecure: true\n    subdomain: api\n    credential_file: api.token\n", control, app.URL, app.URL)
			}
			path := filepath.Join(home, "ngstone."+tc.format)
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"start", "--config", path, "--no-tui"}
			if tc.command == "up" {
				args = []string{"up", "--file", path, "--json"}
			}
			cmd := exec.Command(bin, args...)
			cmd.Env = env
			log := &syncBuf{}
			cmd.Stdout, cmd.Stderr = log, log
			proc := newManagedProc(cmd)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(proc.killAndWait)
			waitBound(t, public, "web.project.example.com")
			waitBound(t, public, "api.project.example.com")
			ps := func() status.Snapshot {
				query := exec.Command(bin, "ps", "--json")
				query.Env = env
				out, err := query.CombinedOutput()
				if err != nil {
					t.Fatalf("ps: %v\n%s", err, out)
				}
				var snapshots []status.Snapshot
				if err := json.Unmarshal(out, &snapshots); err != nil {
					t.Fatal(err)
				}
				if len(snapshots) != 1 || snapshots[0].PID != cmd.Process.Pid || snapshots[0].Command != tc.command {
					t.Fatalf("process snapshots: %+v", snapshots)
				}
				return snapshots[0]
			}
			if got := ps(); len(got.Tunnels) != 2 || got.Tunnels[0].State != "online" || got.Tunnels[1].State != "online" {
				t.Fatalf("online tunnels: %+v", got)
			}
			waitLogContains(t, log, "expired", 8*time.Second)
			for _, tunnel := range ps().Tunnels {
				want := "online"
				if tunnel.Name == "web" {
					want = "expired"
				}
				if tunnel.State != want {
					t.Fatalf("%s state = %s, want %s", tunnel.Name, tunnel.State, want)
				}
			}
			waitStatus(t, public, "web.project.example.com", "/", http.StatusNotFound, 3*time.Second)
			if code, body, err := doGet(public, "api.project.example.com", "/"); err != nil || code != http.StatusOK || body != "scoped\n" {
				t.Fatalf("live sibling: %d %q %v", code, body, err)
			}
			proc.killAndWait()
			if tc.command != "up" {
				return
			}
			preview, err := store.Issue(credentials.Spec{Kind: credentials.KindPreview, OwnerID: "alice"}, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			cmd = exec.Command(bin, "preview", app.URL, "--server", control, "--token", preview.Token, "--insecure", "--json", "--ttl", "3s")
			cmd.Env = env
			previewLog := &syncBuf{}
			cmd.Stdout, cmd.Stderr = previewLog, previewLog
			previewProc := newManagedProc(cmd)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(previewProc.killAndWait)
			waitBound(t, public, "preview-"+preview.Credential.ID+".project.example.com")
			query := exec.Command(bin, "ps", "--json")
			query.Env = env
			out, err := query.CombinedOutput()
			if err != nil {
				t.Fatal(err)
			}
			var snapshots []status.Snapshot
			if err := json.Unmarshal(out, &snapshots); err != nil {
				t.Fatal(err)
			}
			if len(snapshots) != 1 || snapshots[0].PID != cmd.Process.Pid || len(snapshots[0].Tunnels) != 1 || snapshots[0].Tunnels[0].State != "online" {
				t.Fatalf("preview status: %+v", snapshots)
			}
			waitLogContains(t, previewLog, `"state":"expired"`, 6*time.Second)
			if err := previewProc.wait(); err != nil {
				t.Fatalf("preview exit: %v", err)
			}
		})
	}
}
