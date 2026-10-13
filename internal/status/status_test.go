package status

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestServeAndListRoundTrip(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	snap := Snapshot{PID: os.Getpid(), Command: "start", Started: time.Now().Truncate(time.Second),
		Tunnels: []Tunnel{{Name: "web", Kind: "http", State: "online", URL: "https://web.example.com", Target: "http://127.0.0.1:3000"}}}
	if err := Serve(ctx, func() Snapshot { return snap }); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	got, err := List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].PID != snap.PID || got[0].Command != "start" || len(got[0].Tunnels) != 1 || got[0].Tunnels[0].URL != snap.Tunnels[0].URL {
		t.Fatalf("List = %+v, want the served snapshot", got)
	}

	cancel()
	dir, _ := Dir()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(socketPath(dir, os.Getpid())); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket not removed after the context ended")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestListRemovesStaleSocketsAndIgnoresOtherFiles(t *testing.T) {
	rt := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", rt)
	dir := filepath.Join(rt, "ngstone")
	os.MkdirAll(dir, 0o700)

	// A socket file whose process is gone: nothing listens on it.
	stale := socketPath(dir, 999999)
	ln, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	ln.Close() // Go removes the file on Close, so recreate it as a dead socket
	ln2, _ := net.Listen("unix", stale)
	os.Rename(stale, stale+".keep")
	ln2.Close()
	os.Rename(stale+".keep", stale)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600)

	got, err := List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("List = %+v, want nothing", got)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale socket was not removed")
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatal("unrelated file was removed")
	}
}

func TestListWithNoDirIsEmpty(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(t.TempDir(), "missing"))
	got, err := List(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("List = %v, %v; want empty and no error", got, err)
	}
}

func TestDirFallsBackToConfigDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", "/tmp/cfgtest")
	dir, err := Dir()
	if err != nil || dir != filepath.Join("/tmp/cfgtest", "ngstone", "run") {
		t.Fatalf("Dir = %q, %v", dir, err)
	}
	_ = strconv.Itoa
}
