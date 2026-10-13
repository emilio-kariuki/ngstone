// Package status lets running ngstone processes report their tunnels to
// `ngstone ps` over a local unix socket, one socket per process.
package status

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"ngstone/internal/config"
)

// Snapshot is one process's view of its tunnels.
type Snapshot struct {
	PID     int       `json:"pid"`
	Command string    `json:"command"` // "port", "tcp", "serve", "start"
	Started time.Time `json:"started"`
	Tunnels []Tunnel  `json:"tunnels"`
}

// Tunnel is one tunnel's current state.
type Tunnel struct {
	Name    string `json:"name,omitempty"` // from ngstone.yml; empty for single-tunnel commands
	Kind    string `json:"kind"`           // "http" or "tcp"
	State   string `json:"state"`          // connecting, online, reconnecting, evicted, offline
	URL     string `json:"url,omitempty"`
	Target  string `json:"target"`
	Err     string `json:"err,omitempty"`
	Evicted bool   `json:"evicted,omitempty"`
}

// Dir is where the sockets live: $XDG_RUNTIME_DIR/ngstone when set,
// otherwise a run/ directory next to the config file.
func Dir() (string, error) {
	if rt := os.Getenv("XDG_RUNTIME_DIR"); rt != "" {
		return filepath.Join(rt, "ngstone"), nil
	}
	cfg, err := config.Path()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfg), "run"), nil
}

func socketPath(dir string, pid int) string {
	return filepath.Join(dir, strconv.Itoa(pid)+".sock")
}

// Serve publishes snapshot() on this process's socket until ctx is done,
// then removes the socket. It returns once the socket is listening, so a
// `ps` run right after start sees the process.
func Serve(ctx context.Context, snapshot func() Snapshot) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := socketPath(dir, os.Getpid())
	_ = os.Remove(path) // a leftover from an earlier process with this pid
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	_ = os.Chmod(path, 0o600)

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/status" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(snapshot())
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go srv.Serve(ln)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		_ = os.Remove(path)
	}()
	return nil
}

// List asks every live ngstone process for its snapshot. Sockets whose
// process is gone are removed. Results are sorted by PID.
func List(ctx context.Context) ([]Snapshot, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var out []Snapshot
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sock") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		snap, err := query(ctx, path)
		if err != nil {
			if isStale(err) {
				_ = os.Remove(path)
			}
			continue
		}
		out = append(out, snap)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out, nil
}

func query(ctx context.Context, path string) (Snapshot, error) {
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://ngstone/status", nil)
	if err != nil {
		return Snapshot{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return Snapshot{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Snapshot{}, fmt.Errorf("status: %s", resp.Status)
	}
	var snap Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

// isStale reports whether an error means nobody is listening on the socket,
// as opposed to a slow or broken process.
func isStale(err error) bool {
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return false
	}
	return errors.Is(opErr.Err, os.ErrNotExist) || strings.Contains(opErr.Err.Error(), "connection refused")
}
