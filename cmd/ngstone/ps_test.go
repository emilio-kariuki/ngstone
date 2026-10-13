package main

import (
	"strings"
	"testing"
	"time"

	"ngstone/internal/status"
)

func TestFormatPS(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	out := formatPS([]status.Snapshot{
		{PID: 41, Command: "start", Started: now.Add(-90 * time.Minute), Tunnels: []status.Tunnel{
			{Name: "web", Kind: "http", State: "online", URL: "https://web.example.com", Target: "http://127.0.0.1:3000"},
			{Name: "db", Kind: "tcp", State: "reconnecting", Err: "edge-unreachable", Target: "127.0.0.1:5432"},
		}},
		{PID: 42, Command: "port", Started: now.Add(-5 * time.Second), Tunnels: []status.Tunnel{
			{Kind: "http", State: "connecting", Target: "http://127.0.0.1:8080"},
		}},
	}, now)

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d lines, want header plus 3 rows:\n%s", len(lines), out)
	}
	for i, want := range []string{
		"PID  COMMAND  TUNNEL  KIND  STATE",
		"41  start  web  http  online  https://web.example.com  http://127.0.0.1:3000  1h30m",
		"41  start  db  tcp  reconnecting  (edge-unreachable)  -  127.0.0.1:5432  1h30m",
		"42  port  -  http  connecting  -  http://127.0.0.1:8080  5s",
	} {
		if !strings.Contains(squash(lines[i]), want) {
			t.Fatalf("line %d = %q, want it to contain %q", i, lines[i], want)
		}
	}
}

// squash collapses tabwriter padding so tests can compare content.
func squash(s string) string {
	return strings.Join(strings.Fields(s), "  ")
}

func TestFormatUptime(t *testing.T) {
	for d, want := range map[time.Duration]string{-time.Second: "0s", 42 * time.Second: "42s", 3 * time.Minute: "3m", 26*time.Hour + 5*time.Minute: "1d02h", 2*time.Hour + 7*time.Minute: "2h07m"} {
		if got := formatUptime(d); got != want {
			t.Fatalf("formatUptime(%v) = %q, want %q", d, got, want)
		}
	}
}
