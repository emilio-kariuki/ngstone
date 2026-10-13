package tui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"ngstone/internal/inspect"
)

func TestMultiTunnelHeaderAndReplayRouting(t *testing.T) {
	webURL, _ := url.Parse("http://127.0.0.1:3000")
	apiURL, _ := url.Parse("http://127.0.0.1:8080")
	webRT := &http.Transport{}
	apiRT := &http.Transport{}

	m := New(Options{
		Store: inspect.NewStore(),
		Tunnels: []Tunnel{
			{Name: "web", Target: webURL, RT: webRT},
			{Name: "api", Target: apiURL, RT: apiRT},
		},
	})
	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m = next.(Model)
	next, _ = m.Update(statusMsg{StatusEvent{Tunnel: "web", State: "online", URL: "https://web.example.com"}})
	m = next.(Model)

	header := m.renderHeader()
	for _, want := range []string{"1 of 2 tunnels online", "web", "https://web.example.com -> http://127.0.0.1:3000", "api", "-> http://127.0.0.1:8080"} {
		if !strings.Contains(header, want) {
			t.Fatalf("header missing %q:\n%s", want, header)
		}
	}
	if got := len(strings.Split(header, "\n")); got != m.headerLines() {
		t.Fatalf("header renders %d lines but layout reserves %d", got, m.headerLines())
	}

	target, rt := m.replayTarget(&inspect.Exchange{Tunnel: "api"})
	if target != apiURL || rt != apiRT {
		t.Fatalf("api exchange replays to %v, want the api tunnel's target", target)
	}
	target, rt = m.replayTarget(&inspect.Exchange{Tunnel: "web"})
	if target != webURL || rt != webRT {
		t.Fatalf("web exchange replays to %v, want the web tunnel's target", target)
	}
}

func TestSingleTunnelHeaderUnchanged(t *testing.T) {
	m := New(Options{Store: inspect.NewStore()})
	if m.headerLines() != headerHeight {
		t.Fatalf("single-tunnel header lines = %d, want %d", m.headerLines(), headerHeight)
	}
	if !strings.Contains(m.renderHeader(), "Forwarding") {
		t.Fatal("single-tunnel header changed")
	}
}

func TestRowShowsTunnelName(t *testing.T) {
	row := renderRow(&inspect.Exchange{Tunnel: "api", Req: inspect.CapturedReq{Method: "GET", URL: "http://x/users"}}, 80, false, false)
	if !strings.Contains(row, "api") || !strings.Contains(row, "/users") {
		t.Fatalf("row %q does not show the tunnel name and path", row)
	}
}
