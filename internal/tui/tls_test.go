package tui

import (
	"net/url"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"ngstone/internal/inspect"
)

func TestMultiTunnelHeaderListsTLSTunnel(t *testing.T) {
	webURL, _ := url.Parse("http://127.0.0.1:3000")
	m := New(Options{
		Store: inspect.NewStore(),
		Tunnels: []Tunnel{
			{Name: "web", Target: webURL},
			{Name: "secure", Target: &url.URL{Scheme: "tls", Host: "127.0.0.1:8443"}},
		},
	})
	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m = next.(Model)
	next, _ = m.Update(statusMsg{StatusEvent{Tunnel: "secure", State: "online", URL: "tls://secure.example.com"}})
	m = next.(Model)

	header := m.renderHeader()
	if !strings.Contains(header, "tls://secure.example.com -> tls://127.0.0.1:8443") {
		t.Fatalf("header does not list the tls tunnel:\n%s", header)
	}
}
