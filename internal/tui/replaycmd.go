package tui

import (
	"context"
	"net/http"
	"net/url"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"ngstone/internal/inspect"
)

func replayCmd(store *inspect.Store, target *url.URL, rt http.RoundTripper, id string, ov *inspect.Overrides) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ex, err := store.Replay(ctx, id, target, rt, ov)
		return replayResultMsg{sourceID: id, ex: ex, err: err}
	}
}
