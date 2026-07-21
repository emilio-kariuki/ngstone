package tui

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	tea "github.com/charmbracelet/bubbletea"

	"ngstone/internal/inspect"
)

type StatusEvent struct {
	State    string
	Hostname string
	URL      string
	Err      error
}

type Options struct {
	Store  *inspect.Store
	Target *url.URL
	RT     http.RoundTripper
	Status <-chan StatusEvent
	Logs   *LogRing
}

func Run(ctx context.Context, opts Options) error {
	if opts.Store == nil {
		return errors.New("tui: opts.Store is required")
	}
	m := New(opts)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithContext(ctx))
	_, err := p.Run()
	if m.unsub != nil {
		m.unsub()
	}
	if err != nil && ctx.Err() != nil {
		return nil
	}
	return err
}
