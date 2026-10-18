package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type alertEvent struct {
	Type       string            `json:"type"`
	OccurredAt time.Time         `json:"occurred_at"`
	TunnelID   string            `json:"tunnel_id,omitempty"`
	Hostname   string            `json:"hostname,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type alertDispatcher struct {
	url       string
	token     string
	client    *http.Client
	events    chan alertEvent
	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
	wg        sync.WaitGroup
}

func newAlertDispatcher(rawURL, token string) (*alertDispatcher, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("alert webhook URL must be an http(s) URL without credentials, query, or fragment")
	}
	dispatcher := &alertDispatcher{
		url:    u.String(),
		token:  strings.TrimSpace(token),
		client: &http.Client{Timeout: 5 * time.Second},
		events: make(chan alertEvent, 128),
	}
	dispatcher.wg.Add(1)
	go dispatcher.run()
	return dispatcher, nil
}

func (d *alertDispatcher) run() {
	defer d.wg.Done()
	for event := range d.events {
		d.deliver(event)
	}
}

func (d *alertDispatcher) emit(event alertEvent) {
	if d == nil {
		return
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	select {
	case d.events <- event:
	default:
		slog.Warn("edge: alert webhook queue full", "event", event.Type)
	}
}

func (d *alertDispatcher) deliver(event alertEvent) {
	body, err := json.Marshal(event)
	if err != nil {
		slog.Warn("edge: alert webhook encoding failed", "event", event.Type, "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(body))
	if err != nil {
		slog.Warn("edge: alert webhook request failed", "event", event.Type, "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if d.token != "" {
		req.Header.Set("Authorization", "Bearer "+d.token)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		slog.Warn("edge: alert webhook delivery failed", "event", event.Type, "err", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		slog.Warn("edge: alert webhook delivery failed", "event", event.Type, "status", resp.StatusCode)
	}
}

func (d *alertDispatcher) close() {
	if d == nil {
		return
	}
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		close(d.events)
		d.mu.Unlock()
	})
	d.wg.Wait()
}
