package edge

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestAlertDispatcherDeliversLifecycleEvent(t *testing.T) {
	var mu sync.Mutex
	var received *http.Request
	dispatcher := &alertDispatcher{
		url:    "https://alerts.example.test/hook",
		token:  "hook-secret",
		events: make(chan alertEvent, 1),
		client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			mu.Lock()
			received = request
			mu.Unlock()
			return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: request}, nil
		})},
	}
	dispatcher.wg.Add(1)
	go dispatcher.run()
	dispatcher.emit(alertEvent{Type: "connector_reconnected", TunnelID: "tunnel-1", Hostname: "demo.example.com"})
	dispatcher.close()
	mu.Lock()
	defer mu.Unlock()
	if received == nil {
		t.Fatal("webhook did not receive an event")
	}
	if received.Header.Get("Authorization") != "Bearer hook-secret" {
		t.Fatalf("authorization = %q", received.Header.Get("Authorization"))
	}
}

func TestNewAlertDispatcherRejectsUnsafeURL(t *testing.T) {
	for _, raw := range []string{"", "ftp://alerts.example.test/hook", "https://user:pass@alerts.example.test/hook", "https://alerts.example.test/hook#fragment"} {
		dispatcher, err := newAlertDispatcher(raw, "")
		if raw == "" {
			if err != nil || dispatcher != nil {
				t.Fatalf("empty webhook = %#v, %v", dispatcher, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("newAlertDispatcher(%q) succeeded", raw)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
