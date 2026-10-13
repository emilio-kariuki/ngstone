package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCheckHealth(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{name: "healthy", status: http.StatusOK, body: `{"ok":true}`},
		{name: "certificates missing", status: http.StatusServiceUnavailable, body: `{"ok":false,"apex_cert":{"error":"no cert"}}`, wantErr: "no cert"},
		{name: "not found", status: http.StatusNotFound, body: "not here", wantErr: "404"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			err := checkHealth(context.Background(), srv.URL+"/healthz")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("checkHealth: unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("checkHealth error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestCheckHealthUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL + "/healthz"
	srv.Close()

	if err := checkHealth(context.Background(), url); err == nil {
		t.Fatal("checkHealth against a closed server: expected an error")
	}
}

func TestCheckHealthTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := checkHealth(ctx, srv.URL+"/healthz"); err == nil {
		t.Fatal("checkHealth against a hanging server: expected a timeout error")
	}
}

func TestRunHealthcheckExitCode(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer healthy.Close()
	t.Setenv("NGSTONE_HEALTHCHECK_URL", healthy.URL+"/healthz")
	if code := runHealthcheck(); code != 0 {
		t.Fatalf("runHealthcheck() against a healthy server = %d, want 0", code)
	}

	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unhealthy.Close()
	t.Setenv("NGSTONE_HEALTHCHECK_URL", unhealthy.URL+"/healthz")
	if code := runHealthcheck(); code != 1 {
		t.Fatalf("runHealthcheck() against an unhealthy server = %d, want 1", code)
	}
}
