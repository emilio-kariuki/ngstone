package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultHealthcheckURL = "http://127.0.0.1:4041/healthz"
	healthcheckTimeout    = 3 * time.Second
)

// runHealthcheck implements "ngstoned healthcheck", which the container
// image's HEALTHCHECK runs: distroless images have no curl or wget, so the
// binary probes its own loopback ops endpoint. It returns the exit code.
func runHealthcheck() int {
	url := os.Getenv("NGSTONE_HEALTHCHECK_URL")
	if url == "" {
		url = defaultHealthcheckURL
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthcheckTimeout)
	defer cancel()
	if err := checkHealth(ctx, url); err != nil {
		fmt.Fprintf(os.Stderr, "ngstoned healthcheck: %v\n", err)
		return 1
	}
	return 0
}

// checkHealth returns nil when a GET of url answers 200. /healthz answers 503
// until both certificates are loaded, and its body names the failing one, so
// the start of a non-200 body is included in the error.
func checkHealth(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", url, err)
	}
	// No proxy: HTTP_PROXY set for the edge's outbound ACME and DNS API
	// traffic must not capture the probe of its own ops endpoint.
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("GET %s: %s: %s", url, resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}
