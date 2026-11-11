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

func checkHealth(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", url, err)
	}
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
