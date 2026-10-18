package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ngstone/internal/agent"
	"ngstone/internal/config"
)

func TestDoctorReportsHealthyConfigurationAsJSON(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("NGSTONE_TOKEN", "")
	cfg := config.Config{Token: "configured-token", Server: "edge.example.com:4443"}
	if err := config.Save(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/status":
			if r.Header.Get("Authorization") != "Bearer admin-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer admin.Close()

	opts := doctorOptions{
		AdminServer: admin.URL,
		AdminToken:  "admin-token",
		Transport:   agent.TransportAuto,
		Timeout:     time.Second,
		LookupHost: func(context.Context, string) ([]string, error) {
			return []string{"203.0.113.10"}, nil
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			left, right := net.Pipe()
			right.Close()
			return left, nil
		},
		Verify: func(context.Context, agent.Config) error {
			return nil
		},
	}
	var output bytes.Buffer
	code, report := runDoctor(opts, &output, &output)
	if code != 0 || !report.OK {
		t.Fatalf("doctor code/report = %d/%+v\n%s", code, report, output.String())
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal doctor report: %v", err)
	}
	var decoded doctorReport
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decode doctor report: %v", err)
	}
	if !decoded.OK || len(decoded.Checks) < 5 {
		t.Fatalf("decoded doctor report = %+v", decoded)
	}
}

func TestDoctorRejectsUnsafeAdminURL(t *testing.T) {
	if _, err := doctorAdminEndpoint("https://user:pass@example.com", "/healthz", false); err == nil {
		t.Fatal("admin URL with credentials was accepted")
	}
	if _, err := doctorAdminEndpoint("https://example.com/?token=secret", "/healthz", false); err == nil {
		t.Fatal("admin URL with query credentials was accepted")
	}
	if _, err := doctorAdminEndpoint("http://example.com", "/healthz", false); err == nil {
		t.Fatal("external plaintext admin URL was accepted")
	}
	if !strings.Contains(doctorAdminEndpointMust("https://example.com/ops", "/healthz", false), "/ops/healthz") {
		t.Fatal("admin path was not preserved")
	}
}

func doctorAdminEndpointMust(raw, path string, allowInsecure bool) string {
	value, err := doctorAdminEndpoint(raw, path, allowInsecure)
	if err != nil {
		panic(err)
	}
	return value
}
