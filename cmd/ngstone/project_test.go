package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ngstone/internal/agent"
	"ngstone/internal/config"
)

func TestProjectAndDirectOutputFlags(t *testing.T) {
	fs, pf := newPortFlagSet()
	positionals, err := parsePermissive(fs, []string{"--json", "--ttl", "2h", "--har", "requests.har", "--har-include-sensitive", "3000"})
	if err != nil {
		t.Fatalf("parse port flags: %v", err)
	}
	if len(positionals) != 1 || positionals[0] != "3000" {
		t.Fatalf("port positionals = %v, want [3000]", positionals)
	}
	if !pf.json || pf.ttl != 2*time.Hour || pf.harPath != "requests.har" || !pf.harIncludeSensitive {
		t.Fatalf("port output flags = %+v", pf)
	}

	fs, pf = newPortFlagSet()
	if _, err := parsePermissive(fs, []string{"--policy-file", "traffic-policy.json", "--http2", "--multi-connector", "--subdomain", "demo", "3000"}); err != nil {
		t.Fatalf("parse policy file flag: %v", err)
	}
	if pf.policyFile != "traffic-policy.json" {
		t.Fatalf("policy file = %q, want traffic-policy.json", pf.policyFile)
	}
	if !pf.http2 {
		t.Fatal("http2 flag = false, want true")
	}
	if !pf.multiConnector || pf.subdomain != "demo" {
		t.Fatalf("multi-connector flags = %+v, want enabled with demo subdomain", pf)
	}

	fs, tf := newTCPFlagSet()
	positionals, err = parsePermissive(fs, []string{"5432", "--ttl", "30m", "--json"})
	if err != nil {
		t.Fatalf("parse tcp flags: %v", err)
	}
	if len(positionals) != 1 || positionals[0] != "5432" || !tf.json || tf.ttl != 30*time.Minute {
		t.Fatalf("tcp output flags = positionals %v, flags %+v", positionals, tf)
	}
}

func TestPreviewDefaultsAndValidation(t *testing.T) {
	if defaultPreviewTTL <= 0 {
		t.Fatalf("default preview ttl = %s, want positive", defaultPreviewTTL)
	}
	fs, parsed := newPortFlagSetWithTTL(defaultPreviewTTL)
	positionals, err := parsePermissive(fs, []string{"3000"})
	if err != nil || len(positionals) != 1 || parsed.ttl != defaultPreviewTTL {
		t.Fatalf("preview defaults = positionals %v, flags %+v, err %v", positionals, parsed, err)
	}
	flags := &portFlags{ttl: defaultPreviewTTL}
	if err := validatePortFlags(flags, true); err != nil {
		t.Fatalf("default preview flags: %v", err)
	}

	flags.subdomain = "demo"
	if err := validatePortFlags(flags, true); err == nil {
		t.Fatal("preview accepted a requested subdomain")
	}
	flags.subdomain = ""
	flags.ttl = 0
	if err := validatePortFlags(flags, true); err == nil {
		t.Fatal("preview accepted a zero TTL")
	}
	flags.ttl = -time.Minute
	if err := validatePortFlags(flags, true); err == nil {
		t.Fatal("preview accepted a negative TTL")
	}
	flags.ttl = defaultPreviewTTL
	flags.multiConnector = true
	if err := validatePortFlags(flags, true); err == nil {
		t.Fatal("preview accepted multiple connectors")
	}
}

func TestContextForTTL(t *testing.T) {
	ctx, cancel, expiresAt := contextForTTL(context.Background(), 10*time.Millisecond)
	defer cancel()
	if expiresAt.IsZero() {
		t.Fatal("expiresAt is zero for a positive TTL")
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("TTL context did not expire")
	}
}

func TestBuildProjectAgent(t *testing.T) {
	t.Setenv("NGSTONE_TOKEN", "")
	t.Setenv("NGSTONE_CONNECTOR_TOKEN", "pool-secret")
	projectDir := t.TempDir()
	credentials := filepath.Join(projectDir, "basic-auth.txt")
	if err := os.WriteFile(credentials, []byte("demo:secret\n"), 0o600); err != nil {
		t.Fatalf("write credentials: %v", err)
	}
	policyPath := filepath.Join(projectDir, "traffic-policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"default_action":"deny","rules":[{"action":"allow","path_prefix":"/health"}]}`), 0o600); err != nil {
		t.Fatalf("write traffic policy: %v", err)
	}

	acfg, ttl, err := buildProjectAgent("demo-tunnel", config.ProjectTunnel{
		Kind:           "http",
		Target:         "3000",
		Subdomain:      "demo",
		HostHeader:     "demo.localhost:3000",
		HTTP2:          true,
		MultiConnector: true,
		TTL:            "2h",
		BasicAuthFile:  "basic-auth.txt",
		AllowCIDR:      "127.0.0.1/32",
		PolicyFile:     "traffic-policy.json",
	}, projectDir, config.Config{Token: "saved-token", Server: "edge.test:4443"})
	if err != nil {
		t.Fatalf("buildProjectAgent: %v", err)
	}
	if ttl != 2*time.Hour {
		t.Fatalf("ttl = %s, want 2h", ttl)
	}
	if acfg.TargetURL != "http://127.0.0.1:3000" || acfg.Subdomain != "demo" || acfg.HostHeader != "demo.localhost:3000" {
		t.Fatalf("agent target settings = %+v", acfg)
	}
	if !acfg.HTTP2 {
		t.Fatal("agent HTTP/2 mode = false, want true")
	}
	if !acfg.MultiConnector {
		t.Fatal("agent multi-connector mode = false, want true")
	}
	if acfg.Token != "saved-token" || acfg.ControlAddr != "edge.test:4443" {
		t.Fatalf("agent auth settings = %+v", acfg)
	}
	if len(acfg.BasicAuthSHA256) != 1 || len(acfg.AllowCIDRs) != 1 {
		t.Fatalf("agent access settings = %+v", acfg)
	}
	if acfg.Policy == nil || acfg.Policy.DefaultAction != "deny" || len(acfg.Policy.Rules) != 1 {
		t.Fatalf("agent traffic policy = %+v", acfg.Policy)
	}
}

func TestBuildProjectAgentUsesCredentialEnv(t *testing.T) {
	t.Setenv("NGSTONE_TOKEN", "global-token")
	t.Setenv("NGSTONE_TUNNEL_TOKEN", "scoped-token")
	acfg, _, err := buildProjectAgent("", config.ProjectTunnel{
		Target:        "3000",
		CredentialEnv: "NGSTONE_TUNNEL_TOKEN",
	}, t.TempDir(), config.Config{Token: "saved-token"})
	if err != nil {
		t.Fatalf("buildProjectAgent: %v", err)
	}
	if acfg.Token != "scoped-token" {
		t.Fatalf("token = %q, want credential env token", acfg.Token)
	}
}

func TestProjectCredentialsFailClosed(t *testing.T) {
	t.Setenv("NGSTONE_TOKEN", "global-token")
	t.Setenv("NGSTONE_MISSING_TOKEN", "")
	dir := t.TempDir()
	for _, tc := range []struct {
		name   string
		tunnel config.ProjectTunnel
	}{
		{"missing environment", config.ProjectTunnel{Target: "3000", CredentialEnv: "NGSTONE_MISSING_TOKEN"}},
		{"missing file", config.ProjectTunnel{Target: "3000", CredentialFile: "missing.token"}},
		{"conflicting sources", config.ProjectTunnel{Target: "3000", CredentialEnv: "NGSTONE_TOKEN", CredentialFile: "missing.token"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := buildProjectAgent("web", tc.tunnel, dir, config.Config{Token: "saved-token"}); err == nil {
				t.Fatal("explicit credential failure fell back to a global token")
			}
		})
	}
	path := filepath.Join(dir, "private.token")
	for _, tc := range []struct {
		name, token string
		mode        os.FileMode
	}{
		{"empty", " \n", 0o600},
		{"public", "scoped-token", 0o644},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.token), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			if _, _, err := buildProjectAgent("web", config.ProjectTunnel{Target: "3000", CredentialFile: path}, dir, config.Config{Token: "saved-token"}); err == nil {
				t.Fatal("unsafe credential file was accepted")
			}
		})
	}
}

func TestWriteAgentJSONEvent(t *testing.T) {
	var output bytes.Buffer
	event := agent.StatusEvent{State: agent.StateOnline, Hostname: "demo.ngstone.site", URL: "https://demo.ngstone.site"}
	expiresAt := time.Date(2026, time.August, 17, 10, 11, 12, 0, time.UTC)
	if err := writeAgentJSONEvent(json.NewEncoder(&output), "", agent.Config{TargetURL: "http://127.0.0.1:3000"}, expiresAt, event); err != nil {
		t.Fatalf("writeAgentJSONEvent: %v", err)
	}
	var got projectJSONEvent
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatalf("decode JSON event: %v", err)
	}
	if got.Type != "tunnel" || got.Kind != "http" || got.Target != "http://127.0.0.1:3000" || got.State != agent.StateOnline {
		t.Fatalf("event = %+v", got)
	}
	if got.Name != "" || got.ExpiresAt == "" || got.URL != event.URL || got.Hostname != event.Hostname {
		t.Fatalf("event metadata = %+v", got)
	}
}
