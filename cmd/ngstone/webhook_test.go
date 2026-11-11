package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ngstone/internal/config"
	"ngstone/internal/webhook"
)

func writeSecret(t *testing.T, dir, name, value string, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(value), perm); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	return path
}

func TestPortFlagsParseWebhook(t *testing.T) {
	dir := t.TempDir()
	secretPath := writeSecret(t, dir, "secret", "whsec_from_file\n", 0o600)
	fs, pf := newPortFlagSet()
	positionals, err := parsePermissive(fs, []string{"3000", "--verify-webhook", "stripe", "--verify-webhook-secret-file", secretPath, "--verify-webhook-path", "/stripe", "--verify-webhook-tolerance", "90s"})
	if err != nil || len(positionals) != 1 {
		t.Fatalf("parse: %v %v", positionals, err)
	}
	cfg, err := resolveWebhookFlags(&pf.webhook, "env-secret")
	if err != nil {
		t.Fatalf("resolveWebhookFlags: %v", err)
	}
	want := webhook.Config{Provider: "stripe", Secret: "whsec_from_file", PathPrefix: "/stripe", Tolerance: 90 * time.Second}
	if cfg == nil || *cfg != want {
		t.Fatalf("config = %#v", cfg)
	}
	if strings.Contains(cfg.String(), "whsec_from_file") {
		t.Fatalf("String() exposes the secret: %s", cfg.String())
	}
}

func TestValidatePortFlagsRejectsWebhookCombinations(t *testing.T) {
	for _, preview := range []bool{false, true} {
		flags := &portFlags{ttl: time.Minute, http2: true, webhook: webhookFlags{provider: "github"}}
		if err := validatePortFlags(flags, preview); err == nil || !strings.Contains(err.Error(), "--http2") {
			t.Fatalf("preview=%v webhook+http2 error = %v", preview, err)
		}
		flags = &portFlags{ttl: time.Minute, oidc: true, webhook: webhookFlags{provider: "github"}}
		if err := validatePortFlags(flags, preview); err == nil || !strings.Contains(err.Error(), "--oidc") {
			t.Fatalf("preview=%v webhook+oidc error = %v", preview, err)
		}
		flags = &portFlags{ttl: time.Minute, webhook: webhookFlags{provider: "github"}}
		if err := validatePortFlags(flags, preview); err != nil {
			t.Fatalf("preview=%v webhook alone: %v", preview, err)
		}
	}
}

func TestServeRejectsWebhookFlags(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("NGSTONE_TOKEN", "")
	dir := t.TempDir()
	for _, args := range [][]string{
		{"--verify-webhook", "github", dir},
		{"--verify-webhook-path", "/hooks", dir},
	} {
		if code := cmdServe(args); code != 2 {
			t.Fatalf("cmdServe(%v) = %d, want 2", args, code)
		}
	}
	if code := cmdServe([]string{dir}); code != 1 {
		t.Fatalf("cmdServe without webhook flags = %d, want 1 for the missing token", code)
	}
}

func TestServeRejectsFlagsItDoesNotApply(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("NGSTONE_TOKEN", "")
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "deny.json")
	for _, args := range [][]string{
		{"--transport", "raw"},
		{"--http2"},
		{"--multi-connector"},
		{"--connector-token", "x"},
		{"--policy-file", policyPath},
		{"--ttl", "1h"},
		{"--json"},
		{"--har", filepath.Join(dir, "out.har")},
		{"--har-include-sensitive"},
	} {
		if code := cmdServe(append(args, dir)); code != 2 {
			t.Errorf("cmdServe(%v) = %d, want 2", args, code)
		}
	}
	for _, args := range [][]string{
		{"--oidc"},
		{"--oidc", "--oidc-allow-email", "a@example.com", "--oidc-allow-domain", "example.com"},
		{"--basic-auth", "user:pass"},
		{"--basic-auth-file", filepath.Join(dir, "creds")},
		{"--allow-cidr", "10.0.0.0/8"},
		{"--subdomain", "docs", "--host-header", "localhost", "--no-tui"},
		{"--server", "127.0.0.1:1", "--insecure", "--server-name", "x", "--pin", "sha256/AAAA", "--instance-id", "i"},
	} {
		if code := cmdServe(append(args, dir)); code != 1 {
			t.Errorf("cmdServe(%v) = %d, want 1 (flags accepted, token missing)", args, code)
		}
	}
}

func TestResolveWebhookFlags(t *testing.T) {
	if cfg, err := resolveWebhookFlags(&webhookFlags{}, "env"); err != nil || cfg != nil {
		t.Fatalf("no flags = %v, %v", cfg, err)
	}
	if _, err := resolveWebhookFlags(&webhookFlags{pathPrefix: "/x"}, ""); err == nil || !strings.Contains(err.Error(), "need --verify-webhook") {
		t.Fatalf("orphan option error = %v", err)
	}
	if _, err := resolveWebhookFlags(&webhookFlags{provider: "github"}, ""); err == nil || !strings.Contains(err.Error(), config.DefaultWebhookSecretEnv) {
		t.Fatalf("missing secret error = %v", err)
	}
	cfg, err := resolveWebhookFlags(&webhookFlags{provider: "hmac", header: "x-signature", encoding: "base64", prefix: "sha256="}, "env-secret")
	if err != nil {
		t.Fatalf("hmac: %v", err)
	}
	if cfg.Secret != "env-secret" || cfg.Header != "X-Signature" || cfg.Encoding != "base64" || cfg.Prefix != "sha256=" {
		t.Fatalf("hmac config = %#v", cfg)
	}
	_, err = resolveWebhookFlags(&webhookFlags{provider: "github", tolerance: time.Minute}, "env-secret")
	if err == nil || strings.Contains(err.Error(), "env-secret") {
		t.Fatalf("tolerance on github error = %v", err)
	}
	empty := writeSecret(t, t.TempDir(), "empty", "\n", 0o600)
	if _, err := resolveWebhookFlags(&webhookFlags{provider: "github", secretFile: empty}, ""); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty file error = %v", err)
	}
}

func TestResolveProjectWebhook(t *testing.T) {
	dir := t.TempDir()
	writeSecret(t, dir, "gh.secret", "github-secret\n", 0o600)
	writeSecret(t, dir, "open.secret", "github-secret\n", 0o644)

	cfg, err := resolveProjectWebhook(&config.TunnelWebhook{Provider: "github", SecretFile: "gh.secret"}, dir)
	if err != nil || cfg == nil || cfg.Secret != "github-secret" {
		t.Fatalf("secret_file = %#v, %v", cfg, err)
	}
	if _, err := resolveProjectWebhook(&config.TunnelWebhook{Provider: "github", SecretFile: "open.secret"}, dir); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("world readable error = %v", err)
	}

	t.Setenv("NGSTONE_TEST_SLACK_SECRET", "slack-secret")
	cfg, err = resolveProjectWebhook(&config.TunnelWebhook{Provider: "slack", SecretEnv: "NGSTONE_TEST_SLACK_SECRET", Tolerance: "1m"}, dir)
	if err != nil || cfg.Secret != "slack-secret" || cfg.Tolerance != time.Minute {
		t.Fatalf("secret_env = %#v, %v", cfg, err)
	}

	t.Setenv(config.DefaultWebhookSecretEnv, "")
	if _, err := resolveProjectWebhook(&config.TunnelWebhook{Provider: "github"}, dir); err == nil || !strings.Contains(err.Error(), config.DefaultWebhookSecretEnv) {
		t.Fatalf("default env error = %v", err)
	}
	t.Setenv(config.DefaultWebhookSecretEnv, "default-secret")
	cfg, err = resolveProjectWebhook(&config.TunnelWebhook{Provider: "github"}, dir)
	if err != nil || cfg.Secret != "default-secret" {
		t.Fatalf("default env = %#v, %v", cfg, err)
	}
}

func TestBuildProjectAgentCarriesWebhook(t *testing.T) {
	dir := t.TempDir()
	writeSecret(t, dir, "gh.secret", "github-secret", 0o600)
	acfg, _, err := buildProjectAgent("web", config.ProjectTunnel{Token: "tok", Target: "3000", Webhook: &config.TunnelWebhook{Provider: "github", SecretFile: "gh.secret", PathPrefix: "/gh"}}, dir, config.Config{})
	if err != nil {
		t.Fatalf("buildProjectAgent: %v", err)
	}
	if acfg.Webhook == nil || acfg.Webhook.Provider != "github" || acfg.Webhook.Secret != "github-secret" || acfg.Webhook.PathPrefix != "/gh" {
		t.Fatalf("agent webhook = %#v", acfg.Webhook)
	}
	yamlTunnel := projectTunnelFromYAML(config.Tunnel{Kind: config.KindHTTP, Port: 3000, Webhook: &config.TunnelWebhook{Provider: "slack"}})
	if yamlTunnel.Webhook == nil || yamlTunnel.Webhook.Provider != "slack" {
		t.Fatalf("yaml conversion dropped the webhook: %+v", yamlTunnel)
	}
}
