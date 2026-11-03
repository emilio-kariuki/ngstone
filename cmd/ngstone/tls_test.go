package main

import (
	"testing"

	"ngstone/internal/config"
)

func TestVerbFuncDispatchIncludesTLS(t *testing.T) {
	fn, ok := verbFunc("tls")
	if !ok || fn == nil {
		t.Fatalf("verbFunc(%q) ok=%v, want a dispatchable tls verb", "tls", ok)
	}
}

func TestTLSFlagSetParsesSubdomainAndAllowCIDR(t *testing.T) {
	fs, tf := newTLSFlagSet()
	positionals, err := parsePermissive(fs, []string{"8443", "--subdomain", "secure", "--allow-cidr", "10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parsePermissive: %v", err)
	}
	if len(positionals) != 1 || positionals[0] != "8443" {
		t.Fatalf("positionals = %v, want [8443]", positionals)
	}
	if tf.subdomain != "secure" || tf.allowCIDR != "10.0.0.0/8" {
		t.Fatalf("flags = %+v", tf)
	}

	fs, tf = newTLSFlagSet()
	if _, err := parsePermissive(fs, []string{"-s", "short", "app.local:9443"}); err != nil {
		t.Fatalf("parsePermissive short flag: %v", err)
	}
	if tf.subdomain != "short" {
		t.Fatalf("subdomain via -s = %q, want short", tf.subdomain)
	}
}

func TestCmdTLSRejectsBadArguments(t *testing.T) {
	if code := cmdTLS(nil); code != 2 {
		t.Fatalf("cmdTLS() = %d, want 2", code)
	}
	if code := cmdTLS([]string{"not-a-port"}); code != 2 {
		t.Fatalf("cmdTLS(not-a-port) = %d, want 2", code)
	}
	if code := cmdTLS([]string{"8443", "--ttl", "-1s"}); code != 2 {
		t.Fatalf("cmdTLS(--ttl -1s) = %d, want 2", code)
	}
}

func TestBuildProjectAgentTLS(t *testing.T) {
	acfg, _, err := buildProjectAgent("secure", config.ProjectTunnel{
		Kind:      "tls",
		Target:    "8443",
		Subdomain: "secure",
		AllowCIDR: "10.0.0.0/8",
		Token:     "tok",
	}, t.TempDir(), config.Config{})
	if err != nil {
		t.Fatalf("buildProjectAgent: %v", err)
	}
	if acfg.Kind != "tls" || acfg.TargetURL != "127.0.0.1:8443" || acfg.Subdomain != "secure" || len(acfg.AllowCIDRs) != 1 {
		t.Fatalf("agent config = %+v", acfg)
	}
	if got := projectKind(acfg); got != "tls" {
		t.Fatalf("projectKind = %q, want tls", got)
	}
	if u := tunnelTarget(acfg); u == nil || u.String() != "tls://127.0.0.1:8443" {
		t.Fatalf("tunnelTarget = %v, want tls://127.0.0.1:8443", u)
	}
}

func TestProjectTunnelFromYAMLTLS(t *testing.T) {
	got := projectTunnelFromYAML(config.Tunnel{Kind: config.KindTLS, Port: 8443, Subdomain: "secure"})
	if got.Kind != "tls" || got.Target != "127.0.0.1:8443" || got.Subdomain != "secure" {
		t.Fatalf("project tunnel = %+v", got)
	}
	got = projectTunnelFromYAML(config.Tunnel{Kind: config.KindTLS, Address: "app.local:9443"})
	if got.Target != "app.local:9443" {
		t.Fatalf("project tunnel target = %q, want app.local:9443", got.Target)
	}
}
