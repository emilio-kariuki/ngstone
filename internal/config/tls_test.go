package config

import (
	"strings"
	"testing"
)

func TestLoadProjectAcceptsTLSKindWithAllowCIDR(t *testing.T) {
	project, err := LoadProject(writeProject(t, `{"tunnels":{"secure":{"kind":"TLS","target":"8443","subdomain":"secure","allow_cidr":"10.0.0.0/8"}}}`))
	if err != nil {
		t.Fatalf("LoadProject: %v", err)
	}
	tunnel := project.Tunnels["secure"]
	if tunnel.Kind != "tls" || tunnel.AllowCIDR != "10.0.0.0/8" || tunnel.Subdomain != "secure" {
		t.Fatalf("tunnel = %+v", tunnel)
	}
}

func TestLoadProjectRejectsHTTPOnlyFieldsForTLS(t *testing.T) {
	cases := map[string]string{
		"host_header":      `{"tunnels":{"s":{"kind":"tls","target":"8443","host_header":"demo.local"}}}`,
		"basic auth":       `{"tunnels":{"s":{"kind":"tls","target":"8443","basic_auth_file":"credentials"}}}`,
		"policy_file":      `{"tunnels":{"s":{"kind":"tls","target":"8443","policy_file":"policy.json"}}}`,
		"http2":            `{"tunnels":{"s":{"kind":"tls","target":"8443","http2":true}}}`,
		"multi_connector":  `{"tunnels":{"s":{"kind":"tls","target":"8443","subdomain":"s","multi_connector":true}}}`,
		"remote_port":      `{"tunnels":{"s":{"kind":"tls","target":"8443","remote_port":9443}}}`,
		"oidc":             `{"tunnels":{"s":{"kind":"tls","target":"8443","oidc":true}}}`,
		"oidc_allow_email": `{"tunnels":{"s":{"kind":"tls","target":"8443","oidc_allow_email":["a@example.com"]}}}`,
		"webhook":          `{"tunnels":{"s":{"kind":"tls","target":"8443","webhook":{"provider":"github","secret_env":"SECRET"}}}}`,
	}
	for field, data := range cases {
		t.Run(field, func(t *testing.T) {
			_, err := LoadProject(writeProject(t, data))
			if err == nil {
				t.Fatalf("LoadProject(%s) succeeded, want a validation error", data)
			}
			if !strings.Contains(err.Error(), "tls") && !strings.Contains(err.Error(), "only valid for") {
				t.Fatalf("error %q does not explain the tls restriction", err)
			}
		})
	}
}

func TestProjectValidateRejectsBasicAuthPairsForTLS(t *testing.T) {
	p := Project{Tunnels: map[string]ProjectTunnel{"s": {Kind: "tls", Target: "8443", BasicAuth: []string{"u:p"}}}}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate accepted basic auth on a tls tunnel")
	}
}

func TestParseTunnelsAcceptsTLSKind(t *testing.T) {
	f, err := ParseTunnels([]byte("tunnels:\n  secure:\n    kind: tls\n    port: 8443\n    subdomain: secure\n    allow_cidr: [10.0.0.0/8]\n  app:\n    kind: tls\n    address: app.local:9443\n"))
	if err != nil {
		t.Fatalf("ParseTunnels: %v", err)
	}
	if f.Tunnels[0].Kind != KindTLS || f.Tunnels[0].Subdomain != "secure" || f.Tunnels[1].Address != "app.local:9443" {
		t.Fatalf("tunnels = %+v", f.Tunnels)
	}
}

func TestParseTunnelsRejectsBadTLSInput(t *testing.T) {
	cases := map[string]string{
		"tls with url":              "tunnels:\n  s:\n    kind: tls\n    url: https://127.0.0.1:8443\n",
		"tls with host_header":      "tunnels:\n  s:\n    kind: tls\n    port: 8443\n    host_header: x\n",
		"tls with basic auth":       "tunnels:\n  s:\n    kind: tls\n    port: 8443\n    basic_auth: [u:p]\n",
		"tls with http2":            "tunnels:\n  s:\n    kind: tls\n    port: 8443\n    http2: true\n",
		"tls with remote_port":      "tunnels:\n  s:\n    kind: tls\n    port: 8443\n    remote_port: 9443\n",
		"tls with policy_file":      "tunnels:\n  s:\n    kind: tls\n    port: 8443\n    policy_file: policy.json\n",
		"tls with multi_connector":  "tunnels:\n  s:\n    kind: tls\n    port: 8443\n    subdomain: s\n    multi_connector: true\n",
		"tls with oidc":             "tunnels:\n  s:\n    kind: tls\n    port: 8443\n    oidc: true\n",
		"tls with oidc_allow_email": "tunnels:\n  s:\n    kind: tls\n    port: 8443\n    oidc_allow_email: [a@example.com]\n",
		"tls with webhook":          "tunnels:\n  s:\n    kind: tls\n    port: 8443\n    webhook:\n      provider: github\n      secret_env: SECRET\n",
		"tls bad address":           "tunnels:\n  s:\n    kind: tls\n    address: nohost\n",
		"tls without target":        "tunnels:\n  s:\n    kind: tls\n    subdomain: s\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTunnels([]byte(src)); err == nil {
				t.Fatalf("ParseTunnels accepted %q", src)
			}
		})
	}
}
