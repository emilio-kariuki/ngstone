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
		"host_header":     `{"tunnels":{"s":{"kind":"tls","target":"8443","host_header":"demo.local"}}}`,
		"basic auth":      `{"tunnels":{"s":{"kind":"tls","target":"8443","basic_auth_file":"credentials"}}}`,
		"policy_file":     `{"tunnels":{"s":{"kind":"tls","target":"8443","policy_file":"policy.json"}}}`,
		"http2":           `{"tunnels":{"s":{"kind":"tls","target":"8443","http2":true}}}`,
		"multi_connector": `{"tunnels":{"s":{"kind":"tls","target":"8443","subdomain":"s","multi_connector":true}}}`,
		"remote_port":     `{"tunnels":{"s":{"kind":"tls","target":"8443","remote_port":9443}}}`,
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
		"tls with url":         "tunnels:\n  s:\n    kind: tls\n    url: https://127.0.0.1:8443\n",
		"tls with host_header": "tunnels:\n  s:\n    kind: tls\n    port: 8443\n    host_header: x\n",
		"tls with basic auth":  "tunnels:\n  s:\n    kind: tls\n    port: 8443\n    basic_auth: [u:p]\n",
		"tls with http2":       "tunnels:\n  s:\n    kind: tls\n    port: 8443\n    http2: true\n",
		"tls with remote_port": "tunnels:\n  s:\n    kind: tls\n    port: 8443\n    remote_port: 9443\n",
		"tls bad address":      "tunnels:\n  s:\n    kind: tls\n    address: nohost\n",
		"tls without target":   "tunnels:\n  s:\n    kind: tls\n    subdomain: s\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTunnels([]byte(src)); err == nil {
				t.Fatalf("ParseTunnels accepted %q", src)
			}
		})
	}
}
