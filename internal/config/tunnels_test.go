package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTunnelsKeepsFileOrderAndDefaults(t *testing.T) {
	f, err := ParseTunnels([]byte(`
server: example.com:4443
tunnels:
  web:
    port: 3000
    subdomain: demo
  db:
    kind: tcp
    port: 5432
    remote_port: 15432
  api:
    url: http://127.0.0.1:8080
    allow_cidr: [203.0.113.0/24]
`))
	if err != nil {
		t.Fatalf("ParseTunnels: %v", err)
	}
	if f.Server != "example.com:4443" {
		t.Fatalf("server = %q", f.Server)
	}
	var names []string
	for _, tn := range f.Tunnels {
		names = append(names, tn.Name)
	}
	if got := strings.Join(names, ","); got != "web,db,api" {
		t.Fatalf("order = %s, want web,db,api (file order)", got)
	}
	if f.Tunnels[0].Kind != KindHTTP {
		t.Fatalf("default kind = %q, want http", f.Tunnels[0].Kind)
	}
	if f.Tunnels[1].RemotePort != 15432 || f.Tunnels[2].AllowCIDR[0] != "203.0.113.0/24" {
		t.Fatalf("fields not decoded: %+v", f.Tunnels)
	}
}

func TestParseTunnelsRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"unknown key":          "tunnels:\n  web:\n    port: 3000\n    alow_cidr: [1.2.3.4/32]\n",
		"no tunnels":           "server: example.com:4443\n",
		"bad name":             "tunnels:\n  Web App:\n    port: 3000\n",
		"port and url":         "tunnels:\n  web:\n    port: 3000\n    url: http://127.0.0.1:3000\n",
		"neither port nor url": "tunnels:\n  web:\n    subdomain: demo\n",
		"bad url":              "tunnels:\n  web:\n    url: ftp://x\n",
		"port out of range":    "tunnels:\n  web:\n    port: 70000\n",
		"bad kind":             "tunnels:\n  web:\n    kind: udp\n    port: 53\n",
		"tcp with subdomain":   "tunnels:\n  db:\n    kind: tcp\n    port: 5432\n    subdomain: x\n",
		"tcp bad address":      "tunnels:\n  db:\n    kind: tcp\n    address: nohost\n",
		"http remote_port":     "tunnels:\n  web:\n    port: 3000\n    remote_port: 10000\n",
		"bad cidr":             "tunnels:\n  web:\n    port: 3000\n    allow_cidr: [not-a-cidr]\n",
		"duplicate subdomain":  "tunnels:\n  a:\n    port: 1000\n    subdomain: x\n  b:\n    port: 2000\n    subdomain: x\n",
		"both auth sources":    "tunnels:\n  web:\n    port: 3000\n    basic_auth: [u:p]\n    basic_auth_file: f\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTunnels([]byte(src)); err == nil {
				t.Fatalf("ParseTunnels accepted %q", src)
			}
		})
	}
}

func TestTunnelsPathPrefersExplicitThenCwdThenConfigDir(t *testing.T) {
	if got, _ := TunnelsPath("custom.yml"); got != "custom.yml" {
		t.Fatalf("explicit path = %q", got)
	}

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "cfg"))
	wd, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(wd) })
	os.Chdir(dir)

	got, err := TunnelsPath("")
	if err != nil || got != filepath.Join(dir, "cfg", "ngstone", "tunnels.yml") {
		t.Fatalf("fallback path = %q, %v", got, err)
	}
	os.WriteFile(TunnelsFileName, []byte("tunnels: {}"), 0o600)
	if got, _ := TunnelsPath(""); got != TunnelsFileName {
		t.Fatalf("cwd path = %q, want %s", got, TunnelsFileName)
	}
}
