package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ngstone/internal/agent"
	"ngstone/internal/config"
)

func TestSelectTunnelsKeepsFileOrderAndRejectsUnknownNames(t *testing.T) {
	all := []config.NamedTunnel{{Name: "web"}, {Name: "api"}, {Name: "db"}}

	got, err := selectTunnels(all, nil)
	if err != nil || len(got) != 3 {
		t.Fatalf("no names should select all: %v %v", got, err)
	}

	got, err = selectTunnels(all, []string{"db", "web"})
	if err != nil {
		t.Fatalf("selectTunnels: %v", err)
	}
	if got[0].Name != "web" || got[1].Name != "db" {
		t.Fatalf("got %v, want web then db in file order", got)
	}

	if _, err := selectTunnels(all, []string{"web", "nope"}); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("unknown name error = %v", err)
	}
}

func TestTunnelAgentConfig(t *testing.T) {
	opts := startOptions{server: "example.com:4443", token: "tok", serverName: "example.com"}

	t.Run("http port", func(t *testing.T) {
		acfg, err := tunnelAgentConfig(config.NamedTunnel{Name: "web", Tunnel: config.Tunnel{Kind: "http", Port: 3000, Subdomain: "demo", HostHeader: "demo.localhost"}}, opts)
		if err != nil {
			t.Fatal(err)
		}
		if acfg.Name != "web" || acfg.TargetURL != "http://127.0.0.1:3000" || acfg.Subdomain != "demo" ||
			acfg.HostHeader != "demo.localhost" || acfg.ControlAddr != "example.com:4443" || acfg.Token != "tok" || acfg.Kind != "http" {
			t.Fatalf("unexpected config: %+v", acfg)
		}
	})

	t.Run("http url with auth and cidrs", func(t *testing.T) {
		acfg, err := tunnelAgentConfig(config.NamedTunnel{Name: "api", Tunnel: config.Tunnel{
			Kind: "http", URL: "https://localhost:8443", BasicAuth: []string{"user:pass"}, AllowCIDR: []string{"203.0.113.0/24"},
		}}, opts)
		if err != nil {
			t.Fatal(err)
		}
		if acfg.TargetURL != "https://localhost:8443" || len(acfg.BasicAuthSHA256) != 1 || len(acfg.BasicAuthSHA256[0]) != 64 || acfg.AllowCIDRs[0] != "203.0.113.0/24" {
			t.Fatalf("unexpected config: %+v", acfg)
		}
	})

	t.Run("basic auth file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "creds")
		os.WriteFile(path, []byte("# team\nalice:secret\n"), 0o600)
		acfg, err := tunnelAgentConfig(config.NamedTunnel{Name: "web", Tunnel: config.Tunnel{Kind: "http", Port: 3000, BasicAuthFile: path}}, opts)
		if err != nil || len(acfg.BasicAuthSHA256) != 1 {
			t.Fatalf("basic auth file: %+v %v", acfg, err)
		}
	})

	t.Run("tcp port and address", func(t *testing.T) {
		acfg, err := tunnelAgentConfig(config.NamedTunnel{Name: "db", Tunnel: config.Tunnel{Kind: "tcp", Port: 5432, RemotePort: 15432}}, opts)
		if err != nil || acfg.Kind != "tcp" || acfg.TargetURL != "127.0.0.1:5432" || acfg.RemotePort != 15432 {
			t.Fatalf("tcp port: %+v %v", acfg, err)
		}
		acfg, err = tunnelAgentConfig(config.NamedTunnel{Name: "db", Tunnel: config.Tunnel{Kind: "tcp", Address: "db.local:5432"}}, opts)
		if err != nil || acfg.TargetURL != "db.local:5432" {
			t.Fatalf("tcp address: %+v %v", acfg, err)
		}
		if u := tunnelTarget(acfg); u == nil || u.String() != "tcp://db.local:5432" {
			t.Fatalf("tcp display target = %v", u)
		}
	})
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "file", "saved"); got != "file" {
		t.Fatalf("got %q", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Fatalf("got %q", got)
	}
}

type startOptions struct{ server, token, serverName string }

func tunnelAgentConfig(nt config.NamedTunnel, opts startOptions) (agent.Config, error) {
	tunnel := projectTunnelFromYAML(nt.Tunnel)
	tunnel.Token, tunnel.Server, tunnel.ServerName = opts.token, opts.server, opts.serverName
	cfg, _, err := buildProjectAgent(nt.Name, tunnel, ".", config.Config{})
	return cfg, err
}
