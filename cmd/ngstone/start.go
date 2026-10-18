package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ngstone/internal/agent"
	"ngstone/internal/config"
)

func cmdStart(args []string) int {
	flags := flag.NewFlagSet("start", flag.ContinueOnError)
	cfgPath := flags.String("config", "", "tunnels file (default ./"+config.TunnelsFileName+", then tunnels.yml in the config directory)")
	server := flags.String("server", "", "edge control plane address override (defaults to the file's server, then config, then "+defaultServer+")")
	token := flags.String("token", "", "auth token override (defaults to NGSTONE_TOKEN or the saved config)")
	insecure := flags.Bool("insecure", false, "dial the control plane in plaintext (dev/test only)")
	serverName := flags.String("server-name", "", "TLS ServerName/SNI to verify against; defaults to the host in the server address (ignored with -insecure)")
	pin := flags.String("pin", "", "optional \"sha256/BASE64\" SPKI pin, checked in addition to normal chain validation")
	noTUI := flags.Bool("no-tui", false, "disable the terminal inspector UI and log plain text to stderr")
	names, err := parsePermissive(flags, args)
	if err != nil {
		return 2
	}

	path, err := config.TunnelsPath(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}
	tunnels, err := loadConfiguredTunnels(path, names)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}
	saved, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: loading config: %v\n", err)
		return 1
	}
	var acfgs []agent.Config
	var ttls []time.Duration
	for _, named := range tunnels {
		tunnel := named.Tunnel
		tunnel.Server = firstNonEmpty(*server, tunnel.Server)
		tunnel.ServerName = firstNonEmpty(*serverName, tunnel.ServerName)
		tunnel.Pin = firstNonEmpty(*pin, tunnel.Pin)
		tunnel.Insecure = *insecure || tunnel.Insecure
		tunnel.Token = *token
		acfg, ttl, err := buildProjectAgent(named.Name, tunnel, filepath.Dir(path), saved)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ngstone: tunnel %s: %v\n", named.Name, err)
			return 2
		}
		acfgs = append(acfgs, acfg)
		ttls = append(ttls, ttl)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return runTunnelConfigs(ctx, acfgs, ttls, projectRunOptions{Command: "start", TUI: shouldUseTUI(*noTUI)})
}

// selectTunnels keeps file order, optionally narrowed to the named tunnels.
func selectTunnels(all []config.NamedTunnel, names []string) ([]config.NamedTunnel, error) {
	if len(names) == 0 {
		return all, nil
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var out []config.NamedTunnel
	for _, t := range all {
		if want[t.Name] {
			out = append(out, t)
			delete(want, t.Name)
		}
	}
	if len(want) > 0 {
		var missing []string
		for _, n := range names {
			if want[n] {
				missing = append(missing, n)
			}
		}
		return nil, fmt.Errorf("no tunnel named %s in the tunnels file", strings.Join(missing, ", "))
	}
	return out, nil
}

func loadConfiguredTunnels(path string, names []string) ([]config.NamedProjectTunnel, error) {
	var ordered []config.NamedTunnel
	projects := map[string]config.ProjectTunnel{}
	if strings.EqualFold(filepath.Ext(path), ".json") {
		project, err := config.LoadProject(path)
		if err != nil {
			return nil, err
		}
		for _, named := range project.SortedTunnels() {
			ordered = append(ordered, config.NamedTunnel{Name: named.Name})
			projects[named.Name] = named.Tunnel
		}
	} else {
		file, err := config.LoadTunnels(path)
		if err != nil {
			return nil, err
		}
		ordered = file.Tunnels
		for _, named := range ordered {
			tunnel := projectTunnelFromYAML(named.Tunnel)
			tunnel.Server = file.Server
			tunnel.ServerName = file.ServerName
			projects[named.Name] = tunnel
		}
	}
	selected, err := selectTunnels(ordered, names)
	if err != nil {
		return nil, err
	}
	var out []config.NamedProjectTunnel
	for _, named := range selected {
		out = append(out, config.NamedProjectTunnel{Name: named.Name, Tunnel: projects[named.Name]})
	}
	return out, nil
}

func projectTunnelFromYAML(t config.Tunnel) config.ProjectTunnel {
	target := t.URL
	if t.Kind == config.KindTCP {
		target = t.Address
		if target == "" {
			target = net.JoinHostPort("127.0.0.1", strconv.Itoa(t.Port))
		}
	} else if target == "" {
		target = strconv.Itoa(t.Port)
	}
	return config.ProjectTunnel{
		Kind: t.Kind, Target: target, Subdomain: t.Subdomain, RemotePort: t.RemotePort,
		HostHeader: t.HostHeader, BasicAuth: t.BasicAuth, BasicAuthFile: t.BasicAuthFile,
		AllowCIDR: strings.Join(t.AllowCIDR, ","), CredentialEnv: t.CredentialEnv, CredentialFile: t.CredentialFile,
		HTTP2: t.HTTP2, MultiConnector: t.MultiConnector, ConnectorTokenEnv: t.ConnectorTokenEnv, ConnectorTokenFile: t.ConnectorTokenFile,
		TTL: t.TTL, PolicyFile: t.PolicyFile, Transport: t.Transport, Insecure: t.Insecure, Pin: t.Pin,
	}
}

// tunnelTarget is the local service a tunnel forwards to, for display and
// for replaying captured HTTP requests.
func tunnelTarget(acfg agent.Config) *url.URL {
	if acfg.Kind == "tcp" {
		return &url.URL{Scheme: "tcp", Host: acfg.TargetURL}
	}
	u, err := url.Parse(acfg.TargetURL)
	if err != nil {
		return nil
	}
	return u
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
