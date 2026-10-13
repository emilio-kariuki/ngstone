package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"ngstone/internal/agent"
	"ngstone/internal/config"
	"ngstone/internal/inspect"
	"ngstone/internal/tui"
)

const exampleTunnelsFile = `server: example.com:4443
tunnels:
  web:
    port: 3000
    subdomain: demo
  api:
    port: 8080
  db:
    kind: tcp
    port: 5432`

// startOptions holds the connection settings shared by every tunnel.
type startOptions struct {
	server     string
	serverName string
	token      string
	insecure   bool
	pin        string
}

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
	file, err := config.LoadTunnels(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && *cfgPath == "" {
			fmt.Fprintf(os.Stderr, "ngstone: no tunnels file found; create %s, for example:\n\n%s\n", config.TunnelsFileName, exampleTunnelsFile)
			return 1
		}
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}
	tunnels, err := selectTunnels(file.Tunnels, names)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}

	saved, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: loading config: %v\n", err)
		return 1
	}
	tok, err := resolveToken(*token, os.Getenv("NGSTONE_TOKEN"), saved)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ngstone: "+err.Error())
		return 1
	}
	opts := startOptions{
		server:     firstNonEmpty(*server, file.Server, resolveServer("", saved)),
		serverName: firstNonEmpty(*serverName, file.ServerName),
		token:      tok,
		insecure:   *insecure,
		pin:        *pin,
	}

	acfgs := make([]agent.Config, 0, len(tunnels))
	for _, nt := range tunnels {
		acfg, err := tunnelAgentConfig(nt, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ngstone: tunnel %q: %v\n", nt.Name, err)
			return 2
		}
		acfgs = append(acfgs, acfg)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if shouldUseTUI(*noTUI) {
		return runStartTUI(ctx, acfgs)
	}
	return runStartPlain(ctx, acfgs)
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

// tunnelAgentConfig turns one file entry into the same agent.Config that
// `ngstone port` or `ngstone tcp` would build from flags.
func tunnelAgentConfig(nt config.NamedTunnel, opts startOptions) (agent.Config, error) {
	acfg := agent.Config{
		Name:        nt.Name,
		ControlAddr: opts.server,
		Token:       opts.token,
		Insecure:    opts.insecure,
		ServerName:  opts.serverName,
		Pin:         opts.pin,
	}

	if len(nt.AllowCIDR) > 0 {
		cidrs, err := parseAllowCIDRs(strings.Join(nt.AllowCIDR, ","))
		if err != nil {
			return agent.Config{}, err
		}
		acfg.AllowCIDRs = cidrs
	}

	switch nt.Kind {
	case config.KindTCP:
		target := nt.Address
		if target == "" {
			target = net.JoinHostPort("127.0.0.1", strconv.Itoa(nt.Port))
		}
		acfg.Kind = "tcp"
		acfg.TargetURL = target
		acfg.RemotePort = nt.RemotePort
	default:
		target := nt.URL
		if target == "" {
			target = fmt.Sprintf("http://127.0.0.1:%d", nt.Port)
		}
		acfg.TargetURL = target
		acfg.Subdomain = nt.Subdomain
		acfg.HostHeader = nt.HostHeader

		pairs := nt.BasicAuth
		if nt.BasicAuthFile != "" {
			var err error
			if pairs, err = readBasicAuthFile(nt.BasicAuthFile); err != nil {
				return agent.Config{}, err
			}
		}
		if len(pairs) > 0 {
			digests, err := parseBasicAuthCreds(pairs)
			if err != nil {
				return agent.Config{}, err
			}
			acfg.BasicAuthSHA256 = digests
		}
	}
	return acfg, nil
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

// runAgents runs every tunnel until ctx is cancelled. A tunnel that stops
// with a fatal error, such as a subdomain held by another agent, is logged
// and the others keep running.
func runAgents(ctx context.Context, agents []*agent.Agent, names []string) error {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for i, a := range agents {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := a.Run(ctx); err != nil {
				slog.Error("ngstone: tunnel stopped", "tunnel", names[i], "err", err)
				mu.Lock()
				errs = append(errs, fmt.Errorf("tunnel %s: %w", names[i], err))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

func runStartPlain(ctx context.Context, acfgs []agent.Config) int {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	events := make(chan agent.StatusEvent, 64)
	agents, names := newTunnelAgents(acfgs, events, nil)

	targets := map[string]string{}
	width := 0
	for _, acfg := range acfgs {
		targets[acfg.Name] = acfg.TargetURL
		width = max(width, len(acfg.Name))
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-events:
				switch {
				case ev.State == agent.StateOnline && ev.URL != "":
					fmt.Printf("%-*s  %s -> %s\n", width, ev.Tunnel, ev.URL, targets[ev.Tunnel])
				case ev.State == agent.StateEvicted:
					fmt.Printf("%-*s  evicted: another agent took %s\n", width, ev.Tunnel, ev.URL)
				}
			}
		}
	}()

	logger.Info("ngstone: starting", "control", acfgs[0].ControlAddr, "tunnels", strings.Join(names, ","), "insecure", acfgs[0].Insecure)
	if err := runAgents(ctx, agents, names); err != nil {
		logger.Error("ngstone: exited with errors", "err", err)
		return 1
	}
	return 0
}

func runStartTUI(ctx context.Context, acfgs []agent.Config) int {
	ring := tui.NewLogRing(500)
	logger := slog.New(ring)
	slog.SetDefault(logger)

	store := inspect.NewStore()
	events := make(chan agent.StatusEvent, 64)
	agents, names := newTunnelAgents(acfgs, events, store)

	tunnels := make([]tui.Tunnel, len(agents))
	for i, a := range agents {
		tunnels[i] = tui.Tunnel{Name: names[i], Target: tunnelTarget(acfgs[i]), RT: a.Transport()}
	}

	logger.Info("ngstone: starting", "control", acfgs[0].ControlAddr, "tunnels", strings.Join(names, ","), "insecure", acfgs[0].Insecure)
	status := make(chan tui.StatusEvent, 64)

	res := supervise(ctx, agentShutdownGrace,
		func(agentCtx context.Context) error {
			go bridgeStatus(agentCtx, events, status)
			return runAgents(agentCtx, agents, names)
		},
		func(tuiCtx context.Context) error {
			return tui.Run(tuiCtx, tui.Options{
				Store:   store,
				Status:  status,
				Logs:    ring,
				Tunnels: tunnels,
			})
		})

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	return finishPortTUI(os.Stderr, ring.Lines(), res, agentShutdownGrace)
}

func newTunnelAgents(acfgs []agent.Config, events chan<- agent.StatusEvent, store *inspect.Store) ([]*agent.Agent, []string) {
	agents := make([]*agent.Agent, len(acfgs))
	names := make([]string, len(acfgs))
	for i, acfg := range acfgs {
		acfg.Events = events
		if acfg.Kind != "tcp" {
			acfg.Store = store
		}
		agents[i] = agent.New(acfg)
		names[i] = acfg.Name
	}
	return agents, names
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
