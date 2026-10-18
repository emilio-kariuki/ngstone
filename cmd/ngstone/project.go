package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"ngstone/internal/agent"
	"ngstone/internal/config"
	"ngstone/internal/inspect"
	"ngstone/internal/policy"
	"ngstone/internal/tui"
)

type projectRunOptions struct {
	Command             string
	TUI                 bool
	JSON                bool
	HARPath             string
	HARIncludeSensitive bool
}

type projectJSONEvent struct {
	Type      string `json:"type"`
	Time      string `json:"time"`
	Name      string `json:"name,omitempty"`
	Kind      string `json:"kind"`
	Target    string `json:"target"`
	State     string `json:"state"`
	Hostname  string `json:"hostname,omitempty"`
	URL       string `json:"url,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

type projectEvent struct {
	runner *projectRunner
	event  agent.StatusEvent
	done   bool
	err    error
}

type projectRunner struct {
	name      string
	kind      string
	target    string
	ttl       time.Duration
	expiresAt time.Time
	ctx       context.Context
	cancel    context.CancelFunc
	agent     *agent.Agent
	events    chan agent.StatusEvent
}

func cmdUp(args []string) int {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	file := fs.String("file", "", "project file (default: ngstone.json or .ngstone.json)")
	jsonOutput := fs.Bool("json", false, "emit JSON Lines status events")
	noTUI := fs.Bool("no-tui", false, "disable the terminal inspector UI")
	harPath := fs.String("har", "", "write captured HTTP exchanges as a HAR file when the project exits")
	harIncludeSensitive := fs.Bool("har-include-sensitive", false, "include authorization and cookie headers in the HAR export")
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 0 {
		fmt.Fprintln(os.Stderr, "usage: ngstone up [--file path] [--json] [--har path]")
		return 2
	}

	projectPath, err := config.FindProject(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ngstone: "+err.Error())
		return 2
	}
	project, err := config.LoadProject(projectPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ngstone: "+err.Error())
		return 2
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: loading config: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runProject(ctx, project, filepath.Dir(projectPath), cfg, projectRunOptions{
		Command:             "up",
		TUI:                 !*jsonOutput && shouldUseTUI(*noTUI),
		JSON:                *jsonOutput,
		HARPath:             *harPath,
		HARIncludeSensitive: *harIncludeSensitive,
	})
}

func runProject(ctx context.Context, project config.Project, projectDir string, cfg config.Config, opts projectRunOptions) int {
	var configs []agent.Config
	var ttls []time.Duration
	for _, named := range project.SortedTunnels() {
		acfg, ttl, err := buildProjectAgent(named.Name, named.Tunnel, projectDir, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ngstone: tunnel %s: %v\n", named.Name, err)
			return 2
		}
		configs = append(configs, acfg)
		ttls = append(ttls, ttl)
	}
	return runTunnelConfigs(ctx, configs, ttls, opts)
}

func runTunnelConfigs(ctx context.Context, configs []agent.Config, ttls []time.Duration, opts projectRunOptions) int {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var ring *tui.LogRing
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if opts.TUI {
		ring = tui.NewLogRing(500)
		logger = slog.New(ring)
	}
	slog.SetDefault(logger)
	defer slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	var history *inspect.Store
	if opts.TUI || opts.HARPath != "" {
		history = inspect.NewStore()
	}
	var runners []*projectRunner
	var agents []*agent.Agent
	var uiTunnels []tui.Tunnel
	for i, acfg := range configs {
		acfg.Store = history
		events := make(chan agent.StatusEvent, 16)
		acfg.Events = events
		a := agent.New(acfg)
		runner := &projectRunner{name: acfg.Name, kind: projectKind(acfg), target: acfg.TargetURL, agent: a, events: events}
		if i < len(ttls) {
			runner.ttl = ttls[i]
		}
		runners = append(runners, runner)
		agents = append(agents, a)
		uiTunnels = append(uiTunnels, tui.Tunnel{Name: acfg.Name, Target: tunnelTarget(acfg), RT: a.Transport()})
	}
	defer publishStatus(ctx, opts.Command, configs, agents)()
	uiEvents := make(chan agent.StatusEvent, 64)
	uiStatus := make(chan tui.StatusEvent, 64)
	if opts.TUI {
		go bridgeStatus(ctx, uiEvents, uiStatus)
	}
	run := func(runCtx context.Context) error {
		events := make(chan projectEvent, len(runners)*16+1)
		for _, runner := range runners {
			runner.ctx, runner.cancel, runner.expiresAt = contextForTTL(runCtx, runner.ttl)
			defer runner.cancel()
			startProjectRunner(runner, events)
		}
		encoder := json.NewEncoder(os.Stdout)
		var runErrors []error
		for remaining := len(runners); remaining > 0; {
			item := <-events
			if item.done {
				remaining--
				if item.err != nil && item.runner.ctx.Err() == nil && runCtx.Err() == nil {
					runErrors = append(runErrors, fmt.Errorf("tunnel %s: %w", item.runner.name, item.err))
				}
				continue
			}
			if opts.TUI {
				select {
				case uiEvents <- item.event:
				default:
				}
			} else if err := writeProjectEvent(encoder, opts.JSON, item.runner, item.event); err != nil {
				runErrors = append(runErrors, err)
				cancel()
			}
		}
		return errors.Join(runErrors...)
	}
	exitCode := 0
	if opts.TUI {
		result := supervise(ctx, agentShutdownGrace, run, func(uiCtx context.Context) error {
			return tui.Run(uiCtx, tui.Options{Store: history, Status: uiStatus, Logs: ring, Tunnels: uiTunnels})
		})
		exitCode = finishPortTUI(os.Stderr, ring.Lines(), result, agentShutdownGrace)
	} else if err := run(ctx); err != nil {
		logger.Error("ngstone: tunnels stopped", "err", err)
		exitCode = 1
	}
	if opts.HARPath != "" {
		if err := inspect.WriteHAR(opts.HARPath, history.List(), inspect.HAROptions{IncludeSensitive: opts.HARIncludeSensitive}); err != nil {
			fmt.Fprintf(os.Stderr, "ngstone: writing HAR: %v\n", err)
			exitCode = 1
		}
	}
	return exitCode
}

func startProjectRunner(runner *projectRunner, eventCh chan<- projectEvent) {
	forwardDone := make(chan struct{})
	go func() {
		defer close(forwardDone)
		for event := range runner.events {
			eventCh <- projectEvent{runner: runner, event: event}
		}
	}()
	go func() {
		err := runner.agent.Run(runner.ctx)
		close(runner.events)
		<-forwardDone
		eventCh <- projectEvent{runner: runner, err: err, done: true}
	}()
}

func buildProjectAgent(name string, tunnel config.ProjectTunnel, projectDir string, cfg config.Config) (agent.Config, time.Duration, error) {
	key := name
	if key == "" {
		key = "tunnel"
	}
	project := config.Project{Tunnels: map[string]config.ProjectTunnel{key: tunnel}}
	if err := project.Validate(); err != nil {
		return agent.Config{}, 0, err
	}
	tunnel = project.Tunnels[key]
	kind := tunnel.Kind
	if kind == "" {
		kind = "http"
	}

	target := tunnel.Target
	var err error
	if kind == "tcp" {
		target, err = resolveTCPTarget(tunnel.Target)
	} else {
		target, err = resolveTargetURL(tunnel.Target)
	}
	if err != nil {
		return agent.Config{}, 0, err
	}

	tokenEnv := os.Getenv("NGSTONE_TOKEN")
	if tunnel.CredentialEnv != "" {
		tokenEnv = os.Getenv(tunnel.CredentialEnv)
	}
	if tunnel.CredentialEnv != "" && tokenEnv == "" && tunnel.Token == "" {
		return agent.Config{}, 0, fmt.Errorf("credential environment variable %s is empty", tunnel.CredentialEnv)
	}
	if tunnel.CredentialFile != "" && tunnel.Token == "" {
		tokenEnv, err = readPrivateTokenFile(projectDir, tunnel.CredentialFile)
		if err != nil {
			return agent.Config{}, 0, err
		}
	}

	token, err := resolveToken(tunnel.Token, tokenEnv, cfg)
	if err != nil {
		return agent.Config{}, 0, err
	}
	server := resolveServer(tunnel.Server, cfg)
	connectorTokenEnv := tunnel.ConnectorTokenEnv
	if connectorTokenEnv == "" {
		connectorTokenEnv = "NGSTONE_CONNECTOR_TOKEN"
	}
	connectorToken := os.Getenv(connectorTokenEnv)
	if tunnel.ConnectorTokenFile != "" {
		connectorToken, err = readPrivateTokenFile(projectDir, tunnel.ConnectorTokenFile)
		if err != nil {
			return agent.Config{}, 0, err
		}
	}
	if tunnel.MultiConnector && strings.TrimSpace(connectorToken) == "" {
		return agent.Config{}, 0, fmt.Errorf("tunnel %q requires %s for multi-connector mode", tunnel.Subdomain, connectorTokenEnv)
	}

	basicAuthPairs := tunnel.BasicAuth
	if tunnel.BasicAuthFile != "" {
		path := tunnel.BasicAuthFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(projectDir, path)
		}
		basicAuthPairs, err = readBasicAuthFile(path)
		if err != nil {
			return agent.Config{}, 0, err
		}
	}
	basicAuthDigests, err := parseBasicAuthCreds(basicAuthPairs)
	if err != nil {
		return agent.Config{}, 0, err
	}
	allowCIDRs, err := parseAllowCIDRs(tunnel.AllowCIDR)
	if err != nil {
		return agent.Config{}, 0, err
	}
	var trafficPolicy *policy.Policy
	if tunnel.PolicyFile != "" {
		path := tunnel.PolicyFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(projectDir, path)
		}
		trafficPolicy, err = policy.LoadFile(path)
		if err != nil {
			return agent.Config{}, 0, err
		}
	}
	ttl, err := tunnel.TTLDuration()
	if err != nil {
		return agent.Config{}, 0, err
	}

	acfg := agent.Config{
		ControlAddr:     server,
		Transport:       tunnel.Transport,
		Token:           token,
		Name:            name,
		Subdomain:       tunnel.Subdomain,
		TargetURL:       target,
		HostHeader:      tunnel.HostHeader,
		HTTP2:           tunnel.HTTP2,
		MultiConnector:  tunnel.MultiConnector,
		ConnectorToken:  connectorToken,
		Kind:            kind,
		RemotePort:      tunnel.RemotePort,
		BasicAuthSHA256: basicAuthDigests,
		AllowCIDRs:      allowCIDRs,
		Policy:          trafficPolicy,
		Insecure:        tunnel.Insecure,
		ServerName:      tunnel.ServerName,
		Pin:             tunnel.Pin,
	}
	return acfg, ttl, nil
}

func readPrivateTokenFile(directory, path string) (string, error) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(directory, path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("reading token file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("token file must be a regular file readable only by its owner")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading token file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("token file is empty")
	}
	return token, nil
}

func projectKind(acfg agent.Config) string {
	if acfg.Kind == "" {
		return "http"
	}
	return acfg.Kind
}

func contextForTTL(parent context.Context, ttl time.Duration) (context.Context, context.CancelFunc, time.Time) {
	if ttl <= 0 {
		return parent, func() {}, time.Time{}
	}
	ctx, cancel := context.WithTimeout(parent, ttl)
	return ctx, cancel, time.Now().Add(ttl)
}

func writeProjectEvent(encoder *json.Encoder, jsonOutput bool, runner *projectRunner, event agent.StatusEvent) error {
	if jsonOutput {
		return encoder.Encode(projectJSONEvent{
			Type:      "tunnel",
			Time:      time.Now().UTC().Format(time.RFC3339Nano),
			Name:      runner.name,
			Kind:      runner.kind,
			Target:    runner.target,
			State:     event.State,
			Hostname:  event.Hostname,
			URL:       event.URL,
			ExpiresAt: formatTime(runner.expiresAt),
			Error:     event.Err,
		})
	}
	switch event.State {
	case agent.StateOnline:
		fmt.Printf("%s: %s -> %s\n", runner.name, event.URL, runner.target)
	case agent.StateExpired:
		fmt.Printf("%s: expired after %s\n", runner.name, runner.ttl)
	case agent.StateOffline, agent.StateEvicted:
		if event.Err != "" {
			fmt.Fprintf(os.Stderr, "ngstone: %s: %s: %s\n", runner.name, event.State, event.Err)
		}
	}
	return nil
}

func runJSONAgent(ctx context.Context, acfg agent.Config, name, harPath string, harOpts inspect.HAROptions, expiresAt time.Time) int {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	events := make(chan agent.StatusEvent, 16)
	acfg.Events = events
	if harPath != "" {
		acfg.Store = inspect.NewStore()
	}
	a := agent.New(acfg)
	command := "port"
	if acfg.Kind == "tcp" {
		command = "tcp"
	}
	defer publishStatus(ctx, command, []agent.Config{acfg}, []*agent.Agent{a})()
	done := make(chan error, 1)
	go func() {
		err := a.Run(ctx)
		close(events)
		done <- err
	}()

	encoder := json.NewEncoder(os.Stdout)
	for {
		select {
		case event, ok := <-events:
			if !ok {
				err := <-done
				return finishJSONAgent(a, err, ctx, harPath, harOpts)
			}
			if err := writeAgentJSONEvent(encoder, name, acfg, expiresAt, event); err != nil {
				logger.Error("ngstone: writing JSON output", "err", err)
				return 1
			}
		case err := <-done:
			for event := range events {
				if writeErr := writeAgentJSONEvent(encoder, name, acfg, expiresAt, event); writeErr != nil {
					logger.Error("ngstone: writing JSON output", "err", writeErr)
					return 1
				}
			}
			return finishJSONAgent(a, err, ctx, harPath, harOpts)
		}
	}
}

func finishJSONAgent(a *agent.Agent, err error, ctx context.Context, harPath string, harOpts inspect.HAROptions) int {
	exitCode := 0
	if err != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
		slog.Error("ngstone: exited with error", "err", err)
		exitCode = 1
	}
	if harPath != "" && a.Store() != nil {
		if writeErr := inspect.WriteHAR(harPath, a.Store().List(), harOpts); writeErr != nil {
			slog.Error("ngstone: writing HAR", "err", writeErr)
			exitCode = 1
		} else {
			slog.Info("ngstone: HAR export written", "path", harPath, "exchanges", a.Store().Len())
		}
	}
	return exitCode
}

func writeAgentJSONEvent(encoder *json.Encoder, name string, acfg agent.Config, expiresAt time.Time, event agent.StatusEvent) error {
	return encoder.Encode(projectJSONEvent{
		Type:      "tunnel",
		Time:      time.Now().UTC().Format(time.RFC3339Nano),
		Name:      name,
		Kind:      projectKind(acfg),
		Target:    acfg.TargetURL,
		State:     event.State,
		Hostname:  event.Hostname,
		URL:       event.URL,
		ExpiresAt: formatTime(expiresAt),
		Error:     event.Err,
	})
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
