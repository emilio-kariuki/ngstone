package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ngstone/internal/agent"
	"ngstone/internal/config"
	"ngstone/internal/inspect"
)

type tlsFlags struct {
	subdomain  string
	server     string
	transport  string
	token      string
	instanceID string
	insecure   bool
	serverName string
	pin        string
	allowCIDR  string
	ttl        time.Duration
	json       bool
}

func newTLSFlagSet() (*flag.FlagSet, *tlsFlags) {
	fs := flag.NewFlagSet("tls", flag.ContinueOnError)
	tf := &tlsFlags{}
	fs.StringVar(&tf.subdomain, "subdomain", "", "requested subdomain (empty = server-assigned)")
	fs.StringVar(&tf.subdomain, "s", "", "shorthand for -subdomain")
	fs.StringVar(&tf.server, "server", "", "edge control plane address override (defaults to config or "+defaultServer+")")
	fs.StringVar(&tf.transport, "transport", agent.TransportAuto, "control transport: auto, raw, or websocket (auto falls back to HTTPS on port 443)")
	fs.StringVar(&tf.token, "token", "", "auth token override (defaults to NGSTONE_TOKEN or the saved config)")
	fs.StringVar(&tf.instanceID, "instance-id", "", "internal/undocumented: force a specific instance id (testing only)")
	fs.BoolVar(&tf.insecure, "insecure", false, "dial the control plane in plaintext (dev/test only, no certificates involved)")
	fs.StringVar(&tf.serverName, "server-name", "", "TLS ServerName/SNI to verify against; defaults to the host in the server address (ignored with -insecure)")
	fs.StringVar(&tf.pin, "pin", "", "optional \"sha256/BASE64\" SPKI pin, checked in addition to normal chain validation")
	fs.StringVar(&tf.allowCIDR, "allow-cidr", "", "comma-separated CIDRs allowed to reach the tunnel (empty = allow all)")
	fs.DurationVar(&tf.ttl, "ttl", 0, "stop the tunnel after this duration (for example, 2h)")
	fs.BoolVar(&tf.json, "json", false, "emit JSON Lines status events")
	return fs, tf
}

func cmdTLS(args []string) int {
	fs, tf := newTLSFlagSet()
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if err := agent.ValidateTransport(tf.transport); err != nil {
		fmt.Fprintln(os.Stderr, "ngstone: "+err.Error())
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprintln(os.Stderr, "usage: ngstone tls <port|host:port> [--subdomain name]")
		return 2
	}
	if tf.ttl < 0 {
		fmt.Fprintln(os.Stderr, "ngstone: --ttl must be zero or a positive duration")
		return 2
	}

	target, err := resolveTCPTarget(positionals[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: loading config: %v\n", err)
		return 1
	}

	token, err := resolveToken(tf.token, os.Getenv("NGSTONE_TOKEN"), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ngstone: "+err.Error())
		return 1
	}
	server := resolveServer(tf.server, cfg)

	allowCIDRs, err := parseAllowCIDRs(tf.allowCIDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}

	acfg := agent.Config{
		ControlAddr: server,
		Transport:   tf.transport,
		Token:       token,
		Kind:        "tls",
		TargetURL:   target,
		Subdomain:   tf.subdomain,
		InstanceID:  tf.instanceID,

		AllowCIDRs: allowCIDRs,

		Insecure:   tf.insecure,
		ServerName: tf.serverName,
		Pin:        tf.pin,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runCtx, cancel, expiresAt := contextForTTL(ctx, tf.ttl)
	defer cancel()

	if tf.json {
		return runJSONAgent(runCtx, acfg, "", "", inspect.HAROptions{}, expiresAt)
	}
	return runTLSPlain(runCtx, acfg)
}

func runTLSPlain(ctx context.Context, acfg agent.Config) int {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	events := make(chan agent.StatusEvent, 16)
	acfg.Events = events

	a := agent.New(acfg)
	defer publishStatus(ctx, "tls", []agent.Config{acfg}, []*agent.Agent{a})()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-events:
				if !ok {
					return
				}
				if ev.State == agent.StateOnline && ev.URL != "" {
					fmt.Printf("%s -> %s\n", ev.URL, acfg.TargetURL)
				}
			}
		}
	}()

	logger.Info("ngstone: starting", "control", acfg.ControlAddr, "target", acfg.TargetURL, "kind", "tls", "insecure", acfg.Insecure)
	if err := a.Run(ctx); err != nil {
		logger.Error("ngstone: exited with error", "err", err)
		return 1
	}
	return 0
}
