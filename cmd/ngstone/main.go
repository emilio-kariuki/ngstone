package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"ngstone/internal/agent"
	"ngstone/internal/version"
)

func main() {
	controlAddr := flag.String("control", "ngstone.site:4443", "edge control plane address")
	token := flag.String("token", "", "shared auth token (defaults to NGSTONE_TOKEN env var)")
	target := flag.String("target", "http://127.0.0.1:3000", "local target URL to forward requests to")
	subdomain := flag.String("subdomain", "", "requested subdomain (empty = server-assigned)")
	instanceID := flag.String("instance-id", "", "internal/undocumented: force a specific instance id (testing only)")

	insecure := flag.Bool("insecure", false, "dial the control plane in plaintext (dev/test only, no certificates involved)")
	serverName := flag.String("server-name", agent.DefaultServerName, "TLS ServerName/SNI to verify against (ignored with -insecure)")
	pin := flag.String("pin", "", "optional \"sha256/BASE64\" SPKI pin, checked in addition to normal chain validation (off by default)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("ngstone " + version.String())
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	tok := *token
	if tok == "" {
		tok = os.Getenv("NGSTONE_TOKEN")
	}
	if tok == "" {
		logger.Error("ngstone: -token or NGSTONE_TOKEN is required")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := agent.New(agent.Config{
		ControlAddr: *controlAddr,
		Token:       tok,
		Subdomain:   *subdomain,
		TargetURL:   *target,
		InstanceID:  *instanceID,

		Insecure:   *insecure,
		ServerName: *serverName,
		Pin:        *pin,
	})

	logger.Info("ngstone: starting", "control", *controlAddr, "target", *target, "insecure", *insecure)
	if err := a.Run(ctx); err != nil {
		logger.Error("ngstone: exited with error", "err", err)
		os.Exit(1)
	}
}
