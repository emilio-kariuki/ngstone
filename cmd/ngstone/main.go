package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"ngstone/internal/agent"
)

func main() {
	controlAddr := flag.String("control", "127.0.0.1:4443", "edge control plane address")
	token := flag.String("token", "", "shared auth token (defaults to NGSTONE_TOKEN env var)")
	target := flag.String("target", "http://127.0.0.1:3000", "local target URL to forward requests to")
	subdomain := flag.String("subdomain", "", "requested subdomain (empty = server-assigned)")
	flag.Parse()

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
	})

	logger.Info("ngstone: starting", "control", *controlAddr, "target", *target)
	if err := a.Run(ctx); err != nil {
		logger.Error("ngstone: exited with error", "err", err)
		os.Exit(1)
	}
}
