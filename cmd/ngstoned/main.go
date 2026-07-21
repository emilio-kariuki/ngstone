package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"ngstone/internal/edge"
)

func main() {
	publicAddr := flag.String("public", ":8443", "public HTTP listen address")
	controlAddr := flag.String("control", ":4443", "control plane listen address")
	tokenSHA256Hex := flag.String("token-sha256", "", "hex-encoded SHA-256 of the shared auth token")
	domain := flag.String("domain", "ngstone.site", "base domain used to build tunnel hostnames")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	if *tokenSHA256Hex == "" {
		logger.Error("ngstoned: -token-sha256 is required")
		os.Exit(1)
	}
	sum, err := hex.DecodeString(*tokenSHA256Hex)
	if err != nil || len(sum) != sha256.Size {
		logger.Error("ngstoned: -token-sha256 must be a 64-character hex-encoded SHA-256 digest")
		os.Exit(1)
	}
	if *domain == "" {
		logger.Error("ngstoned: -domain is required")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := edge.New(edge.Config{
		ControlAddr: *controlAddr,
		PublicAddr:  *publicAddr,
		Domain:      *domain,
		TokenSHA256: sum,
	})

	logger.Info("ngstoned: starting", "control", *controlAddr, "public", *publicAddr, "domain", *domain)
	if err := srv.Run(ctx); err != nil {
		logger.Error("ngstoned: exited with error", "err", err)
		os.Exit(1)
	}
}
