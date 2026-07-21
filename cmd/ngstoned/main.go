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
	publicAddr := flag.String("public", ":443", "public HTTPS listen address")
	controlAddr := flag.String("control", ":4443", "control plane listen address")
	httpAddr := flag.String("http", ":80", "HTTP redirect listen address (unused with -insecure)")
	tokenSHA256Hex := flag.String("token-sha256", "", "hex-encoded SHA-256 of the shared auth token (defaults to $NGSTONE_TOKEN_SHA256; avoid passing this flag on a shared host, since ps auxww exposes flags but not the environment)")
	domain := flag.String("domain", "ngstone.site", "base domain used to build tunnel hostnames and the two managed certificates")
	publicScheme := flag.String("public-scheme", "https", "scheme advertised in BindOK.URL (http or https)")

	insecure := flag.Bool("insecure", false, "run with no TLS anywhere and no certificate management (dev/test only)")
	acmeCA := flag.String("acme-ca", edge.ACMECAStaging, "ACME CA to use: \"staging\" (default) or \"production\"; a config mistake against production can rate-limit the domain for a week")
	certEmail := flag.String("cert-email", "", "ACME account email (required unless -insecure)")
	certStorage := flag.String("cert-storage", edge.DefaultCertStoragePath, "certmagic FileStorage path; must match the systemd StateDirectory (see deploy/)")
	cfAPIToken := flag.String("cf-api-token", "", "Cloudflare API token scoped to Zone:DNS:Edit on the one zone (required unless -insecure; defaults to $NGSTONE_CF_API_TOKEN; avoid passing this flag on a shared host, since ps auxww exposes flags but not the environment)")

	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	tokenSHA256HexVal := os.Getenv("NGSTONE_TOKEN_SHA256")
	if tokenSHA256HexVal == "" {
		tokenSHA256HexVal = *tokenSHA256Hex
	}
	if tokenSHA256HexVal == "" {
		logger.Error("ngstoned: -token-sha256 (or $NGSTONE_TOKEN_SHA256) is required")
		os.Exit(1)
	}
	sum, err := hex.DecodeString(tokenSHA256HexVal)
	if err != nil || len(sum) != sha256.Size {
		logger.Error("ngstoned: -token-sha256 (or $NGSTONE_TOKEN_SHA256) must be a 64-character hex-encoded SHA-256 digest")
		os.Exit(1)
	}
	if *domain == "" {
		logger.Error("ngstoned: -domain is required")
		os.Exit(1)
	}

	cfToken := os.Getenv("NGSTONE_CF_API_TOKEN")
	if cfToken == "" {
		cfToken = *cfAPIToken
	}
	if !*insecure {
		if *certEmail == "" {
			logger.Error("ngstoned: -cert-email is required unless -insecure")
			os.Exit(1)
		}
		if cfToken == "" {
			logger.Error("ngstoned: -cf-api-token (or $NGSTONE_CF_API_TOKEN) is required unless -insecure")
			os.Exit(1)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := edge.New(edge.Config{
		ControlAddr:  *controlAddr,
		PublicAddr:   *publicAddr,
		HTTPAddr:     *httpAddr,
		Domain:       *domain,
		TokenSHA256:  sum,
		PublicScheme: *publicScheme,

		Insecure:           *insecure,
		ACMECA:             *acmeCA,
		ACMEEmail:          *certEmail,
		CertStoragePath:    *certStorage,
		CloudflareAPIToken: cfToken,
	})

	logger.Info("ngstoned: starting", "control", *controlAddr, "public", *publicAddr, "domain", *domain, "insecure", *insecure, "acme-ca", *acmeCA)
	if err := srv.Run(ctx); err != nil {
		logger.Error("ngstoned: exited with error", "err", err)
		os.Exit(1)
	}
}
