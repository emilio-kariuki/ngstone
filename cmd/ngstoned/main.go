package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/caddyserver/certmagic"

	"ngstone/internal/edge"
	"ngstone/internal/version"
)

func main() {
	publicAddr := flag.String("public", ":443", "public HTTPS listen address")
	controlAddr := flag.String("control", ":4443", "control plane listen address")
	httpAddr := flag.String("http", ":80", "HTTP redirect listen address (unused with -insecure)")
	opsAddr := flag.String("ops", "127.0.0.1:4041", "loopback ops endpoint address (expvar, /healthz, pprof); empty disables it")
	tokenSHA256Hex := flag.String("token-sha256", "", "hex-encoded SHA-256 of the shared auth token (defaults to $NGSTONE_TOKEN_SHA256; avoid passing this flag on a shared host, since ps auxww exposes flags but not the environment)")
	domain := flag.String("domain", "", "base domain used to build tunnel hostnames and the two managed certificates (required), for example example.com")
	publicScheme := flag.String("public-scheme", "https", "scheme advertised in BindOK.URL (http or https)")
	tcpPortRange := flag.String("tcp-ports", "", "port range for raw TCP tunnels, e.g. \"10000-10999\"; empty disables TCP tunnels. These ports are exposed directly to the internet (not behind a reverse proxy) and must be opened in the firewall.")
	tcpBindAddr := flag.String("tcp-bind", "0.0.0.0", "interface address the TCP tunnel port range binds on")
	maxShareTTL := flag.Duration("max-share-ttl", edge.DefaultMaxShareTTL, "longest lifetime an agent may request for a share link (ngstone share --expires)")

	proxyProtocol := flag.Bool("proxy-protocol", false, "require a PROXY protocol v1/v2 header on every connection to the public listener, and use the address it carries as the client address; enable this only when the public port is reachable solely from a trusted TCP proxy (see deploy/README.md), and enable it on both sides at once")
	proxyProtocolTrusted := flag.String("proxy-protocol-trusted", "", "comma-separated CIDRs trusted to originate PROXY protocol headers on the public listener (only meaningful with -proxy-protocol); connections from any other peer are closed immediately. If empty, PROXY headers are accepted from any peer and --allow-cidr per-tunnel checks cannot be trusted unless the public port is firewalled to the proxy")

	insecure := flag.Bool("insecure", false, "run with no TLS anywhere and no certificate management (dev/test only)")
	acmeCA := flag.String("acme-ca", edge.ACMECAStaging, "ACME CA to use: \"staging\" (default) or \"production\"; a config mistake against production can rate-limit the domain for a week")
	certEmail := flag.String("cert-email", "", "ACME account email (required unless -insecure)")
	certStorage := flag.String("cert-storage", edge.DefaultCertStoragePath, "certmagic FileStorage path; must match the systemd StateDirectory (see deploy/)")
	dnsProvider := flag.String("dns-provider", edge.DefaultDNSProvider, "DNS provider used for the DNS-01 certificate challenges; its credentials are read from the environment. Use -dns-provider help to list providers and their variables")
	cfAPIToken := flag.String("cf-api-token", "", "Cloudflare API token, for -dns-provider cloudflare (prefer $NGSTONE_CF_API_TOKEN; ps auxww exposes flags but not the environment)")

	readHeaderTimeout := flag.Duration("read-header-timeout", edge.DefaultReadHeaderTimeout, "public listener ReadHeaderTimeout")
	idleTimeout := flag.Duration("idle-timeout", edge.DefaultIdleTimeout, "public listener IdleTimeout")
	maxHeaderBytes := flag.Int("max-header-bytes", edge.DefaultMaxHeaderBytes, "public listener MaxHeaderBytes")
	maxBodyBytes := flag.Int64("max-body-bytes", edge.DefaultMaxBodyBytes, "maximum request body size before a 413")
	responseHeaderTimeout := flag.Duration("response-header-timeout", edge.DefaultResponseHeaderTimeout, "timeout waiting for the agent's response headers before a 504")
	perIPRate := flag.Float64("per-ip-rate", edge.DefaultPerIPRate, "per-IP requests/sec")
	perIPBurst := flag.Int("per-ip-burst", edge.DefaultPerIPBurst, "per-IP burst size")
	perIPLRU := flag.Int("per-ip-lru", edge.DefaultPerIPLRU, "max distinct IPs tracked by the per-IP limiter")
	globalInFlight := flag.Int64("global-inflight", edge.DefaultGlobalInFlight, "global in-flight request semaphore (memory ceiling = this x yamux window size)")
	perSessionInFlight := flag.Int64("per-session-inflight", edge.DefaultPerSessionInFlight, "per-session concurrent stream cap")
	upgradeInFlight := flag.Int64("upgrade-inflight", 0, "global concurrent upgraded (websocket/SSE) stream cap; 0 uses the built-in default")
	perSessionUpgrade := flag.Int64("per-session-upgrade", 0, "per-session concurrent upgraded (websocket/SSE) stream cap; 0 uses the built-in default")
	handshakeConcurrency := flag.Int("handshake-concurrency", edge.DefaultHandshakeConcurrency, ":4443 concurrent TLS handshake cap")
	unauthSessions := flag.Int("unauth-sessions", edge.DefaultUnauthSessions, ":4443 unauthenticated-session cap")
	perIPInFlight := flag.Int("per-ip-inflight", edge.DefaultPerIPInFlight, "max HTTP requests plus TCP tunnel connections one client address can have in flight (IPv6 grouped by /48)")
	clientIdleTimeout := flag.Duration("client-idle-timeout", edge.DefaultClientIdleTimeout, "max time one read of a request body, or one write of a response, may wait on the public client; a stalled upload gets 408")
	tcpIdleTimeout := flag.Duration("tcp-idle-timeout", edge.DefaultTCPIdleTimeout, "close a TCP tunnel connection after this long with no bytes in either direction")

	showVersion := flag.Bool("version", false, "print version and exit")

	flag.Parse()

	if *showVersion {
		fmt.Println("ngstoned " + version.String())
		return
	}
	if *dnsProvider == "help" {
		fmt.Print("Supported -dns-provider values and the environment variables each reads:\n\n" + edge.DescribeDNSProviders())
		return
	}

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
		logger.Error("ngstoned: -domain is required, for example -domain example.com")
		os.Exit(1)
	}

	var provider certmagic.DNSProvider
	if !*insecure {
		if *certEmail == "" {
			logger.Error("ngstoned: -cert-email is required unless -insecure")
			os.Exit(1)
		}
		getenv := func(key string) string {
			v := os.Getenv(key)
			if v == "" && key == "NGSTONE_CF_API_TOKEN" {
				v = *cfAPIToken
			}
			return v
		}
		provider, err = edge.NewDNSProvider(*dnsProvider, getenv)
		if err != nil {
			logger.Error("ngstoned: DNS provider setup failed; run ngstoned -dns-provider help to list providers and their variables", "err", err)
			os.Exit(1)
		}
	}

	var proxyProtocolTrustedList []string
	if *proxyProtocolTrusted != "" {
		proxyProtocolTrustedList = strings.Split(*proxyProtocolTrusted, ",")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv, err := edge.New(edge.Config{
		ControlAddr:  *controlAddr,
		PublicAddr:   *publicAddr,
		HTTPAddr:     *httpAddr,
		OpsAddr:      *opsAddr,
		Domain:       *domain,
		TokenSHA256:  sum,
		PublicScheme: *publicScheme,
		TCPPortRange: *tcpPortRange,
		TCPBindAddr:  *tcpBindAddr,
		MaxShareTTL:  *maxShareTTL,

		Insecure:             *insecure,
		ProxyProtocol:        *proxyProtocol,
		ProxyProtocolTrusted: proxyProtocolTrustedList,
		ACMECA:               *acmeCA,
		ACMEEmail:            *certEmail,
		CertStoragePath:      *certStorage,
		DNSProvider:          provider,

		Limits: edge.LimitsConfig{
			ReadHeaderTimeout:         *readHeaderTimeout,
			IdleTimeout:               *idleTimeout,
			MaxHeaderBytes:            *maxHeaderBytes,
			MaxBodyBytes:              *maxBodyBytes,
			ResponseHeaderTimeout:     *responseHeaderTimeout,
			PerIPRate:                 *perIPRate,
			PerIPBurst:                *perIPBurst,
			PerIPLRU:                  *perIPLRU,
			GlobalInFlight:            *globalInFlight,
			PerSessionInFlight:        *perSessionInFlight,
			UpgradeInFlight:           *upgradeInFlight,
			PerSessionUpgradeInFlight: *perSessionUpgrade,
			HandshakeConcurrency:      *handshakeConcurrency,
			UnauthSessions:            *unauthSessions,
			PerIPInFlight:             *perIPInFlight,
			ClientIdleTimeout:         *clientIdleTimeout,
			TCPIdleTimeout:            *tcpIdleTimeout,
		},
	})
	if err != nil {
		logger.Error("ngstoned: invalid configuration", "err", err)
		os.Exit(1)
	}

	logger.Info("ngstoned: starting", "control", *controlAddr, "public", *publicAddr, "domain", *domain, "insecure", *insecure, "acme-ca", *acmeCA, "dns-provider", *dnsProvider, "proxy-protocol", *proxyProtocol)
	if err := srv.Run(ctx); err != nil {
		logger.Error("ngstoned: exited with error", "err", err)
		os.Exit(1)
	}
}
