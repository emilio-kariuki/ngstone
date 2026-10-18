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
	"strconv"
	"strings"
	"syscall"

	"github.com/caddyserver/certmagic"

	"ngstone/internal/edge"
	"ngstone/internal/oidc"
	"ngstone/internal/storage"
	"ngstone/internal/version"
)

func main() {
	publicAddr := flag.String("public", ":443", "public HTTPS listen address")
	controlAddr := flag.String("control", ":4443", "control plane listen address")
	httpAddr := flag.String("http", ":80", "HTTP redirect listen address (unused with -insecure)")
	opsAddr := flag.String("ops", "127.0.0.1:4041", "loopback ops endpoint address (dashboard, /api/state, /metrics, expvar, /healthz, pprof); empty disables it")
	tokenSHA256Hex := flag.String("token-sha256", "", "legacy hex-encoded SHA-256 of the shared auth token (defaults to $NGSTONE_TOKEN_SHA256; prefer -credentials-file)")
	credentialsFileFlag := flag.String("credentials-file", "", "versioned per-tunnel credential file (defaults to $NGSTONE_CREDENTIALS_FILE)")
	databaseDriver := flag.String("database-driver", "", "control-plane database driver: sqlite or postgres (defaults from the database URL)")
	databaseURLFlag := flag.String("database-url", "", "control-plane database URL (defaults to $NGSTONE_DATABASE_URL or SQLite at /var/lib/ngstoned/control.db; prefer the environment for PostgreSQL credentials)")
	edgeID := flag.String("edge-id", "", "stable identifier for this edge server (defaults to $NGSTONE_EDGE_ID or a generated value)")
	leaseTTL := flag.Duration("lease-ttl", storage.DefaultLeaseTTL, "connector lease lifetime; heartbeats renew leases before expiry")
	adminTokenSHA256Hex := flag.String("admin-token-sha256", "", "hex-encoded SHA-256 of the management API bearer token (defaults to $NGSTONE_ADMIN_TOKEN_SHA256; loopback-only when unset)")
	alertWebhookURL := flag.String("alert-webhook", "", "HTTP(S) webhook for credential, connector, and lease lifecycle alerts (defaults to $NGSTONE_ALERT_WEBHOOK_URL)")
	oidcIssuer := flag.String("oidc-issuer", "", "OIDC issuer URL (defaults to $NGSTONE_OIDC_ISSUER; HTTPS required outside -insecure loopback development)")
	oidcClientID := flag.String("oidc-client-id", "", "OIDC client ID (defaults to $NGSTONE_OIDC_CLIENT_ID)")
	oidcRedirectURL := flag.String("oidc-redirect-url", "", "OIDC callback URL (defaults to $NGSTONE_OIDC_REDIRECT_URL)")
	oidcGroupsClaim := flag.String("oidc-groups-claim", "groups", "OIDC claim containing team/group names")
	oidcAdminGroups := flag.String("oidc-admin-groups", "", "comma-separated OIDC groups mapped to the admin role")
	oidcOperatorGroups := flag.String("oidc-operator-groups", "", "comma-separated OIDC groups mapped to the operator role")
	oidcViewerGroups := flag.String("oidc-viewer-groups", "", "comma-separated OIDC groups mapped to the viewer role")
	oidcAllowedEmailDomains := flag.String("oidc-allowed-email-domains", "", "comma-separated email domains allowed to log in")
	oidcDefaultRole := flag.String("oidc-default-role", "", "optional role for authenticated OIDC users without a matching group; empty requires a configured group")
	screenTURNURLs := flag.String("screen-turn-urls", "", "comma-separated STUN/TURN URLs delivered to authenticated screen participants (defaults to $NGSTONE_SCREEN_TURN_URLS)")
	screenTURNSecret := flag.String("screen-turn-secret", "", "coturn REST shared secret (defaults to $NGSTONE_SCREEN_TURN_SHARED_SECRET; prefer the environment)")
	screenMaxViewers := flag.Int("screen-max-viewers", edge.DefaultScreenMaxViewers, "maximum viewers allowed for an SFU screen session (1 keeps direct mode)")
	domain := flag.String("domain", "", "base domain used to build tunnel hostnames and the two managed certificates (required), for example example.com")
	publicScheme := flag.String("public-scheme", "https", "scheme advertised in BindOK.URL (http or https)")
	tcpPortRange := flag.String("tcp-ports", "", "port range for raw TCP tunnels, e.g. \"10000-10999\"; empty disables TCP tunnels. These ports are exposed directly to the internet (not behind a reverse proxy) and must be opened in the firewall.")
	tcpBindAddr := flag.String("tcp-bind", "0.0.0.0", "interface address the TCP tunnel port range binds on")
	maxShareTTL := flag.Duration("max-share-ttl", edge.DefaultMaxShareTTL, "longest lifetime an agent may request for a share link (ngstone share --expires)")
	shareAuditLog := flag.String("share-audit-log", "", "append every share audit event (connector joins, connections, closes) as JSON Lines to this file; empty disables it")

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

	credentialsFile := os.Getenv("NGSTONE_CREDENTIALS_FILE")
	if credentialsFile == "" {
		credentialsFile = *credentialsFileFlag
	}
	databaseURL := os.Getenv("NGSTONE_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = *databaseURLFlag
	}
	resolvedDatabaseDriver := os.Getenv("NGSTONE_DATABASE_DRIVER")
	if resolvedDatabaseDriver == "" {
		resolvedDatabaseDriver = *databaseDriver
	}
	resolvedEdgeID := os.Getenv("NGSTONE_EDGE_ID")
	if resolvedEdgeID == "" {
		resolvedEdgeID = *edgeID
	}
	tokenSHA256HexVal := os.Getenv("NGSTONE_TOKEN_SHA256")
	if tokenSHA256HexVal == "" {
		tokenSHA256HexVal = *tokenSHA256Hex
	}
	adminTokenSHA256HexVal := os.Getenv("NGSTONE_ADMIN_TOKEN_SHA256")
	if adminTokenSHA256HexVal == "" {
		adminTokenSHA256HexVal = *adminTokenSHA256Hex
	}
	resolvedAlertWebhookURL := os.Getenv("NGSTONE_ALERT_WEBHOOK_URL")
	if resolvedAlertWebhookURL == "" {
		resolvedAlertWebhookURL = *alertWebhookURL
	}
	alertWebhookToken := os.Getenv("NGSTONE_ALERT_WEBHOOK_TOKEN")
	resolvedOIDCIssuer := os.Getenv("NGSTONE_OIDC_ISSUER")
	if resolvedOIDCIssuer == "" {
		resolvedOIDCIssuer = *oidcIssuer
	}
	resolvedOIDCClientID := os.Getenv("NGSTONE_OIDC_CLIENT_ID")
	if resolvedOIDCClientID == "" {
		resolvedOIDCClientID = *oidcClientID
	}
	resolvedOIDCClientSecret := os.Getenv("NGSTONE_OIDC_CLIENT_SECRET")
	resolvedOIDCRedirectURL := os.Getenv("NGSTONE_OIDC_REDIRECT_URL")
	if resolvedOIDCRedirectURL == "" {
		resolvedOIDCRedirectURL = *oidcRedirectURL
	}
	resolvedOIDCGroupsClaim := os.Getenv("NGSTONE_OIDC_GROUPS_CLAIM")
	if resolvedOIDCGroupsClaim == "" {
		resolvedOIDCGroupsClaim = *oidcGroupsClaim
	}
	resolvedOIDCAdminGroups := os.Getenv("NGSTONE_OIDC_ADMIN_GROUPS")
	if resolvedOIDCAdminGroups == "" {
		resolvedOIDCAdminGroups = *oidcAdminGroups
	}
	resolvedOIDCOperatorGroups := os.Getenv("NGSTONE_OIDC_OPERATOR_GROUPS")
	if resolvedOIDCOperatorGroups == "" {
		resolvedOIDCOperatorGroups = *oidcOperatorGroups
	}
	resolvedOIDCViewerGroups := os.Getenv("NGSTONE_OIDC_VIEWER_GROUPS")
	if resolvedOIDCViewerGroups == "" {
		resolvedOIDCViewerGroups = *oidcViewerGroups
	}
	resolvedOIDCAllowedEmailDomains := os.Getenv("NGSTONE_OIDC_ALLOWED_EMAIL_DOMAINS")
	if resolvedOIDCAllowedEmailDomains == "" {
		resolvedOIDCAllowedEmailDomains = *oidcAllowedEmailDomains
	}
	resolvedOIDCDefaultRole := os.Getenv("NGSTONE_OIDC_DEFAULT_ROLE")
	if resolvedOIDCDefaultRole == "" {
		resolvedOIDCDefaultRole = *oidcDefaultRole
	}
	resolvedScreenTURNURLs := os.Getenv("NGSTONE_SCREEN_TURN_URLS")
	if resolvedScreenTURNURLs == "" {
		resolvedScreenTURNURLs = *screenTURNURLs
	}
	resolvedScreenTURNSecret := os.Getenv("NGSTONE_SCREEN_TURN_SHARED_SECRET")
	if resolvedScreenTURNSecret == "" {
		resolvedScreenTURNSecret = *screenTURNSecret
	}
	resolvedScreenMaxViewers := *screenMaxViewers
	if raw := strings.TrimSpace(os.Getenv("NGSTONE_SCREEN_MAX_VIEWERS")); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil {
			logger.Error("ngstoned: invalid NGSTONE_SCREEN_MAX_VIEWERS", "err", parseErr)
			os.Exit(1)
		}
		resolvedScreenMaxViewers = parsed
	}
	var oidcConfig *oidc.Config
	if resolvedOIDCIssuer != "" || resolvedOIDCClientID != "" || resolvedOIDCRedirectURL != "" || resolvedOIDCClientSecret != "" || os.Getenv("NGSTONE_OIDC_GROUPS_CLAIM") != "" || *oidcGroupsClaim != "groups" || resolvedOIDCAdminGroups != "" || resolvedOIDCOperatorGroups != "" || resolvedOIDCViewerGroups != "" || resolvedOIDCAllowedEmailDomains != "" || resolvedOIDCDefaultRole != "" || os.Getenv("NGSTONE_OIDC_COOKIE_SECRET") != "" {
		cookieSecret, secretErr := oidc.ParseCookieSecret(os.Getenv("NGSTONE_OIDC_COOKIE_SECRET"))
		if secretErr != nil {
			logger.Error("ngstoned: invalid OIDC cookie secret", "err", secretErr)
			os.Exit(1)
		}
		oidcConfig = &oidc.Config{
			Issuer:              resolvedOIDCIssuer,
			ClientID:            resolvedOIDCClientID,
			ClientSecret:        resolvedOIDCClientSecret,
			RedirectURL:         resolvedOIDCRedirectURL,
			CookieSecret:        cookieSecret,
			GroupsClaim:         resolvedOIDCGroupsClaim,
			AdminGroups:         splitCSV(resolvedOIDCAdminGroups),
			OperatorGroups:      splitCSV(resolvedOIDCOperatorGroups),
			ViewerGroups:        splitCSV(resolvedOIDCViewerGroups),
			AllowedEmailDomains: splitCSV(resolvedOIDCAllowedEmailDomains),
			DefaultRole:         resolvedOIDCDefaultRole,
			AllowInsecure:       *insecure,
		}
	}
	var sum []byte
	if databaseURL == "" && credentialsFile == "" && tokenSHA256HexVal == "" {
		databaseURL = storage.DefaultSQLite
	}
	if tokenSHA256HexVal != "" && (databaseURL != "" || credentialsFile != "") {
		logger.Error("ngstoned: legacy -token-sha256 cannot be combined with -database-url or -credentials-file; choose scoped credentials or legacy authentication")
		os.Exit(1)
	}
	if databaseURL == "" && credentialsFile == "" {
		if tokenSHA256HexVal == "" {
			logger.Error("ngstoned: -database-url, -credentials-file, or -token-sha256 is required")
			os.Exit(1)
		}
		var err error
		sum, err = hex.DecodeString(tokenSHA256HexVal)
		if err != nil || len(sum) != sha256.Size {
			logger.Error("ngstoned: -token-sha256 (or $NGSTONE_TOKEN_SHA256) must be a 64-character hex-encoded SHA-256 digest")
			os.Exit(1)
		}
	}
	var adminSum []byte
	if adminTokenSHA256HexVal != "" {
		var err error
		adminSum, err = hex.DecodeString(adminTokenSHA256HexVal)
		if err != nil || len(adminSum) != sha256.Size {
			logger.Error("ngstoned: -admin-token-sha256 (or $NGSTONE_ADMIN_TOKEN_SHA256) must be a 64-character hex-encoded SHA-256 digest")
			os.Exit(1)
		}
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
		var err error
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
		ControlAddr:       *controlAddr,
		PublicAddr:        *publicAddr,
		HTTPAddr:          *httpAddr,
		OpsAddr:           *opsAddr,
		Domain:            *domain,
		TokenSHA256:       sum,
		CredentialsFile:   credentialsFile,
		StorageDriver:     resolvedDatabaseDriver,
		StorageDSN:        databaseURL,
		EdgeID:            resolvedEdgeID,
		LeaseTTL:          *leaseTTL,
		AdminTokenSHA256:  adminSum,
		PublicScheme:      *publicScheme,
		AlertWebhookURL:   resolvedAlertWebhookURL,
		AlertWebhookToken: alertWebhookToken,
		OIDC:              oidcConfig,
		ScreenTURNURLs:    splitCSV(resolvedScreenTURNURLs),
		ScreenTURNSecret:  resolvedScreenTURNSecret,
		ScreenMaxViewers:  resolvedScreenMaxViewers,
		TCPPortRange:      *tcpPortRange,
		TCPBindAddr:       *tcpBindAddr,
		MaxShareTTL:       *maxShareTTL,
		ShareAuditLogPath: *shareAuditLog,

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

	logger.Info("ngstoned: starting", "control", *controlAddr, "public", *publicAddr, "domain", *domain, "insecure", *insecure, "acme-ca", *acmeCA, "dns-provider", *dnsProvider, "proxy-protocol", *proxyProtocol, "scoped_credentials", credentialsFile != "", "durable_storage", databaseURL != "", "admin_bearer", adminTokenSHA256HexVal != "", "oidc", oidcConfig != nil, "screen_turn", len(resolvedScreenTURNURLs) > 0, "screen_max_viewers", resolvedScreenMaxViewers)
	if err := srv.Run(ctx); err != nil {
		logger.Error("ngstoned: exited with error", "err", err)
		os.Exit(1)
	}
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}
