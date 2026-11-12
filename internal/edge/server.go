package edge

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"

	"ngstone/internal/credentials"
	"ngstone/internal/oidc"
	"ngstone/internal/proto"
	"ngstone/internal/storage"
)

type credentialStore interface {
	IssueContext(context.Context, credentials.Spec, time.Duration) (credentials.Issued, error)
	ValidateContext(context.Context, string, time.Time) (credentials.Credential, error)
	ActiveContext(context.Context, string, time.Time) (bool, error)
	RevokeForOwnerContext(context.Context, string, string) error
	ListForOwnerContext(context.Context, string) ([]credentials.Credential, error)
}

type Config struct {
	ControlAddr       string
	PublicAddr        string
	Domain            string
	TokenSHA256       []byte
	CredentialsFile   string
	Storage           *storage.Store
	StorageDriver     string
	StorageDSN        string
	EdgeID            string
	LeaseTTL          time.Duration
	AdminTokenSHA256  []byte
	PublicScheme      string
	AlertWebhookURL   string
	AlertWebhookToken string
	OIDC              *oidc.Config
	VisitorOIDC       *oidc.Config

	Insecure bool

	ProxyProtocol        bool
	ProxyProtocolTrusted []string

	HTTPAddr string
	OpsAddr  string

	AdminMTLSAddr         string
	AdminMTLSClientCAFile string

	PeerAddr        string
	PeerListen      string
	PublicTLSConfig *tls.Config
	CustomCertDir   string
	QUIC            bool

	TCPPortRange string
	TCPBindAddr  string

	// MaxShareTTL caps how far in the future a share may expire; 0 means
	// DefaultMaxShareTTL.
	MaxShareTTL time.Duration
	// ShareAuditLogPath appends every share audit event as JSON Lines to
	// this file; empty disables it.
	ShareAuditLogPath string

	CertStoragePath string
	ACMEEmail       string
	ACMECA          string
	DNSProvider     certmagic.DNSProvider

	Limits LimitsConfig
}

type Server struct {
	cfg Config

	startedAt time.Time
	events    *eventRing

	registry        *Registry
	authLimiter     *authRateLimiter
	adminLimiter    *authRateLimiter
	credentialStore credentialStore
	storage         *storage.Store
	ownsStorage     bool
	randomName      func() string

	aliases *aliasResolver

	perIPLimiter *perIPLimiter
	perIP        *perIPInflight
	globalSem    *globalSemaphore
	upgradeSem   *globalSemaphore
	handshakeSem *globalSemaphore
	unauthSem    *globalSemaphore
	fallbackSem  *globalSemaphore

	webhookBudget *byteBudget

	adminClientCAs *x509.CertPool

	tlsMgr *TLSManager
	tcpMgr *tcpManager
	peers  *peerForwarder

	shares        *shareRegistry
	shareSem      *globalSemaphore
	shareAudit    *shareAuditLog
	observability *observabilityRegistry
	alerts        *alertDispatcher
	oidc          *oidc.Provider
	oidcCodec     *oidc.Codec
	visitor       *visitorLogin
	auditCh       chan storage.AuditEvent
	auditStop     chan struct{}
	auditWG       sync.WaitGroup

	proxyProtoTrusted []netip.Prefix

	// controlConns tracks per-connection control goroutines so Run can wait
	// for each session's Goodbye and drain before returning. Add happens only
	// in acceptControl, which has returned before Run calls Wait.
	controlConns    sync.WaitGroup
	controlMu       sync.Mutex
	controlDraining bool
}

// controlShutdownGrace bounds how long Run waits, after its listeners stop,
// for agent sessions to send Goodbye and drain. A session drains for at most
// drainTimeout plus the TCP release grace; the margin covers a slow peer.
var controlShutdownGrace = drainTimeout + 15*time.Second

func New(cfg Config) (*Server, error) {
	if cfg.MaxShareTTL < 0 {
		return nil, fmt.Errorf("edge: -max-share-ttl must not be negative, got %s", cfg.MaxShareTTL)
	}
	if len(cfg.AdminTokenSHA256) != 0 && len(cfg.AdminTokenSHA256) != sha256.Size {
		return nil, fmt.Errorf("edge: admin token sha256 must be %d bytes", sha256.Size)
	}
	if cfg.PublicScheme == "" {
		cfg.PublicScheme = "https"
	}
	limits, err := cfg.Limits.withDefaults()
	if err != nil {
		return nil, fmt.Errorf("edge: invalid limits config: %w", err)
	}
	cfg.Limits = limits

	var adminClientCAs *x509.CertPool
	if cfg.AdminMTLSAddr != "" || cfg.AdminMTLSClientCAFile != "" {
		if cfg.AdminMTLSAddr == "" || cfg.AdminMTLSClientCAFile == "" {
			return nil, errors.New("edge: admin mTLS needs both an address and a client CA file")
		}
		if cfg.Insecure {
			return nil, errors.New("edge: admin mTLS cannot be combined with insecure mode")
		}
		adminClientCAs, err = loadAdminClientCAs(cfg.AdminMTLSClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("edge: %w", err)
		}
	}

	registry := NewRegistry()
	registry.SetLimits(limits)

	storageConfigured := cfg.Storage != nil || strings.TrimSpace(cfg.StorageDriver) != "" || strings.TrimSpace(cfg.StorageDSN) != ""
	if cfg.PeerAddr != "" || cfg.PeerListen != "" {
		if err := validatePeerAddr(cfg, storageConfigured); err != nil {
			return nil, err
		}
	}

	var durableStore *storage.Store
	if cfg.Storage != nil {
		durableStore = cfg.Storage
	} else if strings.TrimSpace(cfg.StorageDriver) != "" || strings.TrimSpace(cfg.StorageDSN) != "" {
		durableStore, err = storage.Open(storage.Config{
			Driver:   cfg.StorageDriver,
			DSN:      cfg.StorageDSN,
			EdgeID:   cfg.EdgeID,
			LeaseTTL: cfg.LeaseTTL,
		})
		if err != nil {
			return nil, fmt.Errorf("edge: opening control-plane storage: %w", err)
		}
	}
	closeOpenedStorage := func() {
		if durableStore != nil && cfg.Storage == nil {
			_ = durableStore.Close()
		}
	}
	if cfg.PublicTLSConfig != nil && cfg.Insecure {
		closeOpenedStorage()
		return nil, errors.New("edge: a public TLS config cannot be combined with insecure mode")
	}
	if cfg.QUIC && cfg.PublicTLSConfig != nil {
		closeOpenedStorage()
		return nil, errors.New("edge: QUIC control needs managed certificates or insecure mode")
	}
	if cfg.CustomCertDir != "" {
		switch {
		case cfg.Insecure:
			closeOpenedStorage()
			return nil, errors.New("edge: custom certificates cannot be combined with insecure mode")
		case cfg.PublicTLSConfig != nil:
			closeOpenedStorage()
			return nil, errors.New("edge: custom certificates cannot be combined with a public TLS config")
		case durableStore == nil:
			return nil, errors.New("edge: custom certificates need durable storage")
		}
	}
	var credentialStore credentialStore
	if durableStore != nil {
		credentialStore = durableStore
	} else if cfg.CredentialsFile != "" {
		fileStore, openErr := credentials.Open(cfg.CredentialsFile)
		if openErr != nil {
			return nil, fmt.Errorf("edge: opening credentials file: %w", openErr)
		}
		credentialStore = fileStore
	}

	var tcpMgr *tcpManager
	if cfg.TCPPortRange != "" {
		lo, hi, err := parseTCPPortRange(cfg.TCPPortRange)
		if err != nil {
			closeOpenedStorage()
			return nil, err
		}
		bindAddr := cfg.TCPBindAddr
		if bindAddr == "" {
			bindAddr = "0.0.0.0"
		}
		tcpMgr = newTCPManager(lo, hi, bindAddr, newPerIPLimiter(limits.PerIPRate, limits.PerIPBurst, limits.PerIPLRU))
		tcpMgr.idleTimeout = limits.TCPIdleTimeout
	}
	perIP := newPerIPInflight(limits.PerIPInFlight)
	if tcpMgr != nil {
		// One budget per client across HTTP requests and TCP connections.
		tcpMgr.perIP = perIP
	}
	var trustedPrefixes []netip.Prefix
	for _, raw := range cfg.ProxyProtocolTrusted {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			closeOpenedStorage()
			return nil, fmt.Errorf("edge: invalid -proxy-protocol-trusted entry %q: %w", p, err)
		}
		trustedPrefixes = append(trustedPrefixes, prefix)
	}
	if len(cfg.ProxyProtocolTrusted) > 0 && len(trustedPrefixes) == 0 {
		closeOpenedStorage()
		return nil, fmt.Errorf("edge: -proxy-protocol-trusted contains no valid CIDRs")
	}
	alerts, err := newAlertDispatcher(cfg.AlertWebhookURL, cfg.AlertWebhookToken)
	if err != nil {
		closeOpenedStorage()
		return nil, fmt.Errorf("edge: invalid alert webhook: %w", err)
	}
	var oidcProvider *oidc.Provider
	var oidcCodec *oidc.Codec
	if cfg.OIDC != nil {
		oidcProvider, err = oidc.New(*cfg.OIDC)
		if err != nil {
			closeOpenedStorage()
			return nil, fmt.Errorf("edge: invalid OIDC configuration: %w", err)
		}
		oidcCodec, err = oidc.NewCodec(cfg.OIDC.CookieSecret)
		if err != nil {
			closeOpenedStorage()
			return nil, fmt.Errorf("edge: invalid OIDC cookie configuration: %w", err)
		}
	}
	visitor, err := newVisitorLogin(cfg)
	if err != nil {
		closeOpenedStorage()
		return nil, fmt.Errorf("edge: invalid visitor OIDC configuration: %w", err)
	}

	srv := &Server{
		cfg:               cfg,
		adminClientCAs:    adminClientCAs,
		startedAt:         time.Now(),
		events:            newEventRing(200),
		registry:          registry,
		authLimiter:       newAuthRateLimiter(),
		adminLimiter:      newAuthRateLimiter(),
		credentialStore:   credentialStore,
		storage:           durableStore,
		ownsStorage:       cfg.Storage == nil && durableStore != nil,
		randomName:        randomSubdomain,
		perIPLimiter:      newPerIPLimiter(limits.PerIPRate, limits.PerIPBurst, limits.PerIPLRU),
		perIP:             perIP,
		globalSem:         newGlobalSemaphore(limits.GlobalInFlight),
		upgradeSem:        newGlobalSemaphore(limits.UpgradeInFlight),
		handshakeSem:      newGlobalSemaphore(int64(limits.HandshakeConcurrency)),
		unauthSem:         newGlobalSemaphore(int64(limits.UnauthSessions)),
		fallbackSem:       newGlobalSemaphore(int64(limits.UnauthSessions)),
		webhookBudget:     newByteBudget(limits.WebhookBufferBytes),
		tcpMgr:            tcpMgr,
		observability:     newObservabilityRegistry(),
		alerts:            alerts,
		oidc:              oidcProvider,
		oidcCodec:         oidcCodec,
		visitor:           visitor,
		proxyProtoTrusted: trustedPrefixes,
		shares:            newShareRegistry(cfg.MaxShareTTL),
		shareSem:          newGlobalSemaphore(maxGlobalShareConns),
	}
	if durableStore != nil {
		srv.aliases = newAliasResolver(durableStore, srv.customDomainReserved)
	}
	if cfg.PeerAddr != "" {
		srv.peers, err = newPeerForwarder(srv)
		if err != nil {
			alerts.close()
			closeOpenedStorage()
			return nil, err
		}
	}
	srv.shares.onExpire = func(sh *share) { srv.closeShare(sh, proto.ShareReasonExpired) }
	srv.shares.onIdle = func(sh *share) {
		if srv.shares.idleNow(sh) {
			srv.closeShare(sh, proto.ShareReasonIdle)
		}
	}
	if cfg.ShareAuditLogPath != "" {
		audit, err := openShareAuditLog(cfg.ShareAuditLogPath)
		if err != nil {
			alerts.close()
			closeOpenedStorage()
			return nil, fmt.Errorf("edge: -share-audit-log: %w", err)
		}
		srv.shareAudit = audit
	}
	if durableStore != nil && cfg.Storage == nil {
		srv.auditCh = make(chan storage.AuditEvent, 256)
		srv.auditStop = make(chan struct{})
		srv.auditWG.Add(1)
		go srv.auditLoop()
	}
	if tcpMgr != nil {
		tcpMgr.setObserver(srv.observability.observeTCP)
	}
	return srv, nil
}

func (s *Server) fallbackAdmission() *globalSemaphore {
	if s == nil {
		return nil
	}
	if s.fallbackSem == nil {
		return s.unauthSem
	}
	return s.fallbackSem
}

func (s *Server) limitsOrDefault() LimitsConfig {
	return s.cfg.Limits
}

func (s *Server) Run(ctx context.Context) error {
	if s.credentialStore == nil && len(s.cfg.TokenSHA256) != sha256.Size {
		return fmt.Errorf("edge: database, credentials file, or legacy token sha256 must be configured")
	}
	if s.ownsStorage {
		defer s.storage.Close()
	}
	if s.auditStop != nil {
		defer s.stopAudit()
	}
	if s.alerts != nil {
		defer s.alerts.close()
	}
	if s.cfg.Domain == "" {
		return errors.New("edge: domain must not be empty")
	}

	if !s.cfg.Insecure && s.cfg.PublicTLSConfig == nil {
		mgr, err := NewTLSManager(TLSConfig{
			Domain:      s.cfg.Domain,
			DNSProvider: s.cfg.DNSProvider,
			ACMEEmail:   s.cfg.ACMEEmail,
			ACMECA:      s.cfg.ACMECA,
			StoragePath: s.cfg.CertStoragePath,
		})
		if err != nil {
			return fmt.Errorf("edge: tls setup: %w", err)
		}
		if err := mgr.ManageCerts(ctx); err != nil {
			return fmt.Errorf("edge: obtaining certificates: %w", err)
		}
		if err := mgr.CheckApexReady(ctx); err != nil {
			return fmt.Errorf("edge: refusing to start control plane: %w", err)
		}
		if s.cfg.CustomCertDir != "" {
			certs, err := loadCustomCertificates(s.cfg.CustomCertDir, s.customDomainReserved, normalizeHost(s.cfg.Domain), time.Now())
			if err != nil {
				return fmt.Errorf("edge: %w", err)
			}
			if err := mgr.AddCustomCertificates(ctx, certs); err != nil {
				return fmt.Errorf("edge: %w", err)
			}
		}
		s.tlsMgr = mgr
	}

	controlLn, err := net.Listen("tcp", s.cfg.ControlAddr)
	if err != nil {
		return fmt.Errorf("edge: control listen: %w", err)
	}

	publicLn, err := net.Listen("tcp", s.cfg.PublicAddr)
	if err != nil {
		controlLn.Close()
		return fmt.Errorf("edge: public listen: %w", err)
	}

	if s.cfg.ProxyProtocol {
		if len(s.proxyProtoTrusted) == 0 {
			slog.Warn("edge: proxy-protocol is enabled but -proxy-protocol-trusted is empty; PROXY headers are accepted from any peer and --allow-cidr cannot be trusted unless the public port is firewalled to the proxy")
		}
		publicLn = newProxyProtoListener(publicLn, proxyProtoTimeout, s.proxyProtoTrusted)
	}
	publicLn = s.newSNIListener(publicLn)

	var httpLn net.Listener
	var opsLn net.Listener
	var adminMTLSLn net.Listener
	var peerLn net.Listener
	var quicTr *quic.Transport
	var quicLn *quic.Listener

	closeQUIC := func() {
		if quicLn != nil {
			quicLn.Close()
		}
		if quicTr != nil {
			quicTr.Close()
			quicTr.Conn.Close()
		}
	}

	closeAll := func() {
		closeQUIC()
		controlLn.Close()
		publicLn.Close()
		if httpLn != nil {
			httpLn.Close()
		}
		if opsLn != nil {
			opsLn.Close()
		}
		if adminMTLSLn != nil {
			adminMTLSLn.Close()
		}
		if peerLn != nil {
			peerLn.Close()
		}
	}

	if s.cfg.QUIC {
		quicTr, quicLn, err = s.listenQUIC(controlLn.Addr().(*net.TCPAddr))
		if err != nil {
			closeAll()
			return err
		}
	}

	if s.tlsMgr != nil {
		httpAddr := s.cfg.HTTPAddr
		if httpAddr == "" {
			httpAddr = ":80"
		}
		httpLn, err = net.Listen("tcp", httpAddr)
		if err != nil {
			closeAll()
			return fmt.Errorf("edge: http redirect listen: %w", err)
		}
		publicLn = tls.NewListener(publicLn, s.tlsMgr.PublicTLSConfig())
	} else if s.cfg.PublicTLSConfig != nil {
		publicLn = tls.NewListener(publicLn, s.cfg.PublicTLSConfig)
	}

	if s.cfg.OpsAddr != "" {
		opsLn, err = net.Listen("tcp", s.cfg.OpsAddr)
		if err != nil {
			closeAll()
			return fmt.Errorf("edge: ops listen: %w", err)
		}
	}

	if s.adminClientCAs != nil {
		rawLn, listenErr := net.Listen("tcp", s.cfg.AdminMTLSAddr)
		if listenErr != nil {
			closeAll()
			return fmt.Errorf("edge: admin mtls listen: %w", listenErr)
		}
		adminMTLSLn = s.newAdminMTLSListener(rawLn)
	}

	if s.peers != nil {
		peerLn, err = net.Listen("tcp", cmp.Or(s.cfg.PeerListen, s.cfg.PeerAddr))
		if err != nil {
			closeAll()
			return fmt.Errorf("edge: peer listen: %w", err)
		}
		s.peers.ln = peerLn
	}

	limits := s.limitsOrDefault()
	g, gctx := errgroup.WithContext(ctx)
	publicSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.handlePublicListener(gctx, w, r)
		}),
		ReadHeaderTimeout: limits.ReadHeaderTimeout,
		IdleTimeout:       limits.IdleTimeout,
		MaxHeaderBytes:    limits.MaxHeaderBytes,
	}
	if s.cfg.Insecure {
		var protocols http.Protocols
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		publicSrv.Protocols = &protocols
	}

	if s.peers != nil {
		publicSrv.ConnContext = peerConnContext
	}

	var httpSrv *http.Server
	if httpLn != nil {
		httpSrv = &http.Server{
			Handler:           http.HandlerFunc(s.redirectToHTTPS),
			ReadHeaderTimeout: limits.ReadHeaderTimeout,
			IdleTimeout:       limits.IdleTimeout,
			MaxHeaderBytes:    limits.MaxHeaderBytes,
		}
	}

	var opsSrv *http.Server
	if opsLn != nil {
		opsSrv = &http.Server{
			Handler:           s.opsMux(),
			ReadHeaderTimeout: limits.ReadHeaderTimeout,
			IdleTimeout:       limits.IdleTimeout,
			MaxHeaderBytes:    limits.MaxHeaderBytes,
		}
	}

	var adminMTLSSrv *http.Server
	if adminMTLSLn != nil {
		adminMTLSSrv = &http.Server{
			Handler:           s.adminMTLSHandler(),
			ReadHeaderTimeout: limits.ReadHeaderTimeout,
			ReadTimeout:       limits.ReadHeaderTimeout,
			IdleTimeout:       limits.IdleTimeout,
			MaxHeaderBytes:    limits.MaxHeaderBytes,
			ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug),
		}
	}

	g.Go(func() error {
		return s.observabilityLoop(gctx)
	})

	g.Go(func() error {
		<-gctx.Done()
		s.peers.stop()
		s.controlMu.Lock()
		s.controlDraining = true
		s.controlMu.Unlock()
		controlLn.Close()
		if quicLn != nil {
			quicLn.Close()
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), drainTimeout+5*time.Second)
		defer cancel()
		publicSrv.Shutdown(shutdownCtx)
		if httpSrv != nil {
			httpSrv.Shutdown(shutdownCtx)
		}
		if opsSrv != nil {
			opsSrv.Shutdown(shutdownCtx)
		}
		if adminMTLSSrv != nil {
			adminMTLSSrv.Shutdown(shutdownCtx)
		}
		s.peers.waitSplices(shutdownCtx)
		return nil
	})

	g.Go(func() error {
		err := s.serveControl(gctx, controlLn)
		if gctx.Err() != nil {
			return nil
		}
		return err
	})

	if quicLn != nil {
		g.Go(func() error {
			err := s.serveQUIC(gctx, quicLn)
			if gctx.Err() != nil {
				return nil
			}
			return err
		})
	}

	g.Go(func() error {
		err := publicSrv.Serve(publicLn)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	})

	if s.peers != nil {
		g.Go(func() error { return s.peers.acceptLoop(gctx) })
		g.Go(func() error { return s.peers.heartbeat(gctx) })
		if s.tcpMgr != nil {
			g.Go(func() error { return s.peers.watchTCP(gctx) })
		}
	}

	if httpSrv != nil {
		g.Go(func() error {
			err := httpSrv.Serve(httpLn)
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		})
	}

	if opsSrv != nil {
		g.Go(func() error {
			err := opsSrv.Serve(opsLn)
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		})
	}

	if adminMTLSSrv != nil {
		g.Go(func() error {
			err := adminMTLSSrv.Serve(adminMTLSLn)
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		})
	}

	slog.Info("ngstoned: listeners up", "control", s.cfg.ControlAddr, "public", s.cfg.PublicAddr, "insecure", s.cfg.Insecure, "proxy_protocol", s.cfg.ProxyProtocol, "peer_addr", s.cfg.PeerAddr, "peer_listen", s.cfg.PeerListen, "admin_mtls", s.cfg.AdminMTLSAddr, "quic", s.cfg.QUIC)
	s.recordEvent("info", "listeners up", map[string]string{
		"control": s.cfg.ControlAddr,
		"public":  s.cfg.PublicAddr,
	})

	err = g.Wait()
	s.waitControlSessions(controlShutdownGrace)
	closeQUIC()
	s.shareAudit.close()
	return err
}

// waitControlSessions waits for every control-connection goroutine to finish
// its Goodbye/unroute/drain sequence, up to grace. Without it the process
// exits as soon as the listeners close, cutting WebSocket and TCP tunnel
// traffic (which http.Server.Shutdown does not wait for) mid-drain.
func (s *Server) waitControlSessions(grace time.Duration) {
	done := make(chan struct{})
	go func() {
		s.controlConns.Wait()
		close(done)
	}()
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		slog.Warn("edge: shutdown grace expired with agent sessions still draining", "grace", grace)
	}
}

func (s *Server) redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	host := stripPort(r.Host)
	if !hostMatchesDomain(host, s.cfg.Domain) {
		if _, ok := s.aliases.resolve(host, stripPort(r.RemoteAddr)); !ok {
			http.NotFound(w, r)
			return
		}
	}
	target := "https://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

func hostMatchesDomain(host, domain string) bool {
	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}
