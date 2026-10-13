package edge

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
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
	"golang.org/x/sync/errgroup"
)

type Config struct {
	ControlAddr  string
	PublicAddr   string
	Domain       string
	TokenSHA256  []byte
	PublicScheme string

	Insecure bool

	ProxyProtocol        bool
	ProxyProtocolTrusted []string

	HTTPAddr string
	OpsAddr  string

	TCPPortRange string
	TCPBindAddr  string

	CertStoragePath string
	ACMEEmail       string
	ACMECA          string
	DNSProvider     certmagic.DNSProvider

	Limits LimitsConfig
}

type Server struct {
	cfg Config

	registry    *Registry
	authLimiter *authRateLimiter
	randomName  func() string

	perIPLimiter *perIPLimiter
	globalSem    *globalSemaphore
	upgradeSem   *globalSemaphore
	handshakeSem *globalSemaphore
	unauthSem    *globalSemaphore

	tlsMgr *TLSManager
	tcpMgr *tcpManager

	proxyProtoTrusted []netip.Prefix

	// controlConns tracks per-connection control goroutines so Run can wait
	// for each session's Goodbye and drain before returning. Add happens only
	// in acceptControl, which has returned before Run calls Wait.
	controlConns sync.WaitGroup
}

// controlShutdownGrace bounds how long Run waits, after its listeners stop,
// for agent sessions to send Goodbye and drain. A session drains for at most
// drainTimeout plus the TCP release grace; the margin covers a slow peer.
var controlShutdownGrace = drainTimeout + 15*time.Second

func New(cfg Config) (*Server, error) {
	if cfg.PublicScheme == "" {
		cfg.PublicScheme = "https"
	}
	limits, err := cfg.Limits.withDefaults()
	if err != nil {
		return nil, fmt.Errorf("edge: invalid limits config: %w", err)
	}
	cfg.Limits = limits

	registry := NewRegistry()
	registry.SetLimits(limits)

	var tcpMgr *tcpManager
	if cfg.TCPPortRange != "" {
		lo, hi, err := parseTCPPortRange(cfg.TCPPortRange)
		if err != nil {
			return nil, err
		}
		bindAddr := cfg.TCPBindAddr
		if bindAddr == "" {
			bindAddr = "0.0.0.0"
		}
		tcpMgr = newTCPManager(lo, hi, bindAddr, newPerIPLimiter(limits.PerIPRate, limits.PerIPBurst, limits.PerIPLRU))
	}

	var trustedPrefixes []netip.Prefix
	for _, raw := range cfg.ProxyProtocolTrusted {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("edge: invalid -proxy-protocol-trusted entry %q: %w", p, err)
		}
		trustedPrefixes = append(trustedPrefixes, prefix)
	}
	if len(cfg.ProxyProtocolTrusted) > 0 && len(trustedPrefixes) == 0 {
		return nil, fmt.Errorf("edge: -proxy-protocol-trusted contains no valid CIDRs")
	}

	return &Server{
		cfg:               cfg,
		registry:          registry,
		authLimiter:       newAuthRateLimiter(),
		randomName:        randomSubdomain,
		perIPLimiter:      newPerIPLimiter(limits.PerIPRate, limits.PerIPBurst, limits.PerIPLRU),
		globalSem:         newGlobalSemaphore(limits.GlobalInFlight),
		upgradeSem:        newGlobalSemaphore(limits.UpgradeInFlight),
		handshakeSem:      newGlobalSemaphore(int64(limits.HandshakeConcurrency)),
		unauthSem:         newGlobalSemaphore(int64(limits.UnauthSessions)),
		tcpMgr:            tcpMgr,
		proxyProtoTrusted: trustedPrefixes,
	}, nil
}

func (s *Server) limitsOrDefault() LimitsConfig {
	return s.cfg.Limits
}

func (s *Server) Run(ctx context.Context) error {
	if len(s.cfg.TokenSHA256) != sha256.Size {
		return fmt.Errorf("edge: token sha256 must be %d bytes, got %d", sha256.Size, len(s.cfg.TokenSHA256))
	}
	if s.cfg.Domain == "" {
		return errors.New("edge: domain must not be empty")
	}

	if !s.cfg.Insecure {
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

	var httpLn net.Listener
	var opsLn net.Listener

	closeAll := func() {
		controlLn.Close()
		publicLn.Close()
		if httpLn != nil {
			httpLn.Close()
		}
		if opsLn != nil {
			opsLn.Close()
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
	}

	if s.cfg.OpsAddr != "" {
		opsLn, err = net.Listen("tcp", s.cfg.OpsAddr)
		if err != nil {
			closeAll()
			return fmt.Errorf("edge: ops listen: %w", err)
		}
	}

	limits := s.limitsOrDefault()
	publicSrv := &http.Server{
		Handler:           http.HandlerFunc(s.handlePublic),
		ReadHeaderTimeout: limits.ReadHeaderTimeout,
		IdleTimeout:       limits.IdleTimeout,
		MaxHeaderBytes:    limits.MaxHeaderBytes,
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

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-gctx.Done()
		controlLn.Close()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), drainTimeout+5*time.Second)
		defer cancel()
		publicSrv.Shutdown(shutdownCtx)
		if httpSrv != nil {
			httpSrv.Shutdown(shutdownCtx)
		}
		if opsSrv != nil {
			opsSrv.Shutdown(shutdownCtx)
		}
		return nil
	})

	g.Go(func() error {
		err := s.acceptControl(gctx, controlLn)
		if gctx.Err() != nil {
			return nil
		}
		return err
	})

	g.Go(func() error {
		err := publicSrv.Serve(publicLn)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	})

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

	slog.Info("ngstoned: listeners up", "control", s.cfg.ControlAddr, "public", s.cfg.PublicAddr, "insecure", s.cfg.Insecure, "proxy_protocol", s.cfg.ProxyProtocol)

	err = g.Wait()
	s.waitControlSessions(controlShutdownGrace)
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
	if !hostMatchesDomain(stripPort(r.Host), s.cfg.Domain) {
		http.NotFound(w, r)
		return
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
