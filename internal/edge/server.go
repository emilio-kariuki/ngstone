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
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

type Config struct {
	ControlAddr  string
	PublicAddr   string
	Domain       string
	TokenSHA256  []byte
	PublicScheme string

	Insecure bool

	HTTPAddr string

	CertStoragePath    string
	ACMEEmail          string
	ACMECA             string
	CloudflareAPIToken string
}

type Server struct {
	cfg Config

	registry    *Registry
	authLimiter *authRateLimiter
	randomName  func() string

	tlsMgr *TLSManager
}

func New(cfg Config) *Server {
	if cfg.PublicScheme == "" {
		cfg.PublicScheme = "https"
	}
	return &Server{
		cfg:         cfg,
		registry:    NewRegistry(),
		authLimiter: newAuthRateLimiter(),
		randomName:  randomSubdomain,
	}
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
			Domain:             s.cfg.Domain,
			CloudflareAPIToken: s.cfg.CloudflareAPIToken,
			ACMEEmail:          s.cfg.ACMEEmail,
			ACMECA:             s.cfg.ACMECA,
			StoragePath:        s.cfg.CertStoragePath,
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

	var httpLn net.Listener

	closeAll := func() {
		controlLn.Close()
		publicLn.Close()
		if httpLn != nil {
			httpLn.Close()
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

	publicSrv := &http.Server{
		Handler: http.HandlerFunc(s.handlePublic),
	}

	var httpSrv *http.Server
	if httpLn != nil {
		httpSrv = &http.Server{
			Handler: http.HandlerFunc(s.redirectToHTTPS),
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

	slog.Info("ngstoned: listeners up", "control", s.cfg.ControlAddr, "public", s.cfg.PublicAddr, "insecure", s.cfg.Insecure)

	return g.Wait()
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
