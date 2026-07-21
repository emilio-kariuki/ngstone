package edge

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"
)

type Config struct {
	ControlAddr string
	PublicAddr  string
	Domain      string
	TokenSHA256 []byte
}

type Server struct {
	cfg Config

	registry    *Registry
	authLimiter *authRateLimiter
	randomName  func() string
}

func New(cfg Config) *Server {
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

	controlLn, err := net.Listen("tcp", s.cfg.ControlAddr)
	if err != nil {
		return fmt.Errorf("edge: control listen: %w", err)
	}

	publicLn, err := net.Listen("tcp", s.cfg.PublicAddr)
	if err != nil {
		controlLn.Close()
		return fmt.Errorf("edge: public listen: %w", err)
	}

	publicSrv := &http.Server{
		Handler: http.HandlerFunc(s.handlePublic),
	}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-gctx.Done()
		controlLn.Close()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), drainTimeout+5*time.Second)
		defer cancel()
		publicSrv.Shutdown(shutdownCtx)
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

	return g.Wait()
}
