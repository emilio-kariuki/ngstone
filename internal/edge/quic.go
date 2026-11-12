package edge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"ngstone/internal/tunnel"
)

const quicConnCloseWait = 5 * time.Second

type quicAdmissionKey struct{}

type quicAdmission struct {
	s                         *Server
	deadline                  time.Time
	handshakeOnce, unauthOnce sync.Once
	authed                    atomic.Bool
}

func (a *quicAdmission) releaseHandshake() {
	a.handshakeOnce.Do(a.s.handshakeSem.release)
}

func (a *quicAdmission) releaseUnauth() {
	a.unauthOnce.Do(a.s.unauthSem.release)
}

func (a *quicAdmission) authenticated() {
	a.authed.Store(true)
	a.releaseUnauth()
}

func (s *Server) admitQUIC(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
	if !info.AddrVerified {
		return nil, errors.New("edge: quic source address not verified")
	}
	if !s.handshakeSem.tryAcquire() {
		return nil, errors.New("edge: quic handshake capacity exhausted")
	}
	if !s.unauthSem.tryAcquire() {
		s.handshakeSem.release()
		return nil, errors.New("edge: quic unauthenticated session capacity exhausted")
	}
	adm := &quicAdmission{s: s, deadline: time.Now().Add(authDeadline)}
	ctx = context.WithValue(ctx, quicAdmissionKey{}, adm)
	context.AfterFunc(ctx, func() {
		adm.releaseHandshake()
		adm.releaseUnauth()
	})
	return ctx, nil
}

func quicAdmissionFrom(ctx context.Context) *quicAdmission {
	adm, _ := ctx.Value(quicAdmissionKey{}).(*quicAdmission)
	return adm
}

func quicWindowAllowed(ctx context.Context) bool {
	adm := quicAdmissionFrom(ctx)
	return adm != nil && adm.authed.Load()
}

func quicWindowGate(qc *quic.Conn, _ uint64) bool {
	return quicWindowAllowed(qc.Context())
}

func (s *Server) quicTLSConfig() (*tls.Config, error) {
	if s.tlsMgr != nil {
		cfg := s.tlsMgr.ApexTLSConfig().Clone()
		cfg.NextProtos = []string{tunnel.QUICALPN}
		return cfg, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("edge: quic certificate: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, fmt.Errorf("edge: quic certificate: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ngstoned insecure quic"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("edge: quic certificate: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{tunnel.QUICALPN},
	}, nil
}

func (s *Server) listenQUIC(addr *net.TCPAddr) (*quic.Transport, *quic.Listener, error) {
	tlsConf, err := s.quicTLSConfig()
	if err != nil {
		return nil, nil, err
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: addr.IP, Port: addr.Port, Zone: addr.Zone})
	if err != nil {
		return nil, nil, fmt.Errorf("edge: quic listen: %w", err)
	}
	tr := &quic.Transport{
		Conn:                pc,
		VerifySourceAddress: func(net.Addr) bool { return true },
		ConnContext:         s.admitQUIC,
	}
	ln, err := tr.Listen(tlsConf, tunnel.QUICServerConfig(quicWindowGate))
	if err != nil {
		tr.Close()
		pc.Close()
		return nil, nil, fmt.Errorf("edge: quic listen: %w", err)
	}
	return tr, ln, nil
}

func (s *Server) serveQUIC(ctx context.Context, ln *quic.Listener) error {
	for {
		qc, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, quic.ErrServerClosed) {
				return nil
			}
			return err
		}
		adm := quicAdmissionFrom(qc.Context())
		if adm == nil {
			qc.CloseWithError(0, "")
			continue
		}
		adm.releaseHandshake()
		if !s.acceptControl() {
			qc.CloseWithError(0, "draining")
			continue
		}
		go s.handleQUICConn(ctx, qc, adm)
	}
}

func quicRemoteIP(qc *quic.Conn) string {
	if ua, ok := qc.RemoteAddr().(*net.UDPAddr); ok {
		if a, ok := netip.AddrFromSlice(ua.IP); ok {
			return a.Unmap().String()
		}
	}
	return qc.RemoteAddr().String()
}

func (s *Server) handleQUICConn(ctx context.Context, qc *quic.Conn, adm *quicAdmission) {
	leave := sync.OnceFunc(s.controlConns.Done)
	defer leave()
	hardStop := time.AfterFunc(time.Until(adm.deadline), func() {
		if !adm.authed.Load() {
			qc.CloseWithError(0, "")
		}
	})
	defer hardStop.Stop()
	actx, cancel := context.WithDeadline(ctx, adm.deadline)
	nc, err := tunnel.AcceptQUIC(actx, qc)
	cancel()
	if err != nil {
		slog.Warn("edge: quic control stream failed", "ip", quicRemoteIP(qc), "err", err)
		return
	}
	s.handleControlConnTransport(ctx, nc, adm.authenticated, controlTransport{leave: leave, deadline: adm.deadline, name: "quic"})
	nc.Close()
	t := time.NewTimer(quicConnCloseWait)
	defer t.Stop()
	select {
	case <-qc.Context().Done():
	case <-t.C:
	}
}
