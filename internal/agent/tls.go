package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const tlsHandshakeTimeout = 10 * time.Second

// tlsServerName picks the name the edge's certificate is verified against:
// the explicit override when set, otherwise the host part of the control
// address. The edge serves its apex certificate on the control port, so
// dialing example.com:4443 verifies against example.com with no extra flag.
func tlsServerName(cfg Config) (string, error) {
	if cfg.ServerName != "" {
		return cfg.ServerName, nil
	}
	host, _, err := net.SplitHostPort(cfg.ControlAddr)
	if err != nil {
		host = cfg.ControlAddr
	}
	if host == "" {
		return "", fmt.Errorf("agent: cannot derive a TLS server name from control address %q; pass --server-name", cfg.ControlAddr)
	}
	return host, nil
}

func dialControl(ctx context.Context, cfg Config) (net.Conn, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", cfg.ControlAddr)
	if err != nil {
		return nil, fmt.Errorf("agent: dial control: %w", err)
	}

	if cfg.Insecure {
		return raw, nil
	}

	serverName, err := tlsServerName(cfg)
	if err != nil {
		raw.Close()
		return nil, err
	}

	tlsCfg := &tls.Config{
		ServerName: serverName,
		RootCAs:    cfg.RootCAs,
		MinVersion: tls.VersionTLS13,
	}
	if cfg.Pin != "" {
		want, perr := parsePin(cfg.Pin)
		if perr != nil {
			raw.Close()
			return nil, fmt.Errorf("agent: invalid -pin: %w", perr)
		}
		tlsCfg.VerifyPeerCertificate = pinVerifier(want)
	}

	tlsConn := tls.Client(raw, tlsCfg)
	hctx, cancel := context.WithTimeout(ctx, tlsHandshakeTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(hctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("agent: tls handshake: %w", err)
	}
	return tlsConn, nil
}

func parsePin(s string) ([sha256.Size]byte, error) {
	const prefix = "sha256/"
	var out [sha256.Size]byte
	if !strings.HasPrefix(s, prefix) {
		return out, fmt.Errorf("agent: pin must be in the form %sBASE64", prefix)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, prefix))
	if err != nil {
		return out, fmt.Errorf("agent: pin is not valid base64: %w", err)
	}
	if len(raw) != sha256.Size {
		return out, fmt.Errorf("agent: pin must decode to %d bytes (sha256), got %d", sha256.Size, len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

func pinVerifier(want [sha256.Size]byte) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("agent: no peer certificate presented")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("agent: parsing peer certificate: %w", err)
		}
		spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil {
			return fmt.Errorf("agent: marshaling peer public key: %w", err)
		}
		got := sha256.Sum256(spki)
		if got != want {
			return fmt.Errorf("agent: certificate pin mismatch: presented key is sha256/%s", base64.StdEncoding.EncodeToString(got[:]))
		}
		return nil
	}
}
