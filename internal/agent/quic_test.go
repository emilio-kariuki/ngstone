package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"ngstone/internal/tunnel"
)

func startQUICTestServer(t *testing.T, cert tls.Certificate) (string, func()) {
	t.Helper()
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{tunnel.QUICALPN},
	}, tunnel.QUICServerConfig(nil, 5*time.Second))
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	var mu sync.Mutex
	var conns []*quic.Conn
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			qc, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, qc)
			mu.Unlock()
		}
	}()
	closeNow := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, qc := range conns {
			qc.CloseWithError(0, "")
		}
	}
	closeConns := func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			n := len(conns)
			mu.Unlock()
			if n > 0 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		closeNow()
	}
	t.Cleanup(func() {
		cancel()
		<-done
		closeNow()
		ln.Close()
	})
	return ln.Addr().String(), closeConns
}

func quicTestPool(cert tls.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	return pool
}

func quicPin(pin [sha256.Size]byte) string {
	return "sha256/" + base64.StdEncoding.EncodeToString(pin[:])
}

func wrongQUICPin(pin [sha256.Size]byte) string {
	pin[0] ^= 0xFF
	return quicPin(pin)
}

func TestQUICControlRejectsUntrustedCertWithoutPin(t *testing.T) {
	cert, _ := generateSelfSignedCert(t, "quic-untrusted.invalid")
	addr, _ := startQUICTestServer(t, cert)
	conn, err := dialQUICControl(context.Background(), Config{ControlAddr: addr, ServerName: "quic-untrusted.invalid"})
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("dialQUICControl accepted an untrusted certificate with no pin")
	}
}

func TestQUICControlPinDoesNotReplaceChainValidation(t *testing.T) {
	cert, pin := generateSelfSignedCert(t, "quic-chain.invalid")
	addr, _ := startQUICTestServer(t, cert)
	conn, err := dialQUICControl(context.Background(), Config{ControlAddr: addr, ServerName: "quic-chain.invalid", Pin: quicPin(pin)})
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("a matching pin replaced chain validation over QUIC")
	}
}

func TestQUICControlTrustedChainWrongPinFails(t *testing.T) {
	cert, pin := generateSelfSignedCert(t, "quic-wrongpin.invalid")
	addr, _ := startQUICTestServer(t, cert)
	conn, err := dialQUICControl(context.Background(), Config{
		ControlAddr: addr,
		ServerName:  "quic-wrongpin.invalid",
		RootCAs:     quicTestPool(cert),
		Pin:         wrongQUICPin(pin),
	})
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("a trusted chain with a wrong pin was accepted over QUIC")
	}
}

func TestQUICControlTrustedChainCorrectPinSucceeds(t *testing.T) {
	cert, pin := generateSelfSignedCert(t, "quic-ok.invalid")
	addr, closeConns := startQUICTestServer(t, cert)
	conn, err := dialQUICControl(context.Background(), Config{
		ControlAddr: addr,
		ServerName:  "quic-ok.invalid",
		RootCAs:     quicTestPool(cert),
		Pin:         quicPin(pin),
	})
	if err != nil {
		t.Fatalf("dialQUICControl with a trusted chain and the right pin: %v", err)
	}
	closeConns()
	conn.Close()
}

func TestQUICControlWrongServerNameFails(t *testing.T) {
	cert, _ := generateSelfSignedCert(t, "quic-name.invalid")
	addr, _ := startQUICTestServer(t, cert)
	conn, err := dialQUICControl(context.Background(), Config{
		ControlAddr: addr,
		ServerName:  "quic-other.invalid",
		RootCAs:     quicTestPool(cert),
	})
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("a certificate for another name was accepted over QUIC")
	}
}

func TestQUICControlInsecureSkipsVerification(t *testing.T) {
	cert, _ := generateSelfSignedCert(t, "quic-insecure.invalid")
	addr, closeConns := startQUICTestServer(t, cert)
	conn, err := dialQUICControl(context.Background(), Config{ControlAddr: addr, Insecure: true})
	if err != nil {
		t.Fatalf("insecure dialQUICControl: %v", err)
	}
	closeConns()
	conn.Close()
}

func TestQUICControlDialControlModeDispatch(t *testing.T) {
	cert, _ := generateSelfSignedCert(t, "quic-dispatch.invalid")
	addr, closeConns := startQUICTestServer(t, cert)
	conn, err := dialControlMode(context.Background(), Config{ControlAddr: addr, Insecure: true}, TransportQUIC)
	if err != nil {
		t.Fatalf("dialControlMode(quic): %v", err)
	}
	if _, ok := conn.RemoteAddr().(*net.UDPAddr); !ok {
		t.Fatalf("dialControlMode(quic) returned a %T remote address, want a UDP address", conn.RemoteAddr())
	}
	closeConns()
	conn.Close()
}

func TestQUICControlSilentUDPHint(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	start := time.Now()
	conn, err := dialQUICControl(context.Background(), Config{ControlAddr: pc.LocalAddr().String(), Insecure: true})
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("dialQUICControl succeeded against a silent UDP socket")
	}
	if !strings.Contains(err.Error(), "no answer from "+pc.LocalAddr().String()+" over UDP") || !strings.Contains(err.Error(), "-quic") {
		t.Fatalf("error = %v, want the UDP reachability hint", err)
	}
	if time.Since(start) > 8*time.Second {
		t.Fatalf("silent UDP took %v to fail", time.Since(start))
	}
}

func TestQUICControlNotInsecureByDefault(t *testing.T) {
	secure, err := quicTLSConfig(Config{ControlAddr: "edge.invalid:4443"})
	if err != nil {
		t.Fatal(err)
	}
	if secure.InsecureSkipVerify {
		t.Fatal("the default QUIC TLS config skips certificate verification")
	}
	if secure.MinVersion != tls.VersionTLS13 || len(secure.NextProtos) != 1 || secure.NextProtos[0] != tunnel.QUICALPN {
		t.Fatalf("secure config: min version %#x, protos %v", secure.MinVersion, secure.NextProtos)
	}
	if secure.ServerName != "edge.invalid" {
		t.Fatalf("server name = %q, want edge.invalid", secure.ServerName)
	}
	insecure, err := quicTLSConfig(Config{ControlAddr: "edge.invalid:4443", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if !insecure.InsecureSkipVerify || insecure.MinVersion != tls.VersionTLS13 || len(insecure.NextProtos) != 1 || insecure.NextProtos[0] != tunnel.QUICALPN {
		t.Fatalf("insecure config: %+v", insecure)
	}
}
