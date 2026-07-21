package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func generateSelfSignedCert(t *testing.T, dnsName string) (tls.Certificate, [sha256.Size]byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: dnsName},
		DNSNames:              []string{dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pin := sha256.Sum256(spki)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pin
}

func startSelfSignedTLSServer(t *testing.T, cert tls.Certificate) (addr string) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte("hello\n"))
			}(conn)
		}
	}()

	return ln.Addr().String()
}

func TestParsePinAcceptsAndRejectsFormats(t *testing.T) {
	_, pin := generateSelfSignedCert(t, "pin-format.invalid")
	valid := "sha256/" + base64.StdEncoding.EncodeToString(pin[:])
	if _, err := parsePin(valid); err != nil {
		t.Fatalf("parsePin(%q) failed: %v", valid, err)
	}

	invalid := []string{
		"",
		"nope",
		"sha256/not-base64!!!",
		"sha256/" + base64.StdEncoding.EncodeToString([]byte("too-short")),
		"md5/" + base64.StdEncoding.EncodeToString(pin[:]),
	}
	for _, s := range invalid {
		if _, err := parsePin(s); err == nil {
			t.Fatalf("parsePin(%q) should have failed", s)
		}
	}
}

func TestPinVerifierAcceptsMatchingAndRejectsWrongPin(t *testing.T) {
	cert, wantPin := generateSelfSignedCert(t, "pin-verify.invalid")
	rawCerts := cert.Certificate

	if err := pinVerifier(wantPin)(rawCerts, nil); err != nil {
		t.Fatalf("pinVerifier rejected the matching certificate: %v", err)
	}

	var wrongPin [sha256.Size]byte
	copy(wrongPin[:], wantPin[:])
	wrongPin[0] ^= 0xFF
	if err := pinVerifier(wrongPin)(rawCerts, nil); err == nil {
		t.Fatalf("pinVerifier accepted a certificate that does not match the configured pin")
	}
}

func TestDialControlTLSHandshakeAndPinOverRealConnection(t *testing.T) {
	cert, wantPin := generateSelfSignedCert(t, "dial-pin.invalid")
	addr := startSelfSignedTLSServer(t, cert)

	dial := func(pin string) error {
		var d net.Dialer
		raw, err := d.DialContext(context.Background(), "tcp", addr)
		if err != nil {
			return err
		}
		defer raw.Close()

		tlsCfg := &tls.Config{
			ServerName:         "dial-pin.invalid",
			InsecureSkipVerify: true,
		}
		want, perr := parsePin(pin)
		if perr != nil {
			return perr
		}
		tlsCfg.VerifyPeerCertificate = pinVerifier(want)

		conn := tls.Client(raw, tlsCfg)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := conn.HandshakeContext(ctx); err != nil {
			return err
		}
		defer conn.Close()
		buf := make([]byte, 6)
		_, err = io.ReadFull(conn, buf)
		return err
	}

	goodPin := "sha256/" + base64.StdEncoding.EncodeToString(wantPin[:])
	if err := dial(goodPin); err != nil {
		t.Fatalf("dial with the matching pin should succeed: %v", err)
	}

	var wrong [sha256.Size]byte
	copy(wrong[:], wantPin[:])
	wrong[0] ^= 0xFF
	wrongPin := "sha256/" + base64.StdEncoding.EncodeToString(wrong[:])
	if err := dial(wrongPin); err == nil {
		t.Fatalf("dial with a mismatched pin should fail")
	}
}

func TestDialControlRejectsUntrustedSelfSignedCertWithoutPin(t *testing.T) {
	cert, _ := generateSelfSignedCert(t, "untrusted.invalid")
	addr := startSelfSignedTLSServer(t, cert)

	conn, err := dialControl(context.Background(), Config{
		ControlAddr: addr,
		ServerName:  "untrusted.invalid",
	})
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatalf("dialControl accepted a self-signed certificate from an untrusted CA with no pin configured")
	}
}

func TestDialControlPinDoesNotReplaceChainValidation(t *testing.T) {
	cert, wantPin := generateSelfSignedCert(t, "chain-pin.invalid")
	addr := startSelfSignedTLSServer(t, cert)

	goodPin := "sha256/" + base64.StdEncoding.EncodeToString(wantPin[:])
	conn, err := dialControl(context.Background(), Config{
		ControlAddr: addr,
		ServerName:  "chain-pin.invalid",
		Pin:         goodPin,
	})
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatalf("dialControl with a matching pin but an untrusted CA should still fail chain validation; the pin must not replace it")
	}
}

func TestDialControlTrustedChainWrongPinFails(t *testing.T) {
	cert, wantPin := generateSelfSignedCert(t, "chain-pin-wrong.invalid")
	addr := startSelfSignedTLSServer(t, cert)

	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)

	var wrong [sha256.Size]byte
	copy(wrong[:], wantPin[:])
	wrong[0] ^= 0xFF
	wrongPin := "sha256/" + base64.StdEncoding.EncodeToString(wrong[:])

	conn, err := dialControl(context.Background(), Config{
		ControlAddr: addr,
		ServerName:  "chain-pin-wrong.invalid",
		Pin:         wrongPin,
		RootCAs:     pool,
	})
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatalf("dialControl with a trusted chain but a wrong pin should fail")
	}
}

func TestDialControlTrustedChainCorrectPinSucceeds(t *testing.T) {
	cert, wantPin := generateSelfSignedCert(t, "chain-pin-correct.invalid")
	addr := startSelfSignedTLSServer(t, cert)

	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)

	goodPin := "sha256/" + base64.StdEncoding.EncodeToString(wantPin[:])
	conn, err := dialControl(context.Background(), Config{
		ControlAddr: addr,
		ServerName:  "chain-pin-correct.invalid",
		Pin:         goodPin,
		RootCAs:     pool,
	})
	if err != nil {
		t.Fatalf("dialControl with a trusted chain and a matching pin should succeed: %v", err)
	}
	defer conn.Close()
}

func TestDialControlInsecureModeUsesPlaintext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("plaintext-ok\n"))
	}()

	conn, err := dialControl(context.Background(), Config{
		ControlAddr: ln.Addr().String(),
		Insecure:    true,
	})
	if err != nil {
		t.Fatalf("dialControl in insecure mode: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, len("plaintext-ok\n"))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read plaintext greeting: %v", err)
	}
	if string(buf) != "plaintext-ok\n" {
		t.Fatalf("got %q, want plaintext greeting", buf)
	}
}
