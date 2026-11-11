package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func selfSignedTLSCert(t *testing.T, host string, extraNames ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: host, Organization: []string{"ngstone e2e local app"}},
		DNSNames:              append([]string{host}, extraNames...),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func startLocalTLSEcho(t *testing.T, cert tls.Certificate) (string, *atomic.Int64) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen local tls app: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	accepts := new(atomic.Int64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String(), accepts
}

var tlsAdvertRe = regexp.MustCompile(`tls://[^\s]+\s+->`)

func waitLogMatch(t *testing.T, sb *syncBuf, re *regexp.Regexp, max time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if m := re.FindString(sb.String()); m != "" {
			return m
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s; got:\n%s", max, re, sb.String())
	return ""
}

func TestTLSPassthroughEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess tls passthrough end-to-end test in -short mode")
	}
	edgeBin, agentBin := buildBinaries(t)

	token := "e2e-tls-token"
	domain := "tun.example.com"
	hostname := "secure." + domain
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)
	_, publicPort, _ := net.SplitHostPort(publicAddr)

	localCert, localPool := selfSignedTLSCert(t, hostname)
	localAddr, localAccepts := startLocalTLSEcho(t, localCert)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "plain-http-ok")
	}))
	defer origin.Close()

	startEdge(t, edgeBin, controlAddr, publicAddr, token, domain)

	cmd := exec.Command(agentBin, "tls", localAddr,
		"--subdomain", "secure",
		"--server", controlAddr,
		"--token", token,
		"--insecure",
	)
	agentSB := &syncBuf{}
	cmd.Stdout = io.MultiWriter(os.Stderr, agentSB)
	cmd.Stderr = io.MultiWriter(os.Stderr, agentSB)
	proc := newManagedProc(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ngstone tls: %v", err)
	}
	t.Cleanup(proc.killAndWait)

	advert := waitLogMatch(t, agentSB, tlsAdvertRe, 15*time.Second)
	if !strings.HasPrefix(advert, "tls://"+hostname+":"+publicPort) {
		t.Fatalf("advertised %q, want tls://%s:%s", advert, hostname, publicPort)
	}

	t.Run("client_sees_local_app_certificate", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", publicAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial public listener: %v", err)
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(10 * time.Second))
		conn := tls.Client(raw, &tls.Config{ServerName: hostname, RootCAs: localPool})
		if err := conn.Handshake(); err != nil {
			t.Fatalf("handshake with the local app through the edge: %v", err)
		}
		peer := conn.ConnectionState().PeerCertificates
		if len(peer) == 0 || !bytes.Equal(peer[0].Raw, localCert.Leaf.Raw) {
			t.Fatal("client did not receive the local app's self-signed certificate")
		}
		if peer[0].Subject.Organization[0] != "ngstone e2e local app" {
			t.Fatalf("peer certificate subject = %v", peer[0].Subject)
		}
		for i := 0; i < 3; i++ {
			msg := fmt.Sprintf("secret-%d\n", i)
			if _, err := io.WriteString(conn, msg); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != msg {
				t.Fatalf("echo = %q, want %q", got, msg)
			}
		}
	})

	t.Run("unknown_sni_is_not_passed_through", func(t *testing.T) {
		acceptsBefore := localAccepts.Load()
		raw, err := net.DialTimeout("tcp", publicAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial public listener: %v", err)
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(10 * time.Second))
		conn := tls.Client(raw, &tls.Config{ServerName: "other." + domain, RootCAs: localPool})
		if err := conn.Handshake(); err == nil {
			t.Fatal("handshake for an unbound hostname reached the local app")
		}
		settle := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(settle) {
			if got := localAccepts.Load(); got != acceptsBefore {
				t.Fatalf("local app accepted %d connection(s) for an unbound hostname", got-acceptsBefore)
			}
			time.Sleep(20 * time.Millisecond)
		}
	})

	t.Run("http_tunnel_on_same_listener_still_works", func(t *testing.T) {
		startAgent(t, agentBin, controlAddr, token, origin.URL, "web", "")
		waitBound(t, publicAddr, "web."+domain)
		status, body, err := doGet(publicAddr, "web."+domain, "/")
		if err != nil || status != http.StatusOK || body != "plain-http-ok" {
			t.Fatalf("http through shared listener = %d %q %v", status, body, err)
		}
		status, _, err = doGet(publicAddr, hostname, "/")
		if err != nil || status != http.StatusMisdirectedRequest {
			t.Fatalf("plain http to the tls hostname = %d %v, want 421", status, err)
		}
	})

	t.Run("http_bind_on_tls_hostname_is_rejected", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, agentBin, "port", origin.URL,
			"--subdomain", "secure",
			"--server", controlAddr,
			"--token", token,
			"--insecure",
			"--no-tui",
		).CombinedOutput()
		if err == nil {
			t.Fatalf("http tunnel on a tls hostname exited cleanly:\n%s", out)
		}
		if ctx.Err() != nil {
			t.Fatalf("http tunnel on a tls hostname did not fail fast:\n%s", out)
		}
		if !strings.Contains(string(out), "kind_conflict") {
			t.Fatalf("output does not name the kind conflict:\n%s", out)
		}
	})
}
