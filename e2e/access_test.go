package e2e

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func doGetFull(publicAddr, hostname, path, user, pass string) (status int, header http.Header, body string, err error) {
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://"+publicAddr+path, nil)
	if err != nil {
		return 0, nil, "", err
	}
	req.Host = hostname
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, resp.Header, "", err
	}
	return resp.StatusCode, resp.Header, string(b), nil
}

func TestAccessBasicAuthNoCredentials(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "origin-ok")
	}))
	defer origin.Close()

	access := inProcAccess{
		basicAuthSHA256: []string{sha256Hex("alice:secret")},
		basicAuthRealm:  "myrealm",
	}
	h := startInProcessWithAccess(t, "auth-noauth", origin.URL, 0, access)

	waitStatus(t, h.publicAddr, h.hostname, "/", http.StatusUnauthorized, 10*time.Second)

	status, header, _, err := doGetFull(h.publicAddr, h.hostname, "/", "", "")
	if err != nil {
		t.Fatalf("doGetFull: %v", err)
	}
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", status, http.StatusUnauthorized)
	}
	wa := header.Get("WWW-Authenticate")
	if !strings.Contains(wa, "Basic realm=") {
		t.Fatalf("WWW-Authenticate = %q, want it to contain %q", wa, "Basic realm=")
	}
}

func TestAccessBasicAuthWrongCredentials(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "origin-ok")
	}))
	defer origin.Close()

	access := inProcAccess{basicAuthSHA256: []string{sha256Hex("alice:secret")}}
	h := startInProcessWithAccess(t, "auth-wrong", origin.URL, 0, access)

	waitStatus(t, h.publicAddr, h.hostname, "/", http.StatusUnauthorized, 10*time.Second)

	status, _, _, err := doGetFull(h.publicAddr, h.hostname, "/", "alice", "wrongpass")
	if err != nil {
		t.Fatalf("doGetFull: %v", err)
	}
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", status, http.StatusUnauthorized)
	}
}

func TestAccessBasicAuthCorrectCredentials(t *testing.T) {
	const body = "origin-ok-body"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	}))
	defer origin.Close()

	access := inProcAccess{basicAuthSHA256: []string{sha256Hex("alice:secret")}}
	h := startInProcessWithAccess(t, "auth-ok", origin.URL, 0, access)

	waitStatus(t, h.publicAddr, h.hostname, "/", http.StatusUnauthorized, 10*time.Second)

	status, _, got, err := doGetFull(h.publicAddr, h.hostname, "/", "alice", "secret")
	if err != nil {
		t.Fatalf("doGetFull: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if got != body {
		t.Fatalf("body = %q, want %q", got, body)
	}
}

func TestAccessAllowCIDRExcludesLoopback(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "origin-ok")
	}))
	defer origin.Close()

	access := inProcAccess{allowCIDRs: []string{"10.0.0.0/8"}}
	h := startInProcessWithAccess(t, "cidr-deny", origin.URL, 0, access)

	waitStatus(t, h.publicAddr, h.hostname, "/", http.StatusForbidden, 10*time.Second)
}

func TestAccessAllowCIDRIncludesLoopback(t *testing.T) {
	const body = "origin-ok"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	}))
	defer origin.Close()

	access := inProcAccess{allowCIDRs: []string{"127.0.0.0/8"}}
	h := startInProcessWithAccess(t, "cidr-allow", origin.URL, 0, access)

	waitStatus(t, h.publicAddr, h.hostname, "/", http.StatusOK, 10*time.Second)

	status, _, got, err := doGetFull(h.publicAddr, h.hostname, "/", "", "")
	if err != nil {
		t.Fatalf("doGetFull: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if got != body {
		t.Fatalf("body = %q, want %q", got, body)
	}
}

func TestAccessNoFieldsBackCompatOpen(t *testing.T) {
	const body = "origin-ok"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	}))
	defer origin.Close()

	h := startInProcess(t, "open-backcompat", origin.URL, 0)

	waitStatus(t, h.publicAddr, h.hostname, "/", http.StatusOK, 10*time.Second)

	status, _, got, err := doGetFull(h.publicAddr, h.hostname, "/", "", "")
	if err != nil {
		t.Fatalf("doGetFull: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if got != body {
		t.Fatalf("body = %q, want %q", got, body)
	}
}

func TestAccessCombinedCIDRAllowAndBasicAuthNoCreds(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "origin-ok")
	}))
	defer origin.Close()

	access := inProcAccess{
		allowCIDRs:      []string{"127.0.0.0/8"},
		basicAuthSHA256: []string{sha256Hex("alice:secret")},
	}
	h := startInProcessWithAccess(t, "combined", origin.URL, 0, access)

	waitStatus(t, h.publicAddr, h.hostname, "/", http.StatusUnauthorized, 10*time.Second)

	status, _, _, err := doGetFull(h.publicAddr, h.hostname, "/", "", "")
	if err != nil {
		t.Fatalf("doGetFull: %v", err)
	}
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d (CIDR allowed but basic auth should still gate)", status, http.StatusUnauthorized)
	}
}

func doGetWithAuthorizationHeader(publicAddr, hostname, path, authValue string) (status int, gotAuth string, err error) {
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://"+publicAddr+path, nil)
	if err != nil {
		return 0, "", err
	}
	req.Host = hostname
	if authValue != "" {
		req.Header.Set("Authorization", authValue)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.Header.Get("X-Seen-Authorization"), nil
}

func TestAccessBasicAuthDoesNotForwardAuthorizationToOrigin(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Authorization", r.Header.Get("Authorization"))
		io.WriteString(w, "origin-ok")
	}))
	defer origin.Close()

	access := inProcAccess{basicAuthSHA256: []string{sha256Hex("alice:secret")}}
	h := startInProcessWithAccess(t, "auth-strip", origin.URL, 0, access)

	waitStatus(t, h.publicAddr, h.hostname, "/", http.StatusUnauthorized, 10*time.Second)

	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://"+h.publicAddr+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = h.hostname
	req.SetBasicAuth("alice", "secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if seen := resp.Header.Get("X-Seen-Authorization"); seen != "" {
		t.Fatalf("origin saw Authorization header %q, want it stripped by the edge once basic auth succeeded", seen)
	}
}

func TestAccessNoBasicAuthForwardsClientAuthorizationUntouched(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Authorization", r.Header.Get("Authorization"))
		io.WriteString(w, "origin-ok")
	}))
	defer origin.Close()

	h := startInProcess(t, "auth-passthrough", origin.URL, 0)

	waitStatus(t, h.publicAddr, h.hostname, "/", http.StatusOK, 10*time.Second)

	const clientAuth = "Bearer xyz"
	status, gotAuth, err := doGetWithAuthorizationHeader(h.publicAddr, h.hostname, "/", clientAuth)
	if err != nil {
		t.Fatalf("doGetWithAuthorizationHeader: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if gotAuth != clientAuth {
		t.Fatalf("origin saw Authorization = %q, want %q (an app with its own auth scheme must not be broken by the edge)", gotAuth, clientAuth)
	}
}

func TestAccessTCPAllowCIDRExcludesLoopbackRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess tcp end-to-end test in -short mode")
	}

	edgeBin, agentBin := buildBinaries(t)
	echoAddr := startTCPEcho(t)

	token := "e2e-tcp-access-deny-token"
	domain := "tun.example.com"
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)
	tcpLo, tcpHi := freeTCPRange(t, 30)

	startEdgeTCP(t, edgeBin, controlAddr, publicAddr, token, domain, tcpLo, tcpHi)
	_, agentSB := startAgentTCPWithAllowCIDR(t, agentBin, controlAddr, token, echoAddr, 0, "10.0.0.0/8")

	port := waitTCPAssignedPort(t, agentSB, 15*time.Second)
	waitForPort(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))

	conn := dialTunnel(t, port)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(conn, "hello\n")

	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("expected the CIDR-denied connection to be refused/closed without an echo, but read %d byte(s)", n)
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("read timed out: a CIDR-denied tcp connection should be closed promptly, not hang")
	}
}

func TestAccessTCPAllowCIDRIncludesLoopbackEcho(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess tcp end-to-end test in -short mode")
	}

	edgeBin, agentBin := buildBinaries(t)
	echoAddr := startTCPEcho(t)

	token := "e2e-tcp-access-allow-token"
	domain := "tun.example.com"
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)
	tcpLo, tcpHi := freeTCPRange(t, 30)

	startEdgeTCP(t, edgeBin, controlAddr, publicAddr, token, domain, tcpLo, tcpHi)
	_, agentSB := startAgentTCPWithAllowCIDR(t, agentBin, controlAddr, token, echoAddr, 0, "127.0.0.0/8")

	port := waitTCPAssignedPort(t, agentSB, 15*time.Second)
	waitForPort(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))

	conn := dialTunnel(t, port)
	echoRoundTrip(t, conn, "allowed-cidr\n")
}
