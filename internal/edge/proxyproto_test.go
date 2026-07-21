package edge

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"
)

func v2Header(cmd, famProto byte, payload []byte) []byte {
	h := make([]byte, 0, 16+len(payload))
	h = append(h, proxyProtoV2Signature...)
	h = append(h, 0x20|cmd, famProto)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(payload)))
	h = append(h, l[:]...)
	return append(h, payload...)
}

func v2INETPayload(t *testing.T, src, dst string, sport, dport uint16) []byte {
	t.Helper()
	s := netip.MustParseAddr(src)
	d := netip.MustParseAddr(dst)
	if !s.Is4() || !d.Is4() {
		t.Fatalf("v2INETPayload: %s/%s are not IPv4", src, dst)
	}
	p := make([]byte, 0, 12)
	sb := s.As4()
	db := d.As4()
	p = append(p, sb[:]...)
	p = append(p, db[:]...)
	var ports [4]byte
	binary.BigEndian.PutUint16(ports[0:2], sport)
	binary.BigEndian.PutUint16(ports[2:4], dport)
	return append(p, ports[:]...)
}

func v2INET6Payload(t *testing.T, src, dst string, sport, dport uint16) []byte {
	t.Helper()
	s := netip.MustParseAddr(src)
	d := netip.MustParseAddr(dst)
	p := make([]byte, 0, 36)
	sb := s.As16()
	db := d.As16()
	p = append(p, sb[:]...)
	p = append(p, db[:]...)
	var ports [4]byte
	binary.BigEndian.PutUint16(ports[0:2], sport)
	binary.BigEndian.PutUint16(ports[2:4], dport)
	return append(p, ports[:]...)
}

func readWithin(conn net.Conn, buf []byte, d time.Duration) (int, error, bool) {
	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		n, err := conn.Read(buf)
		ch <- res{n, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.err, true
	case <-time.After(d):
		return 0, nil, false
	}
}

type acceptResult struct {
	conn net.Conn
	err  error
}

func newProxyProtoTestListener(t *testing.T, timeout time.Duration) (net.Listener, chan acceptResult) {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := newProxyProtoListener(raw, timeout)
	accepted := make(chan acceptResult, 16)
	go func() {
		for {
			c, err := ln.Accept()
			accepted <- acceptResult{c, err}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln, accepted
}

func dialAndSend(t *testing.T, ln net.Listener, accepted chan acceptResult, payload []byte) (net.Conn, net.Conn) {
	t.Helper()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	if len(payload) > 0 {
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("write header: %v", err)
		}
	}
	select {
	case ar := <-accepted:
		if ar.err != nil {
			t.Fatalf("accept: %v", ar.err)
		}
		t.Cleanup(func() { ar.conn.Close() })
		return client, ar.conn
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for Accept")
		return nil, nil
	}
}

func TestProxyProtoParsesRealClientAddress(t *testing.T) {
	cases := []struct {
		name   string
		header []byte
		want   string
	}{
		{
			name:   "v1 tcp4",
			header: []byte("PROXY TCP4 196.96.9.105 10.0.1.7 62811 443\r\n"),
			want:   "196.96.9.105:62811",
		},
		{
			name:   "v1 tcp4 port zero",
			header: []byte("PROXY TCP4 1.2.3.4 5.6.7.8 0 65535\r\n"),
			want:   "1.2.3.4:0",
		},
		{
			name:   "v1 tcp6",
			header: []byte("PROXY TCP6 2001:db8:1234:5678::1 2001:db8::99 51844 443\r\n"),
			want:   "[2001:db8:1234:5678::1]:51844",
		},
		{
			name:   "v1 tcp6 max length line",
			header: []byte("PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n"),
			want:   "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
		},
		{
			name:   "v2 tcp4",
			header: v2Header(proxyProtoV2CmdProxy, 0x11, v2INETPayload(t, "196.96.9.105", "10.0.1.7", 62811, 443)),
			want:   "196.96.9.105:62811",
		},
		{
			name:   "v2 tcp6",
			header: v2Header(proxyProtoV2CmdProxy, 0x21, v2INET6Payload(t, "2001:db8:1234:5678::1", "2001:db8::99", 51844, 443)),
			want:   "[2001:db8:1234:5678::1]:51844",
		},
		{
			name:   "v2 tcp4 with trailing TLV",
			header: v2Header(proxyProtoV2CmdProxy, 0x11, append(v2INETPayload(t, "203.0.113.9", "10.0.1.7", 4242, 443), 0x04, 0x00, 0x03, 0xAA, 0xBB, 0xCC)),
			want:   "203.0.113.9:4242",
		},
		{
			name:   "v2 tcp6 with trailing TLV",
			header: v2Header(proxyProtoV2CmdProxy, 0x21, append(v2INET6Payload(t, "2001:db8:aaaa::5", "2001:db8::1", 1234, 443), 0x04, 0x00, 0x01, 0x00)),
			want:   "[2001:db8:aaaa::5]:1234",
		},
		{
			name:   "v2 tcp4 mapped into an AF_INET6 block",
			header: v2Header(proxyProtoV2CmdProxy, 0x21, v2INET6Payload(t, "::ffff:198.51.100.7", "::ffff:10.0.1.7", 3000, 443)),
			want:   "198.51.100.7:3000",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ln, accepted := newProxyProtoTestListener(t, 2*time.Second)
			client, server := dialAndSend(t, ln, accepted, c.header)

			if got := server.RemoteAddr().String(); got != c.want {
				t.Fatalf("RemoteAddr() = %q, want %q", got, c.want)
			}

			if _, err := client.Write([]byte("hello")); err != nil {
				t.Fatalf("write payload: %v", err)
			}
			buf := make([]byte, 5)
			server.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := io.ReadFull(server, buf); err != nil {
				t.Fatalf("read payload after header: %v", err)
			}
			if string(buf) != "hello" {
				t.Fatalf("payload after header = %q, want %q (header framing consumed the wrong number of bytes)", buf, "hello")
			}
		})
	}
}

func TestProxyProtoFallsBackToSocketAddressForLocalAndUnknown(t *testing.T) {
	cases := []struct {
		name   string
		header []byte
	}{
		{"v2 LOCAL with empty payload", v2Header(proxyProtoV2CmdLocal, 0x00, nil)},
		{"v2 LOCAL with an address block that must be discarded", v2Header(proxyProtoV2CmdLocal, 0x11, v2INETPayload(t, "8.8.8.8", "9.9.9.9", 1, 2))},
		{"v2 PROXY AF_UNSPEC", v2Header(proxyProtoV2CmdProxy, 0x00, nil)},
		{"v1 UNKNOWN short form", []byte("PROXY UNKNOWN\r\n")},
		{"v1 UNKNOWN with trailing junk", []byte("PROXY UNKNOWN ffff:f::ffff 65535 65535\r\n")},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ln, accepted := newProxyProtoTestListener(t, 2*time.Second)
			client, server := dialAndSend(t, ln, accepted, c.header)

			want := client.LocalAddr().String()
			if got := server.RemoteAddr().String(); got != want {
				t.Fatalf("RemoteAddr() = %q, want the real socket peer %q", got, want)
			}

			if _, err := client.Write([]byte("hello")); err != nil {
				t.Fatalf("write payload: %v", err)
			}
			buf := make([]byte, 5)
			server.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := io.ReadFull(server, buf); err != nil {
				t.Fatalf("read payload after header: %v", err)
			}
			if string(buf) != "hello" {
				t.Fatalf("payload after header = %q, want %q", buf, "hello")
			}
		})
	}
}

func TestProxyProtoRejectsMalformedHeaders(t *testing.T) {
	cases := []struct {
		name   string
		header []byte
	}{
		{"absent header, plain HTTP request", []byte("GET / HTTP/1.1\r\nHost: svc.example.com\r\n\r\n")},
		{"absent header, TLS ClientHello", []byte{0x16, 0x03, 0x01, 0x00, 0xdc, 0x01, 0x00, 0x00, 0xd8, 0x03, 0x03, 0x00, 0x00}},
		{"v1 lowercase keyword", []byte("proxy TCP4 1.2.3.4 5.6.7.8 1 2\r\n")},
		{"v1 unknown protocol token", []byte("PROXY TCP7 1.2.3.4 5.6.7.8 1 2\r\n")},
		{"v1 missing field", []byte("PROXY TCP4 1.2.3.4 5.6.7.8 1\r\n")},
		{"v1 extra field", []byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 2 3\r\n")},
		{"v1 double space", []byte("PROXY TCP4  1.2.3.4 5.6.7.8 1 2\r\n")},
		{"v1 leading zero in address", []byte("PROXY TCP4 010.0.0.1 5.6.7.8 1 2\r\n")},
		{"v1 leading zero in port", []byte("PROXY TCP4 1.2.3.4 5.6.7.8 080 2\r\n")},
		{"v1 signed port", []byte("PROXY TCP4 1.2.3.4 5.6.7.8 +80 2\r\n")},
		{"v1 port out of range", []byte("PROXY TCP4 1.2.3.4 5.6.7.8 65536 2\r\n")},
		{"v1 bare LF instead of CRLF", []byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\n")},
		{"v1 family mismatch v6 address in TCP4", []byte("PROXY TCP4 2001:db8::1 5.6.7.8 1 2\r\n")},
		{"v1 family mismatch v4 address in TCP6", []byte("PROXY TCP6 1.2.3.4 5.6.7.8 1 2\r\n")},
		{"v1 v4-mapped address in TCP6", []byte("PROXY TCP6 ::ffff:1.2.3.4 ::ffff:5.6.7.8 1 2\r\n")},
		{"v1 zoned v6 address", []byte("PROXY TCP6 fe80::1%eth0 2001:db8::1 1 2\r\n")},
		{"v1 line longer than 107 bytes", []byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 2" + strings.Repeat(" ", 200) + "\r\n")},
		{"v2 unknown command nibble", v2Header(0x07, 0x11, v2INETPayload(t, "1.2.3.4", "5.6.7.8", 1, 2))},
		{"v2 AF_INET length too short", v2Header(proxyProtoV2CmdProxy, 0x11, []byte{1, 2, 3, 4, 5, 6, 7, 8})},
		{"v2 AF_INET6 length too short", v2Header(proxyProtoV2CmdProxy, 0x21, v2INETPayload(t, "1.2.3.4", "5.6.7.8", 1, 2))},
		{"v2 declared length exceeds the cap", v2Header(proxyProtoV2CmdProxy, 0x11, make([]byte, proxyProtoV2MaxPayload+1))},
		{"v2 truncated signature", proxyProtoV2Signature[:8]},
		{"v2 truncated payload", v2Header(proxyProtoV2CmdProxy, 0x21, v2INET6Payload(t, "2001:db8::1", "2001:db8::2", 1, 2))[:12+4+10]},
	}

	wrongVersion := v2Header(proxyProtoV2CmdProxy, 0x11, v2INETPayload(t, "1.2.3.4", "5.6.7.8", 1, 2))
	wrongVersion[12] = 0x31
	cases = append(cases, struct {
		name   string
		header []byte
	}{"v2 version nibble is 3", wrongVersion})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ln, accepted := newProxyProtoTestListener(t, 500*time.Millisecond)
			client, server := dialAndSend(t, ln, accepted, append(append([]byte{}, c.header...), []byte("hello")...))

			buf := make([]byte, 64)
			n, err, ok := readWithin(server, buf, 3*time.Second)
			if !ok {
				t.Fatalf("the edge neither accepted nor rejected the connection within 3s; a bad PROXY header must not pin the reader")
			}
			if err == nil {
				t.Fatalf("Read returned %q and no error; a connection without a valid PROXY header must be rejected, never fall back to the socket address", buf[:n])
			}
			if errors.Is(err, io.EOF) {
				t.Fatalf("Read returned io.EOF, want an explicit rejection error")
			}

			client.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, cerr := client.Read(make([]byte, 1))
			if cerr == nil {
				t.Fatalf("the client's connection is still open; a rejected connection must be closed")
			}
			var ne net.Error
			if errors.As(cerr, &ne) && ne.Timeout() {
				t.Fatalf("the client's read timed out instead of observing a close (%v); the edge accepted the connection rather than rejecting it", cerr)
			}
		})
	}
}

func TestProxyProtoStalledPartialHeaderHitsDeadline(t *testing.T) {
	const timeout = 300 * time.Millisecond
	ln, accepted := newProxyProtoTestListener(t, timeout)
	client, server := dialAndSend(t, ln, accepted, []byte("PROXY TCP4 1.2.3."))

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := server.Read(make([]byte, 16))
		done <- err
	}()

	var readErr error
	select {
	case readErr = <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("a stalled partial header pinned the reader for over 3s; the PROXY header read has no working deadline")
	}
	if readErr == nil {
		t.Fatalf("a stalled partial header must not succeed")
	}
	elapsed := time.Since(start)
	if elapsed < timeout/2 {
		t.Fatalf("gave up after %s, well before the %s deadline", elapsed, timeout)
	}

	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatalf("a timed-out connection must be closed")
	}
	t.Logf("stalled partial header closed after %s (deadline %s)", elapsed, timeout)
}

func TestProxyProtoStalledConnectionsDoNotLeakGoroutines(t *testing.T) {
	const timeout = 200 * time.Millisecond
	ln, accepted := newProxyProtoTestListener(t, timeout)

	settle := func() int {
		var n int
		for i := 0; i < 50; i++ {
			runtime.GC()
			time.Sleep(20 * time.Millisecond)
			n = runtime.NumGoroutine()
		}
		return n
	}

	warm, _ := dialAndSend(t, ln, accepted, []byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n"))
	warm.Close()
	before := settle()

	const conns = 40
	clients := make([]net.Conn, 0, conns)
	servers := make([]net.Conn, 0, conns)
	for i := 0; i < conns; i++ {
		c, s := dialAndSend(t, ln, accepted, []byte("PROXY TC"))
		clients = append(clients, c)
		servers = append(servers, s)
	}
	for _, s := range servers {
		go func(s net.Conn) { s.Read(make([]byte, 1)) }(s)
	}
	time.Sleep(timeout + 500*time.Millisecond)
	for _, c := range clients {
		c.Close()
	}

	after := settle()
	if after > before+5 {
		t.Fatalf("goroutine count went from %d to %d across %d rejected connections; stalled PROXY header reads are pinning goroutines", before, after, conns)
	}
}

func newProxyProtoEdge(t *testing.T, limits LimitsConfig, proxyProtocol bool, handler http.HandlerFunc) (string, string) {
	t.Helper()
	publicAddr := freeTCPAddr(t)
	controlAddr := freeTCPAddr(t)

	s, err := New(Config{
		ControlAddr:   controlAddr,
		PublicAddr:    publicAddr,
		Domain:        "example.com",
		TokenSHA256:   sumToken("tok"),
		PublicScheme:  "http",
		Insecure:      true,
		ProxyProtocol: proxyProtocol,
		Limits:        limits,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	as := newFakeAgentSession(t, "inst-pp", handler)
	if _, _, err := s.registry.Bind("svc.example.com", as, true); err != nil {
		t.Fatalf("bind: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-runErrCh
	})
	waitTCPUp(t, publicAddr)
	return publicAddr, controlAddr
}

func echoXFFHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Seen-Forwarded-For", r.Header.Get("X-Forwarded-For"))
	w.WriteHeader(http.StatusOK)
}

func requestThroughEdge(t *testing.T, addr string, header []byte) *http.Response {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial public listener: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if len(header) > 0 {
		if _, err := conn.Write(header); err != nil {
			t.Fatalf("write PROXY header: %v", err)
		}
	}
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: svc.example.com\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestProxyProtoEndToEndStampsTheRealClientIntoXForwardedFor(t *testing.T) {
	addr, _ := newProxyProtoEdge(t, LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000}, true, echoXFFHandler)

	cases := []struct {
		name   string
		header []byte
		want   string
	}{
		{"v1", []byte("PROXY TCP4 196.96.9.105 10.0.1.7 62811 443\r\n"), "196.96.9.105"},
		{"v2", v2Header(proxyProtoV2CmdProxy, 0x11, v2INETPayload(t, "203.0.113.9", "10.0.1.7", 51844, 443)), "203.0.113.9"},
		{"v2 ipv6", v2Header(proxyProtoV2CmdProxy, 0x21, v2INET6Payload(t, "2001:db8:1234::9", "2001:db8::1", 51844, 443)), "2001:db8:1234::9"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := requestThroughEdge(t, addr, c.header)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			got := resp.Header.Get("X-Seen-Forwarded-For")
			if got != c.want {
				t.Fatalf("backend saw X-Forwarded-For %q, want %q (the local app must see the browser's address, not the TCP proxy's)", got, c.want)
			}
		})
	}
}

func TestProxyProtoRateLimiterKeysOnTheRealClientNotTheProxy(t *testing.T) {
	addr, _ := newProxyProtoEdge(t, LimitsConfig{PerIPRate: 1, PerIPBurst: 2}, true, echoXFFHandler)

	for i := 0; i < 6; i++ {
		header := v2Header(proxyProtoV2CmdProxy, 0x11, v2INETPayload(t, fmt.Sprintf("198.51.100.%d", i+1), "10.0.1.7", uint16(40000+i), 443))
		resp := requestThroughEdge(t, addr, header)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d from a distinct client behind the proxy = %d, want 200; the limiter is keying on the proxy's socket address, so one client's traffic locks everyone out", i+1, resp.StatusCode)
		}
	}

	abusive := v2INETPayload(t, "203.0.113.66", "10.0.1.7", 40000, 443)
	var last int
	for i := 0; i < 5; i++ {
		resp := requestThroughEdge(t, addr, v2Header(proxyProtoV2CmdProxy, 0x11, abusive))
		last = resp.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("repeated requests from one client behind the proxy ended with %d, want 429; per-IP limiting is not reaching the real client address", last)
	}
}

func TestProxyProtoRateLimiterMasksIPv6ClientsToSlash48(t *testing.T) {
	addr, _ := newProxyProtoEdge(t, LimitsConfig{PerIPRate: 1, PerIPBurst: 1}, true, echoXFFHandler)

	first := v2Header(proxyProtoV2CmdProxy, 0x21, v2INET6Payload(t, "2001:db8:1234:1::1", "2001:db8::1", 40001, 443))
	if code := requestThroughEdge(t, addr, first).StatusCode; code != http.StatusOK {
		t.Fatalf("first IPv6 request = %d, want 200", code)
	}

	sameSlash48 := v2Header(proxyProtoV2CmdProxy, 0x21, v2INET6Payload(t, "2001:db8:1234:ffff::2", "2001:db8::1", 40002, 443))
	if code := requestThroughEdge(t, addr, sameSlash48).StatusCode; code != http.StatusTooManyRequests {
		t.Fatalf("a second request from a different /64 inside the same /48 = %d, want 429; the parsed IPv6 client address is not reaching the /48 masking in rateLimitKey", code)
	}

	otherSlash48 := v2Header(proxyProtoV2CmdProxy, 0x21, v2INET6Payload(t, "2001:db8:9999::3", "2001:db8::1", 40003, 443))
	if code := requestThroughEdge(t, addr, otherSlash48).StatusCode; code != http.StatusOK {
		t.Fatalf("a request from a distinct /48 = %d, want 200", code)
	}
}

func TestProxyProtoDisabledPreservesExistingBehavior(t *testing.T) {
	addr, _ := newProxyProtoEdge(t, LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000}, false, echoXFFHandler)

	resp := requestThroughEdge(t, addr, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got := resp.Header.Get("X-Seen-Forwarded-For")
	if got != "127.0.0.1" {
		t.Fatalf("with -proxy-protocol off the backend saw X-Forwarded-For %q, want the raw socket address 127.0.0.1", got)
	}
}

func TestProxyProtoDisabledDoesNotConsumeAProxyHeader(t *testing.T) {
	addr, _ := newProxyProtoEdge(t, LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000}, false, echoXFFHandler)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	header := []byte("PROXY TCP4 196.96.9.105 10.0.1.7 62811 443\r\n")
	if _, err := conn.Write(header); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: svc.example.com\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("with -proxy-protocol off, a PROXY header was silently consumed and the request succeeded; the flag must be a no-op by default")
	}
}
