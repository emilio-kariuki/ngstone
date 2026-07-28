package edge

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	proxyProtoTimeout      = 5 * time.Second
	proxyProtoPrefixLen    = 12
	proxyProtoV1MaxLine    = 107
	proxyProtoV2MaxPayload = 1024

	proxyProtoV2CmdLocal = 0x0
	proxyProtoV2CmdProxy = 0x1

	proxyProtoV2FamUnspec = 0x0
	proxyProtoV2FamINET   = 0x1
	proxyProtoV2FamINET6  = 0x2

	proxyProtoV2TransportStream = 0x1

	proxyProtoV2INETLen  = 12
	proxyProtoV2INET6Len = 36
)

var proxyProtoV2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

var errProxyProtoMalformed = errors.New("edge: malformed PROXY protocol header")

type proxyProtoListener struct {
	net.Listener
	timeout time.Duration
	trusted []netip.Prefix
}

func newProxyProtoListener(inner net.Listener, timeout time.Duration, trusted []netip.Prefix) net.Listener {
	if timeout <= 0 {
		timeout = proxyProtoTimeout
	}
	return &proxyProtoListener{Listener: inner, timeout: timeout, trusted: trusted}
}

func (l *proxyProtoListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if len(l.trusted) > 0 {
			ap, err := netip.ParseAddrPort(conn.RemoteAddr().String())
			if err != nil || !prefixesContain(l.trusted, ap.Addr()) {
				slog.Debug("edge: closing connection from untrusted peer on proxy-protocol listener", "peer", conn.RemoteAddr().String())
				conn.Close()
				continue
			}
		}
		return &proxyProtoConn{Conn: conn, timeout: l.timeout}, nil
	}
}

type proxyProtoConn struct {
	net.Conn
	timeout time.Duration

	once   sync.Once
	remote net.Addr
	err    error
}

func (c *proxyProtoConn) resolve() error {
	c.once.Do(func() {
		socketAddr := c.Conn.RemoteAddr()
		if err := c.Conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
			c.fail(socketAddr, err)
			return
		}
		remote, err := readProxyProtoHeader(c.Conn, socketAddr)
		if err != nil {
			c.fail(socketAddr, err)
			return
		}
		if err := c.Conn.SetReadDeadline(time.Time{}); err != nil {
			c.fail(socketAddr, err)
			return
		}
		c.remote = remote
	})
	return c.err
}

func (c *proxyProtoConn) fail(socketAddr net.Addr, err error) {
	c.err = err
	c.remote = socketAddr
	slog.Warn("edge: rejecting connection without a valid PROXY protocol header", "peer", socketAddr.String(), "err", err)
	c.Conn.Close()
}

func (c *proxyProtoConn) RemoteAddr() net.Addr {
	if err := c.resolve(); err != nil {
		return c.Conn.RemoteAddr()
	}
	return c.remote
}

func (c *proxyProtoConn) Read(b []byte) (int, error) {
	if err := c.resolve(); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *proxyProtoConn) Write(b []byte) (int, error) {
	if err := c.resolve(); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

func (c *proxyProtoConn) SetDeadline(t time.Time) error {
	if err := c.resolve(); err != nil {
		return err
	}
	return c.Conn.SetDeadline(t)
}

func (c *proxyProtoConn) SetReadDeadline(t time.Time) error {
	if err := c.resolve(); err != nil {
		return err
	}
	return c.Conn.SetReadDeadline(t)
}

func readProxyProtoHeader(r io.Reader, socketAddr net.Addr) (net.Addr, error) {
	prefix := make([]byte, proxyProtoPrefixLen)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return nil, fmt.Errorf("edge: reading PROXY protocol header: %w", err)
	}
	if string(prefix) == string(proxyProtoV2Signature) {
		return readProxyProtoV2(r, socketAddr)
	}
	if string(prefix[:6]) == "PROXY " {
		return readProxyProtoV1(r, prefix, socketAddr)
	}
	return nil, errProxyProtoMalformed
}

func readProxyProtoV2(r io.Reader, socketAddr net.Addr) (net.Addr, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, fmt.Errorf("edge: reading PROXY protocol v2 header: %w", err)
	}

	verCmd := head[0]
	famProto := head[1]
	payloadLen := int(binary.BigEndian.Uint16(head[2:4]))

	if verCmd>>4 != 0x2 {
		return nil, errProxyProtoMalformed
	}
	cmd := verCmd & 0x0F
	if cmd != proxyProtoV2CmdLocal && cmd != proxyProtoV2CmdProxy {
		return nil, errProxyProtoMalformed
	}
	if payloadLen > proxyProtoV2MaxPayload {
		return nil, fmt.Errorf("%w: v2 payload of %d bytes exceeds the %d byte cap", errProxyProtoMalformed, payloadLen, proxyProtoV2MaxPayload)
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("edge: reading PROXY protocol v2 payload: %w", err)
	}

	if cmd == proxyProtoV2CmdLocal {
		return socketAddr, nil
	}

	if famProto&0x0F != proxyProtoV2TransportStream {
		return socketAddr, nil
	}

	switch famProto >> 4 {
	case proxyProtoV2FamINET:
		if len(payload) < proxyProtoV2INETLen {
			return nil, fmt.Errorf("%w: AF_INET block needs %d bytes, got %d", errProxyProtoMalformed, proxyProtoV2INETLen, len(payload))
		}
		src, ok := netip.AddrFromSlice(payload[0:4])
		if !ok {
			return nil, errProxyProtoMalformed
		}
		return proxyProtoTCPAddr(src, binary.BigEndian.Uint16(payload[8:10]))
	case proxyProtoV2FamINET6:
		if len(payload) < proxyProtoV2INET6Len {
			return nil, fmt.Errorf("%w: AF_INET6 block needs %d bytes, got %d", errProxyProtoMalformed, proxyProtoV2INET6Len, len(payload))
		}
		src, ok := netip.AddrFromSlice(payload[0:16])
		if !ok {
			return nil, errProxyProtoMalformed
		}
		return proxyProtoTCPAddr(src, binary.BigEndian.Uint16(payload[32:34]))
	case proxyProtoV2FamUnspec:
		return socketAddr, nil
	default:
		return socketAddr, nil
	}
}

func readProxyProtoV1(r io.Reader, prefix []byte, socketAddr net.Addr) (net.Addr, error) {
	line := make([]byte, 0, proxyProtoV1MaxLine)
	line = append(line, prefix...)

	var b [1]byte
	for {
		if len(line) >= proxyProtoV1MaxLine {
			return nil, fmt.Errorf("%w: v1 line exceeded %d bytes without CRLF", errProxyProtoMalformed, proxyProtoV1MaxLine)
		}
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return nil, fmt.Errorf("edge: reading PROXY protocol v1 header: %w", err)
		}
		line = append(line, b[0])
		if b[0] == '\n' {
			break
		}
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return nil, errProxyProtoMalformed
	}
	return parseProxyProtoV1Line(string(line[:len(line)-2]), socketAddr)
}

func parseProxyProtoV1Line(line string, socketAddr net.Addr) (net.Addr, error) {
	fields := strings.Split(line, " ")
	if len(fields) < 2 || fields[0] != "PROXY" {
		return nil, errProxyProtoMalformed
	}

	var want6 bool
	switch fields[1] {
	case "UNKNOWN":
		return socketAddr, nil
	case "TCP4":
		want6 = false
	case "TCP6":
		want6 = true
	default:
		return nil, errProxyProtoMalformed
	}

	if len(fields) != 6 {
		return nil, errProxyProtoMalformed
	}

	src, err := parseProxyProtoV1Addr(fields[2], want6)
	if err != nil {
		return nil, err
	}
	if _, err := parseProxyProtoV1Addr(fields[3], want6); err != nil {
		return nil, err
	}
	srcPort, err := parseProxyProtoV1Port(fields[4])
	if err != nil {
		return nil, err
	}
	if _, err := parseProxyProtoV1Port(fields[5]); err != nil {
		return nil, err
	}
	return proxyProtoTCPAddr(src, srcPort)
}

func parseProxyProtoV1Addr(s string, want6 bool) (netip.Addr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, errProxyProtoMalformed
	}
	if addr.Zone() != "" {
		return netip.Addr{}, errProxyProtoMalformed
	}
	if want6 {
		if !addr.Is6() || addr.Is4In6() {
			return netip.Addr{}, errProxyProtoMalformed
		}
		return addr, nil
	}
	if !addr.Is4() {
		return netip.Addr{}, errProxyProtoMalformed
	}
	return addr, nil
}

func parseProxyProtoV1Port(s string) (uint16, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, errProxyProtoMalformed
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errProxyProtoMalformed
		}
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, errProxyProtoMalformed
	}
	return uint16(n), nil
}

func proxyProtoTCPAddr(addr netip.Addr, port uint16) (net.Addr, error) {
	if !addr.IsValid() {
		return nil, errProxyProtoMalformed
	}
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr.Unmap(), port)), nil
}
