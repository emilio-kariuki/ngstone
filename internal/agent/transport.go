package agent

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/websocket"

	"ngstone/internal/tunnel"
)

const (
	TransportAuto      = "auto"
	TransportRaw       = "raw"
	TransportWebSocket = "websocket"

	controlWebSocketPath        = "/_ngstone/control"
	controlWebSocketSubprotocol = "ngstone-control-v1"
)

func ValidateTransport(raw string) error {
	_, err := transportModes(raw)
	return err
}

func transportModes(raw string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", TransportAuto:
		return []string{TransportRaw, TransportWebSocket}, nil
	case TransportRaw, "tcp":
		return []string{TransportRaw}, nil
	case TransportWebSocket, "ws", "wss", "https":
		return []string{TransportWebSocket}, nil
	default:
		return nil, fmt.Errorf("agent: transport must be auto, raw, or websocket; got %q", raw)
	}
}

func dialControlMode(ctx context.Context, cfg Config, mode string) (net.Conn, error) {
	switch mode {
	case TransportRaw:
		return dialRawControl(ctx, cfg)
	case TransportWebSocket:
		return dialWebSocketControl(ctx, cfg)
	default:
		return nil, fmt.Errorf("agent: unsupported control transport %q", mode)
	}
}

func dialWebSocketControl(ctx context.Context, cfg Config) (net.Conn, error) {
	host, err := controlHost(cfg.ControlAddr)
	if err != nil {
		return nil, err
	}
	scheme := "wss"
	originScheme := "https"
	if cfg.Insecure {
		scheme = "ws"
		originScheme = "http"
	}
	authority := net.JoinHostPort(host, "443")
	endpoint := url.URL{Scheme: scheme, Host: authority, Path: controlWebSocketPath}
	origin := url.URL{Scheme: originScheme, Host: authority}
	wsConfig, err := websocket.NewConfig(endpoint.String(), origin.String())
	if err != nil {
		return nil, fmt.Errorf("agent: websocket config: %w", err)
	}
	wsConfig.Protocol = []string{controlWebSocketSubprotocol}
	wsConfig.Dialer = &net.Dialer{Timeout: tlsHandshakeTimeout}
	if !cfg.Insecure {
		wsConfig.TlsConfig, err = controlTLSConfig(cfg)
		if err != nil {
			return nil, err
		}
	}
	ws, err := wsConfig.DialContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("agent: websocket control: %w", err)
	}
	ws.PayloadType = websocket.BinaryFrame
	return ws, nil
}

func controlHost(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", fmt.Errorf("agent: control address is required for websocket fallback")
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if host == "" {
			return "", fmt.Errorf("agent: control address has no host")
		}
		return strings.Trim(host, "[]"), nil
	}
	if strings.Count(addr, ":") > 1 {
		if net.ParseIP(strings.Trim(addr, "[]")) == nil {
			return "", fmt.Errorf("agent: invalid control address %q", addr)
		}
		return strings.Trim(addr, "[]"), nil
	}
	if strings.Contains(addr, ":") {
		return "", fmt.Errorf("agent: invalid control address %q", addr)
	}
	return addr, nil
}

func dialControlSession(ctx context.Context, cfg Config, mode string) (tunnel.Session, error) {
	conn, err := dialControlMode(ctx, cfg, mode)
	if err != nil {
		return nil, err
	}
	sess, err := tunnel.Client(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("agent: session: %w", err)
	}
	return sess, nil
}
