package agent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

// Sharing (protocol v3). A sharer runs the agent in TCP mode with a
// ShareSpec instead of a Bind: the handshake registers the share and the
// edge relays connector streams to the local target. The sharer mints the
// secret, sends only its SHA-256, and prints the link that carries it.

// ErrShareExpired is returned by Run when the share reached its expiry.
var ErrShareExpired = errors.New("agent: share expired")

// ShareSecretBytes is the size of a minted share secret.
const ShareSecretBytes = 32

// ShareSpec describes a share to register on every (re)connect.
type ShareSpec struct {
	Preset        string // postgres, mysql, redis or tcp
	Label         string
	DefaultPort   int // port the connector listens on by default
	SecretSHA256  string
	ExpiresAt     time.Time
	MaxConns      int
	MaxConnectors int
	SingleUse     bool
	AllowCIDRs    []string
}

// Preset ports the connector listens on unless overridden.
var presetPorts = map[string]int{
	"postgres": 5432,
	"mysql":    3306,
	"redis":    6379,
}

// PresetPort returns the conventional local port for a preset, or 0.
func PresetPort(preset string) int {
	return presetPorts[preset]
}

// NewShareSecret mints a share secret and returns its link form
// (base64url, no padding) and the hex SHA-256 the edge stores.
func NewShareSecret() (secret, sha256Hex string, err error) {
	raw := make([]byte, ShareSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("agent: minting share secret: %w", err)
	}
	secret = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(secret))
	return secret, hex.EncodeToString(sum[:]), nil
}

// ShareLink builds ngstone://<edge-host>:<port>/s/<secret>. The host part
// doubles as the TLS server name the connector verifies, so it is the
// control address as the sharer dialed it.
func ShareLink(controlAddr, secret string) string {
	return "ngstone://" + controlAddr + "/s/" + secret
}

// ParseShareLink extracts the control address and secret from a share link.
func ParseShareLink(link string) (controlAddr, secret string, err error) {
	link = strings.TrimSpace(link)
	u, err := url.Parse(link)
	if err != nil {
		return "", "", fmt.Errorf("agent: invalid share link: %w", err)
	}
	if u.Scheme != "ngstone" {
		return "", "", errors.New("agent: share link must start with ngstone://")
	}
	host := u.Host
	if host == "" {
		return "", "", errors.New("agent: share link is missing the edge address")
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		return "", "", fmt.Errorf("agent: share link edge address %q must be host:port", host)
	}
	rest := strings.TrimPrefix(u.Path, "/s/")
	if rest == u.Path || rest == "" || strings.Contains(rest, "/") {
		return "", "", errors.New("agent: share link must look like ngstone://host:port/s/<secret>")
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil || len(raw) != ShareSecretBytes {
		return "", "", errors.New("agent: share link secret is malformed")
	}
	return host, rest, nil
}

func (a *Agent) shareMode() bool {
	return a.cfg.Share != nil
}

func (a *Agent) registerShare(sess tunnel.Session, idgen *proto.IDGen, negotiated int) (proto.ShareOK, error) {
	spec := a.cfg.Share
	if negotiated < 3 {
		return proto.ShareOK{}, fmt.Errorf("%w: this edge does not support sharing (negotiated protocol v%d); upgrade ngstoned", errFatalHandshake, negotiated)
	}
	if !spec.ExpiresAt.After(time.Now()) {
		return proto.ShareOK{}, fmt.Errorf("%w: %w", errFatalHandshake, ErrShareExpired)
	}

	ctrl := sess.Control()
	shareID := idgen.Next()
	if err := ctrl.Write(proto.TypeShare, shareID, proto.Share{
		Kind:          proto.KindTCP,
		SecretSHA256:  spec.SecretSHA256,
		Label:         spec.Label,
		Preset:        spec.Preset,
		DefaultPort:   spec.DefaultPort,
		ExpiresAtMS:   spec.ExpiresAt.UnixMilli(),
		MaxConns:      spec.MaxConns,
		MaxConnectors: spec.MaxConnectors,
		SingleUse:     spec.SingleUse,
		AllowCIDRs:    spec.AllowCIDRs,
	}); err != nil {
		return proto.ShareOK{}, err
	}
	msg, err := ctrl.Read()
	if err != nil {
		return proto.ShareOK{}, err
	}
	switch msg.Type {
	case proto.TypeShareErr:
		e, _ := proto.Decode[proto.ShareErr](msg)
		switch e.Code {
		case proto.CodeShareTaken, proto.CodeInvalidShare, proto.CodeShareTTLTooLong, proto.CodeFeatureUnsupported, proto.CodeTooManyShares:
			return proto.ShareOK{}, fmt.Errorf("%w: share failed: %s: %s", errFatalHandshake, e.Code, e.Message)
		}
		return proto.ShareOK{}, fmt.Errorf("agent: share failed: %s: %s", e.Code, e.Message)
	case proto.TypeShareOK:
		ok, err := proto.Decode[proto.ShareOK](msg)
		if err != nil {
			return proto.ShareOK{}, err
		}
		return ok, nil
	case proto.TypeError:
		e, _ := proto.Decode[proto.Error](msg)
		return proto.ShareOK{}, fmt.Errorf("%w: share failed: %s: %s", errFatalHandshake, e.Code, e.Message)
	default:
		return proto.ShareOK{}, fmt.Errorf("agent: unexpected reply %q to share", msg.Type)
	}
}

func (a *Agent) setShared(ok proto.ShareOK) {
	expires := time.UnixMilli(ok.ExpiresAtMS)
	a.mu.Lock()
	a.status = Status{Hostname: ok.ShareID, URL: "", ShareID: ok.ShareID, ExpiresAt: expires}
	a.mu.Unlock()
	slog.Info("agent: share registered", "share_id", ok.ShareID, "expires_at", expires.UTC().Format(time.RFC3339))
	a.emit(StatusEvent{State: StateOnline, Hostname: ok.ShareID, ShareID: ok.ShareID, ExpiresAt: expires})
}

// deliverShareEvent hands an audit event to the CLI without ever blocking
// the control loop: a consumer that falls behind loses events and gets a
// log line, never a stalled heartbeat.
func (a *Agent) deliverShareEvent(ev proto.ShareEvent) {
	if a.cfg.ShareEvents == nil {
		return
	}
	select {
	case a.cfg.ShareEvents <- ev:
	default:
		slog.Warn("agent: dropping share event, consumer is slow", "event", ev.Event, "conn_id", ev.ConnID)
	}
}

// FormatShareEvent renders an audit event as one terminal line.
func FormatShareEvent(ev proto.ShareEvent) string {
	ts := time.UnixMilli(ev.AtMS).Local().Format("15:04:05")
	switch ev.Event {
	case proto.ShareEventConnectorJoined:
		return fmt.Sprintf("%s  connector joined   %-21s  id %s", ts, hostOnly(ev.ClientAddr), ev.ConnectorID)
	case proto.ShareEventConnectorLeft:
		return fmt.Sprintf("%s  connector left     %-21s  id %s  after %s", ts, hostOnly(ev.ClientAddr), ev.ConnectorID, formatDuration(time.Duration(ev.DurationMS)*time.Millisecond))
	case proto.ShareEventConnOpen:
		return fmt.Sprintf("%s  conn #%-3d open     %-21s  via %s", ts, ev.ConnID, hostOnly(ev.ClientAddr), ev.ConnectorID)
	case proto.ShareEventConnClose:
		return fmt.Sprintf("%s  conn #%-3d closed   %-8s  %s up   %s down", ts, ev.ConnID, formatDuration(time.Duration(ev.DurationMS)*time.Millisecond), formatBytes(ev.BytesUp), formatBytes(ev.BytesDown))
	case proto.ShareEventConnRejected:
		who := ev.ConnectorID
		if who == "" {
			who = hostOnly(ev.ClientAddr)
		}
		return fmt.Sprintf("%s  rejected           %-21s  %s", ts, who, ev.Reason)
	case proto.ShareEventClosed:
		return fmt.Sprintf("%s  share closed       %s", ts, ev.Reason)
	}
	return fmt.Sprintf("%s  %s", ts, ev.Event)
}

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func formatDuration(d time.Duration) string {
	switch {
	case d < time.Second:
		return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}

func formatBytes(n int64) string {
	const unit = 1024
	switch {
	case n < unit:
		return fmt.Sprintf("%d B", n)
	case n < unit*unit:
		return fmt.Sprintf("%.1f KiB", float64(n)/unit)
	case n < unit*unit*unit:
		return fmt.Sprintf("%.1f MiB", float64(n)/(unit*unit))
	}
	return fmt.Sprintf("%.2f GiB", float64(n)/(unit*unit*unit))
}
