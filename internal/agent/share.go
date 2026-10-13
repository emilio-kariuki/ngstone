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
	"sync"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

// Sharing (protocol v3). A sharer runs the agent in TCP mode with a
// ShareSpec instead of a Bind: the handshake registers the share and the
// edge relays connector streams to the local targets. The sharer mints the
// secret, sends only its SHA-256, and prints the link that carries it.

// ErrShareExpired is returned by Run when the share reached its expiry.
var ErrShareExpired = errors.New("agent: share expired")

// ErrShareIdle is returned by Run when the edge closed the share for
// inactivity (ShareSpec.IdleTimeout).
var ErrShareIdle = errors.New("agent: share closed after idle timeout")

// ErrShareRevoked is returned by Run when another operator session revoked
// the share (ngstone unshare).
var ErrShareRevoked = errors.New("agent: share revoked")

// ShareSecretBytes is the size of a minted share secret.
const ShareSecretBytes = 32

// ShareTargetSpec is one local service in a share: what the edge and
// connectors see, plus the local address only the sharer dials.
type ShareTargetSpec struct {
	proto.ShareTarget
	Addr string // host:port the sharer dials for this target
}

// ShareSpec describes a share to register on every (re)connect.
type ShareSpec struct {
	Label            string
	Targets          []ShareTargetSpec
	SecretSHA256     string
	ExpiresAt        time.Time
	MaxConns         int
	MaxConnectors    int
	MaxUses          int
	SingleUse        bool
	AllowCIDRs       []string
	IdleTimeout      time.Duration
	Approve          bool
	PassphraseSHA256 string

	mu sync.Mutex
}

func (s *ShareSpec) expiresAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ExpiresAt
}

func (s *ShareSpec) setExpiresAt(t time.Time) {
	s.mu.Lock()
	s.ExpiresAt = t
	s.mu.Unlock()
}

func (s *ShareSpec) addrFor(targetID string) (string, bool) {
	for _, t := range s.Targets {
		if t.ID == targetID {
			return t.Addr, true
		}
	}
	return "", false
}

// Preset ports the connector listens on unless overridden.
var presetPorts = map[string]int{
	"postgres": 5432,
	"mysql":    3306,
	"redis":    6379,
	"http":     8080,
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
	return secret, ShareSecretDigest(secret), nil
}

// ShareSecretDigest is the hex SHA-256 the edge stores for a secret.
func ShareSecretDigest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// ParseShareSecret checks a secret supplied by the user (from a file or the
// environment) rather than minted here.
func ParseShareSecret(secret string) (string, error) {
	secret = strings.TrimSpace(secret)
	raw, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(raw) != ShareSecretBytes {
		return "", fmt.Errorf("agent: share secret must be %d random bytes in base64url without padding (as printed in a share link)", ShareSecretBytes)
	}
	return secret, nil
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
	if _, err := ParseShareSecret(rest); err != nil {
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
	expiresAt := spec.expiresAt()
	if !expiresAt.After(time.Now()) {
		return proto.ShareOK{}, fmt.Errorf("%w: %w", errFatalHandshake, ErrShareExpired)
	}

	targets := make([]proto.ShareTarget, 0, len(spec.Targets))
	for _, t := range spec.Targets {
		targets = append(targets, t.ShareTarget)
	}

	ctrl := sess.Control()
	shareID := idgen.Next()
	if err := ctrl.Write(proto.TypeShare, shareID, proto.Share{
		Kind:             proto.KindTCP,
		SecretSHA256:     spec.SecretSHA256,
		Label:            spec.Label,
		Targets:          targets,
		ExpiresAtMS:      expiresAt.UnixMilli(),
		MaxConns:         spec.MaxConns,
		MaxConnectors:    spec.MaxConnectors,
		MaxUses:          spec.MaxUses,
		SingleUse:        spec.SingleUse,
		AllowCIDRs:       spec.AllowCIDRs,
		IdleTimeoutMS:    spec.IdleTimeout.Milliseconds(),
		Approve:          spec.Approve,
		PassphraseSHA256: spec.PassphraseSHA256,
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
	if ev.Event == proto.ShareEventExtended && a.cfg.Share != nil && ev.ExpiresAtMS > 0 {
		a.cfg.Share.setExpiresAt(time.UnixMilli(ev.ExpiresAtMS))
	}
	if a.cfg.ShareEvents == nil {
		return
	}
	select {
	case a.cfg.ShareEvents <- ev:
	default:
		slog.Warn("agent: dropping share event, consumer is slow", "event", ev.Event, "conn_id", ev.ConnID)
	}
}

// ---- management from the sharer's own session ----

// control is the live control stream, held while a session is up so the
// CLI can answer approvals and manage the share from the same session.
type liveControl struct {
	ctrl  *proto.Conn
	idgen *proto.IDGen
}

func (a *Agent) setControl(lc *liveControl) {
	a.mu.Lock()
	a.control = lc
	a.mu.Unlock()
}

func (a *Agent) liveControl() (*liveControl, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.control == nil {
		return nil, false
	}
	return a.control, true
}

var ErrNotConnected = errors.New("agent: not connected to the edge")

func (a *Agent) manage(typ string, data any) error {
	lc, ok := a.liveControl()
	if !ok {
		return ErrNotConnected
	}
	id := lc.idgen.Next()
	a.mu.Lock()
	if a.pendingMgmt == nil {
		a.pendingMgmt = make(map[uint64]string)
	}
	a.pendingMgmt[id] = typ
	a.mu.Unlock()
	return lc.ctrl.Write(typ, id, data)
}

// isMgmtReply reports whether a reply id belongs to a management request
// this agent sent, and forgets it.
func (a *Agent) isMgmtReply(id uint64) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	typ, ok := a.pendingMgmt[id]
	if ok {
		delete(a.pendingMgmt, id)
	}
	return typ, ok
}

// Approve answers a connect_pending event for the current share.
func (a *Agent) Approve(connectorID string, allow bool) error {
	return a.manage(proto.TypeApprove, proto.Approve{ShareID: a.Status().ShareID, ConnectorID: connectorID, Allow: allow})
}

// Kick removes one connector from the current share.
func (a *Agent) Kick(connectorID string) error {
	return a.manage(proto.TypeKick, proto.Kick{ShareID: a.Status().ShareID, ConnectorID: connectorID})
}

// Extend moves the current share's expiry.
func (a *Agent) Extend(until time.Time) error {
	return a.manage(proto.TypeShareUpdate, proto.ShareUpdate{ShareID: a.Status().ShareID, ExpiresAtMS: until.UnixMilli()})
}

// ---- rendering ----

// FormatShareEvent renders an audit event as one terminal line.
func FormatShareEvent(ev proto.ShareEvent) string {
	ts := time.UnixMilli(ev.AtMS).Local().Format("15:04:05")
	switch ev.Event {
	case proto.ShareEventConnectorJoined:
		return fmt.Sprintf("%s  connector joined   %-21s  %s", ts, hostOnly(ev.ClientAddr), ev.ConnectorID)
	case proto.ShareEventConnectorLeft:
		why := ""
		if ev.Reason != "" {
			why = "  (" + ev.Reason + ")"
		}
		return fmt.Sprintf("%s  connector left     %-21s  %s  after %s%s", ts, hostOnly(ev.ClientAddr), ev.ConnectorID, formatDuration(time.Duration(ev.DurationMS)*time.Millisecond), why)
	case proto.ShareEventConnOpen:
		target := ""
		if ev.Target != "" {
			target = "  " + ev.Target
		}
		return fmt.Sprintf("%s  conn #%-3d open     %-21s  via %s%s", ts, ev.ConnID, hostOnly(ev.ClientAddr), ev.ConnectorID, target)
	case proto.ShareEventConnClose:
		return fmt.Sprintf("%s  conn #%-3d closed   %-8s  %s up   %s down", ts, ev.ConnID, formatDuration(time.Duration(ev.DurationMS)*time.Millisecond), formatBytes(ev.BytesUp), formatBytes(ev.BytesDown))
	case proto.ShareEventConnRejected:
		who := ev.ConnectorID
		if who == "" {
			who = hostOnly(ev.ClientAddr)
		}
		return fmt.Sprintf("%s  rejected           %-21s  %s", ts, who, ev.Reason)
	case proto.ShareEventConnectPending:
		return fmt.Sprintf("%s  approve?           %-21s  %s wants to connect: type  y %s  or  n %s", ts, hostOnly(ev.ClientAddr), ev.ConnectorID, ev.ConnectorID, ev.ConnectorID)
	case proto.ShareEventExtended:
		return fmt.Sprintf("%s  extended           until %s", ts, time.UnixMilli(ev.ExpiresAtMS).UTC().Format("15:04 UTC"))
	case proto.ShareEventRegistered:
		return fmt.Sprintf("%s  share registered   %s  until %s", ts, ev.Label, time.UnixMilli(ev.ExpiresAtMS).UTC().Format("15:04 UTC"))
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

// FormatBytes and FormatDuration are the exported twins for the CLI.
func FormatBytes(n int64) string            { return formatBytes(n) }
func FormatDuration(d time.Duration) string { return formatDuration(d) }
