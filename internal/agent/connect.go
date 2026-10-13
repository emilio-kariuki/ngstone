package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
	"ngstone/internal/version"
)

// Connector is the receiving side of a share link (protocol v3). It
// authenticates to the edge with the link's secret, joins the share, opens
// one loopback listener per target, and relays every local connection
// through its own tunnel stream. The edge pipes that stream to the sharer.

const (
	// connectReconnectBase is slower than the operator agent's so a connector
	// retrying while its sharer is offline stays under the edge's auth rate
	// limit (five failures per IP per minute).
	connectReconnectBase = 2 * time.Second
	connectReconnectCap  = 30 * time.Second
	// approvalWait bounds the connect reply when the share needs the
	// sharer's approval; the edge gives the sharer 60 s.
	approvalWait = 90 * time.Second
	// approvalNotice is how long a silent connect waits before telling the
	// user it is probably waiting on the sharer.
	approvalNotice = 2 * time.Second
)

var (
	// ErrShareClosed is returned by Connector.Run when the share ended for
	// good: it expired, was revoked, idled out, or this connector was kicked.
	ErrShareClosed = errors.New("agent: share closed")
	// ErrShareRejected is returned when the edge refuses this connector under
	// the share's policy (address not allowed, single-use link locked, uses
	// exhausted, approval denied or timed out).
	ErrShareRejected = errors.New("agent: share rejected this connector")
	// ErrPassphraseRequired is returned when the share needs a passphrase and
	// none, or the wrong one, was given. The CLI prompts and retries.
	ErrPassphraseRequired = errors.New("agent: share needs a passphrase")
)

type ConnectConfig struct {
	ControlAddr string
	Secret      string
	InstanceID  string

	// Name is how the sharer sees this connector; empty means cN.
	Name string
	// Passphrase is sent with connect when the share set one.
	Passphrase string

	// Ports overrides local listen ports by target id or preset name.
	// ListenPort is the override for the share's first target.
	Ports      map[string]int
	ListenPort int
	// ListenHost is the loopback address to listen on; empty means 127.0.0.1.
	ListenHost string

	Insecure   bool
	ServerName string
	Pin        string
	RootCAs    *x509.CertPool

	Events chan<- ConnectEvent
}

// Connect event states, in addition to the agent's StateConnecting etc.
const (
	StateAwaitingApproval = "awaiting_approval"
	StateUpdated          = "updated" // ExpiresAt changed
)

// ConnectEvent reports connector state to the CLI.
type ConnectEvent struct {
	State string
	Err   string

	// Set with StateOnline and StateUpdated.
	ShareID     string
	ConnectorID string
	Label       string
	Targets     []ConnectTarget
	ExpiresAt   time.Time

	// Set with StateOffline when the share ended: expired, revoked, idle,
	// kicked, sharer_gone, edge_shutdown.
	Reason string
}

// ConnectTarget is a target as served locally.
type ConnectTarget struct {
	proto.ShareTarget
	ListenAddr string
}

// ConnectStats is a snapshot of the connector's local activity.
type ConnectStats struct {
	OpenConns  int
	TotalConns int64
	BytesUp    int64
	BytesDown  int64
	ExpiresAt  time.Time
	Connected  bool
}

type Connector struct {
	cfg        ConnectConfig
	instanceID string

	mu        sync.Mutex
	listeners map[string]net.Listener // by target id
	targets   []ConnectTarget
	sess      tunnel.Session // current live session, nil while disconnected
	shareID   string
	expiresAt time.Time
	joined    bool // ever joined; after that an unknown share is a retry, not a fatal
	conns     map[net.Conn]struct{}
	closed    bool
	wg        sync.WaitGroup

	openConns  atomic.Int64
	totalConns atomic.Int64
	bytesUp    atomic.Int64
	bytesDown  atomic.Int64
}

func NewConnector(cfg ConnectConfig) *Connector {
	id := cfg.InstanceID
	if id == "" {
		id = randomHex(16)
	}
	return &Connector{cfg: cfg, instanceID: id, conns: make(map[net.Conn]struct{}), listeners: make(map[string]net.Listener)}
}

// Targets returns the targets as served locally once joined.
func (c *Connector) Targets() []ConnectTarget {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]ConnectTarget(nil), c.targets...)
}

// Stats snapshots local activity for a status line.
func (c *Connector) Stats() ConnectStats {
	c.mu.Lock()
	expires, connected := c.expiresAt, c.sess != nil
	c.mu.Unlock()
	return ConnectStats{
		OpenConns:  int(c.openConns.Load()),
		TotalConns: c.totalConns.Load(),
		BytesUp:    c.bytesUp.Load(),
		BytesDown:  c.bytesDown.Load(),
		ExpiresAt:  expires,
		Connected:  connected,
	}
}

func (c *Connector) emit(ev ConnectEvent) {
	if c.cfg.Events == nil {
		return
	}
	select {
	case c.cfg.Events <- ev:
	default:
	}
}

func (c *Connector) dialConfig() Config {
	return Config{
		ControlAddr: c.cfg.ControlAddr,
		Insecure:    c.cfg.Insecure,
		ServerName:  c.cfg.ServerName,
		Pin:         c.cfg.Pin,
		RootCAs:     c.cfg.RootCAs,
	}
}

// Run connects, serves local connections, and reconnects on transient
// failures until ctx ends, the share closes (ErrShareClosed), the edge
// rejects this connector (ErrShareRejected, ErrPassphraseRequired) or the
// link is bad (ErrBadToken).
func (c *Connector) Run(ctx context.Context) error {
	bo := newBackoff(connectReconnectBase, connectReconnectCap)
	defer c.closeListeners()

	first := true
	for {
		if ctx.Err() != nil {
			return nil
		}
		if first {
			c.emit(ConnectEvent{State: StateConnecting})
			first = false
		} else {
			c.emit(ConnectEvent{State: StateReconnecting})
		}

		err := c.runOnce(ctx, bo)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, errFatalHandshake) || errors.Is(err, ErrShareClosed) || errors.Is(err, ErrShareRejected) || errors.Is(err, ErrPassphraseRequired) {
			c.emit(ConnectEvent{State: StateOffline, Err: err.Error(), Reason: closeReason(err)})
			return err
		}
		if c.expired() {
			c.emit(ConnectEvent{State: StateOffline, Err: ErrShareClosed.Error(), Reason: proto.ShareReasonExpired})
			return fmt.Errorf("%w: %w", ErrShareClosed, &shareClosedErr{reason: proto.ShareReasonExpired})
		}
		if err != nil {
			slog.Warn("connector: connection lost, will reconnect", "err", err)
			c.emit(ConnectEvent{State: StateOffline, Err: err.Error(), Reason: closeReason(err)})
		}

		wait := bo.next()
		slog.Info("connector: reconnecting", "in", wait)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

type shareClosedErr struct{ reason string }

func (e *shareClosedErr) Error() string { return "share closed: " + e.reason }

// CloseReason extracts the share-close reason from an error returned by
// Run, or "".
func CloseReason(err error) string { return closeReason(err) }

func closeReason(err error) string {
	var sc *shareClosedErr
	if errors.As(err, &sc) {
		return sc.reason
	}
	return ""
}

func (c *Connector) expired() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.expiresAt.IsZero() && !c.expiresAt.After(time.Now())
}

func (c *Connector) runOnce(ctx context.Context, bo *backoff) error {
	conn, err := dialControl(ctx, c.dialConfig())
	if err != nil {
		return err
	}
	sess, err := tunnel.Client(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("connector: session: %w", err)
	}
	defer sess.Close("connector session ended")

	idgen := proto.NewAgentIDGen()
	release := guardHandshake(ctx, sess)
	ok, err := c.handshake(ctx, sess, idgen)
	release()
	if err != nil {
		return err
	}
	bo.reset()

	targets, err := c.ensureListeners(ok)
	if err != nil {
		return fmt.Errorf("%w: %w", errFatalHandshake, err)
	}
	c.setSession(sess)
	defer c.setSession(nil)

	c.emit(ConnectEvent{
		State:       StateOnline,
		ShareID:     ok.ShareID,
		ConnectorID: ok.ConnectorID,
		Label:       ok.Label,
		Targets:     targets,
		ExpiresAt:   time.UnixMilli(ok.ExpiresAtMS),
	})

	ctrlErrCh := make(chan error, 1)
	go func() { ctrlErrCh <- c.controlLoop(sess, idgen) }()

	select {
	case <-ctx.Done():
		_ = sess.Control().Write(proto.TypeGoodbye, idgen.Next(), proto.Goodbye{Reason: "shutdown", DrainMS: 0})
		c.closeConns()
		return nil
	case err := <-ctrlErrCh:
		c.closeConns()
		return err
	case <-sess.Done():
		c.closeConns()
		// The edge closes the session right after share_closed, so the
		// control loop's verdict can land a moment after Done fires. Prefer
		// it: it says whether this is a retry or the end of the share.
		select {
		case err := <-ctrlErrCh:
			return err
		case <-time.After(time.Second):
			return errors.New("connector: session closed")
		}
	}
}

func (c *Connector) handshake(ctx context.Context, sess tunnel.Session, idgen *proto.IDGen) (proto.ConnectOK, error) {
	ctrl := sess.Control()

	authID := idgen.Next()
	if err := ctrl.Write(proto.TypeAuth, authID, proto.Auth{
		ShareSecret:   c.cfg.Secret,
		InstanceID:    c.instanceID,
		ClientVersion: version.String(),
		ProtoVersions: proto.SupportedVersions,
	}); err != nil {
		return proto.ConnectOK{}, err
	}
	msg, err := ctrl.Read()
	if err != nil {
		return proto.ConnectOK{}, err
	}
	switch msg.Type {
	case proto.TypeAuthErr:
		e, _ := proto.Decode[proto.AuthErr](msg)
		if e.Code == proto.CodeBadShare {
			// Once joined, an unknown share usually means the sharer is
			// reconnecting and has not re-registered yet: keep trying until
			// the expiry we were told.
			if c.hasJoined() {
				return proto.ConnectOK{}, fmt.Errorf("connector: share not available yet: %s", e.Message)
			}
			return proto.ConnectOK{}, fmt.Errorf("%w: %w: %s", errFatalHandshake, ErrBadToken, e.Message)
		}
		return proto.ConnectOK{}, fmt.Errorf("%w: %w", errFatalHandshake, &authErr{code: e.Code, message: e.Message})
	case proto.TypeAuthOK:
		ok, err := proto.Decode[proto.AuthOK](msg)
		if err != nil {
			return proto.ConnectOK{}, err
		}
		if ok.ProtoVersion < 3 {
			return proto.ConnectOK{}, fmt.Errorf("%w: edge negotiated protocol v%d, sharing needs v3", errFatalHandshake, ok.ProtoVersion)
		}
		if ok.Scope != proto.ScopeConnector {
			return proto.ConnectOK{}, fmt.Errorf("%w: edge granted scope %q, want %q", errFatalHandshake, ok.Scope, proto.ScopeConnector)
		}
	case proto.TypeError:
		e, _ := proto.Decode[proto.Error](msg)
		return proto.ConnectOK{}, fmt.Errorf("%w: %s: %s", errFatalHandshake, e.Code, e.Message)
	default:
		return proto.ConnectOK{}, fmt.Errorf("connector: unexpected reply %q to auth", msg.Type)
	}

	// The connect reply may wait on the sharer's approval, which is longer
	// than the handshake guard allows.
	_ = ctrl.SetDeadline(time.Now().Add(approvalWait))
	connectID := idgen.Next()
	if err := ctrl.Write(proto.TypeConnect, connectID, proto.Connect{Name: c.cfg.Name, Passphrase: c.cfg.Passphrase}); err != nil {
		return proto.ConnectOK{}, err
	}
	type readResult struct {
		msg proto.Msg
		err error
	}
	replyCh := make(chan readResult, 1)
	go func() {
		m, err := ctrl.Read()
		replyCh <- readResult{m, err}
	}()
	notice := time.NewTimer(approvalNotice)
	defer notice.Stop()
	var rr readResult
	for rr.msg.Type == "" && rr.err == nil {
		select {
		case rr = <-replyCh:
		case <-notice.C:
			c.emit(ConnectEvent{State: StateAwaitingApproval})
		case <-ctx.Done():
			return proto.ConnectOK{}, ctx.Err()
		}
	}
	if rr.err != nil {
		return proto.ConnectOK{}, rr.err
	}
	msg = rr.msg
	switch msg.Type {
	case proto.TypeConnectErr:
		e, _ := proto.Decode[proto.ConnectErr](msg)
		switch e.Code {
		case proto.CodeBadPassphrase:
			return proto.ConnectOK{}, fmt.Errorf("%w: %s", ErrPassphraseRequired, e.Message)
		case proto.CodeForbiddenCIDR, proto.CodeShareLocked, proto.CodeShareUsesExhausted, proto.CodeApprovalDenied, proto.CodeApprovalTimeout:
			return proto.ConnectOK{}, fmt.Errorf("%w: %s: %s", ErrShareRejected, e.Code, e.Message)
		case proto.CodeShareFull:
			return proto.ConnectOK{}, fmt.Errorf("connector: %s: %s", e.Code, e.Message)
		}
		return proto.ConnectOK{}, fmt.Errorf("connector: connect failed: %s: %s", e.Code, e.Message)
	case proto.TypeConnectOK:
		ok, err := proto.Decode[proto.ConnectOK](msg)
		if err != nil {
			return proto.ConnectOK{}, err
		}
		c.mu.Lock()
		c.joined = true
		c.shareID = ok.ShareID
		c.expiresAt = time.UnixMilli(ok.ExpiresAtMS)
		c.mu.Unlock()
		return ok, nil
	case proto.TypeError:
		e, _ := proto.Decode[proto.Error](msg)
		return proto.ConnectOK{}, fmt.Errorf("%w: %s: %s", errFatalHandshake, e.Code, e.Message)
	default:
		return proto.ConnectOK{}, fmt.Errorf("connector: unexpected reply %q to connect", msg.Type)
	}
}

func (c *Connector) hasJoined() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.joined
}

func (c *Connector) setSession(sess tunnel.Session) {
	c.mu.Lock()
	c.sess = sess
	c.mu.Unlock()
}

// portFor picks the local port for a target: an explicit override by target
// id or preset, the first-target override, the preset's port, or 0 for any.
func (c *Connector) portFor(i int, t proto.ShareTarget) (port int, explicit bool) {
	if p, ok := c.cfg.Ports[t.ID]; ok {
		return p, true
	}
	if p, ok := c.cfg.Ports[t.Preset]; ok {
		return p, true
	}
	if i == 0 && c.cfg.ListenPort != 0 {
		return c.cfg.ListenPort, true
	}
	return t.DefaultPort, false
}

// ensureListeners opens one loopback listener per target on the first
// successful join and keeps them across reconnects so local addresses never
// change. One accept loop serves each; every accepted connection relays
// through whichever session is live at that moment.
func (c *Connector) ensureListeners(ok proto.ConnectOK) ([]ConnectTarget, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("connector: closed")
	}
	host := c.cfg.ListenHost
	if host == "" {
		host = "127.0.0.1"
	}
	var out []ConnectTarget
	for i, t := range ok.Targets {
		ln, have := c.listeners[t.ID]
		if !have {
			port, explicit := c.portFor(i, t)
			var err error
			ln, err = listenLoopback(host, port, explicit)
			if err != nil {
				return nil, err
			}
			c.listeners[t.ID] = ln
			c.wg.Add(1)
			go func(id string, ln net.Listener) {
				defer c.wg.Done()
				c.acceptLoop(id, ln)
			}(t.ID, ln)
		}
		out = append(out, ConnectTarget{ShareTarget: t, ListenAddr: ln.Addr().String()})
	}
	c.targets = out
	return out, nil
}

func listenLoopback(host string, port int, explicit bool) (net.Listener, error) {
	if port != 0 {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err == nil {
			return ln, nil
		}
		if explicit {
			return nil, fmt.Errorf("connector: listen on %s:%d: %w", host, port, err)
		}
		slog.Warn("connector: default port busy, picking a free one", "port", port, "err", err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return nil, fmt.Errorf("connector: listen: %w", err)
	}
	return ln, nil
}

func (c *Connector) closeListeners() {
	c.mu.Lock()
	c.closed = true
	lns := c.listeners
	c.listeners = make(map[string]net.Listener)
	c.mu.Unlock()
	for _, ln := range lns {
		ln.Close()
	}
	c.closeConns()
	c.wg.Wait()
}

func (c *Connector) closeConns() {
	c.mu.Lock()
	conns := make([]net.Conn, 0, len(c.conns))
	for conn := range c.conns {
		conns = append(conns, conn)
	}
	c.mu.Unlock()
	for _, conn := range conns {
		conn.Close()
	}
}

func (c *Connector) acceptLoop(targetID string, ln net.Listener) {
	for {
		local, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			slog.Warn("connector: accept failed", "err", err)
			return
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			local.Close()
			return
		}
		sess := c.sess
		shareID := c.shareID
		c.wg.Add(1)
		c.mu.Unlock()
		if sess == nil {
			// Disconnected: fail the local client fast rather than hold it
			// while we reconnect, the way a down database would.
			c.wg.Done()
			local.Close()
			continue
		}
		go func() {
			defer c.wg.Done()
			c.relay(sess, shareID, targetID, local)
		}()
	}
}

type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (cw countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n.Add(int64(n))
	return n, err
}

func (c *Connector) relay(sess tunnel.Session, shareID, targetID string, local net.Conn) {
	c.mu.Lock()
	c.conns[local] = struct{}{}
	c.mu.Unlock()
	c.openConns.Add(1)
	c.totalConns.Add(1)
	defer func() {
		c.mu.Lock()
		delete(c.conns, local)
		c.mu.Unlock()
		c.openConns.Add(-1)
		local.Close()
	}()

	dialCtx, cancel := context.WithTimeout(context.Background(), tcpDialTimeout)
	stream, err := sess.OpenStream(dialCtx, proto.StreamOpen{
		Kind:       proto.KindShare,
		Host:       shareID,
		ShareID:    shareID,
		Target:     targetID,
		ReqID:      randomHex(8),
		ClientAddr: local.RemoteAddr().String(),
	})
	cancel()
	if err != nil {
		slog.Warn("connector: open stream failed", "err", err)
		return
	}
	defer stream.Close()

	c.mu.Lock()
	c.conns[stream] = struct{}{}
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.conns, stream)
		c.mu.Unlock()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(countingWriter{stream, &c.bytesUp}, local)
		halfCloseWrite(stream)
	}()
	go func() {
		defer wg.Done()
		io.Copy(countingWriter{local, &c.bytesDown}, stream)
		halfCloseWrite(local)
	}()
	wg.Wait()
}

func (c *Connector) controlLoop(sess tunnel.Session, idgen *proto.IDGen) error {
	ctrl := sess.Control()

	type readResult struct {
		msg proto.Msg
		err error
	}
	msgCh := make(chan readResult)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			m, err := ctrl.Read()
			select {
			case msgCh <- readResult{m, err}:
			case <-stop:
				return
			}
			if err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	awaitingPong := false
	misses := 0

	for {
		select {
		case rr := <-msgCh:
			if rr.err != nil {
				return rr.err
			}
			m := rr.msg
			switch m.Type {
			case proto.TypePing:
				p, err := proto.Decode[proto.Ping](m)
				if err != nil {
					return fmt.Errorf("connector: malformed ping: %w", err)
				}
				if err := ctrl.Write(proto.TypePong, m.ID, proto.Pong{TS: p.TS}); err != nil {
					return err
				}
			case proto.TypePong:
				awaitingPong = false
				misses = 0
			case proto.TypeShareUpdated:
				su, _ := proto.Decode[proto.ShareUpdated](m)
				until := time.UnixMilli(su.ExpiresAtMS)
				c.mu.Lock()
				c.expiresAt = until
				c.mu.Unlock()
				c.emit(ConnectEvent{State: StateUpdated, ShareID: su.ShareID, ExpiresAt: until})
			case proto.TypeShareClosed:
				sc, _ := proto.Decode[proto.ShareClosed](m)
				slog.Warn("connector: share closed", "share_id", sc.ShareID, "reason", sc.Reason)
				switch sc.Reason {
				case proto.ShareReasonExpired, proto.ShareReasonRevoked, proto.ShareReasonIdle, proto.ShareReasonKicked:
					return fmt.Errorf("%w: %w", ErrShareClosed, &shareClosedErr{reason: sc.Reason})
				}
				return &shareClosedErr{reason: sc.Reason}
			case proto.TypeGoodbye:
				return errEdgeGoodbye
			case proto.TypeError:
				e, _ := proto.Decode[proto.Error](m)
				return fmt.Errorf("connector: edge protocol error: %s: %s", e.Code, e.Message)
			default:
				slog.Warn("connector: unexpected control message", "type", m.Type)
			}
		case <-ticker.C:
			if awaitingPong {
				misses++
				if misses >= heartbeatMisses {
					return errors.New("connector: edge heartbeat missed 3x")
				}
			}
			if err := ctrl.Write(proto.TypePing, idgen.Next(), proto.Ping{TS: time.Now().UnixMilli()}); err != nil {
				return err
			}
			awaitingPong = true
		}
	}
}
