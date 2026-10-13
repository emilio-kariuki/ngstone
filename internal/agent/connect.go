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
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
	"ngstone/internal/version"
)

// Connector is the receiving side of a share link (protocol v3). It
// authenticates to the edge with the link's secret, joins the share, opens a
// loopback listener, and relays every local connection through its own
// tunnel stream. The edge pipes that stream to the sharer.

const (
	// connectReconnectBase is slower than the operator agent's so a connector
	// retrying while its sharer is offline stays under the edge's auth rate
	// limit (five failures per IP per minute).
	connectReconnectBase = 2 * time.Second
	connectReconnectCap  = 30 * time.Second
)

var (
	// ErrShareClosed is returned by Connector.Run when the share ended for
	// good: it expired or the sharer revoked it.
	ErrShareClosed = errors.New("agent: share closed")
	// ErrShareRejected is returned when the edge refuses this connector under
	// the share's policy (address not allowed, single-use link locked).
	ErrShareRejected = errors.New("agent: share rejected this connector")
)

type ConnectConfig struct {
	ControlAddr string
	Secret      string
	InstanceID  string

	// ListenPort overrides the share's default local port. 0 means the
	// share's default, falling back to a free port when that one is busy.
	ListenPort int
	// ListenHost is the loopback address to listen on; empty means 127.0.0.1.
	ListenHost string

	Insecure   bool
	ServerName string
	Pin        string
	RootCAs    *x509.CertPool

	Events chan<- ConnectEvent
}

// ConnectEvent reports connector state to the CLI.
type ConnectEvent struct {
	State string // StateConnecting, StateOnline, StateReconnecting, StateOffline
	Err   string

	// Set with StateOnline.
	ShareID     string
	ConnectorID string
	Label       string
	Preset      string
	ListenAddr  string
	ExpiresAt   time.Time

	// Set with StateOffline when the share ended: expired, revoked,
	// sharer_gone, edge_shutdown.
	Reason string
}

type Connector struct {
	cfg        ConnectConfig
	instanceID string

	mu        sync.Mutex
	ln        net.Listener
	sess      tunnel.Session // current live session, nil while disconnected
	shareID   string
	expiresAt time.Time
	joined    bool // ever joined; after that an unknown share is a retry, not a fatal
	conns     map[net.Conn]struct{}
	wg        sync.WaitGroup
}

func NewConnector(cfg ConnectConfig) *Connector {
	id := cfg.InstanceID
	if id == "" {
		id = randomHex(16)
	}
	return &Connector{cfg: cfg, instanceID: id, conns: make(map[net.Conn]struct{})}
}

// ListenAddr returns the local address once the listener is open, else "".
func (c *Connector) ListenAddr() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ln == nil {
		return ""
	}
	return c.ln.Addr().String()
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
// rejects this connector (ErrShareRejected) or the link is bad (ErrBadToken).
func (c *Connector) Run(ctx context.Context) error {
	bo := newBackoff(connectReconnectBase, connectReconnectCap)
	defer c.closeListener()

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
		if errors.Is(err, errFatalHandshake) || errors.Is(err, ErrShareClosed) || errors.Is(err, ErrShareRejected) {
			c.emit(ConnectEvent{State: StateOffline, Err: err.Error(), Reason: closeReason(err)})
			return err
		}
		if c.expired() {
			c.emit(ConnectEvent{State: StateOffline, Err: ErrShareClosed.Error(), Reason: proto.ShareReasonExpired})
			return fmt.Errorf("%w: expired", ErrShareClosed)
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
	ok, err := c.handshake(sess, idgen)
	release()
	if err != nil {
		return err
	}
	bo.reset()

	ln, err := c.ensureListener(ok)
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
		Preset:      ok.Preset,
		ListenAddr:  ln.Addr().String(),
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

func (c *Connector) handshake(sess tunnel.Session, idgen *proto.IDGen) (proto.ConnectOK, error) {
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

	connectID := idgen.Next()
	if err := ctrl.Write(proto.TypeConnect, connectID, proto.Connect{}); err != nil {
		return proto.ConnectOK{}, err
	}
	msg, err = ctrl.Read()
	if err != nil {
		return proto.ConnectOK{}, err
	}
	switch msg.Type {
	case proto.TypeConnectErr:
		e, _ := proto.Decode[proto.ConnectErr](msg)
		switch e.Code {
		case proto.CodeForbiddenCIDR, proto.CodeShareLocked:
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

// ensureListener opens the loopback listener on the first successful join
// and keeps it across reconnects so the local address never changes. One
// accept loop serves it for the connector's lifetime; each accepted
// connection relays through whichever session is live at that moment.
func (c *Connector) ensureListener(ok proto.ConnectOK) (net.Listener, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ln != nil {
		return c.ln, nil
	}
	ln, err := c.listenLocked(ok)
	if err != nil {
		return nil, err
	}
	c.ln = ln
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.acceptLoop(ln)
	}()
	return ln, nil
}

func (c *Connector) listenLocked(ok proto.ConnectOK) (net.Listener, error) {
	host := c.cfg.ListenHost
	if host == "" {
		host = "127.0.0.1"
	}
	port := c.cfg.ListenPort
	if port == 0 {
		port = ok.DefaultPort
	}
	if port != 0 {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err == nil {
			return ln, nil
		}
		if c.cfg.ListenPort != 0 {
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

func (c *Connector) closeListener() {
	c.mu.Lock()
	ln := c.ln
	c.ln = nil
	c.mu.Unlock()
	if ln != nil {
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

func (c *Connector) acceptLoop(ln net.Listener) {
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
		if c.ln == nil {
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
			c.relay(sess, shareID, local)
		}()
	}
}

func (c *Connector) relay(sess tunnel.Session, shareID string, local net.Conn) {
	c.mu.Lock()
	c.conns[local] = struct{}{}
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.conns, local)
		c.mu.Unlock()
		local.Close()
	}()

	dialCtx, cancel := context.WithTimeout(context.Background(), tcpDialTimeout)
	stream, err := sess.OpenStream(dialCtx, proto.StreamOpen{
		Kind:       proto.KindShare,
		Host:       shareID,
		ShareID:    shareID,
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
		io.Copy(stream, local)
		halfCloseWrite(stream)
	}()
	go func() {
		defer wg.Done()
		io.Copy(local, stream)
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
			case proto.TypeShareClosed:
				sc, _ := proto.Decode[proto.ShareClosed](m)
				slog.Warn("connector: share closed", "share_id", sc.ShareID, "reason", sc.Reason)
				switch sc.Reason {
				case proto.ShareReasonExpired, proto.ShareReasonRevoked:
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
