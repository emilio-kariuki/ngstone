package agent

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"ngstone/internal/inspect"
	"ngstone/internal/policy"
	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
	"ngstone/internal/version"
)

const (
	reconnectBase = 500 * time.Millisecond
	reconnectCap  = 30 * time.Second

	heartbeatInterval = 15 * time.Second
	heartbeatMisses   = 3

	drainTimeout = 15 * time.Second
)

// handshakeTimeout bounds the auth+bind exchange on the control stream. The
// edge gives an agent 5s to send Auth; this is the symmetric guard on the
// agent's side, so a silent or wedged edge cannot hang a reconnect forever.
var handshakeTimeout = 15 * time.Second

var errFatalHandshake = errors.New("agent: fatal handshake error")
var errEdgeGoodbye = errors.New("agent: edge said goodbye")

type preBindTransportError struct {
	err error
}

func (e *preBindTransportError) Error() string { return e.err.Error() }
func (e *preBindTransportError) Unwrap() error { return e.err }

func isPreBindTransportError(err error) bool {
	var target *preBindTransportError
	return errors.As(err, &target)
}

var (
	ErrBadToken    = errors.New("agent: token rejected by server")
	ErrUnreachable = errors.New("agent: cannot reach server")
)

type authErr struct {
	code    string
	message string
}

func (e *authErr) Error() string {
	return fmt.Sprintf("auth failed: %s: %s", e.code, e.message)
}

type Config struct {
	// Name identifies this tunnel when one process runs several; it tags
	// status events and captured exchanges. Empty for a single tunnel.
	Name string

	ControlAddr string
	Transport   string
	Token       string
	Subdomain   string
	TargetURL   string
	HostHeader  string

	Kind           string
	RemotePort     int
	HTTP2          bool
	MultiConnector bool
	ConnectorToken string

	BasicAuthSHA256 []string
	BasicAuthRealm  string
	AllowCIDRs      []string
	Policy          *policy.Policy

	InstanceID string

	Insecure   bool
	ServerName string
	Pin        string
	RootCAs    *x509.CertPool

	Store  *inspect.Store
	Events chan<- StatusEvent

	// Share switches the agent into sharer mode (protocol v3): instead of a
	// Bind, the handshake registers this share and the edge relays
	// connector streams to TargetURL (a host:port, as for Kind "tcp").
	Share *ShareSpec
	// ShareEvents receives the edge's audit events for the share. Sends
	// never block; a full channel drops the event with a log line.
	ShareEvents chan<- proto.ShareEvent
}

type Status struct {
	State    string // one of the State* constants; empty before the first attempt
	Hostname string
	URL      string
	Err      string // last error text when not online
	Evicted  bool

	ShareID   string
	ExpiresAt time.Time
}

const (
	StateConnecting   = "connecting"
	StateOnline       = "online"
	StateReconnecting = "reconnecting"
	StateEvicted      = "evicted"
	StateOffline      = "offline"
	StateExpired      = "expired"
)

type StatusEvent struct {
	Tunnel   string
	State    string
	Hostname string
	URL      string
	Err      string

	// Set in sharer mode once the share is registered.
	ShareID   string
	ExpiresAt time.Time
}

type Agent struct {
	cfg        Config
	instanceID string

	transport      *http.Transport
	http2Transport *http2.Transport
	store          *inspect.Store
	target         *url.URL
	targetErr      error

	mu          sync.Mutex
	status      Status
	control     *liveControl      // live control stream in sharer mode, for Approve/Kick/Extend
	pendingMgmt map[uint64]string // ids of management requests awaiting a reply
}

func New(cfg Config) *Agent {
	id := cfg.InstanceID
	if id == "" {
		id = randomHex(16)
	}
	a := &Agent{
		cfg:        cfg,
		instanceID: id,
		store:      cfg.Store,
		transport: &http.Transport{
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     90 * time.Second,
			ForceAttemptHTTP2:   false,
		},
	}
	if u, err := url.Parse(cfg.TargetURL); err == nil {
		a.target = u
		if cfg.HTTP2 {
			a.http2Transport = newHTTP2Transport(u)
		}
	} else {
		a.targetErr = err
	}
	return a
}

func (a *Agent) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.status
}

func (a *Agent) Store() *inspect.Store { return a.store }

func (a *Agent) Transport() http.RoundTripper { return a.transport }

func (a *Agent) Target() *url.URL {
	if a.target == nil {
		return nil
	}
	u := *a.target
	return &u
}

func (a *Agent) emit(ev StatusEvent) {
	if a.cfg.Events == nil {
		return
	}
	ev.Tunnel = a.cfg.Name
	select {
	case a.cfg.Events <- ev:
	default:
	}
}

func (a *Agent) emitState(state, errText string) {
	a.mu.Lock()
	a.status.State = state
	a.status.Err = errText
	st := a.status
	a.mu.Unlock()
	a.emit(StatusEvent{State: state, Hostname: st.Hostname, URL: st.URL, Err: errText})
}

func (a *Agent) setBound(hostname, url string) {
	a.mu.Lock()
	a.status = Status{State: StateOnline, Hostname: hostname, URL: url}
	a.mu.Unlock()
	slog.Info("agent: bound", "hostname", hostname, "url", url)
	a.emit(StatusEvent{State: StateOnline, Hostname: hostname, URL: url})
}

func (a *Agent) setEvicted(hostname string) {
	a.mu.Lock()
	a.status.Evicted = true
	a.status.State = StateEvicted
	url := a.status.URL
	a.mu.Unlock()
	slog.Warn("agent: tunnel evicted, no longer advertising", "hostname", hostname)
	a.emit(StatusEvent{State: StateEvicted, Hostname: hostname, URL: url})
}

func (a *Agent) Run(ctx context.Context) error {
	defer func() {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			a.emitState(StateExpired, "")
		} else if ctx.Err() != nil {
			a.emitState(StateOffline, "")
		}
	}()
	bo := newBackoff(reconnectBase, reconnectCap)
	defer a.transport.CloseIdleConnections()
	defer func() {
		if a.http2Transport != nil {
			a.http2Transport.CloseIdleConnections()
		}
	}()

	first := true

	for {
		if ctx.Err() != nil {
			return nil
		}

		if first {
			a.emitState(StateConnecting, "")
			first = false
		} else {
			a.emitState(StateReconnecting, "")
		}

		err := a.runOnce(ctx, bo)

		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, errFatalHandshake) {
			a.emitState(StateOffline, err.Error())
			return err
		}
		if err != nil {
			slog.Warn("agent: connection lost, will reconnect", "err", err)
			a.emitState(StateOffline, err.Error())
		} else {
			a.emitState(StateOffline, "")
		}

		wait := bo.next()
		slog.Info("agent: reconnecting", "in", wait)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

func (a *Agent) runOnce(ctx context.Context, bo *backoff) error {
	modes, err := transportModes(a.cfg.Transport)
	if err != nil {
		return fmt.Errorf("%w: %v", errFatalHandshake, err)
	}
	var lastErr error
	for i, mode := range modes {
		lastErr = a.runOnceTransport(ctx, bo, mode)
		if lastErr == nil || ctx.Err() != nil || errors.Is(lastErr, errFatalHandshake) || !isPreBindTransportError(lastErr) || i == len(modes)-1 {
			return lastErr
		}
		slog.Warn("agent: control transport failed, trying fallback", "transport", mode, "err", lastErr)
	}
	return lastErr
}

func (a *Agent) runOnceTransport(ctx context.Context, bo *backoff, mode string) error {
	sess, err := dialControlSession(ctx, a.cfg, mode)
	if err != nil {
		return &preBindTransportError{err: err}
	}
	defer sess.Close("agent session ended")

	idgen := proto.NewAgentIDGen()

	release := guardHandshake(ctx, sess)
	if a.shareMode() {
		shareOK, err := a.handshakeShare(sess, idgen)
		release()
		if err != nil {
			if errors.Is(err, errFatalHandshake) {
				return err
			}
			return &preBindTransportError{err: err}
		}
		a.setShared(shareOK)
	} else {
		bindOK, err := a.handshake(sess, idgen)
		release()
		if err != nil {
			if errors.Is(err, errFatalHandshake) {
				return err
			}
			return &preBindTransportError{err: err}
		}
		a.setBound(bindOK.Hostname, a.advertisedURL(bindOK))
	}
	bo.reset()

	ln, err := tunnel.NewListener(sess)
	if err != nil {
		return err
	}
	defer ln.Close()

	srv, err := a.newServer()
	if err != nil {
		return err
	}

	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- srv.Serve(ln) }()

	if a.shareMode() {
		a.setControl(&liveControl{ctrl: sess.Control(), idgen: idgen})
		defer a.setControl(nil)
	}

	ctrlErrCh := make(chan error, 1)
	go func() { ctrlErrCh <- a.controlLoop(sess, idgen) }()

	select {
	case <-ctx.Done():
		a.sendGoodbye(sess, idgen, "shutdown")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		defer cancel()
		srv.Shutdown(shutdownCtx)
		<-serveErrCh
		return nil
	case err := <-serveErrCh:
		srv.Close()
		return fmt.Errorf("agent: local server: %w", err)
	case err := <-ctrlErrCh:
		if errors.Is(err, errEdgeGoodbye) {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), drainTimeout)
			defer cancel()
			srv.Shutdown(shutdownCtx)
			<-serveErrCh
			return err
		}
		srv.Close()
		return fmt.Errorf("agent: control loop: %w", err)
	case <-sess.Done():
		srv.Close()
		return errors.New("agent: session closed")
	}
}

type tunnelServer interface {
	Serve(ln net.Listener) error
	Shutdown(ctx context.Context) error
	Close() error
}

func (a *Agent) bindKind() string {
	if a.shareMode() {
		return proto.KindTCP
	}
	if a.cfg.Kind == "" {
		return proto.KindHTTP
	}
	return a.cfg.Kind
}

func (a *Agent) advertisedURL(b proto.BindOK) string {
	if a.cfg.Kind == proto.KindTCP {
		return fmt.Sprintf("tcp://%s:%d", b.Hostname, b.Port)
	}
	return b.URL
}

func (a *Agent) newServer() (tunnelServer, error) {
	if a.shareMode() {
		srv := newTCPServer(a.cfg.TargetURL)
		spec := a.cfg.Share
		srv.resolve = func(stream net.Conn) (string, error) {
			pc, ok := stream.(preambleConn)
			if !ok {
				return "", errors.New("agent: share stream without a preamble")
			}
			pre := pc.Preamble()
			target := pre.Target
			if target == "" && len(spec.Targets) == 1 {
				target = spec.Targets[0].ID
			}
			addr, ok := spec.addrFor(target)
			if !ok {
				return "", fmt.Errorf("agent: share stream for unknown target %q", pre.Target)
			}
			return addr, nil
		}
		return srv, nil
	}
	if a.bindKind() == proto.KindTCP {
		return newTCPServer(a.cfg.TargetURL), nil
	}
	target := a.Target()
	if target == nil {
		return nil, fmt.Errorf("agent: parse target: %w", a.targetErr)
	}
	if a.cfg.HTTP2 && a.http2Transport == nil {
		return nil, errors.New("agent: HTTP/2 mode requires an http or https target")
	}
	if a.cfg.HTTP2 {
		return newHTTP2TunnelServer(a.buildProxy(target), a.buildHTTP2Proxy(target)), nil
	}
	return &http.Server{
		Handler:     a.buildProxy(target),
		ConnContext: streamConnContext,
	}, nil
}

type preambleConn interface {
	Preamble() proto.StreamOpen
}

func streamConnContext(ctx context.Context, c net.Conn) context.Context {
	pc, ok := c.(preambleConn)
	if !ok {
		return ctx
	}
	pre := pc.Preamble()
	return inspect.WithStreamInfo(ctx, inspect.StreamInfo{
		ReqID:      pre.ReqID,
		Host:       pre.Host,
		ClientAddr: pre.ClientAddr,
	})
}

// guardHandshake bounds a handshake running on sess. The control stream gets
// a handshakeTimeout deadline, and the session is closed if ctx is cancelled
// first, so neither a silent edge nor Ctrl-C can leave the agent blocked in a
// control-stream read. The returned func lifts both guards; call it as soon
// as the handshake is over, before the control loop starts.
func guardHandshake(ctx context.Context, sess tunnel.Session) (release func()) {
	ctrl := sess.Control()
	_ = ctrl.SetDeadline(time.Now().Add(handshakeTimeout))

	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-ctx.Done():
			sess.Close("context cancelled during handshake")
		case <-done:
		}
	}()

	return func() {
		close(done)
		<-exited
		_ = ctrl.SetDeadline(time.Time{})
	}
}

func (a *Agent) authenticate(sess tunnel.Session, idgen *proto.IDGen) (int, error) {
	ctrl := sess.Control()

	authID := idgen.Next()
	if err := ctrl.Write(proto.TypeAuth, authID, proto.Auth{
		Token:         a.cfg.Token,
		InstanceID:    a.instanceID,
		ClientVersion: version.String(),
		ProtoVersions: proto.SupportedVersions,
	}); err != nil {
		return 0, err
	}
	msg, err := ctrl.Read()
	if err != nil {
		return 0, err
	}
	switch msg.Type {
	case proto.TypeAuthErr:
		e, _ := proto.Decode[proto.AuthErr](msg)
		return 0, fmt.Errorf("%w: %w", errFatalHandshake, &authErr{code: e.Code, message: e.Message})
	case proto.TypeAuthOK:
		ok, err := proto.Decode[proto.AuthOK](msg)
		if err != nil {
			return 0, err
		}
		if !slices.Contains(proto.SupportedVersions, ok.ProtoVersion) {
			return 0, fmt.Errorf("%w: edge selected unsupported protocol version %d", errFatalHandshake, ok.ProtoVersion)
		}
		return ok.ProtoVersion, nil
	default:
		return 0, fmt.Errorf("agent: unexpected reply %q to auth", msg.Type)
	}
}

// handshakeShare authenticates with the operator token and registers the
// configured share.
func (a *Agent) handshakeShare(sess tunnel.Session, idgen *proto.IDGen) (proto.ShareOK, error) {
	negotiated, err := a.authenticate(sess, idgen)
	if err != nil {
		return proto.ShareOK{}, err
	}
	return a.registerShare(sess, idgen, negotiated)
}

func (a *Agent) handshake(sess tunnel.Session, idgen *proto.IDGen) (proto.BindOK, error) {
	negotiated, err := a.authenticate(sess, idgen)
	if err != nil {
		return proto.BindOK{}, err
	}

	if a.cfg.Policy != nil {
		if err := a.cfg.Policy.Validate(); err != nil {
			return proto.BindOK{}, fmt.Errorf("%w: invalid traffic policy: %v", errFatalHandshake, err)
		}
	}

	if (len(a.cfg.BasicAuthSHA256) > 0 || len(a.cfg.AllowCIDRs) > 0 || a.cfg.Policy != nil || a.cfg.HTTP2 || a.cfg.MultiConnector) && negotiated < 2 {
		return proto.BindOK{}, fmt.Errorf("%w: edge does not support access control, traffic policies, HTTP/2 tunnels, or multiple connectors (negotiated protocol v%d); upgrade ngstoned", errFatalHandshake, negotiated)
	}

	if a.bindKind() == proto.KindTCP && (len(a.cfg.BasicAuthSHA256) > 0 || a.cfg.Policy != nil || a.cfg.HTTP2 || a.cfg.MultiConnector) {
		return proto.BindOK{}, fmt.Errorf("%w: basic auth, traffic policies, HTTP/2, and multiple connectors are not supported for tcp tunnels", errFatalHandshake)
	}

	policyDigest := ""
	if a.cfg.Policy != nil {
		policyDigest = a.cfg.Policy.Digest()
	}
	connectorTokenDigest := ""
	if a.cfg.MultiConnector {
		if strings.TrimSpace(a.cfg.ConnectorToken) == "" {
			return proto.BindOK{}, fmt.Errorf("%w: multiple connectors require a connector token", errFatalHandshake)
		}
		sum := sha256.Sum256([]byte(a.cfg.ConnectorToken))
		connectorTokenDigest = hex.EncodeToString(sum[:])
	}

	ctrl := sess.Control()

	bindMsg := proto.Bind{
		Kind:                 a.bindKind(),
		Name:                 a.cfg.Name,
		Subdomain:            a.cfg.Subdomain,
		RemotePort:           a.cfg.RemotePort,
		Takeover:             a.bindKind() == proto.KindHTTP,
		HTTP2:                a.cfg.HTTP2,
		MultiConnector:       a.cfg.MultiConnector,
		ConnectorTokenSHA256: connectorTokenDigest,
		AllowCIDRs:           a.cfg.AllowCIDRs,
		Policy:               a.cfg.Policy,
		PolicyDigest:         policyDigest,
	}
	if a.bindKind() == proto.KindHTTP {
		bindMsg.BasicAuthSHA256 = a.cfg.BasicAuthSHA256
		if len(a.cfg.BasicAuthSHA256) > 0 {
			bindMsg.BasicAuthRealm = a.cfg.BasicAuthRealm
		}
	}

	bindID := idgen.Next()
	if err := ctrl.Write(proto.TypeBind, bindID, bindMsg); err != nil {
		return proto.BindOK{}, err
	}
	msg, err := ctrl.Read()
	if err != nil {
		return proto.BindOK{}, err
	}
	switch msg.Type {
	case proto.TypeBindErr:
		e, _ := proto.Decode[proto.BindErr](msg)
		if e.Code == proto.CodeInvalidSubdomain || e.Code == proto.CodeKindUnsupported || e.Code == proto.CodeInvalidAccess || e.Code == proto.CodeConnectorConfigMismatch || e.Code == proto.CodeCredentialScope {
			return proto.BindOK{}, fmt.Errorf("%w: bind failed: %s: %s", errFatalHandshake, e.Code, e.Message)
		}
		if e.Code == proto.CodeSubdomainTaken && a.cfg.Subdomain != "" {
			return proto.BindOK{}, fmt.Errorf("%w: bind failed: %s: %s", errFatalHandshake, e.Code, e.Message)
		}
		return proto.BindOK{}, fmt.Errorf("agent: bind failed: %s: %s", e.Code, e.Message)
	case proto.TypeBindOK:
		bindOK, err := proto.Decode[proto.BindOK](msg)
		if err != nil {
			return proto.BindOK{}, err
		}
		if policyDigest != "" && bindOK.PolicyDigest != policyDigest {
			return proto.BindOK{}, fmt.Errorf("%w: edge did not acknowledge the traffic policy; upgrade ngstoned", errFatalHandshake)
		}
		if a.cfg.HTTP2 && !bindOK.HTTP2 {
			return proto.BindOK{}, fmt.Errorf("%w: edge did not acknowledge HTTP/2 mode; upgrade ngstoned", errFatalHandshake)
		}
		if a.cfg.MultiConnector && !bindOK.MultiConnector {
			return proto.BindOK{}, fmt.Errorf("%w: edge did not acknowledge multiple-connector mode; upgrade ngstoned", errFatalHandshake)
		}
		return bindOK, nil
	default:
		return proto.BindOK{}, fmt.Errorf("agent: unexpected reply %q to bind", msg.Type)
	}
}

func (a *Agent) sendGoodbye(sess tunnel.Session, idgen *proto.IDGen, reason string) {
	_ = sess.Control().Write(proto.TypeGoodbye, idgen.Next(), proto.Goodbye{
		Reason:  reason,
		DrainMS: int(drainTimeout / time.Millisecond),
	})
}

func (a *Agent) controlLoop(sess tunnel.Session, idgen *proto.IDGen) error {
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
	var lastPingSent time.Time

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
					return fmt.Errorf("agent: malformed ping: %w", err)
				}
				if err := ctrl.Write(proto.TypePong, m.ID, proto.Pong{TS: p.TS}); err != nil {
					return err
				}
			case proto.TypePong:
				awaitingPong = false
				misses = 0
				if !lastPingSent.IsZero() {
					slog.Debug("agent: heartbeat rtt", "rtt", time.Since(lastPingSent))
				}
			case proto.TypeEvicted:
				ev, _ := proto.Decode[proto.Evicted](m)
				a.setEvicted(ev.Hostname)
				return fmt.Errorf("agent: evicted: %s (%s)", ev.Hostname, ev.Reason)
			case proto.TypeGoodbye:
				gb, _ := proto.Decode[proto.Goodbye](m)
				if gb.Reason == proto.GoodbyeReasonCredentialInactive {
					return fmt.Errorf("%w: %s", errFatalHandshake, gb.Reason)
				}
				return errEdgeGoodbye
			case proto.TypeShareEvent:
				ev, err := proto.Decode[proto.ShareEvent](m)
				if err != nil {
					return fmt.Errorf("agent: malformed share event: %w", err)
				}
				a.deliverShareEvent(ev)
				if ev.Event == proto.ShareEventClosed {
					switch ev.Reason {
					case proto.ShareReasonExpired:
						return fmt.Errorf("%w: %w", errFatalHandshake, ErrShareExpired)
					case proto.ShareReasonIdle:
						return fmt.Errorf("%w: %w", errFatalHandshake, ErrShareIdle)
					case proto.ShareReasonRevoked:
						return fmt.Errorf("%w: %w", errFatalHandshake, ErrShareRevoked)
					}
					return fmt.Errorf("agent: share closed by edge: %s", ev.Reason)
				}
			case proto.TypeApproveOK, proto.TypeKickOK, proto.TypeShareOK, proto.TypeShareErr:
				// Replies to management requests sent from the sharer's
				// terminal; failures are reported there, not fatal here.
				if _, ok := a.isMgmtReply(m.ID); ok {
					if m.Type == proto.TypeShareErr {
						e, _ := proto.Decode[proto.ShareErr](m)
						a.deliverShareEvent(proto.ShareEvent{Event: "error", AtMS: time.Now().UnixMilli(), Reason: e.Code + ": " + e.Message})
					}
				}
			case proto.TypeError:
				e, _ := proto.Decode[proto.Error](m)
				if _, ok := a.isMgmtReply(m.ID); ok {
					a.deliverShareEvent(proto.ShareEvent{Event: "error", AtMS: time.Now().UnixMilli(), Reason: e.Code + ": " + e.Message})
					continue
				}
				return fmt.Errorf("agent: edge protocol error: %s: %s", e.Code, e.Message)
			default:
				slog.Warn("agent: unexpected control message", "type", m.Type)
			}
		case <-ticker.C:
			if awaitingPong {
				misses++
				if misses >= heartbeatMisses {
					return errors.New("agent: edge heartbeat missed 3x")
				}
			}
			lastPingSent = time.Now()
			if err := ctrl.Write(proto.TypePing, idgen.Next(), proto.Ping{TS: lastPingSent.UnixMilli()}); err != nil {
				return err
			}
			awaitingPong = true
		}
	}
}

func Verify(ctx context.Context, cfg Config) error {
	a := New(cfg)
	modes, err := transportModes(cfg.Transport)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	var lastErr error
	for i, mode := range modes {
		sess, dialErr := dialControlSession(ctx, cfg, mode)
		if dialErr != nil {
			lastErr = dialErr
			continue
		}
		idgen := proto.NewAgentIDGen()
		release := guardHandshake(ctx, sess)
		_, authErrValue := a.authenticate(sess, idgen)
		release()
		if authErrValue == nil {
			a.sendGoodbye(sess, idgen, "verify done")
			sess.Close("verify done")
			return nil
		}
		sess.Close("verify failed")
		var ae *authErr
		if errors.As(authErrValue, &ae) && ae.code == proto.CodeBadToken {
			return fmt.Errorf("%w: %s", ErrBadToken, ae.message)
		}
		lastErr = authErrValue
		if errors.Is(authErrValue, errFatalHandshake) || i == len(modes)-1 {
			return authErrValue
		}
	}
	return fmt.Errorf("%w: %v", ErrUnreachable, lastErr)
}
