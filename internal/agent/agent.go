package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

const (
	reconnectBase = 500 * time.Millisecond
	reconnectCap  = 30 * time.Second

	heartbeatInterval = 15 * time.Second
	heartbeatMisses   = 3

	drainTimeout = 15 * time.Second
)

var errFatalHandshake = errors.New("agent: fatal handshake error")
var errEdgeGoodbye = errors.New("agent: edge said goodbye")

type Config struct {
	ControlAddr string
	Token       string
	Subdomain   string
	TargetURL   string

	InstanceID string
}

type Status struct {
	Hostname string
	URL      string
	Evicted  bool
}

type Agent struct {
	cfg        Config
	instanceID string

	mu     sync.Mutex
	status Status
}

func New(cfg Config) *Agent {
	id := cfg.InstanceID
	if id == "" {
		id = randomHex(16)
	}
	return &Agent{cfg: cfg, instanceID: id}
}

func (a *Agent) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.status
}

func (a *Agent) setBound(hostname, url string) {
	a.mu.Lock()
	a.status = Status{Hostname: hostname, URL: url}
	a.mu.Unlock()
	slog.Info("agent: bound", "hostname", hostname, "url", url)
}

func (a *Agent) setEvicted(hostname string) {
	a.mu.Lock()
	a.status.Evicted = true
	a.mu.Unlock()
	slog.Warn("agent: tunnel evicted, no longer advertising", "hostname", hostname)
}

func (a *Agent) Run(ctx context.Context) error {
	bo := newBackoff(reconnectBase, reconnectCap)

	for {
		if ctx.Err() != nil {
			return nil
		}

		err := a.runOnce(ctx, bo)

		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, errFatalHandshake) {
			return err
		}
		if err != nil {
			slog.Warn("agent: connection lost, will reconnect", "err", err)
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
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", a.cfg.ControlAddr)
	if err != nil {
		return fmt.Errorf("agent: dial control: %w", err)
	}

	sess, err := tunnel.Client(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("agent: session: %w", err)
	}
	defer sess.Close("agent session ended")

	idgen := proto.NewAgentIDGen()

	bindOK, err := a.handshake(sess, idgen)
	if err != nil {
		return err
	}
	a.setBound(bindOK.Hostname, bindOK.URL)
	bo.reset()

	ln, err := tunnel.NewListener(sess)
	if err != nil {
		return err
	}
	defer ln.Close()

	target, err := url.Parse(a.cfg.TargetURL)
	if err != nil {
		return fmt.Errorf("agent: parse target: %w", err)
	}

	handler, transport := a.buildProxy(target)
	defer transport.CloseIdleConnections()
	srv := &http.Server{Handler: handler}

	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- srv.Serve(ln) }()

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

func (a *Agent) handshake(sess tunnel.Session, idgen *proto.IDGen) (proto.BindOK, error) {
	ctrl := sess.Control()

	authID := idgen.Next()
	if err := ctrl.Write(proto.TypeAuth, authID, proto.Auth{
		Token:         a.cfg.Token,
		InstanceID:    a.instanceID,
		ClientVersion: "ngstone/m2",
		ProtoVersions: []int{proto.ProtoVersion},
	}); err != nil {
		return proto.BindOK{}, err
	}
	msg, err := ctrl.Read()
	if err != nil {
		return proto.BindOK{}, err
	}
	switch msg.Type {
	case proto.TypeAuthErr:
		e, _ := proto.Decode[proto.AuthErr](msg)
		return proto.BindOK{}, fmt.Errorf("%w: auth failed: %s: %s", errFatalHandshake, e.Code, e.Message)
	case proto.TypeAuthOK:
	default:
		return proto.BindOK{}, fmt.Errorf("agent: unexpected reply %q to auth", msg.Type)
	}

	bindID := idgen.Next()
	if err := ctrl.Write(proto.TypeBind, bindID, proto.Bind{
		Kind:      proto.KindHTTP,
		Subdomain: a.cfg.Subdomain,
		Takeover:  true,
	}); err != nil {
		return proto.BindOK{}, err
	}
	msg, err = ctrl.Read()
	if err != nil {
		return proto.BindOK{}, err
	}
	switch msg.Type {
	case proto.TypeBindErr:
		e, _ := proto.Decode[proto.BindErr](msg)
		if e.Code == proto.CodeInvalidSubdomain || e.Code == proto.CodeKindUnsupported {
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
				return errEdgeGoodbye
			case proto.TypeError:
				e, _ := proto.Decode[proto.Error](m)
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
