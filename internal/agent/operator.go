package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

// Operator runs one-shot share management calls from a fresh operator
// session: list, revoke, extend, kick, and a watch loop. It is what
// `ngstone shares`, `ngstone unshare`, `ngstone extend` and `ngstone kick`
// use, so a share started in one terminal can be managed from another.
type Operator struct {
	cfg Config
}

func NewOperator(cfg Config) *Operator {
	return &Operator{cfg: cfg}
}

var ErrShareNotFound = errors.New("agent: no such live share")

// session dials, authenticates and returns the live session; the caller
// says goodbye and closes it.
func (o *Operator) session(ctx context.Context) (tunnel.Session, *proto.IDGen, error) {
	conn, err := dialControl(ctx, o.cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	sess, err := tunnel.Client(conn)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	a := New(o.cfg)
	idgen := proto.NewAgentIDGen()
	release := guardHandshake(ctx, sess)
	negotiated, err := a.authenticate(sess, idgen)
	release()
	if err != nil {
		sess.Close("operator auth failed")
		var ae *authErr
		if errors.As(err, &ae) && ae.code == proto.CodeBadToken {
			return nil, nil, fmt.Errorf("%w: %s", ErrBadToken, ae.message)
		}
		return nil, nil, err
	}
	if negotiated < 3 {
		sess.Close("operator: no v3")
		return nil, nil, fmt.Errorf("this edge does not support sharing (negotiated protocol v%d); upgrade ngstoned", negotiated)
	}
	return sess, idgen, nil
}

// call sends one request and returns its reply, skipping any pings the
// edge interleaves.
func call(ctx context.Context, sess tunnel.Session, idgen *proto.IDGen, typ string, data any) (proto.Msg, error) {
	ctrl := sess.Control()
	id := idgen.Next()
	if err := ctrl.Write(typ, id, data); err != nil {
		return proto.Msg{}, err
	}
	deadline := time.Now().Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = ctrl.SetReadDeadline(deadline)
	defer ctrl.SetReadDeadline(time.Time{})
	for {
		m, err := ctrl.Read()
		if err != nil {
			return proto.Msg{}, err
		}
		if m.Type == proto.TypePing {
			p, _ := proto.Decode[proto.Ping](m)
			_ = ctrl.Write(proto.TypePong, m.ID, proto.Pong{TS: p.TS})
			continue
		}
		if m.ID != id {
			continue
		}
		return m, nil
	}
}

func replyError(m proto.Msg) error {
	switch m.Type {
	case proto.TypeError:
		e, _ := proto.Decode[proto.Error](m)
		if e.Code == proto.CodeShareNotFound {
			return ErrShareNotFound
		}
		return fmt.Errorf("edge: %s: %s", e.Code, e.Message)
	case proto.TypeShareErr:
		e, _ := proto.Decode[proto.ShareErr](m)
		if e.Code == proto.CodeShareNotFound {
			return ErrShareNotFound
		}
		return fmt.Errorf("edge: %s: %s", e.Code, e.Message)
	}
	return nil
}

func (o *Operator) once(ctx context.Context, typ string, data any) (proto.Msg, error) {
	sess, idgen, err := o.session(ctx)
	if err != nil {
		return proto.Msg{}, err
	}
	defer sess.Close("operator done")
	m, err := call(ctx, sess, idgen, typ, data)
	if err != nil {
		return proto.Msg{}, err
	}
	_ = sess.Control().Write(proto.TypeGoodbye, idgen.Next(), proto.Goodbye{Reason: "done"})
	if err := replyError(m); err != nil {
		return m, err
	}
	return m, nil
}

// ListShares returns every live share on the edge.
func (o *Operator) ListShares(ctx context.Context) ([]proto.ShareInfo, error) {
	m, err := o.once(ctx, proto.TypeListShares, proto.ListShares{})
	if err != nil {
		return nil, err
	}
	ok, err := proto.Decode[proto.SharesOK](m)
	if err != nil {
		return nil, err
	}
	return ok.Shares, nil
}

// Unshare revokes a share by id.
func (o *Operator) Unshare(ctx context.Context, shareID string) error {
	_, err := o.once(ctx, proto.TypeUnshare, proto.Unshare{ShareID: shareID})
	return err
}

// Extend moves a share's expiry and returns the new deadline.
func (o *Operator) Extend(ctx context.Context, shareID string, until time.Time) (time.Time, error) {
	m, err := o.once(ctx, proto.TypeShareUpdate, proto.ShareUpdate{ShareID: shareID, ExpiresAtMS: until.UnixMilli()})
	if err != nil {
		return time.Time{}, err
	}
	ok, err := proto.Decode[proto.ShareOK](m)
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMilli(ok.ExpiresAtMS), nil
}

// Kick removes one connector from a share.
func (o *Operator) Kick(ctx context.Context, shareID, connectorID string) error {
	_, err := o.once(ctx, proto.TypeKick, proto.Kick{ShareID: shareID, ConnectorID: connectorID})
	return err
}

// Watch streams every share's audit events to fn until ctx ends or the
// session drops.
func (o *Operator) Watch(ctx context.Context, fn func(proto.ShareEvent)) error {
	sess, idgen, err := o.session(ctx)
	if err != nil {
		return err
	}
	defer sess.Close("watch done")
	if m, err := call(ctx, sess, idgen, proto.TypeWatchShares, proto.WatchShares{}); err != nil {
		return err
	} else if err := replyError(m); err != nil {
		return err
	}

	ctrl := sess.Control()
	type readResult struct {
		msg proto.Msg
		err error
	}
	msgCh := make(chan readResult, 1)
	go func() {
		for {
			m, err := ctrl.Read()
			msgCh <- readResult{m, err}
			if err != nil {
				return
			}
		}
	}()
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = ctrl.Write(proto.TypeGoodbye, idgen.Next(), proto.Goodbye{Reason: "done"})
			return nil
		case <-sess.Done():
			return errors.New("agent: edge closed the session")
		case <-ticker.C:
			_ = ctrl.Write(proto.TypePing, idgen.Next(), proto.Ping{TS: time.Now().UnixMilli()})
		case rr := <-msgCh:
			if rr.err != nil {
				return rr.err
			}
			switch rr.msg.Type {
			case proto.TypePing:
				p, _ := proto.Decode[proto.Ping](rr.msg)
				_ = ctrl.Write(proto.TypePong, rr.msg.ID, proto.Pong{TS: p.TS})
			case proto.TypeShareEvent:
				ev, err := proto.Decode[proto.ShareEvent](rr.msg)
				if err == nil {
					fn(ev)
				}
			case proto.TypeGoodbye:
				return errEdgeGoodbye
			}
		}
	}
}
