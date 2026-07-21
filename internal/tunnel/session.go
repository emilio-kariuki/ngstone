package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/hashicorp/yamux"

	"ngstone/internal/proto"
)

const preambleDeadline = 5 * time.Second

var ErrSessionClosed = errors.New("tunnel: session closed")

type Session interface {
	OpenStream(ctx context.Context, pre proto.StreamOpen) (net.Conn, error)
	AcceptRaw(ctx context.Context) (net.Conn, error)
	Control() *proto.Conn
	Done() <-chan struct{}
	Close(reason string) error
}

type session struct {
	ys      *yamux.Session
	control *proto.Conn
}

func Client(nc net.Conn) (Session, error) {
	ys, err := yamux.Client(nc, newYamuxConfig())
	if err != nil {
		return nil, err
	}
	ctrl, err := ys.OpenStream()
	if err != nil {
		ys.Close()
		return nil, err
	}
	return &session{ys: ys, control: proto.NewConn(ctrl)}, nil
}

func Server(nc net.Conn) (Session, error) {
	ys, err := yamux.Server(nc, newYamuxConfig())
	if err != nil {
		return nil, err
	}
	ctrl, err := ys.AcceptStream()
	if err != nil {
		ys.Close()
		return nil, err
	}
	return &session{ys: ys, control: proto.NewConn(ctrl)}, nil
}

func (s *session) OpenStream(ctx context.Context, pre proto.StreamOpen) (net.Conn, error) {
	type result struct {
		stream *yamux.Stream
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		st, err := s.ys.OpenStream()
		if err != nil {
			ch <- result{nil, err}
			return
		}
		data, err := json.Marshal(pre)
		if err != nil {
			st.Close()
			ch <- result{nil, err}
			return
		}
		if err := st.SetWriteDeadline(time.Now().Add(preambleDeadline)); err != nil {
			st.Close()
			ch <- result{nil, err}
			return
		}
		if err := proto.WriteMsg(st, proto.Msg{Type: proto.TypeStreamOpen, Data: data}); err != nil {
			st.Close()
			ch <- result{nil, err}
			return
		}
		if err := st.SetWriteDeadline(time.Time{}); err != nil {
			st.Close()
			ch <- result{nil, err}
			return
		}
		ch <- result{st, nil}
	}()

	drainLate := func() {
		go func() {
			r := <-ch
			if r.err == nil {
				r.stream.Close()
			}
		}()
	}

	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		return r.stream, nil
	case <-ctx.Done():
		drainLate()
		return nil, ctx.Err()
	case <-s.ys.CloseChan():
		drainLate()
		return nil, ErrSessionClosed
	}
}

func (s *session) AcceptRaw(ctx context.Context) (net.Conn, error) {
	return s.ys.AcceptStreamWithContext(ctx)
}

func (s *session) Control() *proto.Conn {
	return s.control
}

func (s *session) Done() <-chan struct{} {
	return s.ys.CloseChan()
}

func (s *session) Close(reason string) error {
	slog.Debug("tunnel: closing session", "reason", reason)
	return s.ys.Close()
}

func readPreamble(stream net.Conn) (proto.StreamOpen, error) {
	if err := stream.SetReadDeadline(time.Now().Add(preambleDeadline)); err != nil {
		return proto.StreamOpen{}, err
	}
	m, err := proto.ReadMsg(stream)
	if err != nil {
		return proto.StreamOpen{}, err
	}
	if m.Type != proto.TypeStreamOpen {
		return proto.StreamOpen{}, fmt.Errorf("tunnel: unexpected preamble type %q", m.Type)
	}
	pre, err := proto.Decode[proto.StreamOpen](m)
	if err != nil {
		return proto.StreamOpen{}, err
	}
	if pre.Kind == "" || pre.Host == "" {
		return proto.StreamOpen{}, errors.New("tunnel: preamble missing kind or host")
	}
	if err := stream.SetReadDeadline(time.Time{}); err != nil {
		return proto.StreamOpen{}, err
	}
	return pre, nil
}
