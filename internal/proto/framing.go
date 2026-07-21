package proto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const MaxFrameSize = 64 << 10

var (
	ErrFrameTooLarge = errors.New("proto: frame exceeds max size")
	ErrEmptyFrame    = errors.New("proto: empty frame")
	ErrNoPayload     = errors.New("proto: message has no payload")
)

func WriteMsg(w io.Writer, m Msg) error {
	payload, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(payload)))
	copy(buf[4:], payload)
	_, err = w.Write(buf)
	return err
}

func ReadMsg(r io.Reader) (Msg, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Msg{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return Msg{}, ErrEmptyFrame
	}
	if n > MaxFrameSize {
		return Msg{}, ErrFrameTooLarge
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Msg{}, err
	}
	var m Msg
	if err := json.Unmarshal(payload, &m); err != nil {
		return Msg{}, err
	}
	return m, nil
}

type Conn struct {
	nc  net.Conn
	wmu sync.Mutex
}

func NewConn(nc net.Conn) *Conn {
	return &Conn{nc: nc}
}

func (c *Conn) Read() (Msg, error) {
	return ReadMsg(c.nc)
}

func (c *Conn) Write(typ string, id uint64, data any) error {
	var raw json.RawMessage
	if data != nil {
		b, err := json.Marshal(data)
		if err != nil {
			return err
		}
		raw = b
	}
	m := Msg{Type: typ, ID: id, Data: raw}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return WriteMsg(c.nc, m)
}

func (c *Conn) Close() error {
	return c.nc.Close()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.nc.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.nc.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.nc.SetWriteDeadline(t)
}

func Decode[T any](m Msg) (T, error) {
	var v T
	if len(m.Data) == 0 || bytes.Equal(m.Data, []byte("null")) {
		return v, ErrNoPayload
	}
	err := json.Unmarshal(m.Data, &v)
	return v, err
}
