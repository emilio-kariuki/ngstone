package edge

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"testing"
	"testing/iotest"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

func realClientCapture(t *testing.T, typ string, data any) (captured []byte, secret string, ok bool) {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	errCh := make(chan error, 1)
	go func() {
		sess, err := tunnel.Client(c1)
		if err != nil {
			errCh <- err
			return
		}
		errCh <- sess.Control().Write(typ, 1, data)
	}()
	c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	captured, secret, ok = sniffShareSecret(c2)
	if err := <-errCh; err != nil {
		t.Fatalf("client write: %v", err)
	}
	return captured, secret, ok
}

func testShareAuth() proto.Auth {
	return proto.Auth{ShareSecret: "s3cret", InstanceID: "i", ClientVersion: "v", ProtoVersions: []int{3, 2, 1}}
}

func yamuxHdr(typ byte, flags uint16, stream, length uint32) []byte {
	h := make([]byte, 12)
	h[1] = typ
	binary.BigEndian.PutUint16(h[2:4], flags)
	binary.BigEndian.PutUint32(h[4:8], stream)
	binary.BigEndian.PutUint32(h[8:12], length)
	return h
}

func protoFrameBytes(t *testing.T, typ string, data any) []byte {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := proto.WriteMsg(&buf, proto.Msg{Type: typ, ID: 1, Data: raw}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func dataFrame(stream uint32, payload []byte) []byte {
	return append(yamuxHdr(0, 0, stream, uint32(len(payload))), payload...)
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestSniffShareSecret(t *testing.T) {
	captured, secret, ok := realClientCapture(t, proto.TypeAuth, testShareAuth())
	if !ok || secret != "s3cret" {
		t.Fatalf("sniff = ok %v secret %q, want ok with s3cret", ok, secret)
	}

	trailer := []byte("trailing-bytes-after-auth")
	stream := append(append([]byte{}, captured...), trailer...)
	cr := &countingReader{r: bytes.NewReader(stream)}
	got, secret, ok := sniffShareSecret(cr)
	if !ok || secret != "s3cret" {
		t.Fatalf("sniff of replay = ok %v secret %q", ok, secret)
	}
	if !bytes.Equal(got, captured) {
		t.Fatalf("captured %d bytes, want exactly %d", len(got), len(captured))
	}
	if cr.n != len(captured) {
		t.Fatalf("read %d bytes, want %d (no read-ahead)", cr.n, len(captured))
	}

	slow, secret, ok := sniffShareSecret(iotest.OneByteReader(bytes.NewReader(stream)))
	if !ok || secret != "s3cret" || !bytes.Equal(slow, captured) {
		t.Fatalf("one-byte sniff = ok %v secret %q captured-equal %v", ok, secret, bytes.Equal(slow, captured))
	}

	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	type result struct {
		msg proto.Msg
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		sess, err := tunnel.Server(p2)
		if err != nil {
			resCh <- result{err: err}
			return
		}
		defer sess.Close("test done")
		msg, err := sess.Control().Read()
		resCh <- result{msg: msg, err: err}
	}()
	go io.Copy(io.Discard, p1)
	go p1.Write(captured)
	var res result
	select {
	case res = <-resCh:
	case <-time.After(5 * time.Second):
		t.Fatal("replayed bytes did not reach the tunnel server")
	}
	if res.err != nil {
		t.Fatalf("server read: %v", res.err)
	}
	auth, err := proto.Decode[proto.Auth](res.msg)
	if err != nil || auth.ShareSecret != "s3cret" || res.msg.Type != proto.TypeAuth {
		t.Fatalf("replayed auth = %+v err %v type %q", auth, err, res.msg.Type)
	}
}

func TestSniffRejectsTokenAuth(t *testing.T) {
	captured, secret, ok := realClientCapture(t, proto.TypeAuth, proto.Auth{Token: "tok", InstanceID: "i", ClientVersion: "v", ProtoVersions: []int{3}})
	if ok || secret != "" {
		t.Fatalf("token auth: ok %v secret %q", ok, secret)
	}
	if len(captured) == 0 {
		t.Fatal("captured must hold every consumed byte")
	}
	both := testShareAuth()
	both.Token = "tok"
	_, secret, ok = realClientCapture(t, proto.TypeAuth, both)
	if ok || secret != "" {
		t.Fatalf("token plus share secret: ok %v secret %q", ok, secret)
	}
}

func TestSniffRejectsNonAuthFirstFrame(t *testing.T) {
	_, secret, ok := realClientCapture(t, proto.TypeListShares, map[string]string{"share_secret": "s3cret"})
	if ok || secret != "" {
		t.Fatalf("non-auth first frame: ok %v secret %q", ok, secret)
	}
}

func TestSniffCap(t *testing.T) {
	var pings bytes.Buffer
	for i := 0; i < 4000; i++ {
		pings.Write(yamuxHdr(2, 1, 0, uint32(i)))
	}
	pings.Write(dataFrame(1, protoFrameBytes(t, proto.TypeAuth, testShareAuth())))
	cr := &countingReader{r: &pings}
	captured, _, ok := sniffShareSecret(cr)
	if ok {
		t.Fatal("ping flood followed by auth must not be accepted past the cap")
	}
	if len(captured) > maxControlSniff || cr.n > maxControlSniff {
		t.Fatalf("captured %d, read %d, cap %d", len(captured), cr.n, maxControlSniff)
	}

	big := append(yamuxHdr(0, 0, 1, maxControlSniff+1), make([]byte, maxControlSniff+1)...)
	captured, _, ok = sniffShareSecret(bytes.NewReader(big))
	if ok || len(captured) > maxControlSniff {
		t.Fatalf("oversized data frame: ok %v captured %d", ok, len(captured))
	}
}

func TestSniffRejectsOtherStream(t *testing.T) {
	frame := dataFrame(3, protoFrameBytes(t, proto.TypeAuth, testShareAuth()))
	_, secret, ok := sniffShareSecret(bytes.NewReader(frame))
	if ok || secret != "" {
		t.Fatalf("auth on stream 3: ok %v secret %q", ok, secret)
	}
	win := yamuxHdr(1, 1, 3, 100)
	_, _, ok = sniffShareSecret(bytes.NewReader(append(win, dataFrame(1, protoFrameBytes(t, proto.TypeAuth, testShareAuth()))...)))
	if ok {
		t.Fatal("window update on stream 3 must be rejected")
	}
}

func TestSniffRejectsOversizedProtoFrame(t *testing.T) {
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint32(prefix, proto.MaxFrameSize+1)
	cr := &countingReader{r: bytes.NewReader(append(dataFrame(1, prefix), make([]byte, 1<<20)...))}
	captured, _, ok := sniffShareSecret(cr)
	if ok {
		t.Fatal("oversized proto frame must be rejected")
	}
	if len(captured) != 12+4 || cr.n != 12+4 {
		t.Fatalf("captured %d read %d, want %d", len(captured), cr.n, 12+4)
	}
}
