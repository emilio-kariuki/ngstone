package tunnel

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"ngstone/internal/proto"
)

func newSessionPair(t *testing.T) (Session, Session) {
	t.Helper()
	c1, c2 := net.Pipe()

	type result struct {
		sess Session
		err  error
	}
	clientCh := make(chan result, 1)
	serverCh := make(chan result, 1)
	go func() {
		s, err := Client(c1)
		clientCh <- result{s, err}
	}()
	go func() {
		s, err := Server(c2)
		serverCh <- result{s, err}
	}()

	cr := <-clientCh
	if cr.err != nil {
		t.Fatalf("client session: %v", cr.err)
	}
	sr := <-serverCh
	if sr.err != nil {
		t.Fatalf("server session: %v", sr.err)
	}
	return cr.sess, sr.sess
}

func TestSessionControlRoundTrip(t *testing.T) {
	client, server := newSessionPair(t)
	defer client.Close("test done")
	defer server.Close("test done")

	go func() {
		client.Control().Write(proto.TypeAuth, 1, proto.Auth{Token: "tok", InstanceID: "abc"})
	}()

	msg, err := server.Control().Read()
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if msg.Type != proto.TypeAuth {
		t.Fatalf("got type %q, want %q", msg.Type, proto.TypeAuth)
	}
	auth, err := proto.Decode[proto.Auth](msg)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if auth.Token != "tok" || auth.InstanceID != "abc" {
		t.Fatalf("auth mismatch: %+v", auth)
	}

	if err := server.Control().Write(proto.TypeAuthOK, msg.ID, proto.AuthOK{ProtoVersion: 1}); err != nil {
		t.Fatalf("server write: %v", err)
	}
	reply, err := client.Control().Read()
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if reply.Type != proto.TypeAuthOK || reply.ID != msg.ID {
		t.Fatalf("reply mismatch: %+v", reply)
	}
}

func TestOpenAcceptStreamPreambleRoundTrip(t *testing.T) {
	client, server := newSessionPair(t)
	defer client.Close("test done")
	defer server.Close("test done")

	pre := proto.StreamOpen{
		Kind:       proto.KindHTTP,
		Host:       "x.example.com",
		ReqID:      "r1",
		ClientAddr: "1.2.3.4:5",
	}

	openErrCh := make(chan error, 1)
	var clientConn net.Conn
	go func() {
		var err error
		clientConn, err = client.OpenStream(context.Background(), pre)
		openErrCh <- err
	}()

	serverConn, err := server.AcceptRaw(context.Background())
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer serverConn.Close()

	gotPre, err := readPreamble(serverConn)
	if err != nil {
		t.Fatalf("readPreamble: %v", err)
	}

	if err := <-openErrCh; err != nil {
		t.Fatalf("open: %v", err)
	}
	defer clientConn.Close()

	if gotPre != pre {
		t.Fatalf("preamble mismatch: got %+v want %+v", gotPre, pre)
	}

	go clientConn.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(serverConn, buf); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("body mismatch: %q", buf)
	}
}

func TestOpenStreamCancelledContextReturnsPromptlyAndDoesNotLeak(t *testing.T) {
	client, server := newSessionPair(t)
	defer client.Close("test done")
	defer server.Close("test done")

	acceptedCh := make(chan struct{}, 4)
	go func() {
		for {
			conn, err := server.AcceptRaw(context.Background())
			if err != nil {
				select {
				case <-server.Done():
					return
				default:
					continue
				}
			}
			conn.Close()
			acceptedCh <- struct{}{}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := client.OpenStream(ctx, proto.StreamOpen{Kind: proto.KindHTTP, Host: "x"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error opening a stream with an already-cancelled context")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("OpenStream with cancelled ctx took too long: %v", elapsed)
	}

	conn2, err := client.OpenStream(context.Background(), proto.StreamOpen{Kind: proto.KindHTTP, Host: "y"})
	if err != nil {
		t.Fatalf("follow-up OpenStream failed (possible SYN slot leak): %v", err)
	}
	defer conn2.Close()

	select {
	case <-acceptedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("follow-up stream was never accepted (possible leak from the cancelled open)")
	}
}
