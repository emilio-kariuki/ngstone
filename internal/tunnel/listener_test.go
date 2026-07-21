package tunnel

import (
	"context"
	"net"
	"testing"
	"time"

	"ngstone/internal/proto"
)

func TestListenerRemoteAddrFromPreamble(t *testing.T) {
	client, server := newSessionPair(t)
	defer client.Close("test done")
	defer server.Close("test done")

	ln, err := NewListener(server)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	pre := proto.StreamOpen{
		Kind:       proto.KindHTTP,
		Host:       "a.example.com",
		ReqID:      "r1",
		ClientAddr: "203.0.113.5:4111",
	}

	openErrCh := make(chan error, 1)
	go func() {
		_, err := client.OpenStream(context.Background(), pre)
		openErrCh <- err
	}()

	acceptedCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			acceptedCh <- c
		}
	}()

	select {
	case c := <-acceptedCh:
		defer c.Close()
		if got := c.RemoteAddr().String(); got != "203.0.113.5:4111" {
			t.Fatalf("RemoteAddr = %q, want %q", got, "203.0.113.5:4111")
		}
		sc, ok := c.(*streamConn)
		if !ok {
			t.Fatalf("conn is %T, want *streamConn", c)
		}
		if sc.Preamble() != pre {
			t.Fatalf("Preamble() = %+v, want %+v", sc.Preamble(), pre)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener never accepted the stream")
	}

	if err := <-openErrCh; err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
}

func TestListenerSilentStreamDoesNotBlockOthers(t *testing.T) {
	client, server := newSessionPair(t)
	defer client.Close("test done")
	defer server.Close("test done")

	ln, err := NewListener(server)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	cs, ok := client.(*session)
	if !ok {
		t.Fatalf("client is %T, want *session", client)
	}
	silent, err := cs.ys.OpenStream()
	if err != nil {
		t.Fatalf("open silent stream: %v", err)
	}
	defer silent.Close()

	pre := proto.StreamOpen{
		Kind:       proto.KindHTTP,
		Host:       "good.example.com",
		ReqID:      "r2",
		ClientAddr: "10.0.0.1:1",
	}
	openErrCh := make(chan error, 1)
	go func() {
		_, err := client.OpenStream(context.Background(), pre)
		openErrCh <- err
	}()

	acceptedCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			acceptedCh <- c
		}
	}()

	select {
	case c := <-acceptedCh:
		defer c.Close()
		sc, ok := c.(*streamConn)
		if !ok {
			t.Fatalf("conn is %T, want *streamConn", c)
		}
		if sc.Preamble().Host != "good.example.com" {
			t.Fatalf("accepted wrong stream: %+v", sc.Preamble())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("well-formed stream was blocked by the silent (no-preamble) stream")
	}

	if err := <-openErrCh; err != nil {
		t.Fatalf("OpenStream (good): %v", err)
	}
}

func TestListenerClosesSilentStreamAfterPreambleDeadline(t *testing.T) {
	client, server := newSessionPair(t)
	defer client.Close("test done")
	defer server.Close("test done")

	ln, err := NewListener(server)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	cs, ok := client.(*session)
	if !ok {
		t.Fatalf("client is %T, want *session", client)
	}
	silent, err := cs.ys.OpenStream()
	if err != nil {
		t.Fatalf("open silent stream: %v", err)
	}
	defer silent.Close()

	if err := silent.SetReadDeadline(time.Now().Add(preambleDeadline + 3*time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	start := time.Now()
	buf := make([]byte, 1)
	_, err = silent.Read(buf)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected the silent (no-preamble) stream to be closed by the listener, got no error")
	}
	if elapsed > preambleDeadline+2*time.Second {
		t.Fatalf("silent stream took %v to close, want close within ~%v of the preamble deadline", elapsed, preambleDeadline)
	}
}
