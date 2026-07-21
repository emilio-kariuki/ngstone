package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"testing"
	"time"

	"ngstone/internal/edge"
)

func freeTCPAddrForVerifyTest(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func startVerifyTestEdge(t *testing.T, token string) string {
	t.Helper()
	controlAddr := freeTCPAddrForVerifyTest(t)
	publicAddr := freeTCPAddrForVerifyTest(t)
	sum := sha256.Sum256([]byte(token))

	s, err := edge.New(edge.Config{
		ControlAddr:  controlAddr,
		PublicAddr:   publicAddr,
		Domain:       "example.com",
		TokenSHA256:  sum[:],
		PublicScheme: "http",
		Insecure:     true,
	})
	if err != nil {
		t.Fatalf("edge.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-runErrCh
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", controlAddr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return controlAddr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("edge control listener never came up on %s", controlAddr)
	return ""
}

func TestVerifySucceedsWithGoodToken(t *testing.T) {
	controlAddr := startVerifyTestEdge(t, "correct-token")

	err := Verify(context.Background(), Config{
		ControlAddr: controlAddr,
		Token:       "correct-token",
		Insecure:    true,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyReturnsBadTokenError(t *testing.T) {
	controlAddr := startVerifyTestEdge(t, "correct-token")

	err := Verify(context.Background(), Config{
		ControlAddr: controlAddr,
		Token:       "wrong-token",
		Insecure:    true,
	})
	if err == nil {
		t.Fatalf("expected an error for a wrong token")
	}
	if !errors.Is(err, ErrBadToken) {
		t.Fatalf("Verify error = %v, want errors.Is(err, ErrBadToken)", err)
	}
	if errors.Is(err, ErrUnreachable) {
		t.Fatalf("Verify error = %v, must not also look unreachable", err)
	}
}

func TestVerifyReturnsUnreachableWhenNothingListening(t *testing.T) {
	addr := freeTCPAddrForVerifyTest(t)

	err := Verify(context.Background(), Config{
		ControlAddr: addr,
		Token:       "whatever",
		Insecure:    true,
	})
	if err == nil {
		t.Fatalf("expected an error when nothing is listening")
	}
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("Verify error = %v, want errors.Is(err, ErrUnreachable)", err)
	}
	if errors.Is(err, ErrBadToken) {
		t.Fatalf("Verify error = %v, must not also look like a bad token", err)
	}
}
