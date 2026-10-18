package edge

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"ngstone/internal/inspect"
	"ngstone/internal/proto"
	"ngstone/internal/tunnel"
)

func newFakeH2AgentSession(t *testing.T, instanceID string, handler http.Handler) *AgentSession {
	return newFakeH2AgentSessionWithCount(t, instanceID, handler, nil)
}

func newFakeH2AgentSessionWithCount(t *testing.T, instanceID string, handler http.Handler, connectionCount *atomic.Int64) *AgentSession {
	t.Helper()
	c1, c2 := net.Pipe()

	type result struct {
		sess tunnel.Session
		err  error
	}
	agentCh := make(chan result, 1)
	edgeCh := make(chan result, 1)
	go func() {
		s, err := tunnel.Client(c1)
		agentCh <- result{s, err}
	}()
	go func() {
		s, err := tunnel.Server(c2)
		edgeCh <- result{s, err}
	}()

	agentSide := <-agentCh
	if agentSide.err != nil {
		t.Fatalf("agent-side session: %v", agentSide.err)
	}
	edgeSide := <-edgeCh
	if edgeSide.err != nil {
		t.Fatalf("edge-side session: %v", edgeSide.err)
	}

	ln, err := tunnel.NewListener(agentSide.sess)
	if err != nil {
		t.Fatalf("tunnel.NewListener: %v", err)
	}
	server := &http2.Server{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if connectionCount != nil {
					connectionCount.Add(1)
				}
				server.ServeConn(conn, &http2.ServeConnOpts{Handler: handler})
				conn.Close()
			}()
		}
	}()

	t.Cleanup(func() {
		ln.Close()
		agentSide.sess.Close("test done")
		edgeSide.sess.Close("test done")
	})
	return &AgentSession{
		ID:         randomHex(4),
		InstanceID: instanceID,
		Sess:       edgeSide.sess,
		IDGen:      proto.NewEdgeIDGen(),
	}
}

func grpcFrame(payload []byte) []byte {
	frame := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	return frame
}

func readGRPCFrame(r io.Reader) ([]byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if header[0] != 0 {
		return nil, errors.New("compressed gRPC frames are not supported by this test")
	}
	size := binary.BigEndian.Uint32(header[1:5])
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func startHTTP2PublicServer(t *testing.T, s *Server) (*httptest.Server, *http.Client) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(s.handlePublic))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, server.Client()
}

func TestHTTP2BindingForwardsTrailersOverNativeStream(t *testing.T) {
	as := newFakeH2AgentSession(t, "h2-instance", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("request protocol = %s, want HTTP/2", r.Proto)
		}
		if r.Header.Get(inspect.RequestIDHeader) == "" || r.Header.Get(inspect.ClientAddrHeader) != "203.0.113.20:4321" {
			t.Errorf("request metadata headers = %v, want per-request edge metadata", r.Header)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			return
		}
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
		w.Header().Set("Grpc-Status", "0")
	}))
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "grpc.example.com", Session: as, Takeover: true, HTTP2: true}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	t.Cleanup(func() { s.registry.ReleaseSession(as) })

	req := httptest.NewRequest(http.MethodPost, "http://grpc.example.com/test.Service/Call", strings.NewReader("request"))
	req.Host = "grpc.example.com"
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.RemoteAddr = "203.0.113.20:4321"
	rec := httptest.NewRecorder()
	s.handlePublic(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "request" {
		t.Fatalf("body = %q, want request", got)
	}
	if got := rec.Result().Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("Grpc-Status trailer = %q, want 0; headers=%v trailer=%v", got, rec.Header(), rec.Result().Trailer)
	}
}

func TestNativeGRPCTrailersLargeMessagesAndConnectionReuse(t *testing.T) {
	var connectionCount atomic.Int64
	as := newFakeH2AgentSessionWithCount(t, "h2-instance", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/grpc" {
			t.Errorf("content type = %q, want application/grpc", r.Header.Get("Content-Type"))
		}
		payload, err := readGRPCFrame(r.Body)
		if err != nil {
			t.Errorf("read gRPC frame: %v", err)
			return
		}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("drain gRPC request: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "grpc-status")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(grpcFrame(payload)); err != nil {
			t.Errorf("write gRPC response: %v", err)
			return
		}
		w.Header().Set("grpc-status", "0")
	}), &connectionCount)
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "grpc.example.com", Session: as, Takeover: true, HTTP2: true}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	t.Cleanup(func() { s.registry.ReleaseSession(as) })
	public, client := startHTTP2PublicServer(t, s)

	payloads := [][]byte{
		bytes.Repeat([]byte("g"), 2<<20),
		[]byte("second request"),
	}
	for i, payload := range payloads {
		req, err := http.NewRequest(http.MethodPost, public.URL+"/test.Service/Call", bytes.NewReader(grpcFrame(payload)))
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		req.Host = "grpc.example.com"
		req.Header.Set("Content-Type", "application/grpc")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("read response %d: %v", i+1, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("response %d status = %d, want 200", i+1, resp.StatusCode)
		}
		if !bytes.Equal(body, grpcFrame(payload)) {
			t.Fatalf("response %d body length = %d, want %d", i+1, len(body), len(grpcFrame(payload)))
		}
		if got := resp.Trailer.Get("grpc-status"); got != "0" {
			t.Fatalf("response %d grpc-status = %q, want 0", i+1, got)
		}
	}
	if got := connectionCount.Load(); got != 1 {
		t.Fatalf("backend HTTP/2 connections = %d, want one reused connection", got)
	}
}

func TestNativeGRPCBidirectionalStreaming(t *testing.T) {
	as := newFakeH2AgentSession(t, "h2-instance", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "grpc-status")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("gRPC response does not support flushing")
			return
		}
		flusher.Flush()
		for {
			payload, err := readGRPCFrame(r.Body)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Errorf("read streaming frame: %v", err)
				return
			}
			if _, err := w.Write(grpcFrame(payload)); err != nil {
				return
			}
			flusher.Flush()
		}
		w.Header().Set("grpc-status", "0")
	}))
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "grpc.example.com", Session: as, Takeover: true, HTTP2: true}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	t.Cleanup(func() { s.registry.ReleaseSession(as) })
	public, client := startHTTP2PublicServer(t, s)

	reader, writer := io.Pipe()
	defer writer.Close()
	req, err := http.NewRequest(http.MethodPost, public.URL+"/test.Service/Stream", reader)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Host = "grpc.example.com"
	req.Header.Set("Content-Type", "application/grpc")
	responseCh := make(chan struct {
		response *http.Response
		err      error
	}, 1)
	go func() {
		response, err := client.Do(req)
		responseCh <- struct {
			response *http.Response
			err      error
		}{response, err}
	}()

	var result struct {
		response *http.Response
		err      error
	}
	select {
	case result = <-responseCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for streaming response headers")
	}
	if result.err != nil {
		t.Fatalf("streaming request: %v", result.err)
	}
	defer result.response.Body.Close()

	for _, payload := range [][]byte{[]byte("one"), []byte("two")} {
		if _, err := writer.Write(grpcFrame(payload)); err != nil {
			t.Fatalf("write streaming request: %v", err)
		}
		got, err := readGRPCFrame(result.response.Body)
		if err != nil {
			t.Fatalf("read streaming response: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("stream response = %q, want %q", got, payload)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close streaming request: %v", err)
	}
	if _, err := io.ReadAll(result.response.Body); err != nil {
		t.Fatalf("finish streaming response: %v", err)
	}
	if got := result.response.Trailer.Get("grpc-status"); got != "0" {
		t.Fatalf("stream grpc-status = %q, want 0", got)
	}
}

func TestNativeGRPCCancellationReachesLocalHandler(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	as := newFakeH2AgentSession(t, "h2-instance", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}))
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "grpc.example.com", Session: as, Takeover: true, HTTP2: true}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	t.Cleanup(func() { s.registry.ReleaseSession(as) })
	public, client := startHTTP2PublicServer(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, public.URL+"/test.Service/Cancel", bytes.NewReader(grpcFrame([]byte("cancel"))))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Host = "grpc.example.com"
	req.Header.Set("Content-Type", "application/grpc")
	responseCh := make(chan error, 1)
	go func() {
		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		responseCh <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("local gRPC handler did not start")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("request cancellation did not reach the local gRPC handler")
	}
	select {
	case err := <-responseCh:
		if err == nil {
			t.Fatal("cancelled gRPC request returned without an error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled gRPC request did not finish")
	}
}

func TestNativeGRPCDeadlinePropagatesToLocalHandler(t *testing.T) {
	started := make(chan struct{})
	deadlineReached := make(chan struct{})
	as := newFakeH2AgentSession(t, "h2-instance", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("grpc-timeout") != "1S" {
			t.Errorf("grpc-timeout = %q, want 1S", r.Header.Get("grpc-timeout"))
		}
		close(started)
		<-r.Context().Done()
		close(deadlineReached)
	}))
	s := newServerForTest(LimitsConfig{PerIPRate: 1000, PerIPBurst: 1000})
	if _, _, err := s.registry.BindWithOptions(BindOptions{Host: "grpc.example.com", Session: as, Takeover: true, HTTP2: true}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	t.Cleanup(func() { s.registry.ReleaseSession(as) })
	public, client := startHTTP2PublicServer(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, public.URL+"/test.Service/Deadline", bytes.NewReader(grpcFrame([]byte("deadline"))))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Host = "grpc.example.com"
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("grpc-timeout", "1S")
	responseCh := make(chan error, 1)
	go func() {
		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		responseCh <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("local gRPC handler did not start")
	}
	select {
	case <-deadlineReached:
	case <-time.After(3 * time.Second):
		t.Fatal("client deadline did not reach the local gRPC handler")
	}
	select {
	case err := <-responseCh:
		if err == nil {
			t.Fatal("deadline-limited gRPC request returned without an error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("deadline-limited gRPC request did not finish")
	}
}
