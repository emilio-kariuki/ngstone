package agent

import (
	"bytes"
	"context"
	"encoding/binary"
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

func startH2CTestServer(t *testing.T, handler http.Handler) string {
	return startH2CTestServerWithCount(t, handler, nil)
}

func startH2CTestServerWithCount(t *testing.T, handler http.Handler, connectionCount *atomic.Int64) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http2.Server{}
	done := make(chan struct{})
	go func() {
		defer close(done)
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
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("h2c accept loop did not stop")
		}
	})
	return "http://" + ln.Addr().String()
}

func grpcTestFrame(payload []byte) []byte {
	frame := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	return frame
}

func readGRPCTestFrame(r io.Reader) ([]byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if header[0] != 0 {
		return nil, io.ErrUnexpectedEOF
	}
	payload := make([]byte, binary.BigEndian.Uint32(header[1:5]))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func TestHTTP2ProxyForwardsH2CRequestsAndTrailers(t *testing.T) {
	target := startH2CTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("request protocol = %s, want HTTP/2", r.Proto)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
		w.Header().Set("Grpc-Status", "0")
	}))

	a := New(Config{TargetURL: target, HTTP2: true})
	req := httptest.NewRequest(http.MethodPost, "http://public.example/rpc.Test/Call?x=1", strings.NewReader("hello"))
	req.Host = "public.example"
	rec := httptest.NewRecorder()
	a.buildHTTP2Proxy(a.Target()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); body != "hello" {
		t.Fatalf("body = %q, want hello", body)
	}
	if status := rec.Result().Trailer.Get("Grpc-Status"); status != "0" {
		t.Fatalf("Grpc-Status trailer = %q, want 0; headers=%v trailer=%v", status, rec.Header().Get("Grpc-Status"), rec.Result().Trailer)
	}
}

func TestHTTP2ProxyForwardsLargeH2CMessageAndReusesConnection(t *testing.T) {
	var connectionCount atomic.Int64
	target := startH2CTestServerWithCount(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("request protocol = %s, want HTTP/2", r.Proto)
		}
		payload, err := readGRPCTestFrame(r.Body)
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
		if _, err := w.Write(grpcTestFrame(payload)); err != nil {
			t.Errorf("write gRPC response: %v", err)
			return
		}
		w.Header().Set("grpc-status", "0")
	}), &connectionCount)
	a := New(Config{TargetURL: target, HTTP2: true})
	large := bytes.Repeat([]byte("h"), 2<<20)
	for i, payload := range [][]byte{large, []byte("reused")} {
		req := httptest.NewRequest(http.MethodPost, "http://public.example/rpc.Test/Call", bytes.NewReader(grpcTestFrame(payload)))
		req.Header.Set("Content-Type", "application/grpc")
		rec := httptest.NewRecorder()
		a.buildHTTP2Proxy(a.Target()).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i+1, rec.Code)
		}
		if !bytes.Equal(rec.Body.Bytes(), grpcTestFrame(payload)) {
			t.Fatalf("request %d body length = %d, want %d", i+1, rec.Body.Len(), len(grpcTestFrame(payload)))
		}
		if got := rec.Result().Trailer.Get("grpc-status"); got != "0" {
			t.Fatalf("request %d grpc-status = %q, want 0", i+1, got)
		}
	}
	if got := connectionCount.Load(); got != 1 {
		t.Fatalf("h2c connections = %d, want one reused connection", got)
	}
}

func TestHTTP2TunnelServerDispatchesH2Streams(t *testing.T) {
	agentSess, edgeSess, cleanup := newTestSessionPair(t)
	defer cleanup()

	ln, err := tunnel.NewListener(agentSess)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	server := newHTTP2TunnelServer(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Trailer", "Grpc-Status")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, "native-h2")
			w.Header().Set("Grpc-Status", "0")
			if r.ProtoMajor != 2 {
				t.Errorf("request protocol = %s, want HTTP/2", r.Proto)
			}
			if r.Context().Value(http.ServerContextKey) == nil {
				t.Errorf("request context is missing the HTTP server context")
			}
			if r.URL.Path != "/health" {
				t.Errorf("request path = %q, want /health", r.URL.Path)
			}
			if r.Host != "native.example" {
				t.Errorf("request host = %q, want native.example", r.Host)
			}
			info := inspect.StreamInfoFrom(r.Context())
			if info.ReqID != "req-1" || info.ClientAddr != "203.0.113.10:1234" {
				t.Errorf("stream info = %+v, want request metadata from the preamble", info)
			}
		}),
	)
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ln) }()

	stream, err := edgeSess.OpenStream(context.Background(), proto.StreamOpen{
		Kind:       proto.KindHTTP2,
		Host:       "native.example",
		ReqID:      "req-1",
		ClientAddr: "203.0.113.10:1234",
	})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	clientConn, err := (&http2.Transport{}).NewClientConn(stream)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	resp, err := clientConn.RoundTrip(httptest.NewRequest(http.MethodGet, "http://native.example/health", nil))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(body) != "native-h2" || resp.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("response body=%q trailer=%v, want native-h2 and Grpc-Status=0", body, resp.Trailer)
	}
	stream.Close()
	server.Close()
	select {
	case <-serveErr:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP/2 tunnel server did not stop")
	}
}
