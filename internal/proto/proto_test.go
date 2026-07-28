package proto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRoundTripMessages(t *testing.T) {
	cases := []struct {
		name string
		typ  string
		id   uint64
		data any
	}{
		{"auth_ok", TypeAuthOK, 2, AuthOK{ProtoVersion: 1, SessionID: "sess1", ServerVersion: "ngstoned/0.1"}},
		{"auth_err", TypeAuthErr, 3, AuthErr{Code: CodeBadToken, Message: "bad token"}},
		{"bind", TypeBind, 5, Bind{Kind: KindHTTP, Subdomain: "foo", Takeover: true}},
		{"bind_ok", TypeBindOK, 6, BindOK{Hostname: "foo.example.com", URL: "https://foo.example.com"}},
		{"bind_err", TypeBindErr, 7, BindErr{Code: CodeSubdomainTaken, Message: "taken"}},
		{"unbind", TypeUnbind, 9, Unbind{Hostname: "foo.example.com"}},
		{"unbind_ok", TypeUnbindOK, 10, UnbindOK{Hostname: "foo.example.com"}},
		{"evicted", TypeEvicted, 12, Evicted{Hostname: "foo.example.com", Reason: "takeover"}},
		{"error", TypeError, 13, Error{Code: CodeMalformed, Message: "bad frame"}},
		{"ping", TypePing, 15, Ping{TS: 1234}},
		{"pong", TypePong, 16, Pong{TS: 1234}},
		{"goodbye", TypeGoodbye, 17, Goodbye{Reason: "shutdown", DrainMS: 15000}},
		{"stream_open", TypeStreamOpen, 18, StreamOpen{Kind: KindHTTP, Host: "foo.example.com", ReqID: "01ABC", ClientAddr: "1.2.3.4:5678"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.data)
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}
			in := Msg{Type: tc.typ, ID: tc.id, Data: raw}

			var buf bytes.Buffer
			if err := WriteMsg(&buf, in); err != nil {
				t.Fatalf("WriteMsg: %v", err)
			}
			out, err := ReadMsg(&buf)
			if err != nil {
				t.Fatalf("ReadMsg: %v", err)
			}
			if out.Type != tc.typ || out.ID != tc.id {
				t.Fatalf("envelope mismatch: got %+v", out)
			}

			switch v := tc.data.(type) {
			case AuthOK:
				got, err := Decode[AuthOK](out)
				checkEqual(t, got, v, err)
			case AuthErr:
				got, err := Decode[AuthErr](out)
				checkEqual(t, got, v, err)
			case Bind:
				got, err := Decode[Bind](out)
				checkDeepEqual(t, got, v, err)
			case BindOK:
				got, err := Decode[BindOK](out)
				checkEqual(t, got, v, err)
			case BindErr:
				got, err := Decode[BindErr](out)
				checkEqual(t, got, v, err)
			case Unbind:
				got, err := Decode[Unbind](out)
				checkEqual(t, got, v, err)
			case UnbindOK:
				got, err := Decode[UnbindOK](out)
				checkEqual(t, got, v, err)
			case Evicted:
				got, err := Decode[Evicted](out)
				checkEqual(t, got, v, err)
			case Error:
				got, err := Decode[Error](out)
				checkEqual(t, got, v, err)
			case Ping:
				got, err := Decode[Ping](out)
				checkEqual(t, got, v, err)
			case Pong:
				got, err := Decode[Pong](out)
				checkEqual(t, got, v, err)
			case Goodbye:
				got, err := Decode[Goodbye](out)
				checkEqual(t, got, v, err)
			case StreamOpen:
				got, err := Decode[StreamOpen](out)
				checkEqual(t, got, v, err)
			}
		})
	}
}

func checkEqual[T comparable](t *testing.T, got, want T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != want {
		t.Fatalf("decoded mismatch: got %+v want %+v", got, want)
	}
}

func checkDeepEqual[T any](t *testing.T, got, want T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded mismatch: got %+v want %+v", got, want)
	}
}

func TestRoundTripAuth(t *testing.T) {
	a := Auth{Token: "tok", InstanceID: "inst1", ClientVersion: "ngstone/0.1", ProtoVersions: []int{1, 2}}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteMsg(&buf, Msg{Type: TypeAuth, ID: 1, Data: raw}); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}
	out, err := ReadMsg(&buf)
	if err != nil {
		t.Fatalf("ReadMsg: %v", err)
	}
	got, err := Decode[Auth](out)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Token != a.Token || got.InstanceID != a.InstanceID || got.ClientVersion != a.ClientVersion {
		t.Fatalf("mismatch: got %+v want %+v", got, a)
	}
	if len(got.ProtoVersions) != len(a.ProtoVersions) {
		t.Fatalf("proto versions mismatch: got %v want %v", got.ProtoVersions, a.ProtoVersions)
	}
	for i := range a.ProtoVersions {
		if got.ProtoVersions[i] != a.ProtoVersions[i] {
			t.Fatalf("proto versions mismatch: got %v want %v", got.ProtoVersions, a.ProtoVersions)
		}
	}
}

func TestGoldenWireFormat(t *testing.T) {
	cases := []struct {
		name string
		v    any
		want string
	}{
		{"auth", Auth{Token: "tok", InstanceID: "inst1", ClientVersion: "ngstone/0.1", ProtoVersions: []int{1, 2}},
			`{"token":"tok","instance_id":"inst1","client_version":"ngstone/0.1","proto_versions":[1,2]}`},
		{"auth_ok", AuthOK{ProtoVersion: 1, SessionID: "sess1", ServerVersion: "ngstoned/0.1"},
			`{"proto_version":1,"session_id":"sess1","server_version":"ngstoned/0.1"}`},
		{"auth_err", AuthErr{Code: CodeBadToken, Message: "bad token"},
			`{"code":"bad_token","message":"bad token"}`},
		{"bind", Bind{Kind: KindHTTP, Subdomain: "foo", Takeover: true},
			`{"kind":"http","subdomain":"foo","takeover":true}`},
		{"bind_ok", BindOK{Hostname: "foo.example.com", URL: "https://foo.example.com"},
			`{"hostname":"foo.example.com","url":"https://foo.example.com"}`},
		{"bind_err", BindErr{Code: CodeSubdomainTaken, Message: "taken"},
			`{"code":"subdomain_taken","message":"taken"}`},
		{"unbind", Unbind{Hostname: "foo.example.com"},
			`{"hostname":"foo.example.com"}`},
		{"unbind_ok", UnbindOK{Hostname: "foo.example.com"},
			`{"hostname":"foo.example.com"}`},
		{"evicted", Evicted{Hostname: "foo.example.com", Reason: "takeover"},
			`{"hostname":"foo.example.com","reason":"takeover"}`},
		{"error", Error{Code: CodeMalformed, Message: "bad frame"},
			`{"code":"malformed","message":"bad frame"}`},
		{"ping", Ping{TS: 1234},
			`{"ts_unix_ms":1234}`},
		{"pong", Pong{TS: 1234},
			`{"ts_unix_ms":1234}`},
		{"goodbye", Goodbye{Reason: "shutdown", DrainMS: 15000},
			`{"reason":"shutdown","drain_ms":15000}`},
		{"stream_open", StreamOpen{Kind: KindHTTP, Host: "foo.example.com", ReqID: "01ABC", ClientAddr: "1.2.3.4:5678"},
			`{"kind":"http","host":"foo.example.com","req_id":"01ABC","client_addr":"1.2.3.4:5678"}`},
		{"bind_remote_port", Bind{Kind: KindTCP, RemotePort: 5432},
			`{"kind":"tcp","remote_port":5432}`},
		{"bind_ok_port", BindOK{Hostname: "foo.example.com", URL: "https://foo.example.com", Port: 5432},
			`{"hostname":"foo.example.com","url":"https://foo.example.com","port":5432}`},
	}

	if len(cases) != 16 {
		t.Fatalf("got %d golden cases, want 16", len(cases))
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(tc.v)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

type unexpectedMsgError struct {
	m Msg
}

func (e unexpectedMsgError) Error() string {
	return "unexpected message: " + e.m.Type
}

func errUnexpected(m Msg) error {
	return unexpectedMsgError{m: m}
}

func TestHandshakeOverPipe(t *testing.T) {
	edgeConnRaw, agentConnRaw := net.Pipe()
	edge := NewConn(edgeConnRaw)
	agent := NewConn(agentConnRaw)

	var wg sync.WaitGroup
	wg.Add(2)
	agentErrs := make(chan error, 1)
	edgeErrs := make(chan error, 1)

	go func() {
		defer wg.Done()
		if err := agent.Write(TypeAuth, 1, Auth{Token: "tok", InstanceID: "inst1", ClientVersion: "v", ProtoVersions: []int{1}}); err != nil {
			agentErrs <- err
			return
		}
		m, err := agent.Read()
		if err != nil {
			agentErrs <- err
			return
		}
		if m.Type != TypeAuthOK || m.ID != 1 {
			agentErrs <- errUnexpected(m)
			return
		}
		if err := agent.Write(TypeBind, 3, Bind{Kind: KindHTTP}); err != nil {
			agentErrs <- err
			return
		}
		m, err = agent.Read()
		if err != nil {
			agentErrs <- err
			return
		}
		if m.Type != TypeBindOK || m.ID != 3 {
			agentErrs <- errUnexpected(m)
			return
		}
		if err := agent.Write(TypePing, 5, Ping{TS: 42}); err != nil {
			agentErrs <- err
			return
		}
		m, err = agent.Read()
		if err != nil {
			agentErrs <- err
			return
		}
		if m.Type != TypePong || m.ID != 5 {
			agentErrs <- errUnexpected(m)
			return
		}
		agentErrs <- nil
	}()

	go func() {
		defer wg.Done()
		m, err := edge.Read()
		if err != nil {
			edgeErrs <- err
			return
		}
		if m.Type != TypeAuth || m.ID != 1 {
			edgeErrs <- errUnexpected(m)
			return
		}
		if err := edge.Write(TypeAuthOK, m.ID, AuthOK{ProtoVersion: 1, SessionID: "sess1", ServerVersion: "v"}); err != nil {
			edgeErrs <- err
			return
		}
		m, err = edge.Read()
		if err != nil {
			edgeErrs <- err
			return
		}
		if m.Type != TypeBind || m.ID != 3 {
			edgeErrs <- errUnexpected(m)
			return
		}
		if err := edge.Write(TypeBindOK, m.ID, BindOK{Hostname: "foo.example.com", URL: "https://foo.example.com"}); err != nil {
			edgeErrs <- err
			return
		}
		m, err = edge.Read()
		if err != nil {
			edgeErrs <- err
			return
		}
		if m.Type != TypePing || m.ID != 5 {
			edgeErrs <- errUnexpected(m)
			return
		}
		ping, err := Decode[Ping](m)
		if err != nil {
			edgeErrs <- err
			return
		}
		if err := edge.Write(TypePong, m.ID, Pong{TS: ping.TS}); err != nil {
			edgeErrs <- err
			return
		}
		edgeErrs <- nil
	}()

	wg.Wait()
	close(agentErrs)
	close(edgeErrs)
	if err := <-agentErrs; err != nil {
		t.Fatalf("agent side: %v", err)
	}
	if err := <-edgeErrs; err != nil {
		t.Fatalf("edge side: %v", err)
	}
}

func TestKnownType(t *testing.T) {
	known := []string{
		TypeAuth, TypeAuthOK, TypeAuthErr, TypeBind, TypeBindOK, TypeBindErr,
		TypeUnbind, TypeUnbindOK, TypeEvicted, TypeError, TypePing, TypePong,
		TypeGoodbye, TypeStreamOpen,
	}
	for _, typ := range known {
		if !KnownType(typ) {
			t.Fatalf("KnownType(%q) = false, want true", typ)
		}
	}
	if KnownType("bogus_type") {
		t.Fatalf("KnownType(%q) = true, want false", "bogus_type")
	}
	if KnownType("") {
		t.Fatalf("KnownType(\"\") = true, want false")
	}
}

func TestUnknownMsgType(t *testing.T) {
	serverRaw, clientRaw := net.Pipe()
	server := NewConn(serverRaw)
	client := NewConn(clientRaw)

	type senderResult struct {
		writeErr error
		reply    Msg
		replyErr error
		afterErr error
	}
	resultCh := make(chan senderResult, 1)
	go func() {
		var res senderResult
		res.writeErr = client.Write("bogus_type", 1, nil)
		res.reply, res.replyErr = client.Read()
		_, res.afterErr = client.Read()
		resultCh <- res
	}()

	m, err := server.Read()
	if err != nil {
		t.Fatalf("server Read: %v", err)
	}
	if KnownType(m.Type) {
		t.Fatalf("expected %q to be unknown", m.Type)
	}
	if err := server.Write(TypeError, m.ID, Error{Code: CodeUnknownType, Message: "unknown message type"}); err != nil {
		t.Fatalf("server Write: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("server Close: %v", err)
	}

	res := <-resultCh
	if res.writeErr != nil {
		t.Fatalf("client Write: %v", res.writeErr)
	}
	if res.replyErr != nil {
		t.Fatalf("client Read reply: %v", res.replyErr)
	}
	if res.reply.Type != TypeError || res.reply.ID != 1 {
		t.Fatalf("got %+v want type %q id 1", res.reply, TypeError)
	}
	got, err := Decode[Error](res.reply)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Code != CodeUnknownType {
		t.Fatalf("got code %q want %q", got.Code, CodeUnknownType)
	}
	if res.afterErr == nil {
		t.Fatalf("expected client's next read to fail after server close")
	}
}

func TestDecodeNoPayload(t *testing.T) {
	m := Msg{Type: TypeAuth, ID: 1}
	_, err := Decode[Auth](m)
	if err != ErrNoPayload {
		t.Fatalf("got %v want ErrNoPayload", err)
	}
}

func TestDecodeNullPayload(t *testing.T) {
	m := Msg{Type: TypeAuth, ID: 1, Data: json.RawMessage("null")}
	_, err := Decode[Auth](m)
	if err != ErrNoPayload {
		t.Fatalf("got %v want ErrNoPayload", err)
	}
}

func TestFramingZeroLength(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 0)
	buf.Write(hdr[:])
	_, err := ReadMsg(&buf)
	if err != ErrEmptyFrame {
		t.Fatalf("got %v want ErrEmptyFrame", err)
	}
}

func exactSizedFrame(t *testing.T, size int) []byte {
	t.Helper()
	base, err := json.Marshal(Msg{Type: TypeAuth, Data: json.RawMessage(`""`)})
	if err != nil {
		t.Fatalf("marshal base: %v", err)
	}
	pad := size - len(base)
	if pad < 0 {
		t.Fatalf("size %d too small for envelope overhead %d", size, len(base))
	}
	quoted, err := json.Marshal(strings.Repeat("a", pad))
	if err != nil {
		t.Fatalf("marshal padding: %v", err)
	}
	out, err := json.Marshal(Msg{Type: TypeAuth, Data: json.RawMessage(quoted)})
	if err != nil {
		t.Fatalf("marshal msg: %v", err)
	}
	if len(out) != size {
		t.Fatalf("built frame of size %d, want %d", len(out), size)
	}
	return out
}

func TestFramingExactMax(t *testing.T) {
	payload := exactSizedFrame(t, MaxFrameSize)

	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	buf.Write(hdr[:])
	buf.Write(payload)

	out, err := ReadMsg(&buf)
	if err != nil {
		t.Fatalf("ReadMsg at exactly MaxFrameSize: %v", err)
	}
	if out.Type != TypeAuth {
		t.Fatalf("got %+v", out)
	}
}

func TestFramingOverMax(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxFrameSize+1)
	buf.Write(hdr[:])
	_, err := ReadMsg(&buf)
	if err != ErrFrameTooLarge {
		t.Fatalf("got %v want ErrFrameTooLarge", err)
	}
}

func TestFramingTruncatedPayload(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 100)
	buf.Write(hdr[:])
	buf.Write([]byte("short"))
	_, err := ReadMsg(&buf)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("got %v want io.ErrUnexpectedEOF", err)
	}
}

func TestFramingInvalidJSON(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("not json")
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	buf.Write(hdr[:])
	buf.Write(payload)
	_, err := ReadMsg(&buf)
	if err == nil {
		t.Fatalf("expected error decoding invalid json")
	}
}

func TestFramingEmptyReader(t *testing.T) {
	var buf bytes.Buffer
	_, err := ReadMsg(&buf)
	if err != io.EOF {
		t.Fatalf("got %v want io.EOF", err)
	}
}

type countingWriter struct {
	writes int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.writes++
	return len(p), nil
}

func TestWriteMsgOversizeBeforeWrite(t *testing.T) {
	quoted, err := json.Marshal(strings.Repeat("a", MaxFrameSize))
	if err != nil {
		t.Fatalf("marshal padding: %v", err)
	}
	m := Msg{Type: TypeAuth, Data: json.RawMessage(quoted)}

	var w countingWriter
	err = WriteMsg(&w, m)
	if err != ErrFrameTooLarge {
		t.Fatalf("got %v want ErrFrameTooLarge", err)
	}
	if w.writes != 0 {
		t.Fatalf("expected no writes on oversize reject, got %d", w.writes)
	}
}

type fakeAddr struct{}

func (fakeAddr) Network() string { return "fake" }
func (fakeAddr) String() string  { return "fake" }

type unsyncBufConn struct {
	buf *bytes.Buffer
}

func (c *unsyncBufConn) Read(p []byte) (int, error)         { return 0, io.EOF }
func (c *unsyncBufConn) Write(p []byte) (int, error)        { return c.buf.Write(p) }
func (c *unsyncBufConn) Close() error                       { return nil }
func (c *unsyncBufConn) LocalAddr() net.Addr                { return fakeAddr{} }
func (c *unsyncBufConn) RemoteAddr() net.Addr               { return fakeAddr{} }
func (c *unsyncBufConn) SetDeadline(t time.Time) error      { return nil }
func (c *unsyncBufConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *unsyncBufConn) SetWriteDeadline(t time.Time) error { return nil }

func TestConnConcurrentWriters(t *testing.T) {
	var buf bytes.Buffer
	conn := NewConn(&unsyncBufConn{buf: &buf})

	const n = 50
	writeErrs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			writeErrs <- conn.Write(TypePing, uint64(i), Ping{TS: int64(i)})
		}(i)
	}
	wg.Wait()
	close(writeErrs)
	for err := range writeErrs {
		if err != nil {
			t.Fatalf("Write error: %v", err)
		}
	}

	r := bytes.NewReader(buf.Bytes())
	received := make(map[int64]bool)
	for i := 0; i < n; i++ {
		m, err := ReadMsg(r)
		if err != nil {
			t.Fatalf("ReadMsg frame %d: %v", i, err)
		}
		if m.Type != TypePing {
			t.Fatalf("frame %d: got type %q want %q", i, m.Type, TypePing)
		}
		p, err := Decode[Ping](m)
		if err != nil {
			t.Fatalf("Decode frame %d: %v", i, err)
		}
		received[p.TS] = true
	}
	if len(received) != n {
		t.Fatalf("got %d distinct pings, want %d", len(received), n)
	}
}

func TestIDGenAllocator(t *testing.T) {
	agent := NewAgentIDGen()
	edge := NewEdgeIDGen()

	var mu sync.Mutex
	seenAgent := make(map[uint64]bool)
	seenEdge := make(map[uint64]bool)

	const perGoroutine = 100
	const goroutines = 8

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				id := agent.Next()
				if id%2 == 0 {
					t.Errorf("agent id %d not odd", id)
				}
				mu.Lock()
				if seenAgent[id] {
					t.Errorf("duplicate agent id %d", id)
				}
				seenAgent[id] = true
				mu.Unlock()
			}
		}()
	}
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				id := edge.Next()
				if id%2 != 0 {
					t.Errorf("edge id %d not even", id)
				}
				mu.Lock()
				if seenEdge[id] {
					t.Errorf("duplicate edge id %d", id)
				}
				seenEdge[id] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
}

func FuzzReadMsg(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 1, '{'})

	seed := Msg{Type: TypeAuth, ID: 1}
	raw, err := json.Marshal(seed)
	if err != nil {
		f.Fatalf("marshal seed: %v", err)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(raw)))
	f.Add(append(hdr[:], raw...))

	big := make([]byte, 4)
	binary.BigEndian.PutUint32(big, 0xFFFFFFFF)
	f.Add(big)

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ReadMsg panicked: %v", r)
			}
		}()
		_, _ = ReadMsg(bytes.NewReader(data))
	})
}

func TestBindRemotePortOmitEmpty(t *testing.T) {
	t.Run("zero_value_omitted", func(t *testing.T) {
		got, err := json.Marshal(Bind{Kind: KindHTTP, Subdomain: "foo"})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if strings.Contains(string(got), "remote_port") {
			t.Fatalf("got %s want no remote_port field", got)
		}
	})

	t.Run("nonzero_round_trip", func(t *testing.T) {
		in := Bind{Kind: KindTCP, RemotePort: 5432}
		got, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !strings.Contains(string(got), `"remote_port":5432`) {
			t.Fatalf("got %s want substring %s", got, `"remote_port":5432`)
		}

		var out Bind
		if err := json.Unmarshal(got, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !reflect.DeepEqual(out, in) {
			t.Fatalf("got %+v want %+v", out, in)
		}
	})
}

func TestBindOKPortOmitEmpty(t *testing.T) {
	t.Run("zero_value_omitted", func(t *testing.T) {
		got, err := json.Marshal(BindOK{Hostname: "foo.example.com", URL: "https://foo.example.com"})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if strings.Contains(string(got), `"port":`) {
			t.Fatalf("got %s want no port field", got)
		}
	})

	t.Run("nonzero_round_trip", func(t *testing.T) {
		in := BindOK{Hostname: "foo.example.com", URL: "https://foo.example.com", Port: 5432}
		got, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !strings.Contains(string(got), `"port":5432`) {
			t.Fatalf("got %s want substring %s", got, `"port":5432`)
		}

		var out BindOK
		if err := json.Unmarshal(got, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out != in {
			t.Fatalf("got %+v want %+v", out, in)
		}
	})
}
