package edge

import (
	"path/filepath"
	"testing"

	"ngstone/internal/proto"
	"ngstone/internal/storage"
)

func TestHandleBindTCPLeaseStorageErrorIsInternal(t *testing.T) {
	fx := newTCPFixture(t, echoHandler)
	defer fx.cleanup()

	store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	s := newTestServer("tok")
	s.tcpMgr = fx.mgr
	s.storage = store

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleBindTCP(fx.as, fx.as.Sess.Control(), 7, proto.Bind{Kind: proto.KindTCP, RemotePort: 20003})
	}()
	reply, err := fx.agent.Control().Read()
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	<-done
	if reply.Type != proto.TypeBindErr {
		t.Fatalf("reply type = %q, want bind_err", reply.Type)
	}
	be, err := proto.Decode[proto.BindErr](reply)
	if err != nil {
		t.Fatal(err)
	}
	if be.Code != proto.CodeInternal {
		t.Fatalf("code = %q, want %q", be.Code, proto.CodeInternal)
	}
}
