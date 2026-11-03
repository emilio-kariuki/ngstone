package agent

import (
	"testing"

	"ngstone/internal/proto"
)

func TestTLSKindSplicesThroughTCPPipe(t *testing.T) {
	a := New(Config{Kind: proto.KindTLS, TargetURL: "127.0.0.1:8443"})
	if got := a.bindKind(); got != proto.KindTLS {
		t.Fatalf("bindKind = %q, want tls", got)
	}
	srv, err := a.newServer()
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	pipe, ok := srv.(*tcpServer)
	if !ok {
		t.Fatalf("newServer = %T, want *tcpServer", srv)
	}
	if pipe.target != "127.0.0.1:8443" {
		t.Fatalf("tcp pipe target = %q", pipe.target)
	}
	if got := a.advertisedURL(proto.BindOK{Hostname: "secure.example.com", URL: "tls://secure.example.com"}); got != "tls://secure.example.com" {
		t.Fatalf("advertisedURL = %q", got)
	}
}
