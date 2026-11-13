package agent

import (
	"errors"
	"testing"

	"ngstone/internal/proto"
)

func TestHTTPHandshakeRequestsRememberedSubdomainOnReconnect(t *testing.T) {
	a := New(Config{TargetURL: "http://127.0.0.1:1"})

	ok, binds, err := handshakeAgainst(t, a, []bindReply{{hostname: "amber-fox-42.example.com"}})
	if err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	if ok.Hostname != "amber-fox-42.example.com" {
		t.Fatalf("first hostname = %q", ok.Hostname)
	}
	if len(binds) != 1 || binds[0].Subdomain != "" || !binds[0].Takeover {
		t.Fatalf("first binds = %+v, want one bind with no subdomain and Takeover", binds)
	}

	_, binds, err = handshakeAgainst(t, a, []bindReply{{hostname: "amber-fox-42.example.com"}})
	if err != nil {
		t.Fatalf("reconnect handshake: %v", err)
	}
	if len(binds) != 1 || binds[0].Subdomain != "amber-fox-42" || !binds[0].Takeover {
		t.Fatalf("reconnect binds = %+v, want the remembered subdomain amber-fox-42 with Takeover", binds)
	}
}

func TestHTTPHandshakeFallsBackToRandomWhenRememberedSubdomainTaken(t *testing.T) {
	a := New(Config{TargetURL: "http://127.0.0.1:1"})

	if _, _, err := handshakeAgainst(t, a, []bindReply{{hostname: "amber-fox-42.example.com"}}); err != nil {
		t.Fatalf("first handshake: %v", err)
	}

	ok, binds, err := handshakeAgainst(t, a, []bindReply{
		{errCode: proto.CodeSubdomainTaken},
		{hostname: "quiet-lynx-7.example.com"},
	})
	if err != nil {
		t.Fatalf("reconnect should fall back to a fresh name, got: %v", err)
	}
	if ok.Hostname != "quiet-lynx-7.example.com" {
		t.Fatalf("fallback hostname = %q", ok.Hostname)
	}
	if len(binds) != 2 || binds[0].Subdomain != "amber-fox-42" || binds[1].Subdomain != "" {
		t.Fatalf("binds = %+v, want the remembered name then a random one", binds)
	}

	_, binds, err = handshakeAgainst(t, a, []bindReply{{hostname: "quiet-lynx-7.example.com"}})
	if err != nil {
		t.Fatalf("third handshake: %v", err)
	}
	if len(binds) != 1 || binds[0].Subdomain != "quiet-lynx-7" {
		t.Fatalf("third binds = %+v, want the newly remembered name quiet-lynx-7", binds)
	}
}

func TestHTTPHandshakeUserSubdomainDoesNotFallBack(t *testing.T) {
	a := New(Config{TargetURL: "http://127.0.0.1:1", Subdomain: "demo"})

	_, binds, err := handshakeAgainst(t, a, []bindReply{{errCode: proto.CodeSubdomainTaken}})
	if !errors.Is(err, errFatalHandshake) {
		t.Fatalf("err = %v, want a fatal handshake error for a user-requested subdomain", err)
	}
	if len(binds) != 1 || binds[0].Subdomain != "demo" {
		t.Fatalf("binds = %+v, want exactly one bind for demo", binds)
	}
}

func TestHTTPHandshakeTransientErrorKeepsRememberedSubdomain(t *testing.T) {
	a := New(Config{TargetURL: "http://127.0.0.1:1"})

	if _, _, err := handshakeAgainst(t, a, []bindReply{{hostname: "amber-fox-42.example.com"}}); err != nil {
		t.Fatalf("first handshake: %v", err)
	}

	_, binds, err := handshakeAgainst(t, a, []bindReply{
		{errCode: proto.CodeInternal},
		{hostname: "quiet-lynx-7.example.com"},
	})
	if err == nil || errors.Is(err, errFatalHandshake) {
		t.Fatalf("an internal bind error must stay retryable, got %v", err)
	}
	if len(binds) != 1 || binds[0].Subdomain != "amber-fox-42" {
		t.Fatalf("binds = %+v, want exactly one bind for the remembered name", binds)
	}

	_, binds, err = handshakeAgainst(t, a, []bindReply{{hostname: "amber-fox-42.example.com"}})
	if err != nil {
		t.Fatalf("next handshake: %v", err)
	}
	if len(binds) != 1 || binds[0].Subdomain != "amber-fox-42" {
		t.Fatalf("binds = %+v, want the remembered name kept", binds)
	}
}

func TestHTTPHandshakeFailedFallbackForgetsTakenSubdomain(t *testing.T) {
	a := New(Config{TargetURL: "http://127.0.0.1:1"})

	if _, _, err := handshakeAgainst(t, a, []bindReply{{hostname: "amber-fox-42.example.com"}}); err != nil {
		t.Fatalf("first handshake: %v", err)
	}

	_, binds, err := handshakeAgainst(t, a, []bindReply{
		{errCode: proto.CodeSubdomainTaken},
		{errCode: proto.CodeInternal},
	})
	if err == nil || errors.Is(err, errFatalHandshake) {
		t.Fatalf("want a retryable error after the fallback bind fails, got %v", err)
	}
	if len(binds) != 2 {
		t.Fatalf("binds = %+v, want the remembered name then none", binds)
	}

	_, binds, err = handshakeAgainst(t, a, []bindReply{{hostname: "quiet-lynx-7.example.com"}})
	if err != nil {
		t.Fatalf("next handshake: %v", err)
	}
	if len(binds) != 1 || binds[0].Subdomain != "" {
		t.Fatalf("binds = %+v, want a single bind without the taken name", binds)
	}
}

func TestSubdomainOf(t *testing.T) {
	for in, want := range map[string]string{"amber-fox-42.example.com": "amber-fox-42", "a.b.c": "a", "example.com": "example", "nodots": "", "": ""} {
		if got := subdomainOf(in); got != want {
			t.Fatalf("subdomainOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHandshakeRememberedNameFallsBackOnKindConflict(t *testing.T) {
	a := New(Config{TargetURL: "http://127.0.0.1:1"})

	if _, _, err := handshakeAgainst(t, a, []bindReply{{hostname: "amber-fox-42.example.com"}}); err != nil {
		t.Fatalf("first handshake: %v", err)
	}

	ok, binds, err := handshakeAgainst(t, a, []bindReply{
		{errCode: proto.CodeKindConflict},
		{hostname: "quiet-lynx-7.example.com"},
	})
	if err != nil {
		t.Fatalf("a kind conflict on a remembered name must fall back, got: %v", err)
	}
	if ok.Hostname != "quiet-lynx-7.example.com" {
		t.Fatalf("fallback hostname = %q", ok.Hostname)
	}
	if len(binds) != 2 || binds[0].Subdomain != "amber-fox-42" || binds[1].Subdomain != "" {
		t.Fatalf("binds = %+v, want the remembered name then a random one", binds)
	}
}

func TestHandshakePreviewCredentialScopeStopsRemembering(t *testing.T) {
	a := New(Config{TargetURL: "http://127.0.0.1:1"})

	if _, _, err := handshakeAgainst(t, a, []bindReply{{hostname: "amber-fox-42.example.com"}}); err != nil {
		t.Fatalf("first handshake: %v", err)
	}

	ok, binds, err := handshakeAgainst(t, a, []bindReply{
		{errCode: proto.CodeCredentialScope},
		{hostname: "preview-x.example.com"},
	})
	if err != nil {
		t.Fatalf("a credential_scope refusal on a remembered name must fall back, got: %v", err)
	}
	if ok.Hostname != "preview-x.example.com" {
		t.Fatalf("fallback hostname = %q", ok.Hostname)
	}
	if len(binds) != 2 || binds[0].Subdomain != "amber-fox-42" || binds[1].Subdomain != "" {
		t.Fatalf("binds = %+v, want the remembered name then a random one", binds)
	}

	_, binds, err = handshakeAgainst(t, a, []bindReply{{hostname: "preview-x.example.com"}})
	if err != nil {
		t.Fatalf("next handshake: %v", err)
	}
	if len(binds) != 1 || binds[0].Subdomain != "" {
		t.Fatalf("binds = %+v, want no remembered name once the credential refused it", binds)
	}
}

func TestTLSHandshakeRequestsRememberedSubdomain(t *testing.T) {
	a := New(Config{Kind: proto.KindTLS, TargetURL: "127.0.0.1:1"})

	if _, _, err := handshakeAgainst(t, a, []bindReply{{hostname: "amber-fox-42.example.com"}}); err != nil {
		t.Fatalf("first handshake: %v", err)
	}

	_, binds, err := handshakeAgainst(t, a, []bindReply{{hostname: "amber-fox-42.example.com"}})
	if err != nil {
		t.Fatalf("reconnect handshake: %v", err)
	}
	if len(binds) != 1 || binds[0].Subdomain != "amber-fox-42" || !binds[0].Takeover {
		t.Fatalf("reconnect binds = %+v, want the remembered subdomain amber-fox-42 with Takeover", binds)
	}
}
