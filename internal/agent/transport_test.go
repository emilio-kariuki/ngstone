package agent

import (
	"errors"
	"reflect"
	"testing"
)

func TestTransportFallbackOnlyAppliesBeforeBind(t *testing.T) {
	preBind := &preBindTransportError{err: errors.New("dial failed")}
	if !isPreBindTransportError(preBind) {
		t.Fatal("pre-bind transport error was not classified for fallback")
	}

	postBind := errors.New("session dropped")
	if isPreBindTransportError(postBind) {
		t.Fatal("post-bind transport error was classified for fallback")
	}
}

func TestTransportModes(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "default", want: []string{TransportRaw, TransportWebSocket}},
		{name: "auto", input: "auto", want: []string{TransportRaw, TransportWebSocket}},
		{name: "raw", input: "raw", want: []string{TransportRaw}},
		{name: "tcp alias", input: "tcp", want: []string{TransportRaw}},
		{name: "websocket", input: "websocket", want: []string{TransportWebSocket}},
		{name: "https alias", input: "https", want: []string{TransportWebSocket}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := transportModes(tc.input)
			if err != nil {
				t.Fatalf("transportModes(%q): %v", tc.input, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("transportModes(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestTransportModesRejectUnknownTransport(t *testing.T) {
	if _, err := transportModes("quic"); err == nil {
		t.Fatal("transportModes(quic) succeeded")
	}
}

func TestControlHost(t *testing.T) {
	cases := map[string]string{
		"ngstone.site:4443": "ngstone.site",
		"127.0.0.1:4443":    "127.0.0.1",
		"[::1]:4443":        "::1",
		"ngstone.site":      "ngstone.site",
	}
	for input, want := range cases {
		got, err := controlHost(input)
		if err != nil {
			t.Fatalf("controlHost(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("controlHost(%q) = %q, want %q", input, got, want)
		}
	}
}
