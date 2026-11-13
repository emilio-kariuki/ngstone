package agent

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"ngstone/internal/tunnel"
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
		{name: "quic", input: "quic", want: []string{TransportQUIC}},
		{name: "quic mixed case", input: " QUIC ", want: []string{TransportQUIC}},
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
	if _, err := transportModes("sctp"); err == nil {
		t.Fatal("transportModes(sctp) succeeded")
	}
}

type stubSession struct{ tunnel.Session }

func stubDialModes(t *testing.T, fn func(ctx context.Context, cfg Config, mode string) (tunnel.Session, error)) *[]string {
	t.Helper()
	var modes []string
	orig := dialControlSessionFn
	dialControlSessionFn = func(ctx context.Context, cfg Config, mode string) (tunnel.Session, error) {
		modes = append(modes, mode)
		return fn(ctx, cfg, mode)
	}
	t.Cleanup(func() { dialControlSessionFn = orig })
	return &modes
}

func TestDialControlSessionModesFallsBack(t *testing.T) {
	want := &stubSession{}
	rawErr := errors.New("raw refused")
	wsErr := errors.New("websocket refused")

	t.Run("auto falls through to websocket", func(t *testing.T) {
		modes := stubDialModes(t, func(_ context.Context, _ Config, mode string) (tunnel.Session, error) {
			if mode == TransportRaw {
				return nil, rawErr
			}
			return want, nil
		})
		sess, err := dialControlSessionModes(context.Background(), Config{Transport: TransportAuto})
		if err != nil || sess != tunnel.Session(want) {
			t.Fatalf("session = %v, err = %v; want the websocket session", sess, err)
		}
		if got := strings.Join(*modes, ","); got != "raw,websocket" {
			t.Fatalf("modes tried = %s, want raw,websocket", got)
		}
	})

	t.Run("raw never tries websocket", func(t *testing.T) {
		modes := stubDialModes(t, func(context.Context, Config, string) (tunnel.Session, error) {
			return nil, rawErr
		})
		_, err := dialControlSessionModes(context.Background(), Config{Transport: TransportRaw})
		if !errors.Is(err, rawErr) || strings.Contains(err.Error(), "websocket") {
			t.Fatalf("err = %v, want only the raw failure", err)
		}
		if got := strings.Join(*modes, ","); got != "raw" {
			t.Fatalf("modes tried = %s, want raw", got)
		}
	})

	t.Run("quic is never part of auto and is dialled alone when chosen", func(t *testing.T) {
		modes := stubDialModes(t, func(context.Context, Config, string) (tunnel.Session, error) {
			return nil, rawErr
		})
		dialControlSessionModes(context.Background(), Config{Transport: TransportAuto})
		dialControlSessionModes(context.Background(), Config{Transport: TransportQUIC})
		if got := strings.Join(*modes, ","); got != "raw,websocket,quic" {
			t.Fatalf("modes tried = %s, want raw,websocket,quic", got)
		}
	})

	t.Run("both failures stay on one line", func(t *testing.T) {
		stubDialModes(t, func(_ context.Context, _ Config, mode string) (tunnel.Session, error) {
			if mode == TransportRaw {
				return nil, rawErr
			}
			return nil, wsErr
		})
		_, err := dialControlSessionModes(context.Background(), Config{})
		if !errors.Is(err, rawErr) || !errors.Is(err, wsErr) || strings.Contains(err.Error(), "\n") {
			t.Fatalf("err = %q, want both failures on one line", err)
		}
	})

	t.Run("a cancelled context stops the fallback", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		modes := stubDialModes(t, func(context.Context, Config, string) (tunnel.Session, error) {
			cancel()
			return nil, rawErr
		})
		_, err := dialControlSessionModes(ctx, Config{Transport: TransportAuto})
		if !errors.Is(err, rawErr) {
			t.Fatalf("err = %v, want the raw failure", err)
		}
		if got := strings.Join(*modes, ","); got != "raw" {
			t.Fatalf("modes tried = %s, want raw only after cancellation", got)
		}
	})

	t.Run("an unknown transport dials nothing", func(t *testing.T) {
		modes := stubDialModes(t, func(context.Context, Config, string) (tunnel.Session, error) {
			return want, nil
		})
		if _, err := dialControlSessionModes(context.Background(), Config{Transport: "carrier-pigeon"}); err == nil {
			t.Fatal("unknown transport accepted")
		}
		if len(*modes) != 0 {
			t.Fatalf("modes tried = %v, want none", *modes)
		}
	})
}

func TestConnectDialConfigCarriesTransport(t *testing.T) {
	c := NewConnector(ConnectConfig{ControlAddr: "edge.example:4443", Transport: TransportQUIC})
	if got := c.dialConfig().Transport; got != TransportQUIC {
		t.Fatalf("dialConfig().Transport = %q, want %q", got, TransportQUIC)
	}
}

func TestOperatorSessionHonoursTransport(t *testing.T) {
	var seen string
	modes := stubDialModes(t, func(_ context.Context, cfg Config, _ string) (tunnel.Session, error) {
		seen = cfg.Transport
		return nil, errors.New("unreachable")
	})
	_, _, err := NewOperator(Config{ControlAddr: "edge.example:4443", Transport: TransportQUIC}).session(context.Background())
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
	if seen != TransportQUIC || strings.Join(*modes, ",") != "quic" {
		t.Fatalf("operator dialled transport %q modes %v, want quic only", seen, *modes)
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
