package tui

import (
	"net/http"
	"testing"

	"ngstone/internal/inspect"
)

func TestClassifyFilter(t *testing.T) {
	cases := []struct {
		query    string
		wantKind filterKind
		wantVal  string
	}{
		{"", filterNone, ""},
		{"   ", filterNone, ""},
		{"get", filterMethod, "GET"},
		{"POST", filterMethod, "POST"},
		{"ws", filterMethod, "WS"},
		{"2xx", filterStatusClass, "2"},
		{"4XX", filterStatusClass, "4"},
		{"/api/users", filterSubstring, "/api/users"},
	}

	for _, c := range cases {
		kind, val := classifyFilter(c.query)
		if kind != c.wantKind || val != c.wantVal {
			t.Errorf("classifyFilter(%q) = (%v, %q), want (%v, %q)", c.query, kind, val, c.wantKind, c.wantVal)
		}
	}
}

func TestMatchFilter(t *testing.T) {
	get200 := &inspect.Exchange{
		Kind: inspect.KindHTTP,
		Req:  inspect.CapturedReq{Method: "GET", URL: "https://example.com/api/users"},
		Resp: inspect.CapturedResp{Status: 200},
	}
	post500 := &inspect.Exchange{
		Kind: inspect.KindHTTP,
		Req:  inspect.CapturedReq{Method: "POST", URL: "https://example.com/api/orders"},
		Resp: inspect.CapturedResp{Status: 500},
	}
	pending := &inspect.Exchange{
		Kind: inspect.KindHTTP,
		Req:  inspect.CapturedReq{Method: "GET", URL: "https://example.com/pending"},
		Resp: inspect.CapturedResp{Status: 0},
	}
	upgrade := &inspect.Exchange{
		Kind: inspect.KindUpgrade,
		Req:  inspect.CapturedReq{Method: "GET", URL: "https://example.com/ws", Header: http.Header{}},
	}

	cases := []struct {
		name  string
		query string
		ex    *inspect.Exchange
		want  bool
	}{
		{"empty matches everything", "", get200, true},
		{"method match", "GET", get200, true},
		{"method mismatch", "POST", get200, false},
		{"status class match", "2xx", get200, true},
		{"status class mismatch", "5xx", get200, false},
		{"status class no response never matches", "2xx", pending, false},
		{"substring match", "orders", post500, true},
		{"substring mismatch", "users", post500, false},
		{"upgrade matches WS", "WS", upgrade, true},
		{"upgrade matches lowercase ws", "ws", upgrade, true},
		{"upgrade does not match GET", "GET", upgrade, false},
	}

	for _, c := range cases {
		if got := matchFilter(c.query, c.ex); got != c.want {
			t.Errorf("%s: matchFilter(%q) = %v, want %v", c.name, c.query, got, c.want)
		}
	}
}
