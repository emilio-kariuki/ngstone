package main

import (
	"strings"
	"testing"
	"time"

	"ngstone/internal/agent"
)

func TestResolveShareTarget(t *testing.T) {
	cases := []struct {
		args             []string
		preset, target   string
		port             int
		wantErrSubstring string
	}{
		{[]string{"postgres"}, "postgres", "127.0.0.1:5432", 5432, ""},
		{[]string{"MySQL"}, "mysql", "127.0.0.1:3306", 3306, ""},
		{[]string{"redis", "6380"}, "redis", "127.0.0.1:6380", 6379, ""},
		{[]string{"postgres", "db.local:5433"}, "postgres", "db.local:5433", 5432, ""},
		{[]string{"tcp", "9000"}, "tcp", "127.0.0.1:9000", 9000, ""},
		{[]string{"tcp", "10.0.0.5:27017"}, "tcp", "10.0.0.5:27017", 27017, ""},
		{[]string{}, "", "", 0, "usage"},
		{[]string{"tcp"}, "", "", 0, "usage: ngstone share tcp"},
		{[]string{"mongo"}, "", "", 0, "unknown preset"},
		{[]string{"postgres", "1", "2"}, "", "", 0, "usage"},
		{[]string{"tcp", "notaport"}, "", "", 0, "invalid port"},
	}
	for _, tc := range cases {
		preset, target, port, err := resolveShareTarget(tc.args)
		if tc.wantErrSubstring != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstring) {
				t.Errorf("%v: err = %v, want containing %q", tc.args, err, tc.wantErrSubstring)
			}
			continue
		}
		if err != nil {
			t.Errorf("%v: unexpected error %v", tc.args, err)
			continue
		}
		if preset != tc.preset || target != tc.target || port != tc.port {
			t.Errorf("%v: got (%q, %q, %d), want (%q, %q, %d)", tc.args, preset, target, port, tc.preset, tc.target, tc.port)
		}
	}
}

func TestResolveShareLink(t *testing.T) {
	if got, err := resolveShareLink([]string{"ngstone://a:1/s/x"}, "", strings.NewReader("")); err != nil || got != "ngstone://a:1/s/x" {
		t.Fatalf("positional: %q, %v", got, err)
	}
	if got, err := resolveShareLink(nil, " ngstone://env:1/s/x \n", strings.NewReader("")); err != nil || got != "ngstone://env:1/s/x" {
		t.Fatalf("env: %q, %v", got, err)
	}
	if got, err := resolveShareLink([]string{"-"}, "", strings.NewReader("ngstone://stdin:1/s/x\n")); err != nil || got != "ngstone://stdin:1/s/x" {
		t.Fatalf("stdin: %q, %v", got, err)
	}
	if got, err := resolveShareLink([]string{"-"}, "", strings.NewReader("ngstone://noeol:1/s/x")); err != nil || got != "ngstone://noeol:1/s/x" {
		t.Fatalf("stdin without newline: %q, %v", got, err)
	}
	if _, err := resolveShareLink([]string{"-"}, "", strings.NewReader("")); err == nil {
		t.Fatalf("empty stdin should fail")
	}
	if _, err := resolveShareLink(nil, "", strings.NewReader("")); err == nil {
		t.Fatalf("no link anywhere should fail")
	}
	if _, err := resolveShareLink([]string{"a", "b"}, "", strings.NewReader("")); err == nil {
		t.Fatalf("two positionals should fail")
	}
}

func TestShareFlagsParse(t *testing.T) {
	fs, sf := newShareFlagSet()
	positionals, err := parsePermissive(fs, []string{"postgres", "--expires", "2h", "--label", "staging replica", "--single-use", "--max-conns", "4", "-allow-cidr", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if len(positionals) != 1 || positionals[0] != "postgres" {
		t.Fatalf("positionals = %v", positionals)
	}
	if sf.expires != 2*time.Hour || sf.label != "staging replica" || !sf.singleUse || sf.maxConns != 4 || sf.allowCIDR != "10.0.0.0/8" {
		t.Fatalf("flags = %+v", sf)
	}
}

func TestRoundDuration(t *testing.T) {
	cases := map[time.Duration]string{
		30 * time.Second:                      "30s",
		59*time.Second + 600*time.Millisecond: "1m",
		45 * time.Minute:                      "45m",
		2 * time.Hour:                         "2h",
		time.Hour + 58*time.Minute:            "1h58m",
		-5 * time.Second:                      "0s",
	}
	for d, want := range cases {
		if got := roundDuration(d); got != want {
			t.Errorf("roundDuration(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestConnectHintAndPolicyText(t *testing.T) {
	if got := connectHint("postgres", "127.0.0.1:5432"); got != `psql "postgres://127.0.0.1:5432/"` {
		t.Fatalf("postgres hint = %q", got)
	}
	if got := connectHint("tcp", "127.0.0.1:9000"); got != "nc 127.0.0.1:9000" {
		t.Fatalf("tcp hint = %q", got)
	}
	spec := &agent.ShareSpec{MaxConns: 16, MaxConnectors: 8}
	if got := sharePolicyText(spec); got != "allow all, 16 conns, 8 connectors" {
		t.Fatalf("policy text = %q", got)
	}
	spec.AllowCIDRs = []string{"10.0.0.0/8"}
	spec.SingleUse = true
	if got := sharePolicyText(spec); got != "allow 10.0.0.0/8, 16 conns, 8 connectors, single-use" {
		t.Fatalf("policy text = %q", got)
	}
}
