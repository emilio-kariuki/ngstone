package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"ngstone/internal/agent"
	"ngstone/internal/proto"
)

func TestResolveShareTargets(t *testing.T) {
	cases := []struct {
		args    []string
		want    []string // preset addr pairs
		wantErr string
	}{
		{[]string{"postgres"}, []string{"postgres 127.0.0.1:5432"}, ""},
		{[]string{"MySQL"}, []string{"mysql 127.0.0.1:3306"}, ""},
		{[]string{"redis", "6380"}, []string{"redis 127.0.0.1:6380"}, ""},
		{[]string{"postgres", "db.local:5433"}, []string{"postgres db.local:5433"}, ""},
		{[]string{"tcp", "9000"}, []string{"tcp 127.0.0.1:9000"}, ""},
		{[]string{"tcp:10.0.0.5:27017"}, []string{"tcp 10.0.0.5:27017"}, ""},
		{[]string{"postgres", "redis:6380", "tcp:9000"}, []string{"postgres 127.0.0.1:5432", "redis 127.0.0.1:6380", "tcp 127.0.0.1:9000"}, ""},
		{[]string{"http:3000"}, []string{"http 127.0.0.1:3000"}, ""},
		{[]string{}, nil, "usage"},
		{[]string{"tcp"}, nil, "tcp needs a port"},
		{[]string{"mongo"}, nil, "unknown preset"},
		{[]string{"tcp", "notaport"}, nil, "tcp needs a port"},
		{[]string{"postgres:bad"}, nil, "invalid port"},
	}
	for _, tc := range cases {
		targets, err := resolveShareTargets(tc.args)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%v: err = %v, want containing %q", tc.args, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%v: unexpected error %v", tc.args, err)
			continue
		}
		var got []string
		for i, tg := range targets {
			got = append(got, tg.Preset+" "+tg.Addr)
			if tg.ID != "t"+strconv.Itoa(i+1) {
				t.Errorf("%v: target %d id = %q", tc.args, i, tg.ID)
			}
		}
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%v: got %v, want %v", tc.args, got, tc.want)
		}
	}
	if ts, _ := resolveShareTargets([]string{"tcp:9000"}); ts[0].DefaultPort != 9000 {
		t.Fatalf("tcp default port = %d, want 9000", ts[0].DefaultPort)
	}
	if ts, _ := resolveShareTargets([]string{"postgres:5433"}); ts[0].DefaultPort != 5432 {
		t.Fatalf("postgres default port = %d, want the preset's 5432", ts[0].DefaultPort)
	}
}

func TestResolveShareSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	s1, d1, reused, err := resolveShareSecret(path, "")
	if err != nil || reused {
		t.Fatalf("first use: %v reused=%v", err, reused)
	}
	s2, d2, reused, err := resolveShareSecret(path, "")
	if err != nil || !reused || s1 != s2 || d1 != d2 {
		t.Fatalf("second use should reuse: %v reused=%v same=%v", err, reused, s1 == s2)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("secret file mode = %o, want 600", info.Mode().Perm())
	}
	if _, _, _, err := resolveShareSecret("", "not-a-secret"); err == nil {
		t.Fatalf("bad env secret accepted")
	}
	s3, _, reused, err := resolveShareSecret("", s1)
	if err != nil || !reused || s3 != s1 {
		t.Fatalf("env secret: %v reused=%v", err, reused)
	}
	s4, _, reused, err := resolveShareSecret("", "")
	if err != nil || reused || s4 == s1 {
		t.Fatalf("minted secret: %v reused=%v", err, reused)
	}
}

func TestPortOverrides(t *testing.T) {
	var p portOverrides
	for _, v := range []string{"5433", "redis=6380", "t2=7000"} {
		if err := p.Set(v); err != nil {
			t.Fatal(err)
		}
	}
	if p[""] != 5433 || p["redis"] != 6380 || p["t2"] != 7000 {
		t.Fatalf("overrides = %v", p)
	}
	if err := p.Set("redis=70000"); err == nil {
		t.Fatalf("out of range port accepted")
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
	pg := agent.ConnectTarget{ShareTarget: proto.ShareTarget{Preset: "postgres"}, ListenAddr: "127.0.0.1:5432"}
	if got := connectHint(pg); got != `psql "postgres://127.0.0.1:5432/"` {
		t.Fatalf("postgres hint = %q", got)
	}
	pg.User = "readonly"
	if got := connectHint(pg); got != `psql "postgres://readonly@127.0.0.1:5432/"` {
		t.Fatalf("postgres hint with user = %q", got)
	}
	my := agent.ConnectTarget{ShareTarget: proto.ShareTarget{Preset: "mysql", User: "ro"}, ListenAddr: "127.0.0.1:3306"}
	if got := connectHint(my); got != "mysql -h 127.0.0.1 -P 3306 -u ro" {
		t.Fatalf("mysql hint = %q", got)
	}
	if got := connectHint(agent.ConnectTarget{ShareTarget: proto.ShareTarget{Preset: "http"}, ListenAddr: "127.0.0.1:8080"}); got != "open http://127.0.0.1:8080/" {
		t.Fatalf("http hint = %q", got)
	}
	if got := connectHint(agent.ConnectTarget{ShareTarget: proto.ShareTarget{Preset: "tcp"}, ListenAddr: "127.0.0.1:9000"}); got != "nc 127.0.0.1:9000" {
		t.Fatalf("tcp hint = %q", got)
	}
	spec := &agent.ShareSpec{MaxConns: 16, MaxConnectors: 8}
	if got := sharePolicyText(spec); got != "allow all, 16 conns, 8 connectors" {
		t.Fatalf("policy text = %q", got)
	}
	spec.AllowCIDRs = []string{"10.0.0.0/8"}
	spec.SingleUse = true
	spec.IdleTimeout = 30 * time.Minute
	spec.Approve = true
	spec.PassphraseSHA256 = "ab"
	if got := sharePolicyText(spec); got != "allow 10.0.0.0/8, 16 conns, 8 connectors, single-use, idle 30m, approval required, passphrase" {
		t.Fatalf("policy text = %q", got)
	}
	spec.SingleUse = false
	spec.MaxUses = 3
	if got := sharePolicyText(spec); !strings.Contains(got, "3 uses") {
		t.Fatalf("policy text = %q", got)
	}
}
