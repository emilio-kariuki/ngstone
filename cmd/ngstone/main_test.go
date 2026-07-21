package main

import (
	"bytes"
	"context"
	"flag"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ngstone/internal/config"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func buildNgstoneBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "ngstone-under-test")
	build := exec.Command("go", "build", "-o", out, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building ngstone binary: %v\n%s", err, out)
	}
	return out
}

func runNgstone(t *testing.T, bin string, timeout time.Duration, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("ngstone %v did not exit within %s; stdout=%q stderr=%q", args, timeout, outBuf.String(), errBuf.String())
	}
	if err == nil {
		return outBuf.String(), errBuf.String(), 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return outBuf.String(), errBuf.String(), exitErr.ExitCode()
	}
	t.Fatalf("running ngstone %v: %v", args, err)
	return "", "", -1
}

func TestBareInvocationPrintsUsageAndExitsNonZero(t *testing.T) {
	bin := buildNgstoneBinary(t)
	start := time.Now()
	stdout, stderr, code := runNgstone(t, bin, 5*time.Second)
	elapsed := time.Since(start)

	if code == 0 {
		t.Fatalf("bare invocation exit code = 0, want non-zero")
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "Usage:") || !strings.Contains(combined, "ngstone port 3000") {
		t.Fatalf("bare invocation output = %q, want it to contain usage text", combined)
	}
	if strings.Contains(combined, "starting") || strings.Contains(combined, "daring") {
		t.Fatalf("bare invocation output = %q, looks like it attempted to start a tunnel", combined)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("bare invocation took %s, want it to return immediately without attempting a connection", elapsed)
	}
}

func TestHelpFlagPrintsUsageAndExitsZero(t *testing.T) {
	bin := buildNgstoneBinary(t)
	for _, flag := range []string{"-h", "--help"} {
		stdout, stderr, code := runNgstone(t, bin, 5*time.Second, flag)
		if code != 0 {
			t.Fatalf("ngstone %s exit code = %d, want 0; stdout=%q stderr=%q", flag, code, stdout, stderr)
		}
		if !strings.Contains(stdout, "Usage:") {
			t.Fatalf("ngstone %s stdout = %q, want it to contain usage text", flag, stdout)
		}
	}
}

func TestLegacyFlagInvocationRoutesToLegacyPathNotUsage(t *testing.T) {
	bin := buildNgstoneBinary(t)

	cmd := exec.Command(bin,
		"-insecure", "-control", "127.0.0.1:1", "-target", "http://127.0.0.1:9",
		"-subdomain", "demo", "-token", "abc")
	var outBuf, errBuf syncBuffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting ngstone: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(errBuf.String(), "starting") {
		time.Sleep(20 * time.Millisecond)
	}

	combined := outBuf.String() + errBuf.String()
	if !strings.Contains(combined, "starting") {
		_ = cmd.Process.Kill()
		t.Fatalf("legacy flag invocation output = %q, want it to log that it started attempting to connect", combined)
	}
	if strings.Contains(combined, "Usage:") {
		_ = cmd.Process.Kill()
		t.Fatalf("legacy flag invocation output = %q, should not print the new usage text", combined)
	}

	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

func TestVerbFuncDispatch(t *testing.T) {
	cases := []struct {
		arg     string
		wantOK  bool
		wantVal bool
	}{
		{"auth", true, true},
		{"port", true, true},
		{"config", true, true},
		{"logout", true, true},
		{"version", true, true},
		{"-control", false, false},
		{"-insecure", false, false},
		{"-token", false, false},
		{"bogus-verb", false, false},
		{"", false, false},
	}

	for _, tc := range cases {
		fn, ok := verbFunc(tc.arg)
		if ok != tc.wantOK {
			t.Fatalf("verbFunc(%q) ok = %v, want %v", tc.arg, ok, tc.wantOK)
		}
		if ok && fn == nil {
			t.Fatalf("verbFunc(%q) returned ok=true but nil func", tc.arg)
		}
		if !ok && fn != nil {
			t.Fatalf("verbFunc(%q) returned ok=false but non-nil func", tc.arg)
		}
	}
}

func TestLegacyFlagLeadingArgFallsThrough(t *testing.T) {
	legacyStyleArgs := []string{"-insecure", "-control", "127.0.0.1:7443", "-target", "http://127.0.0.1:3001", "-subdomain", "demo", "-token", "abc", "-instance-id", "xyz"}
	if _, ok := verbFunc(legacyStyleArgs[0]); ok {
		t.Fatalf("verbFunc(%q) = ok, want the legacy bare-flag form to fall through to flag.Parse()", legacyStyleArgs[0])
	}
}

func TestResolveTargetURL(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"3001", "http://127.0.0.1:3001", false},
		{"1", "http://127.0.0.1:1", false},
		{"65535", "http://127.0.0.1:65535", false},
		{"http://127.0.0.1:3001", "http://127.0.0.1:3001", false},
		{"https://example.com:8443", "https://example.com:8443", false},
		{"0", "", true},
		{"70000", "", true},
		{"-1", "", true},
		{"abc", "", true},
		{"", "", true},
	}

	for _, tc := range cases {
		got, err := resolveTargetURL(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("resolveTargetURL(%q) = %q, nil; want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("resolveTargetURL(%q) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("resolveTargetURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestResolveTokenPrecedenceFlagBeatsEnvBeatsConfig(t *testing.T) {
	cfg := config.Config{Token: "config-token"}

	got, err := resolveToken("flag-token", "env-token", cfg)
	if err != nil {
		t.Fatalf("resolveToken: %v", err)
	}
	if got != "flag-token" {
		t.Fatalf("resolveToken with all three set = %q, want flag to win (%q)", got, "flag-token")
	}

	got, err = resolveToken("", "env-token", cfg)
	if err != nil {
		t.Fatalf("resolveToken: %v", err)
	}
	if got != "env-token" {
		t.Fatalf("resolveToken with flag empty = %q, want env to win (%q)", got, "env-token")
	}

	got, err = resolveToken("", "", cfg)
	if err != nil {
		t.Fatalf("resolveToken: %v", err)
	}
	if got != "config-token" {
		t.Fatalf("resolveToken with flag and env empty = %q, want config value (%q)", got, "config-token")
	}

	_, err = resolveToken("", "", config.Config{})
	if err == nil {
		t.Fatalf("resolveToken with nothing set should error, pointing at 'ngstone auth'")
	}
	if err != errNoToken {
		t.Fatalf("resolveToken error = %v, want errNoToken", err)
	}
}

func TestParsePermissiveAcceptsFlagsAfterPositional(t *testing.T) {
	fs := flag.NewFlagSet("port", flag.ContinueOnError)
	subdomain := fs.String("subdomain", "", "")
	insecure := fs.Bool("insecure", false, "")

	positionals, err := parsePermissive(fs, []string{"3001", "--subdomain", "demo", "--insecure"})
	if err != nil {
		t.Fatalf("parsePermissive: %v", err)
	}
	if len(positionals) != 1 || positionals[0] != "3001" {
		t.Fatalf("positionals = %v, want [3001]", positionals)
	}
	if *subdomain != "demo" {
		t.Fatalf("subdomain = %q, want demo", *subdomain)
	}
	if !*insecure {
		t.Fatalf("insecure = false, want true")
	}
}

func TestParsePermissiveAcceptsFlagsBeforePositional(t *testing.T) {
	fs := flag.NewFlagSet("port", flag.ContinueOnError)
	subdomain := fs.String("subdomain", "", "")

	positionals, err := parsePermissive(fs, []string{"--subdomain", "demo", "3001"})
	if err != nil {
		t.Fatalf("parsePermissive: %v", err)
	}
	if len(positionals) != 1 || positionals[0] != "3001" {
		t.Fatalf("positionals = %v, want [3001]", positionals)
	}
	if *subdomain != "demo" {
		t.Fatalf("subdomain = %q, want demo", *subdomain)
	}
}

func TestResolveServerPrecedenceFlagBeatsConfigBeatsDefault(t *testing.T) {
	cfg := config.Config{Server: "config.example.com:4443"}

	if got := resolveServer("flag.example.com:4443", cfg); got != "flag.example.com:4443" {
		t.Fatalf("resolveServer with flag set = %q, want flag to win", got)
	}
	if got := resolveServer("", cfg); got != "config.example.com:4443" {
		t.Fatalf("resolveServer with flag empty = %q, want config value", got)
	}
	if got := resolveServer("", config.Config{}); got != defaultServer {
		t.Fatalf("resolveServer with nothing set = %q, want default %q", got, defaultServer)
	}
}
