package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ngstone/internal/agent"
	"ngstone/internal/config"
	"ngstone/internal/tui"
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

func TestVerbFuncDispatchIncludesTCP(t *testing.T) {
	fn, ok := verbFunc("tcp")
	if !ok || fn == nil {
		t.Fatalf("verbFunc(%q) ok=%v (nil func=%v), want a dispatchable tcp verb", "tcp", ok, fn == nil)
	}
}

func TestResolveTCPTarget(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"22", "127.0.0.1:22", false},
		{"5432", "127.0.0.1:5432", false},
		{"1", "127.0.0.1:1", false},
		{"65535", "127.0.0.1:65535", false},
		{"127.0.0.1:22", "127.0.0.1:22", false},
		{"db.local:5432", "db.local:5432", false},
		{"0", "", true},
		{"70000", "", true},
		{"abc", "", true},
		{"", "", true},
		{"host:0", "", true},
		{"host:70000", "", true},
		{"host:abc", "", true},
		{":22", "", true},
	}

	for _, tc := range cases {
		got, err := resolveTCPTarget(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("resolveTCPTarget(%q) = %q, nil; want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("resolveTCPTarget(%q) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("resolveTCPTarget(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTCPFlagSetParsesRemotePort(t *testing.T) {
	fs, tf := newTCPFlagSet()
	positionals, err := parsePermissive(fs, []string{"5432", "--remote-port", "15432"})
	if err != nil {
		t.Fatalf("parsePermissive: %v", err)
	}
	if len(positionals) != 1 || positionals[0] != "5432" {
		t.Fatalf("positionals = %v, want [5432]", positionals)
	}
	if tf.remotePort != 15432 {
		t.Fatalf("remotePort = %d, want 15432", tf.remotePort)
	}

	fs, tf = newTCPFlagSet()
	if _, err := parsePermissive(fs, []string{"-r", "2222", "db.local:22"}); err != nil {
		t.Fatalf("parsePermissive short flag: %v", err)
	}
	if tf.remotePort != 2222 {
		t.Fatalf("remotePort via -r = %d, want 2222", tf.remotePort)
	}

	fs, tf = newTCPFlagSet()
	if _, err := parsePermissive(fs, []string{"5432"}); err != nil {
		t.Fatalf("parsePermissive without flag: %v", err)
	}
	if tf.remotePort != 0 {
		t.Fatalf("remotePort default = %d, want 0 (server-assigned)", tf.remotePort)
	}
}

func TestTCPLeadingFlagFallsThroughToLegacy(t *testing.T) {
	if _, ok := verbFunc("-remote-port"); ok {
		t.Fatalf("verbFunc(%q) = ok, want a leading -flag to fall through to the legacy path", "-remote-port")
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

func TestPortFlagSetParsesNoTUI(t *testing.T) {
	fs, pf := newPortFlagSet()
	positionals, err := parsePermissive(fs, []string{"3001", "--no-tui"})
	if err != nil {
		t.Fatalf("parsePermissive: %v", err)
	}
	if len(positionals) != 1 || positionals[0] != "3001" {
		t.Fatalf("positionals = %v, want [3001]; --no-tui must be treated as a boolean flag", positionals)
	}
	if !pf.noTUI {
		t.Fatalf("pf.noTUI = false after --no-tui, want true")
	}

	fs, pf = newPortFlagSet()
	if _, err := parsePermissive(fs, []string{"3001"}); err != nil {
		t.Fatalf("parsePermissive: %v", err)
	}
	if pf.noTUI {
		t.Fatalf("pf.noTUI = true without the flag, want false")
	}

	fs, pf = newPortFlagSet()
	if _, err := parsePermissive(fs, []string{"3001", "-no-tui", "--subdomain", "demo"}); err != nil {
		t.Fatalf("parsePermissive with single-dash form: %v", err)
	}
	if !pf.noTUI {
		t.Fatalf("pf.noTUI = false after -no-tui, want true")
	}
	if pf.subdomain != "demo" {
		t.Fatalf("subdomain = %q, want demo; -no-tui must not swallow the next argument", pf.subdomain)
	}
}

func TestShouldUseTUIRequiresFlagAndTerminal(t *testing.T) {
	orig := stdoutIsTerminal
	t.Cleanup(func() { stdoutIsTerminal = orig })

	cases := []struct {
		terminal bool
		noTUI    bool
		want     bool
	}{
		{terminal: true, noTUI: false, want: true},
		{terminal: true, noTUI: true, want: false},
		{terminal: false, noTUI: false, want: false},
		{terminal: false, noTUI: true, want: false},
	}
	for _, tc := range cases {
		stdoutIsTerminal = func() bool { return tc.terminal }
		if got := shouldUseTUI(tc.noTUI); got != tc.want {
			t.Fatalf("shouldUseTUI(noTUI=%v) with terminal=%v = %v, want %v", tc.noTUI, tc.terminal, got, tc.want)
		}
	}
}

func TestNonTTYStdoutSelectsPlainMode(t *testing.T) {
	if defaultStdoutIsTerminal() {
		t.Skip("test process stdout is a terminal; this check needs a non-TTY stdout")
	}
	if shouldUseTUI(false) {
		t.Fatalf("shouldUseTUI(false) = true with a non-TTY stdout, want plain mode")
	}
}

func TestDefaultStdoutIsTerminalRejectsPipes(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	orig := os.Stdout
	os.Stdout = w
	got := defaultStdoutIsTerminal()
	os.Stdout = orig

	if got {
		t.Fatalf("defaultStdoutIsTerminal() = true for a pipe, want false")
	}
}

func TestLegacyPathNeverUsesTUI(t *testing.T) {
	orig := stdoutIsTerminal
	t.Cleanup(func() { stdoutIsTerminal = orig })
	stdoutIsTerminal = func() bool { return true }

	for _, noTUI := range []bool{false, true} {
		if legacyShouldUseTUI(noTUI) {
			t.Fatalf("legacyShouldUseTUI(%v) = true, want the legacy bare-flag path to always stay plain", noTUI)
		}
	}
}

func TestSuperviseCancelsAgentWhenTUIExits(t *testing.T) {
	agentSawCancel := make(chan struct{})
	runAgent := func(ctx context.Context) error {
		<-ctx.Done()
		close(agentSawCancel)
		return nil
	}
	runTUI := func(ctx context.Context) error { return nil }

	start := time.Now()
	res := supervise(context.Background(), 2*time.Second, runAgent, runTUI)
	elapsed := time.Since(start)

	if !res.agentStopped {
		t.Fatalf("agentStopped = false, want the agent context to be cancelled when the TUI exits")
	}
	select {
	case <-agentSawCancel:
	default:
		t.Fatalf("agent goroutine never observed context cancellation")
	}
	if res.agentErr != nil || res.tuiErr != nil {
		t.Fatalf("agentErr = %v, tuiErr = %v, want both nil", res.agentErr, res.tuiErr)
	}
	if elapsed > time.Second {
		t.Fatalf("supervise took %s, want it to return as soon as the agent stops", elapsed)
	}
}

func TestSuperviseTearsDownTUIWhenAgentExitsFirst(t *testing.T) {
	fatal := errors.New("bad token")
	runAgent := func(ctx context.Context) error { return fatal }

	tuiTornDown := make(chan struct{})
	runTUI := func(ctx context.Context) error {
		<-ctx.Done()
		close(tuiTornDown)
		return nil
	}

	var res superviseResult
	superviseDone := make(chan struct{})
	go func() {
		defer close(superviseDone)
		res = supervise(context.Background(), 2*time.Second, runAgent, runTUI)
	}()

	select {
	case <-superviseDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("supervise did not return; the TUI was never torn down after the agent exited")
	}

	select {
	case <-tuiTornDown:
	default:
		t.Fatalf("TUI was never torn down after the agent exited")
	}
	if !errors.Is(res.agentErr, fatal) {
		t.Fatalf("agentErr = %v, want the fatal agent error to be surfaced", res.agentErr)
	}
	if !res.agentStopped {
		t.Fatalf("agentStopped = false, want true")
	}
}

func TestSuperviseReportsAgentThatIgnoresCancellation(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	runAgent := func(ctx context.Context) error {
		<-release
		return nil
	}
	runTUI := func(ctx context.Context) error { return nil }

	res := supervise(context.Background(), 50*time.Millisecond, runAgent, runTUI)
	if res.agentStopped {
		t.Fatalf("agentStopped = true, want false when the agent outlives the grace period")
	}
}

func TestDumpLogRingWritesEveryLineInOrder(t *testing.T) {
	var buf syncBuffer
	dumpLogRing(&buf, []string{"a", "b", "c"})

	if got := buf.String(); got != "a\nb\nc\n" {
		t.Fatalf("dumped log ring = %q, want every line in order", got)
	}
}

func TestDumpLogRingWithNoLinesWritesNothing(t *testing.T) {
	var buf syncBuffer
	dumpLogRing(&buf, nil)
	dumpLogRing(&buf, []string{})

	if got := buf.String(); got != "" {
		t.Fatalf("dumped empty log ring = %q, want nothing written", got)
	}
}

func TestFinishPortTUIDumpsLogsAndReportsExitCode(t *testing.T) {
	agentFatal := errors.New("bad token")
	tuiFatal := errors.New("inspector blew up")

	cases := []struct {
		name     string
		res      superviseResult
		wantCode int
		wantMsg  string
	}{
		{
			name:     "clean shutdown",
			res:      superviseResult{agentStopped: true},
			wantCode: 0,
		},
		{
			name:     "agent error",
			res:      superviseResult{agentStopped: true, agentErr: agentFatal},
			wantCode: 1,
			wantMsg:  "ngstone: exited with error: bad token",
		},
		{
			name:     "tui error",
			res:      superviseResult{agentStopped: true, tuiErr: tuiFatal},
			wantCode: 1,
			wantMsg:  "ngstone: inspector exited with error: inspector blew up",
		},
		{
			name:     "agent outlived grace",
			res:      superviseResult{agentStopped: false, tuiErr: tuiFatal},
			wantCode: 1,
			wantMsg:  "ngstone: timed out after 5s waiting for the tunnel to shut down",
		},
	}

	lines := []string{"level=INFO msg=starting", "level=ERROR msg=dial failed"}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf syncBuffer
			got := finishPortTUI(&buf, lines, tc.res, 5*time.Second)
			out := buf.String()

			if got != tc.wantCode {
				t.Fatalf("finishPortTUI exit code = %d, want %d (output %q)", got, tc.wantCode, out)
			}
			for _, line := range lines {
				if !strings.Contains(out, line+"\n") {
					t.Fatalf("finishPortTUI output = %q, want the buffered log line %q to survive the TUI teardown", out, line)
				}
			}
			if tc.wantMsg != "" && !strings.Contains(out, tc.wantMsg) {
				t.Fatalf("finishPortTUI output = %q, want it to contain %q", out, tc.wantMsg)
			}
			if tc.wantCode == 0 && strings.Contains(out, "ngstone: ") {
				t.Fatalf("finishPortTUI output = %q, want no failure message on a clean exit", out)
			}
		})
	}
}

func TestBridgeStatusConvertsAndExitsOnContextDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	in := make(chan agent.StatusEvent, 4)
	out := make(chan tui.StatusEvent, 4)

	done := make(chan struct{})
	go func() {
		bridgeStatus(ctx, in, out)
		close(done)
	}()

	in <- agent.StatusEvent{State: agent.StateOnline, Hostname: "demo.ngstone.site", URL: "https://demo.ngstone.site"}
	in <- agent.StatusEvent{State: agent.StateOffline, Err: "boom"}

	got := make([]tui.StatusEvent, 0, 2)
	for len(got) < 2 {
		select {
		case ev := <-out:
			got = append(got, ev)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for bridged status events, got %v", got)
		}
	}

	if got[0].State != agent.StateOnline || got[0].Hostname != "demo.ngstone.site" || got[0].Err != nil {
		t.Fatalf("first bridged event = %+v, want the online event with a nil error", got[0])
	}
	if got[1].Err == nil || got[1].Err.Error() != "boom" {
		t.Fatalf("second bridged event err = %v, want an error carrying %q", got[1].Err, "boom")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("bridgeStatus did not exit after context cancellation")
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
