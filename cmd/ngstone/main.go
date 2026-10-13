package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ngstone/internal/agent"
	"ngstone/internal/config"
	"ngstone/internal/inspect"
	"ngstone/internal/tui"
	"ngstone/internal/version"
)

const defaultServer = "ngstone.site:4443"

var errNoToken = errors.New("no token configured; run 'ngstone auth <token>' first")

var verbs = map[string]func([]string) int{
	"auth":    cmdAuth,
	"port":    cmdPort,
	"tcp":     cmdTCP,
	"start":   cmdStart,
	"config":  cmdConfig,
	"logout":  cmdLogout,
	"version": cmdVersion,
}

func verbFunc(arg string) (func([]string) int, bool) {
	if strings.HasPrefix(arg, "-") {
		return nil, false
	}
	fn, ok := verbs[arg]
	return fn, ok
}

const usageText = `ngstone exposes a local port to the internet through the ngstone relay.

Usage:
  ngstone <command> [arguments]

Commands:
  auth <token>            verify and save an auth token
  port <port|url>         expose a local port or URL through the tunnel
  tcp <port|host:port>    expose a raw TCP service through the tunnel
  start [name ...]        start the tunnels defined in ngstone.yml
  config                  view or set local configuration
  logout                  remove the saved auth token
  version                 print the ngstone version

Examples:
  ngstone auth <token>
  ngstone port 3000
  ngstone port 3000 --subdomain demo
  ngstone port 3000 --host-header demo.localhost:3000
  ngstone tcp 5432
  ngstone tcp db.local:5432 --remote-port 15432
`

func printUsage(w *os.File) {
	fmt.Fprint(w, usageText)
}

func isHelpFlag(arg string) bool {
	return arg == "-h" || arg == "--help" || arg == "-help"
}

func main() {
	if len(os.Args) <= 1 {
		printUsage(os.Stderr)
		os.Exit(1)
	}
	if isHelpFlag(os.Args[1]) {
		printUsage(os.Stdout)
		os.Exit(0)
	}
	if fn, ok := verbFunc(os.Args[1]); ok {
		os.Exit(fn(os.Args[2:]))
	}
	legacyMain()
}

func resolveToken(flagVal, envVal string, cfg config.Config) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if envVal != "" {
		return envVal, nil
	}
	if cfg.Token != "" {
		return cfg.Token, nil
	}
	return "", errNoToken
}

func resolveServer(flagVal string, cfg config.Config) string {
	if flagVal != "" {
		return flagVal
	}
	if cfg.Server != "" {
		return cfg.Server
	}
	return defaultServer
}

func resolveTargetURL(arg string) (string, error) {
	if strings.Contains(arg, "://") {
		u, err := url.Parse(arg)
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("invalid target URL %q", arg)
		}
		return arg, nil
	}
	n, err := strconv.Atoi(arg)
	if err != nil {
		return "", fmt.Errorf("invalid port %q: must be a port number or a URL like http://127.0.0.1:3000", arg)
	}
	if n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid port %d: must be between 1 and 65535", n)
	}
	return fmt.Sprintf("http://127.0.0.1:%d", n), nil
}

func splitFlagsAndPositionals(fs *flag.FlagSet, args []string) (flagArgs, positionals []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positionals = append(positionals, a)
			continue
		}
		flagArgs = append(flagArgs, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue
		}
		f := fs.Lookup(name)
		isBool := false
		if f != nil {
			if bv, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bv.IsBoolFlag() {
				isBool = true
			}
		}
		if !isBool && i+1 < len(args) {
			i++
			flagArgs = append(flagArgs, args[i])
		}
	}
	return flagArgs, positionals
}

func parsePermissive(fs *flag.FlagSet, args []string) ([]string, error) {
	flagArgs, positionals := splitFlagsAndPositionals(fs, args)
	if err := fs.Parse(flagArgs); err != nil {
		return nil, err
	}
	return positionals, nil
}

const agentShutdownGrace = 5 * time.Second

var stdoutIsTerminal = defaultStdoutIsTerminal

func defaultStdoutIsTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func shouldUseTUI(noTUI bool) bool {
	if noTUI {
		return false
	}
	return stdoutIsTerminal()
}

func legacyShouldUseTUI(noTUI bool) bool {
	return false
}

func displayOrNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func cmdAuth(args []string) int {
	fs := flag.NewFlagSet("auth", flag.ContinueOnError)
	serverFlag := fs.String("server", "", "edge control plane address to verify against (defaults to config or "+defaultServer+")")
	insecure := fs.Bool("insecure", false, "dial the control plane in plaintext (dev/test only)")
	serverName := fs.String("server-name", agent.DefaultServerName, "TLS ServerName/SNI to verify against (ignored with -insecure)")
	pin := fs.String("pin", "", "optional \"sha256/BASE64\" SPKI pin")
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprintln(os.Stderr, "usage: ngstone auth <token>")
		return 2
	}
	token := positionals[0]

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: loading config: %v\n", err)
		return 1
	}
	server := resolveServer(*serverFlag, cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	verr := agent.Verify(ctx, agent.Config{
		ControlAddr: server,
		Token:       token,
		Insecure:    *insecure,
		ServerName:  *serverName,
		Pin:         *pin,
	})
	if verr != nil {
		switch {
		case errors.Is(verr, agent.ErrBadToken):
			fmt.Fprintf(os.Stderr, "ngstone: %s rejected this token: %v\n", server, verr)
			fmt.Fprintln(os.Stderr, "double-check the token and try again")
		case errors.Is(verr, agent.ErrUnreachable):
			fmt.Fprintf(os.Stderr, "ngstone: could not reach %s: %v\n", server, verr)
			fmt.Fprintln(os.Stderr, "check the server address (ngstone config set server <addr>) and your network connection")
		default:
			fmt.Fprintf(os.Stderr, "ngstone: verify failed: %v\n", verr)
		}
		return 1
	}

	cfg.Token = token
	cfg.Server = server
	if err := config.Save(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: saving config: %v\n", err)
		return 1
	}
	fmt.Printf("verified against %s and saved\n", server)
	return 0
}

type stringSliceValue []string

func (s *stringSliceValue) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *stringSliceValue) Set(v string) error {
	*s = append(*s, v)
	return nil
}

const maxAccessListLen = 64

func parseBasicAuthCreds(pairs []string) ([]string, error) {
	if len(pairs) > maxAccessListLen {
		return nil, fmt.Errorf("too many -basic-auth entries (max %d)", maxAccessListLen)
	}
	digests := make([]string, 0, len(pairs))
	for i, pair := range pairs {
		user, pass, ok := strings.Cut(pair, ":")
		if !ok || user == "" || pass == "" {
			return nil, fmt.Errorf("invalid --basic-auth entry #%d: expected user:pass with a non-empty user and password", i+1)
		}
		sum := sha256.Sum256([]byte(user + ":" + pass))
		digests = append(digests, hex.EncodeToString(sum[:]))
	}
	return digests, nil
}

func parseAllowCIDRs(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	cidrs := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("--allow-cidr %q contains no valid CIDRs", s)
		}
		if _, err := netip.ParsePrefix(p); err != nil {
			return nil, fmt.Errorf("invalid -allow-cidr entry %q: %v", p, err)
		}
		cidrs = append(cidrs, p)
	}
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("--allow-cidr %q contains no valid CIDRs", s)
	}
	if len(cidrs) > maxAccessListLen {
		return nil, fmt.Errorf("too many -allow-cidr entries (max %d)", maxAccessListLen)
	}
	return cidrs, nil
}

type portFlags struct {
	subdomain     string
	server        string
	token         string
	instanceID    string
	insecure      bool
	serverName    string
	pin           string
	hostHeader    string
	noTUI         bool
	basicAuth     stringSliceValue
	basicAuthFile string
	allowCIDR     string
}

func newPortFlagSet() (*flag.FlagSet, *portFlags) {
	fs := flag.NewFlagSet("port", flag.ContinueOnError)
	pf := &portFlags{}
	fs.StringVar(&pf.subdomain, "subdomain", "", "requested subdomain (empty = server-assigned)")
	fs.StringVar(&pf.subdomain, "s", "", "shorthand for -subdomain")
	fs.StringVar(&pf.server, "server", "", "edge control plane address override (defaults to config or "+defaultServer+")")
	fs.StringVar(&pf.token, "token", "", "auth token override (defaults to NGSTONE_TOKEN or the saved config)")
	fs.StringVar(&pf.instanceID, "instance-id", "", "internal/undocumented: force a specific instance id (testing only)")
	fs.BoolVar(&pf.insecure, "insecure", false, "dial the control plane in plaintext (dev/test only, no certificates involved)")
	fs.StringVar(&pf.serverName, "server-name", agent.DefaultServerName, "TLS ServerName/SNI to verify against (ignored with -insecure)")
	fs.StringVar(&pf.pin, "pin", "", "optional \"sha256/BASE64\" SPKI pin, checked in addition to normal chain validation")
	fs.StringVar(&pf.hostHeader, "host-header", "", "Host header sent to the local app (empty = preserve the public host)")
	fs.BoolVar(&pf.noTUI, "no-tui", false, "disable the terminal inspector UI and log plain text to stderr")
	fs.Var(&pf.basicAuth, "basic-auth", "require HTTP basic auth (user:pass); repeatable for multiple credentials; WARNING: visible to other local users via ps/proc for this process's lifetime, prefer -basic-auth-file or $NGSTONE_BASIC_AUTH")
	fs.StringVar(&pf.basicAuthFile, "basic-auth-file", "", "path to a file with one user:pass credential per line (blank lines and lines starting with # are ignored); safer than -basic-auth")
	fs.StringVar(&pf.allowCIDR, "allow-cidr", "", "comma-separated CIDRs allowed to reach the tunnel (empty = allow all)")
	return fs, pf
}

func splitBasicAuthEnv(v string) []string {
	lines := strings.Split(v, "\n")
	pairs := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		pairs = append(pairs, l)
	}
	return pairs
}

func readBasicAuthFile(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading -basic-auth-file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "ngstone: warning: %s is group/world readable; consider chmod 600 to protect credentials\n", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading -basic-auth-file: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	pairs := make([]string, 0, len(lines))
	for i, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		user, pass, ok := strings.Cut(l, ":")
		if !ok || user == "" || pass == "" {
			return nil, fmt.Errorf("--basic-auth-file %s line %d: expected user:pass with a non-empty user and password", path, i+1)
		}
		pairs = append(pairs, l)
	}
	return pairs, nil
}

func resolveBasicAuthPairs(flagPairs []string, filePath, envVal string) ([]string, error) {
	if len(flagPairs) > 0 {
		return flagPairs, nil
	}
	if filePath != "" {
		pairs, err := readBasicAuthFile(filePath)
		if err != nil {
			return nil, err
		}
		if len(pairs) == 0 {
			return nil, fmt.Errorf("--basic-auth-file %s contains no credentials", filePath)
		}
		return pairs, nil
	}
	if envVal != "" {
		pairs := splitBasicAuthEnv(envVal)
		if len(pairs) == 0 {
			return nil, fmt.Errorf("NGSTONE_BASIC_AUTH is set but contains no credentials")
		}
		return pairs, nil
	}
	return nil, nil
}

func cmdPort(args []string) int {
	fs, pf := newPortFlagSet()
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprintln(os.Stderr, "usage: ngstone port <port|url> [--subdomain name]")
		return 2
	}

	targetURL, err := resolveTargetURL(positionals[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: loading config: %v\n", err)
		return 1
	}

	token, err := resolveToken(pf.token, os.Getenv("NGSTONE_TOKEN"), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ngstone: "+err.Error())
		return 1
	}
	server := resolveServer(pf.server, cfg)

	basicAuthPairs, err := resolveBasicAuthPairs(pf.basicAuth, pf.basicAuthFile, os.Getenv("NGSTONE_BASIC_AUTH"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}
	basicAuthDigests, err := parseBasicAuthCreds(basicAuthPairs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}
	allowCIDRs, err := parseAllowCIDRs(pf.allowCIDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}

	acfg := agent.Config{
		ControlAddr: server,
		Token:       token,
		Subdomain:   pf.subdomain,
		TargetURL:   targetURL,
		HostHeader:  pf.hostHeader,
		InstanceID:  pf.instanceID,

		BasicAuthSHA256: basicAuthDigests,
		AllowCIDRs:      allowCIDRs,

		Insecure:   pf.insecure,
		ServerName: pf.serverName,
		Pin:        pf.pin,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if shouldUseTUI(pf.noTUI) {
		return runPortTUI(ctx, acfg)
	}
	return runPortPlain(ctx, acfg)
}

func runPortPlain(ctx context.Context, acfg agent.Config) int {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	a := agent.New(acfg)

	logger.Info("ngstone: starting", "control", acfg.ControlAddr, "target", acfg.TargetURL, "insecure", acfg.Insecure)
	if err := a.Run(ctx); err != nil {
		logger.Error("ngstone: exited with error", "err", err)
		return 1
	}
	return 0
}

func validatePort(s string) error {
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("must be a port number")
	}
	if n < 1 || n > 65535 {
		return fmt.Errorf("must be between 1 and 65535")
	}
	return nil
}

func resolveTCPTarget(arg string) (string, error) {
	if strings.Contains(arg, ":") {
		host, port, err := net.SplitHostPort(arg)
		if err != nil {
			return "", fmt.Errorf("invalid target %q: %v", arg, err)
		}
		if host == "" {
			return "", fmt.Errorf("invalid target %q: missing host", arg)
		}
		if err := validatePort(port); err != nil {
			return "", fmt.Errorf("invalid target %q: port %v", arg, err)
		}
		return net.JoinHostPort(host, port), nil
	}
	if err := validatePort(arg); err != nil {
		return "", fmt.Errorf("invalid port %q: %v", arg, err)
	}
	return net.JoinHostPort("127.0.0.1", arg), nil
}

type tcpFlags struct {
	remotePort int
	server     string
	token      string
	instanceID string
	insecure   bool
	serverName string
	pin        string
	allowCIDR  string
}

func newTCPFlagSet() (*flag.FlagSet, *tcpFlags) {
	fs := flag.NewFlagSet("tcp", flag.ContinueOnError)
	tf := &tcpFlags{}
	fs.IntVar(&tf.remotePort, "remote-port", 0, "requested remote port (0 = server-assigned)")
	fs.IntVar(&tf.remotePort, "r", 0, "shorthand for -remote-port")
	fs.StringVar(&tf.server, "server", "", "edge control plane address override (defaults to config or "+defaultServer+")")
	fs.StringVar(&tf.token, "token", "", "auth token override (defaults to NGSTONE_TOKEN or the saved config)")
	fs.StringVar(&tf.instanceID, "instance-id", "", "internal/undocumented: force a specific instance id (testing only)")
	fs.BoolVar(&tf.insecure, "insecure", false, "dial the control plane in plaintext (dev/test only, no certificates involved)")
	fs.StringVar(&tf.serverName, "server-name", agent.DefaultServerName, "TLS ServerName/SNI to verify against (ignored with -insecure)")
	fs.StringVar(&tf.pin, "pin", "", "optional \"sha256/BASE64\" SPKI pin, checked in addition to normal chain validation")
	fs.StringVar(&tf.allowCIDR, "allow-cidr", "", "comma-separated CIDRs allowed to reach the tunnel (empty = allow all)")
	return fs, tf
}

func cmdTCP(args []string) int {
	fs, tf := newTCPFlagSet()
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprintln(os.Stderr, "usage: ngstone tcp <port|host:port> [--remote-port N]")
		return 2
	}

	target, err := resolveTCPTarget(positionals[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: loading config: %v\n", err)
		return 1
	}

	token, err := resolveToken(tf.token, os.Getenv("NGSTONE_TOKEN"), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ngstone: "+err.Error())
		return 1
	}
	server := resolveServer(tf.server, cfg)

	allowCIDRs, err := parseAllowCIDRs(tf.allowCIDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}

	acfg := agent.Config{
		ControlAddr: server,
		Token:       token,
		Kind:        "tcp",
		TargetURL:   target,
		RemotePort:  tf.remotePort,
		InstanceID:  tf.instanceID,

		AllowCIDRs: allowCIDRs,

		Insecure:   tf.insecure,
		ServerName: tf.serverName,
		Pin:        tf.pin,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return runTCPPlain(ctx, acfg)
}

func runTCPPlain(ctx context.Context, acfg agent.Config) int {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	events := make(chan agent.StatusEvent, 16)
	acfg.Events = events

	a := agent.New(acfg)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-events:
				if !ok {
					return
				}
				if ev.State == agent.StateOnline && ev.URL != "" {
					fmt.Printf("%s -> %s\n", ev.URL, acfg.TargetURL)
				}
			}
		}
	}()

	logger.Info("ngstone: starting", "control", acfg.ControlAddr, "target", acfg.TargetURL, "kind", "tcp", "insecure", acfg.Insecure)
	if err := a.Run(ctx); err != nil {
		logger.Error("ngstone: exited with error", "err", err)
		return 1
	}
	return 0
}

func runPortTUI(ctx context.Context, acfg agent.Config) int {
	ring := tui.NewLogRing(500)
	logger := slog.New(ring)
	slog.SetDefault(logger)

	events := make(chan agent.StatusEvent, 16)
	acfg.Store = inspect.NewStore()
	acfg.Events = events

	a := agent.New(acfg)

	logger.Info("ngstone: starting", "control", acfg.ControlAddr, "target", acfg.TargetURL, "insecure", acfg.Insecure)

	status := make(chan tui.StatusEvent, 16)

	res := supervise(ctx, agentShutdownGrace,
		func(agentCtx context.Context) error {
			go bridgeStatus(agentCtx, events, status)
			return a.Run(agentCtx)
		},
		func(tuiCtx context.Context) error {
			return tui.Run(tuiCtx, tui.Options{
				Store:  a.Store(),
				Target: a.Target(),
				RT:     a.Transport(),
				Status: status,
				Logs:   ring,
			})
		})

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	return finishPortTUI(os.Stderr, ring.Lines(), res, agentShutdownGrace)
}

func dumpLogRing(w io.Writer, lines []string) {
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
}

func finishPortTUI(w io.Writer, lines []string, res superviseResult, grace time.Duration) int {
	dumpLogRing(w, lines)

	if !res.agentStopped {
		fmt.Fprintf(w, "ngstone: timed out after %s waiting for the tunnel to shut down\n", grace)
		return 1
	}
	if res.agentErr != nil {
		fmt.Fprintf(w, "ngstone: exited with error: %v\n", res.agentErr)
		return 1
	}
	if res.tuiErr != nil {
		fmt.Fprintf(w, "ngstone: inspector exited with error: %v\n", res.tuiErr)
		return 1
	}
	return 0
}

type superviseResult struct {
	agentErr     error
	tuiErr       error
	agentStopped bool
}

func supervise(ctx context.Context, grace time.Duration, runAgent, runTUI func(context.Context) error) superviseResult {
	agentCtx, cancelAgent := context.WithCancel(ctx)
	defer cancelAgent()

	var agentErr error
	agentDone := make(chan struct{})
	go func() {
		defer close(agentDone)
		agentErr = runAgent(agentCtx)
	}()

	tuiCtx, cancelTUI := context.WithCancel(ctx)
	defer cancelTUI()

	tuiDone := make(chan struct{})
	go func() {
		select {
		case <-agentDone:
			cancelTUI()
		case <-tuiDone:
		}
	}()

	tuiErr := runTUI(tuiCtx)
	close(tuiDone)

	cancelAgent()

	agentStopped := true
	select {
	case <-agentDone:
	case <-time.After(grace):
		agentStopped = false
	}

	res := superviseResult{tuiErr: tuiErr, agentStopped: agentStopped}
	if agentStopped {
		res.agentErr = agentErr
	}
	return res
}

func bridgeStatus(ctx context.Context, in <-chan agent.StatusEvent, out chan<- tui.StatusEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-in:
			if !ok {
				return
			}
			var err error
			if ev.Err != "" {
				err = errors.New(ev.Err)
			}
			select {
			case out <- tui.StatusEvent{Tunnel: ev.Tunnel, State: ev.State, Hostname: ev.Hostname, URL: ev.URL, Err: err}:
			case <-ctx.Done():
				return
			default:
			}
		}
	}
}

func cmdConfig(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ngstone config <set|get|path> ...")
		return 2
	}
	switch args[0] {
	case "set":
		return cmdConfigSet(args[1:])
	case "get":
		return cmdConfigGet(args[1:])
	case "path":
		return cmdConfigPath(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "ngstone: unknown config subcommand %q\n", args[0])
		return 2
	}
}

func cmdConfigSet(args []string) int {
	if len(args) != 2 || args[0] != "server" {
		fmt.Fprintln(os.Stderr, "usage: ngstone config set server <addr>")
		return 2
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: loading config: %v\n", err)
		return 1
	}
	cfg.Server = args[1]
	if err := config.Save(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: saving config: %v\n", err)
		return 1
	}
	fmt.Printf("server set to %s\n", args[1])
	return 0
}

func cmdConfigGet(args []string) int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: loading config: %v\n", err)
		return 1
	}
	red := cfg.Redacted()
	if len(args) == 0 {
		fmt.Printf("token: %s\n", displayOrNone(red.Token))
		fmt.Printf("server: %s\n", displayOrNone(red.Server))
		return 0
	}
	switch args[0] {
	case "token":
		fmt.Println(displayOrNone(red.Token))
	case "server":
		fmt.Println(displayOrNone(red.Server))
	default:
		fmt.Fprintf(os.Stderr, "ngstone: unknown config key %q\n", args[0])
		return 2
	}
	return 0
}

func cmdConfigPath(args []string) int {
	p, err := config.Path()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}
	fmt.Println(p)
	return 0
}

func cmdLogout(args []string) int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: loading config: %v\n", err)
		return 1
	}
	cfg.Token = ""
	if err := config.Save(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: saving config: %v\n", err)
		return 1
	}
	fmt.Println("logged out")
	return 0
}

func cmdVersion(args []string) int {
	fmt.Println("ngstone " + version.String())
	return 0
}

func legacyMain() {
	controlAddr := flag.String("control", defaultServer, "edge control plane address")
	token := flag.String("token", "", "shared auth token (defaults to NGSTONE_TOKEN env var)")
	target := flag.String("target", "http://127.0.0.1:3000", "local target URL to forward requests to")
	subdomain := flag.String("subdomain", "", "requested subdomain (empty = server-assigned)")
	hostHeader := flag.String("host-header", "", "Host header sent to the local app (empty = preserve the public host)")
	instanceID := flag.String("instance-id", "", "internal/undocumented: force a specific instance id (testing only)")

	insecure := flag.Bool("insecure", false, "dial the control plane in plaintext (dev/test only, no certificates involved)")
	serverName := flag.String("server-name", agent.DefaultServerName, "TLS ServerName/SNI to verify against (ignored with -insecure)")
	pin := flag.String("pin", "", "optional \"sha256/BASE64\" SPKI pin, checked in addition to normal chain validation (off by default)")
	showVersion := flag.Bool("version", false, "print version and exit")
	noTUI := flag.Bool("no-tui", false, "disable the terminal inspector UI (this legacy flag form is always plain output)")
	flag.Parse()

	if *showVersion {
		fmt.Println("ngstone " + version.String())
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	cfg, _ := config.Load()

	ctl := *controlAddr
	controlExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "control" {
			controlExplicit = true
		}
	})
	if !controlExplicit && cfg.Server != "" {
		ctl = cfg.Server
	}

	tok, err := resolveToken(*token, os.Getenv("NGSTONE_TOKEN"), cfg)
	if err != nil {
		logger.Error("ngstone: " + err.Error())
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	acfg := agent.Config{
		ControlAddr: ctl,
		Token:       tok,
		Subdomain:   *subdomain,
		TargetURL:   *target,
		HostHeader:  *hostHeader,
		InstanceID:  *instanceID,

		Insecure:   *insecure,
		ServerName: *serverName,
		Pin:        *pin,
	}

	if legacyShouldUseTUI(*noTUI) {
		os.Exit(runPortTUI(ctx, acfg))
	}

	a := agent.New(acfg)

	logger.Info("ngstone: starting", "control", ctl, "target", *target, "insecure", *insecure)
	if err := a.Run(ctx); err != nil {
		logger.Error("ngstone: exited with error", "err", err)
		os.Exit(1)
	}
}
