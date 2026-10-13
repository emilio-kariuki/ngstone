package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"ngstone/internal/agent"
	"ngstone/internal/config"
	"ngstone/internal/proto"
)

const (
	defaultShareExpiry     = time.Hour
	defaultShareMaxConns   = 16
	defaultShareConnectors = 8
	expiryWarnFirst        = 5 * time.Minute
	expiryWarnLast         = time.Minute
	connectStatusEvery     = 30 * time.Second
)

var sharePresets = map[string]struct {
	port int
	hint string
}{
	"postgres": {5432, `psql "postgres://%s127.0.0.1:%d/"`},
	"mysql":    {3306, `mysql -h 127.0.0.1 -P %d%s`},
	"redis":    {6379, `redis-cli -p %d`},
	"http":     {8080, `open http://127.0.0.1:%d/`},
}

type shareFlags struct {
	expires       time.Duration
	label         string
	allowCIDR     string
	maxConns      int
	maxConnectors int
	maxUses       int
	singleUse     bool
	idle          time.Duration
	approve       bool
	passphrase    string
	user          string
	auditLog      string
	secretFile    string

	server     string
	token      string
	instanceID string
	insecure   bool
	serverName string
	pin        string
}

func newShareFlagSet() (*flag.FlagSet, *shareFlags) {
	fs := flag.NewFlagSet("share", flag.ContinueOnError)
	sf := &shareFlags{}
	fs.DurationVar(&sf.expires, "expires", defaultShareExpiry, "share lifetime; the edge revokes the link when it elapses (capped by the edge's -max-share-ttl)")
	fs.StringVar(&sf.label, "label", "", "label shown to connectors (defaults to the first target's preset)")
	fs.StringVar(&sf.allowCIDR, "allow-cidr", "", "comma-separated CIDRs connectors must come from (empty = allow all)")
	fs.IntVar(&sf.maxConns, "max-conns", defaultShareMaxConns, "concurrent relayed connections across all connectors")
	fs.IntVar(&sf.maxConnectors, "max-connectors", defaultShareConnectors, "concurrent connector agents")
	fs.IntVar(&sf.maxUses, "max-uses", 0, "how many connector agents may ever join (0 = unlimited; 1 is the same as --single-use)")
	fs.BoolVar(&sf.singleUse, "single-use", false, "lock the link to the first connector agent that uses it")
	fs.DurationVar(&sf.idle, "idle", 0, "close the share after this long with no open connection (0 = never; minimum 30s)")
	fs.BoolVar(&sf.approve, "approve", false, "ask in this terminal before each connector is admitted (y/n within 60s)")
	fs.StringVar(&sf.passphrase, "passphrase", "", "require connectors to type this passphrase too (prefer $NGSTONE_SHARE_PASSPHRASE; ps auxww exposes flags)")
	fs.StringVar(&sf.user, "user", "", "database user to put in the connection hint shown to connectors, e.g. a read-only role")
	fs.StringVar(&sf.auditLog, "audit-log", "", "append every audit event as JSON Lines to this file")
	fs.StringVar(&sf.secretFile, "secret-file", "", "reuse the share secret stored in this file instead of minting one, so the link stays the same across runs; created with mode 0600 if missing ($NGSTONE_SHARE_SECRET also works)")
	fs.StringVar(&sf.server, "server", "", "edge control plane address override (defaults to config or "+defaultServer+")")
	fs.StringVar(&sf.token, "token", "", "auth token override (defaults to NGSTONE_TOKEN or the saved config)")
	fs.StringVar(&sf.instanceID, "instance-id", "", "internal/undocumented: force a specific instance id (testing only)")
	fs.BoolVar(&sf.insecure, "insecure", false, "dial the control plane in plaintext (dev/test only); connectors must pass -insecure too")
	fs.StringVar(&sf.serverName, "server-name", "", "TLS ServerName/SNI to verify against; defaults to the host in the server address (ignored with -insecure)")
	fs.StringVar(&sf.pin, "pin", "", "optional \"sha256/BASE64\" SPKI pin, checked in addition to normal chain validation")
	return fs, sf
}

// parseTargetSpec turns "postgres", "postgres:5433", "redis:db.local:6379",
// "tcp:9000" or "tcp:host:port" into a target.
func parseTargetSpec(spec string, index int) (agent.ShareTargetSpec, error) {
	preset, rest, hasRest := strings.Cut(spec, ":")
	preset = strings.ToLower(preset)
	p, isPreset := sharePresets[preset]
	if !isPreset && preset != "tcp" {
		return agent.ShareTargetSpec{}, fmt.Errorf("unknown preset %q in %q: use postgres, mysql, redis, http or tcp", preset, spec)
	}
	var addr string
	switch {
	case hasRest && rest != "":
		var err error
		addr, err = resolveTCPTarget(rest)
		if err != nil {
			return agent.ShareTargetSpec{}, fmt.Errorf("in %q: %v", spec, err)
		}
	case isPreset:
		addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(p.port))
	default:
		return agent.ShareTargetSpec{}, fmt.Errorf("tcp needs a port or host:port, e.g. tcp:9000")
	}
	defaultPort := p.port
	if preset == "tcp" {
		_, portStr, _ := net.SplitHostPort(addr)
		defaultPort, _ = strconv.Atoi(portStr)
	}
	return agent.ShareTargetSpec{
		ShareTarget: proto.ShareTarget{
			ID:          "t" + strconv.Itoa(index+1),
			Preset:      preset,
			Label:       preset,
			DefaultPort: defaultPort,
		},
		Addr: addr,
	}, nil
}

// resolveShareTargets accepts the two forms:
//
//	ngstone share postgres [port|host:port]        one target, old form
//	ngstone share postgres redis:6380 tcp:9000     one target per spec
func resolveShareTargets(positionals []string) ([]agent.ShareTargetSpec, error) {
	if len(positionals) == 0 {
		return nil, errors.New("usage: ngstone share <preset[:port|:host:port]>... | <preset> [port|host:port]")
	}
	if len(positionals) == 2 && !strings.Contains(positionals[0], ":") {
		if _, _, err := net.SplitHostPort(positionals[1]); err == nil || validatePort(positionals[1]) == nil {
			t, err := parseTargetSpec(positionals[0]+":"+positionals[1], 0)
			if err != nil {
				return nil, err
			}
			return []agent.ShareTargetSpec{t}, nil
		}
	}
	out := make([]agent.ShareTargetSpec, 0, len(positionals))
	for i, spec := range positionals {
		t, err := parseTargetSpec(spec, i)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// resolveShareSecret returns the secret to use and its digest: from a file
// (created on first use), the environment, or freshly minted.
func resolveShareSecret(secretFile, env string) (secret, digest string, reused bool, err error) {
	if secretFile != "" {
		data, rerr := os.ReadFile(secretFile)
		switch {
		case rerr == nil:
			s, perr := agent.ParseShareSecret(string(data))
			if perr != nil {
				return "", "", false, fmt.Errorf("--secret-file %s: %w", secretFile, perr)
			}
			return s, agent.ShareSecretDigest(s), true, nil
		case errors.Is(rerr, os.ErrNotExist):
			s, d, merr := agent.NewShareSecret()
			if merr != nil {
				return "", "", false, merr
			}
			if werr := os.WriteFile(secretFile, []byte(s+"\n"), 0o600); werr != nil {
				return "", "", false, fmt.Errorf("--secret-file %s: %w", secretFile, werr)
			}
			return s, d, false, nil
		default:
			return "", "", false, fmt.Errorf("--secret-file %s: %w", secretFile, rerr)
		}
	}
	if env != "" {
		s, perr := agent.ParseShareSecret(env)
		if perr != nil {
			return "", "", false, fmt.Errorf("NGSTONE_SHARE_SECRET: %w", perr)
		}
		return s, agent.ShareSecretDigest(s), true, nil
	}
	s, d, merr := agent.NewShareSecret()
	return s, d, false, merr
}

func cmdShare(args []string) int {
	fs, sf := newShareFlagSet()
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	targets, err := resolveShareTargets(positionals)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}
	if sf.expires <= 0 {
		fmt.Fprintln(os.Stderr, "ngstone: --expires must be a positive duration such as 30m or 2h")
		return 2
	}
	if sf.maxConns < 1 || sf.maxConnectors < 1 || sf.maxUses < 0 {
		fmt.Fprintln(os.Stderr, "ngstone: --max-conns and --max-connectors must be at least 1, --max-uses at least 0")
		return 2
	}
	if sf.idle < 0 || (sf.idle > 0 && sf.idle < 30*time.Second) {
		fmt.Fprintln(os.Stderr, "ngstone: --idle must be 0 or at least 30s")
		return 2
	}
	allowCIDRs, err := parseAllowCIDRs(sf.allowCIDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: loading config: %v\n", err)
		return 1
	}
	token, err := resolveToken(sf.token, os.Getenv("NGSTONE_TOKEN"), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ngstone: "+err.Error())
		return 1
	}
	server := resolveServer(sf.server, cfg)

	var audit io.WriteCloser
	if sf.auditLog != "" {
		f, err := os.OpenFile(sf.auditLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ngstone: opening --audit-log: %v\n", err)
			return 1
		}
		audit = f
		defer f.Close()
	}

	secret, secretHash, reused, err := resolveShareSecret(sf.secretFile, os.Getenv("NGSTONE_SHARE_SECRET"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}
	passphrase := sf.passphrase
	if passphrase == "" {
		passphrase = os.Getenv("NGSTONE_SHARE_PASSPHRASE")
	}
	label := sf.label
	if label == "" {
		label = targets[0].Preset
	}
	if sf.user != "" {
		for i := range targets {
			targets[i].User = sf.user
		}
	}

	spec := &agent.ShareSpec{
		Label:         label,
		Targets:       targets,
		SecretSHA256:  secretHash,
		ExpiresAt:     time.Now().Add(sf.expires),
		MaxConns:      sf.maxConns,
		MaxConnectors: sf.maxConnectors,
		MaxUses:       sf.maxUses,
		SingleUse:     sf.singleUse,
		AllowCIDRs:    allowCIDRs,
		IdleTimeout:   sf.idle,
		Approve:       sf.approve,
	}
	if passphrase != "" {
		spec.PassphraseSHA256 = proto.PassphraseDigest(secretHash, passphrase)
	}

	acfg := agent.Config{
		ControlAddr: server,
		Token:       token,
		Kind:        proto.KindTCP,
		TargetURL:   targets[0].Addr,
		InstanceID:  sf.instanceID,
		Insecure:    sf.insecure,
		ServerName:  sf.serverName,
		Pin:         sf.pin,
		Share:       spec,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return runShare(ctx, os.Stdout, os.Stdin, acfg, agent.ShareLink(server, secret), reused, audit)
}

func sharePolicyText(spec *agent.ShareSpec) string {
	var parts []string
	if len(spec.AllowCIDRs) == 0 {
		parts = append(parts, "allow all")
	} else {
		parts = append(parts, "allow "+strings.Join(spec.AllowCIDRs, ","))
	}
	parts = append(parts, fmt.Sprintf("%d conns", spec.MaxConns), fmt.Sprintf("%d connectors", spec.MaxConnectors))
	switch {
	case spec.SingleUse || spec.MaxUses == 1:
		parts = append(parts, "single-use")
	case spec.MaxUses > 1:
		parts = append(parts, fmt.Sprintf("%d uses", spec.MaxUses))
	}
	if spec.IdleTimeout > 0 {
		parts = append(parts, "idle "+roundDuration(spec.IdleTimeout))
	}
	if spec.Approve {
		parts = append(parts, "approval required")
	}
	if spec.PassphraseSHA256 != "" {
		parts = append(parts, "passphrase")
	}
	return strings.Join(parts, ", ")
}

func expiresText(at time.Time) string {
	return fmt.Sprintf("in %s (%s UTC)", roundDuration(time.Until(at)), at.UTC().Format("15:04"))
}

// roundDuration renders a duration the way a person says it: 2h, 1h58m,
// 45m, 30s.
func roundDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		d = d.Round(time.Second)
		if d < time.Minute {
			return fmt.Sprintf("%ds", int(d.Seconds()))
		}
	}
	d = d.Round(time.Minute)
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	h, m := int(d.Hours()), int(d.Minutes())%60
	if m == 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh%02dm", h, m)
}

func targetsText(targets []agent.ShareTargetSpec) string {
	parts := make([]string, 0, len(targets))
	for _, t := range targets {
		parts = append(parts, fmt.Sprintf("%s %s", t.Preset, t.Addr))
	}
	return strings.Join(parts, "  ")
}

// shareCommand is one line typed into the sharer's terminal.
type shareCommand struct {
	verb string
	args []string
}

// readShareCommands turns lines on stdin into commands until stdin ends.
func readShareCommands(ctx context.Context, in io.Reader, out chan<- shareCommand) {
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		cmd := shareCommand{verb: strings.ToLower(fields[0]), args: fields[1:]}
		select {
		case out <- cmd:
		case <-ctx.Done():
			return
		}
	}
}

func runShare(ctx context.Context, out io.Writer, in io.Reader, acfg agent.Config, link string, reusedSecret bool, audit io.Writer) int {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	slog.SetDefault(logger)

	spec := acfg.Share
	events := make(chan agent.StatusEvent, 16)
	shareEvents := make(chan proto.ShareEvent, 256)
	acfg.Events = events
	acfg.ShareEvents = shareEvents

	a := agent.New(acfg)

	fmt.Fprintf(out, "share     %s  %s\n", spec.Label, targetsText(spec.Targets))
	fmt.Fprintf(out, "expires   %s   policy: %s\n", expiresText(spec.ExpiresAt), sharePolicyText(spec))
	fmt.Fprintf(out, "link      %s\n", link)
	if reusedSecret {
		fmt.Fprintf(out, "          (same link as last time: the secret came from a file or the environment)\n")
	}
	fmt.Fprintf(out, "\nsend the link to a teammate; they run:  ngstone connect <link>%s\n", insecureHint(acfg.Insecure))
	fmt.Fprintf(out, "commands here:  y <id> / n <id> (approve)   kick <id>   extend 1h   q\n\n")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	commands := make(chan shareCommand, 8)
	go readShareCommands(ctx, in, commands)

	var pendingApprovals []string
	writeAudit := func(ev proto.ShareEvent) {
		if audit == nil {
			return
		}
		if b, err := json.Marshal(ev); err == nil {
			audit.Write(append(b, '\n'))
		}
	}
	handleEvent := func(ev proto.ShareEvent) {
		switch ev.Event {
		case "error":
			fmt.Fprintf(out, "%s  edge refused       %s\n", time.Now().Format("15:04:05"), ev.Reason)
			return
		case proto.ShareEventConnectPending:
			pendingApprovals = append(pendingApprovals, ev.ConnectorID)
		case proto.ShareEventConnectorJoined, proto.ShareEventConnRejected:
			pendingApprovals = removeString(pendingApprovals, ev.ConnectorID)
		}
		fmt.Fprintln(out, agent.FormatShareEvent(ev))
		writeAudit(ev)
	}
	handleCommand := func(cmd shareCommand) {
		now := time.Now().Format("15:04:05")
		switch cmd.verb {
		case "y", "yes", "n", "no":
			allow := cmd.verb == "y" || cmd.verb == "yes"
			id := ""
			if len(cmd.args) > 0 {
				id = cmd.args[0]
			} else if len(pendingApprovals) > 0 {
				id = pendingApprovals[0]
			}
			if id == "" {
				fmt.Fprintf(out, "%s  nothing is waiting for approval\n", now)
				return
			}
			if err := a.Approve(id, allow); err != nil {
				fmt.Fprintf(out, "%s  %v\n", now, err)
				return
			}
			pendingApprovals = removeString(pendingApprovals, id)
			verdict := "approved"
			if !allow {
				verdict = "declined"
			}
			fmt.Fprintf(out, "%s  %s %s\n", now, verdict, id)
		case "kick":
			if len(cmd.args) != 1 {
				fmt.Fprintf(out, "%s  usage: kick <connector id>\n", now)
				return
			}
			if err := a.Kick(cmd.args[0]); err != nil {
				fmt.Fprintf(out, "%s  %v\n", now, err)
			}
		case "extend":
			if len(cmd.args) != 1 {
				fmt.Fprintf(out, "%s  usage: extend <duration>, e.g. extend 1h\n", now)
				return
			}
			d, err := time.ParseDuration(cmd.args[0])
			if err != nil || d <= 0 {
				fmt.Fprintf(out, "%s  bad duration %q\n", now, cmd.args[0])
				return
			}
			if err := a.Extend(time.Now().Add(d)); err != nil {
				fmt.Fprintf(out, "%s  %v\n", now, err)
			}
		case "q", "quit", "exit":
			cancel()
		case "help", "?":
			fmt.Fprintf(out, "commands:  y <id> / n <id>   kick <id>   extend <duration>   q\n")
		default:
			fmt.Fprintf(out, "%s  unknown command %q (try help)\n", now, cmd.verb)
		}
	}

	printerDone := make(chan struct{})
	go func() {
		defer close(printerDone)
		announced := false
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-events:
				switch ev.State {
				case agent.StateOnline:
					if !announced {
						fmt.Fprintf(out, "%s  share live         id %s\n", time.Now().Format("15:04:05"), ev.ShareID)
						announced = true
					} else {
						fmt.Fprintf(out, "%s  reconnected        id %s\n", time.Now().Format("15:04:05"), ev.ShareID)
					}
				case agent.StateReconnecting:
					fmt.Fprintf(out, "%s  edge connection lost, reconnecting\n", time.Now().Format("15:04:05"))
				}
			case ev := <-shareEvents:
				handleEvent(ev)
			case cmd := <-commands:
				handleCommand(cmd)
			}
		}
	}()

	err := a.Run(ctx)
	interrupted := ctx.Err() != nil
	cancel()
	<-printerDone
	// Let queued events print before the final line.
	deadline := time.After(200 * time.Millisecond)
drain:
	for {
		select {
		case ev := <-shareEvents:
			handleEvent(ev)
		case <-deadline:
			break drain
		}
	}

	now := time.Now().Format("15:04:05")
	switch {
	case interrupted && err == nil:
		fmt.Fprintf(out, "%s  share revoked      connectors are being told\n", now)
		return 0
	case errors.Is(err, agent.ErrShareExpired):
		fmt.Fprintf(out, "%s  share expired\n", now)
		return 0
	case errors.Is(err, agent.ErrShareIdle):
		fmt.Fprintf(out, "%s  share closed       idle for %s\n", now, roundDuration(spec.IdleTimeout))
		return 0
	case errors.Is(err, agent.ErrShareRevoked):
		fmt.Fprintf(out, "%s  share revoked      by another terminal (ngstone unshare)\n", now)
		return 0
	case err != nil:
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}
	return 0
}

func removeString(list []string, s string) []string {
	out := list[:0]
	for _, v := range list {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

func insecureHint(insecure bool) string {
	if insecure {
		return " --insecure"
	}
	return ""
}

// ---- connect ----

type portOverrides map[string]int

func (p *portOverrides) String() string { return "" }

// Set accepts "5433" (first target) or "redis=6380" / "t2=6380".
func (p *portOverrides) Set(v string) error {
	if *p == nil {
		*p = map[string]int{}
	}
	key, val, hasKey := strings.Cut(v, "=")
	if !hasKey {
		val, key = key, ""
	}
	n, err := strconv.Atoi(val)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %q", val)
	}
	(*p)[key] = n
	return nil
}

type connectFlags struct {
	ports      portOverrides
	name       string
	passphrase string
	instanceID string
	insecure   bool
	serverName string
	pin        string
}

func newConnectFlagSet() (*flag.FlagSet, *connectFlags) {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	cf := &connectFlags{}
	fs.Var(&cf.ports, "port", "local port to listen on: N for the first target, or preset=N / t2=N per target; repeatable (default: the share's preset ports, or a free port if busy)")
	fs.Var(&cf.ports, "p", "shorthand for -port")
	fs.StringVar(&cf.name, "as", "", "name the sharer sees for this connector (letters, digits, . _ -); default c1, c2, ...")
	fs.StringVar(&cf.passphrase, "passphrase", "", "passphrase the share requires (prefer $NGSTONE_SHARE_PASSPHRASE, or the prompt)")
	fs.StringVar(&cf.instanceID, "instance-id", "", "internal/undocumented: force a specific instance id (testing only)")
	fs.BoolVar(&cf.insecure, "insecure", false, "dial the edge in plaintext (dev/test only; only for links from an edge running with -insecure)")
	fs.StringVar(&cf.serverName, "server-name", "", "TLS ServerName/SNI to verify against; defaults to the host in the link (ignored with -insecure)")
	fs.StringVar(&cf.pin, "pin", "", "optional \"sha256/BASE64\" SPKI pin, checked in addition to normal chain validation")
	return fs, cf
}

// resolveShareLink takes the link from the argument, $NGSTONE_SHARE_LINK, or
// standard input when the argument is "-", so the secret can stay out of
// shell history.
func resolveShareLink(positionals []string, env string, stdin io.Reader) (string, error) {
	switch {
	case len(positionals) == 1 && positionals[0] == "-":
		r := bufio.NewReader(stdin)
		line, err := r.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("reading link from stdin: %w", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return "", errors.New("no share link on stdin")
		}
		return line, nil
	case len(positionals) == 1:
		return positionals[0], nil
	case len(positionals) == 0 && env != "":
		return strings.TrimSpace(env), nil
	}
	return "", errors.New("usage: ngstone connect <link|-> [--port N] [--as NAME]   (or set NGSTONE_SHARE_LINK)")
}

// promptPassphrase reads a passphrase without echo when stdin is a
// terminal; otherwise it reports that no prompt is possible.
var promptPassphrase = func(prompt string) (string, bool) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", false
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

func cmdConnect(args []string) int {
	fs, cf := newConnectFlagSet()
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	link, err := resolveShareLink(positionals, os.Getenv("NGSTONE_SHARE_LINK"), os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}
	controlAddr, secret, err := agent.ParseShareLink(link)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}
	passphrase := cf.passphrase
	if passphrase == "" {
		passphrase = os.Getenv("NGSTONE_SHARE_PASSPHRASE")
	}

	ports := map[string]int(cf.ports)
	listenPort := ports[""]
	delete(ports, "")

	ccfg := agent.ConnectConfig{
		ControlAddr: controlAddr,
		Secret:      secret,
		InstanceID:  cf.instanceID,
		Name:        cf.name,
		Passphrase:  passphrase,
		Ports:       ports,
		ListenPort:  listenPort,
		Insecure:    cf.insecure,
		ServerName:  cf.serverName,
		Pin:         cf.pin,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for attempt := 0; ; attempt++ {
		code, needPass := runConnect(ctx, os.Stdout, ccfg)
		if !needPass || attempt >= 2 {
			return code
		}
		pw, ok := promptPassphrase("passphrase for this share: ")
		if !ok {
			fmt.Fprintln(os.Stderr, "ngstone: this share needs a passphrase; pass --passphrase or set NGSTONE_SHARE_PASSPHRASE")
			return 1
		}
		ccfg.Passphrase = pw
	}
}

func connectHint(t agent.ConnectTarget) string {
	_, portStr, err := net.SplitHostPort(t.ListenAddr)
	if err != nil {
		return ""
	}
	port, _ := strconv.Atoi(portStr)
	switch t.Preset {
	case "postgres":
		user := ""
		if t.User != "" {
			user = t.User + "@"
		}
		return fmt.Sprintf(sharePresets[t.Preset].hint, user, port)
	case "mysql":
		user := ""
		if t.User != "" {
			user = " -u " + t.User
		}
		return fmt.Sprintf(sharePresets[t.Preset].hint, port, user)
	case "redis", "http":
		return fmt.Sprintf(sharePresets[t.Preset].hint, port)
	}
	return "nc " + t.ListenAddr
}

func connectStatusLine(st agent.ConnectStats) string {
	state := "connected"
	if !st.Connected {
		state = "reconnecting"
	}
	return fmt.Sprintf("%s  %s  %d open, %d total  %s up  %s down  expires %s",
		time.Now().Format("15:04:05"), state, st.OpenConns, st.TotalConns,
		agent.FormatBytes(st.BytesUp), agent.FormatBytes(st.BytesDown), expiresText(st.ExpiresAt))
}

// runConnect runs the connector and returns the exit code and whether a
// passphrase prompt would help.
func runConnect(ctx context.Context, out io.Writer, ccfg agent.ConnectConfig) (int, bool) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	slog.SetDefault(logger)

	events := make(chan agent.ConnectEvent, 16)
	ccfg.Events = events
	c := agent.NewConnector(ccfg)

	fmt.Fprintf(out, "connecting to %s\n", ccfg.ControlAddr)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		online := false
		var expiresAt time.Time
		warned := map[time.Duration]bool{}
		var lastStatus agent.ConnectStats
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		lastPrinted := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-events:
				now := time.Now().Format("15:04:05")
				switch ev.State {
				case agent.StateOnline:
					expiresAt = ev.ExpiresAt
					if !online {
						fmt.Fprintf(out, "connected  %q as %s  expires %s\n", ev.Label, ev.ConnectorID, expiresText(ev.ExpiresAt))
						for _, t := range ev.Targets {
							fmt.Fprintf(out, "listening  %-21s  %-9s ->  %s\n", t.ListenAddr, t.Label, connectHint(t))
						}
						online = true
					} else {
						fmt.Fprintf(out, "%s  reconnected\n", now)
					}
				case agent.StateAwaitingApproval:
					fmt.Fprintf(out, "%s  waiting for the sharer to approve this connection\n", now)
				case agent.StateUpdated:
					expiresAt = ev.ExpiresAt
					warned = map[time.Duration]bool{}
					fmt.Fprintf(out, "%s  share extended     expires %s\n", now, expiresText(ev.ExpiresAt))
				case agent.StateReconnecting:
					fmt.Fprintf(out, "%s  edge connection lost, reconnecting (open connections were dropped)\n", now)
				case agent.StateOffline:
					switch ev.Reason {
					case proto.ShareReasonSharerGone:
						fmt.Fprintf(out, "%s  sharer went offline, waiting for it to come back\n", now)
					case proto.ShareReasonEdgeShutdown:
						fmt.Fprintf(out, "%s  edge is restarting, waiting\n", now)
					}
				}
			case <-ticker.C:
				if !online {
					continue
				}
				left := time.Until(expiresAt)
				for _, w := range []time.Duration{expiryWarnFirst, expiryWarnLast} {
					if left <= w && left > 0 && !warned[w] {
						warned[w] = true
						fmt.Fprintf(out, "%s  warning: share expires in %s; open connections will be cut\n", time.Now().Format("15:04:05"), roundDuration(left))
					}
				}
				st := c.Stats()
				changed := st.OpenConns != lastStatus.OpenConns || st.TotalConns != lastStatus.TotalConns || st.BytesUp != lastStatus.BytesUp || st.BytesDown != lastStatus.BytesDown
				if changed && time.Since(lastPrinted) >= connectStatusEvery {
					fmt.Fprintln(out, connectStatusLine(st))
					lastStatus = st
					lastPrinted = time.Now()
				}
			}
		}
	}()

	err := c.Run(ctx)
	interrupted := ctx.Err() != nil
	cancel()
	now := time.Now().Format("15:04:05")
	switch {
	case interrupted && err == nil:
		fmt.Fprintln(out, "disconnected")
		return 0, false
	case errors.Is(err, agent.ErrPassphraseRequired):
		fmt.Fprintf(out, "%s  this share needs a passphrase\n", now)
		return 1, true
	case errors.Is(err, agent.ErrShareClosed):
		reason := agent.CloseReason(err)
		text := map[string]string{
			proto.ShareReasonExpired: "expired",
			proto.ShareReasonRevoked: "revoked by the sharer",
			proto.ShareReasonIdle:    "closed after sitting idle",
			proto.ShareReasonKicked:  "closed: the sharer removed this connector",
		}[reason]
		if text == "" {
			text = "closed (" + reason + ")"
		}
		fmt.Fprintf(out, "%s  share %s; disconnecting\n", now, text)
		return 3, false
	case errors.Is(err, agent.ErrShareRejected):
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1, false
	case errors.Is(err, agent.ErrBadToken):
		fmt.Fprintf(os.Stderr, "ngstone: this link is not valid on %s: it may have expired, been revoked, or the sharer may be offline\n", ccfg.ControlAddr)
		return 1, false
	case err != nil:
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1, false
	}
	return 0, false
}

// ---- shares / unshare / extend / kick ----

type opFlags struct {
	server     string
	token      string
	insecure   bool
	serverName string
	pin        string
	jsonOut    bool
	watch      bool
}

func newOpFlagSet(name string) (*flag.FlagSet, *opFlags) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	of := &opFlags{}
	fs.StringVar(&of.server, "server", "", "edge control plane address override (defaults to config or "+defaultServer+")")
	fs.StringVar(&of.token, "token", "", "auth token override (defaults to NGSTONE_TOKEN or the saved config)")
	fs.BoolVar(&of.insecure, "insecure", false, "dial the control plane in plaintext (dev/test only)")
	fs.StringVar(&of.serverName, "server-name", "", "TLS ServerName/SNI to verify against (ignored with -insecure)")
	fs.StringVar(&of.pin, "pin", "", "optional \"sha256/BASE64\" SPKI pin")
	if name == "shares" {
		fs.BoolVar(&of.jsonOut, "json", false, "print the raw list as JSON")
		fs.BoolVar(&of.watch, "watch", false, "stay attached and print every share's audit events as they happen")
	}
	return fs, of
}

func newOperator(of *opFlags) (*agent.Operator, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("loading config: %v", err)
	}
	token, err := resolveToken(of.token, os.Getenv("NGSTONE_TOKEN"), cfg)
	if err != nil {
		return nil, err
	}
	return agent.NewOperator(agent.Config{
		ControlAddr: resolveServer(of.server, cfg),
		Token:       token,
		Insecure:    of.insecure,
		ServerName:  of.serverName,
		Pin:         of.pin,
	}), nil
}

func opError(err error) int {
	switch {
	case errors.Is(err, agent.ErrShareNotFound):
		fmt.Fprintln(os.Stderr, "ngstone: no live share with that id (ngstone shares lists them)")
	case errors.Is(err, agent.ErrBadToken):
		fmt.Fprintln(os.Stderr, "ngstone: the edge rejected this token")
	case errors.Is(err, agent.ErrUnreachable):
		fmt.Fprintf(os.Stderr, "ngstone: could not reach the edge: %v\n", err)
	default:
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
	}
	return 1
}

func formatShareInfo(w io.Writer, s proto.ShareInfo) {
	mine := ""
	if s.Mine {
		mine = "  (this session)"
	}
	targets := make([]string, 0, len(s.Targets))
	for _, t := range s.Targets {
		targets = append(targets, t.Preset)
	}
	fmt.Fprintf(w, "%s  %-24s %-20s expires %s%s\n", s.ShareID, s.Label, strings.Join(targets, ","), expiresText(time.UnixMilli(s.ExpiresAtMS)), mine)
	policy := []string{fmt.Sprintf("%d conns", s.MaxConns), fmt.Sprintf("%d connectors", s.MaxConnectors)}
	if s.MaxUses > 0 {
		policy = append(policy, fmt.Sprintf("%d/%d uses", s.Uses, s.MaxUses))
	}
	if len(s.AllowCIDRs) > 0 {
		policy = append(policy, "allow "+strings.Join(s.AllowCIDRs, ","))
	}
	if s.IdleTimeoutMS > 0 {
		policy = append(policy, "idle "+roundDuration(time.Duration(s.IdleTimeoutMS)*time.Millisecond))
	}
	if s.Approve {
		policy = append(policy, "approval")
	}
	if s.Passphrase {
		policy = append(policy, "passphrase")
	}
	fmt.Fprintf(w, "%20s  policy: %s;  %d open connections\n", "", strings.Join(policy, ", "), s.OpenConns)
	for _, c := range s.Connectors {
		fmt.Fprintf(w, "%20s  connector %-12s %-21s joined %s ago\n", "", c.ID, hostOnlyAddr(c.Addr), roundDuration(time.Since(time.UnixMilli(c.JoinedMS))))
	}
}

func hostOnlyAddr(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func cmdShares(args []string) int {
	fs, of := newOpFlagSet("shares")
	if _, err := parsePermissive(fs, args); err != nil {
		return 2
	}
	op, err := newOperator(of)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if of.watch {
		fmt.Println("watching every share; Ctrl-C stops")
		err := op.Watch(ctx, func(ev proto.ShareEvent) {
			label := ev.Label
			if label == "" {
				label = ev.ShareID
			}
			fmt.Printf("%-24s %s\n", label, agent.FormatShareEvent(ev))
		})
		if err != nil && ctx.Err() == nil {
			return opError(err)
		}
		return 0
	}

	shares, err := op.ListShares(ctx)
	if err != nil {
		return opError(err)
	}
	if of.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(shares)
		return 0
	}
	if len(shares) == 0 {
		fmt.Println("no live shares")
		return 0
	}
	for _, s := range shares {
		formatShareInfo(os.Stdout, s)
	}
	return 0
}

func cmdUnshare(args []string) int {
	fs, of := newOpFlagSet("unshare")
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprintln(os.Stderr, "usage: ngstone unshare <share id>")
		return 2
	}
	op, err := newOperator(of)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := op.Unshare(ctx, positionals[0]); err != nil {
		return opError(err)
	}
	fmt.Printf("revoked %s; its connectors are being told\n", positionals[0])
	return 0
}

func cmdExtend(args []string) int {
	fs, of := newOpFlagSet("extend")
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 2 {
		fmt.Fprintln(os.Stderr, "usage: ngstone extend <share id> <duration from now, e.g. 1h>")
		return 2
	}
	d, err := time.ParseDuration(positionals[1])
	if err != nil || d <= 0 {
		fmt.Fprintf(os.Stderr, "ngstone: bad duration %q\n", positionals[1])
		return 2
	}
	op, err := newOperator(of)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	until, err := op.Extend(ctx, positionals[0], time.Now().Add(d))
	if err != nil {
		return opError(err)
	}
	fmt.Printf("%s now expires %s\n", positionals[0], expiresText(until))
	return 0
}

func cmdKick(args []string) int {
	fs, of := newOpFlagSet("kick")
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 2 {
		fmt.Fprintln(os.Stderr, "usage: ngstone kick <share id> <connector id>")
		return 2
	}
	op, err := newOperator(of)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := op.Kick(ctx, positionals[0], positionals[1]); err != nil {
		return opError(err)
	}
	fmt.Printf("removed %s from %s\n", positionals[1], positionals[0])
	return 0
}
