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

	"ngstone/internal/agent"
	"ngstone/internal/config"
	"ngstone/internal/proto"
)

const (
	defaultShareExpiry     = time.Hour
	defaultShareMaxConns   = 16
	defaultShareConnectors = 8
)

var sharePresets = map[string]struct {
	port int
	hint string
}{
	"postgres": {5432, `psql "postgres://127.0.0.1:%d/"`},
	"mysql":    {3306, `mysql -h 127.0.0.1 -P %d`},
	"redis":    {6379, `redis-cli -p %d`},
}

type shareFlags struct {
	expires       time.Duration
	label         string
	allowCIDR     string
	maxConns      int
	maxConnectors int
	singleUse     bool
	auditLog      string

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
	fs.StringVar(&sf.label, "label", "", "label shown to connectors (defaults to the preset name)")
	fs.StringVar(&sf.allowCIDR, "allow-cidr", "", "comma-separated CIDRs connectors must come from (empty = allow all)")
	fs.IntVar(&sf.maxConns, "max-conns", defaultShareMaxConns, "concurrent relayed connections across all connectors")
	fs.IntVar(&sf.maxConnectors, "max-connectors", defaultShareConnectors, "concurrent connector agents")
	fs.BoolVar(&sf.singleUse, "single-use", false, "lock the link to the first connector agent that uses it")
	fs.StringVar(&sf.auditLog, "audit-log", "", "append every audit event as JSON Lines to this file")
	fs.StringVar(&sf.server, "server", "", "edge control plane address override (defaults to config or "+defaultServer+")")
	fs.StringVar(&sf.token, "token", "", "auth token override (defaults to NGSTONE_TOKEN or the saved config)")
	fs.StringVar(&sf.instanceID, "instance-id", "", "internal/undocumented: force a specific instance id (testing only)")
	fs.BoolVar(&sf.insecure, "insecure", false, "dial the control plane in plaintext (dev/test only); connectors must pass -insecure too")
	fs.StringVar(&sf.serverName, "server-name", "", "TLS ServerName/SNI to verify against; defaults to the host in the server address (ignored with -insecure)")
	fs.StringVar(&sf.pin, "pin", "", "optional \"sha256/BASE64\" SPKI pin, checked in addition to normal chain validation")
	return fs, sf
}

// resolveShareTarget turns "postgres", "postgres 5433", "tcp 9000" or
// "tcp db.local:5432" into a preset name, the local host:port to share and
// the port connectors listen on by default.
func resolveShareTarget(positionals []string) (preset, target string, defaultPort int, err error) {
	if len(positionals) == 0 {
		return "", "", 0, errors.New("usage: ngstone share <postgres|mysql|redis|tcp> [port|host:port]")
	}
	preset = strings.ToLower(positionals[0])
	p, isPreset := sharePresets[preset]
	switch {
	case isPreset:
		target = net.JoinHostPort("127.0.0.1", strconv.Itoa(p.port))
		defaultPort = p.port
		if len(positionals) == 2 {
			target, err = resolveTCPTarget(positionals[1])
			if err != nil {
				return "", "", 0, err
			}
		} else if len(positionals) > 2 {
			return "", "", 0, fmt.Errorf("usage: ngstone share %s [port|host:port]", preset)
		}
	case preset == "tcp":
		if len(positionals) != 2 {
			return "", "", 0, errors.New("usage: ngstone share tcp <port|host:port>")
		}
		target, err = resolveTCPTarget(positionals[1])
		if err != nil {
			return "", "", 0, err
		}
		_, portStr, _ := net.SplitHostPort(target)
		defaultPort, _ = strconv.Atoi(portStr)
	default:
		return "", "", 0, fmt.Errorf("unknown preset %q: use postgres, mysql, redis or tcp", positionals[0])
	}
	return preset, target, defaultPort, nil
}

func cmdShare(args []string) int {
	fs, sf := newShareFlagSet()
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	preset, target, defaultPort, err := resolveShareTarget(positionals)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 2
	}
	if sf.expires <= 0 {
		fmt.Fprintln(os.Stderr, "ngstone: --expires must be a positive duration such as 30m or 2h")
		return 2
	}
	if sf.maxConns < 1 || sf.maxConnectors < 1 {
		fmt.Fprintln(os.Stderr, "ngstone: --max-conns and --max-connectors must be at least 1")
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

	secret, secretHash, err := agent.NewShareSecret()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}
	label := sf.label
	if label == "" {
		label = preset
	}
	expiresAt := time.Now().Add(sf.expires)

	acfg := agent.Config{
		ControlAddr: server,
		Token:       token,
		Kind:        proto.KindTCP,
		TargetURL:   target,
		InstanceID:  sf.instanceID,
		Insecure:    sf.insecure,
		ServerName:  sf.serverName,
		Pin:         sf.pin,
		Share: &agent.ShareSpec{
			Preset:        preset,
			Label:         label,
			DefaultPort:   defaultPort,
			SecretSHA256:  secretHash,
			ExpiresAt:     expiresAt,
			MaxConns:      sf.maxConns,
			MaxConnectors: sf.maxConnectors,
			SingleUse:     sf.singleUse,
			AllowCIDRs:    allowCIDRs,
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return runShare(ctx, os.Stdout, acfg, agent.ShareLink(server, secret), audit)
}

func sharePolicyText(spec *agent.ShareSpec) string {
	var parts []string
	if len(spec.AllowCIDRs) == 0 {
		parts = append(parts, "allow all")
	} else {
		parts = append(parts, "allow "+strings.Join(spec.AllowCIDRs, ","))
	}
	parts = append(parts, fmt.Sprintf("%d conns", spec.MaxConns), fmt.Sprintf("%d connectors", spec.MaxConnectors))
	if spec.SingleUse {
		parts = append(parts, "single-use")
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

func runShare(ctx context.Context, out io.Writer, acfg agent.Config, link string, audit io.Writer) int {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	slog.SetDefault(logger)

	spec := acfg.Share
	events := make(chan agent.StatusEvent, 16)
	shareEvents := make(chan proto.ShareEvent, 256)
	acfg.Events = events
	acfg.ShareEvents = shareEvents

	a := agent.New(acfg)

	fmt.Fprintf(out, "share     %s  %s  %s\n", spec.Label, spec.Preset, acfg.TargetURL)
	fmt.Fprintf(out, "expires   %s   policy: %s\n", expiresText(spec.ExpiresAt), sharePolicyText(spec))
	fmt.Fprintf(out, "link      %s\n\n", link)
	fmt.Fprintf(out, "send the link to a teammate; they run:  ngstone connect <link>%s\n\n", insecureHint(acfg.Insecure))

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
				fmt.Fprintln(out, agent.FormatShareEvent(ev))
				if audit != nil {
					if b, err := json.Marshal(ev); err == nil {
						audit.Write(append(b, '\n'))
					}
				}
			}
		}
	}()

	err := a.Run(ctx)
	stopPrinter := func() {
		// Let queued events print before the final line.
		deadline := time.After(200 * time.Millisecond)
		for {
			select {
			case ev := <-shareEvents:
				fmt.Fprintln(out, agent.FormatShareEvent(ev))
				if audit != nil {
					if b, err := json.Marshal(ev); err == nil {
						audit.Write(append(b, '\n'))
					}
				}
			case <-deadline:
				return
			}
		}
	}
	stopPrinter()

	switch {
	case ctx.Err() != nil:
		fmt.Fprintf(out, "%s  share revoked      connectors are being told\n", time.Now().Format("15:04:05"))
		return 0
	case errors.Is(err, agent.ErrShareExpired):
		fmt.Fprintf(out, "%s  share expired\n", time.Now().Format("15:04:05"))
		return 0
	case err != nil:
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}
	return 0
}

func insecureHint(insecure bool) string {
	if insecure {
		return " --insecure"
	}
	return ""
}

type connectFlags struct {
	port       int
	instanceID string
	insecure   bool
	serverName string
	pin        string
}

func newConnectFlagSet() (*flag.FlagSet, *connectFlags) {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	cf := &connectFlags{}
	fs.IntVar(&cf.port, "port", 0, "local port to listen on (default: the share's preset port, or a free port if that is busy)")
	fs.IntVar(&cf.port, "p", 0, "shorthand for -port")
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
	return "", errors.New("usage: ngstone connect <link|-> [--port N]   (or set NGSTONE_SHARE_LINK)")
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
	if cf.port != 0 && (cf.port < 1 || cf.port > 65535) {
		fmt.Fprintln(os.Stderr, "ngstone: --port must be between 1 and 65535")
		return 2
	}

	ccfg := agent.ConnectConfig{
		ControlAddr: controlAddr,
		Secret:      secret,
		InstanceID:  cf.instanceID,
		ListenPort:  cf.port,
		Insecure:    cf.insecure,
		ServerName:  cf.serverName,
		Pin:         cf.pin,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return runConnect(ctx, os.Stdout, ccfg)
}

func connectHint(preset, listenAddr string) string {
	_, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return ""
	}
	port, _ := strconv.Atoi(portStr)
	if p, ok := sharePresets[preset]; ok {
		return fmt.Sprintf(p.hint, port)
	}
	return "nc " + listenAddr
}

func runConnect(ctx context.Context, out io.Writer, ccfg agent.ConnectConfig) int {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	slog.SetDefault(logger)

	events := make(chan agent.ConnectEvent, 16)
	ccfg.Events = events
	c := agent.NewConnector(ccfg)

	fmt.Fprintf(out, "connecting to %s\n", ccfg.ControlAddr)

	go func() {
		online := false
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-events:
				switch ev.State {
				case agent.StateOnline:
					if !online {
						fmt.Fprintf(out, "connected  %q (%s)  expires %s\n", ev.Label, ev.Preset, expiresText(ev.ExpiresAt))
						fmt.Fprintf(out, "listening  %s  ->  %s\n", ev.ListenAddr, connectHint(ev.Preset, ev.ListenAddr))
						online = true
					} else {
						fmt.Fprintf(out, "%s  reconnected\n", time.Now().Format("15:04:05"))
					}
				case agent.StateReconnecting:
					fmt.Fprintf(out, "%s  edge connection lost, reconnecting (open connections were dropped)\n", time.Now().Format("15:04:05"))
				case agent.StateOffline:
					switch ev.Reason {
					case proto.ShareReasonSharerGone:
						fmt.Fprintf(out, "%s  sharer went offline, waiting for it to come back\n", time.Now().Format("15:04:05"))
					case proto.ShareReasonEdgeShutdown:
						fmt.Fprintf(out, "%s  edge is restarting, waiting\n", time.Now().Format("15:04:05"))
					}
				}
			}
		}
	}()

	err := c.Run(ctx)
	switch {
	case ctx.Err() != nil:
		fmt.Fprintln(out, "disconnected")
		return 0
	case errors.Is(err, agent.ErrShareClosed):
		reason := "closed"
		if strings.Contains(err.Error(), proto.ShareReasonExpired) {
			reason = "expired"
		} else if strings.Contains(err.Error(), proto.ShareReasonRevoked) {
			reason = "revoked by the sharer"
		}
		fmt.Fprintf(out, "%s  share %s; disconnecting\n", time.Now().Format("15:04:05"), reason)
		return 3
	case errors.Is(err, agent.ErrShareRejected):
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	case errors.Is(err, agent.ErrBadToken):
		fmt.Fprintf(os.Stderr, "ngstone: this link is not valid on %s: it may have expired, been revoked, or the sharer may be offline\n", ccfg.ControlAddr)
		return 1
	case err != nil:
		fmt.Fprintf(os.Stderr, "ngstone: %v\n", err)
		return 1
	}
	return 0
}
