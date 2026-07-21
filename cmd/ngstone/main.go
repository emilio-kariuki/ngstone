package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"ngstone/internal/agent"
	"ngstone/internal/config"
	"ngstone/internal/version"
)

const defaultServer = "ngstone.site:4443"

var errNoToken = errors.New("no token configured; run 'ngstone auth <token>' first")

var verbs = map[string]func([]string) int{
	"auth":    cmdAuth,
	"port":    cmdPort,
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

func main() {
	if len(os.Args) > 1 {
		if fn, ok := verbFunc(os.Args[1]); ok {
			os.Exit(fn(os.Args[2:]))
		}
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

func cmdPort(args []string) int {
	fs := flag.NewFlagSet("port", flag.ContinueOnError)
	var subdomain string
	fs.StringVar(&subdomain, "subdomain", "", "requested subdomain (empty = server-assigned)")
	fs.StringVar(&subdomain, "s", "", "shorthand for -subdomain")
	serverFlag := fs.String("server", "", "edge control plane address override (defaults to config or "+defaultServer+")")
	tokenFlag := fs.String("token", "", "auth token override (defaults to NGSTONE_TOKEN or the saved config)")
	instanceID := fs.String("instance-id", "", "internal/undocumented: force a specific instance id (testing only)")
	insecure := fs.Bool("insecure", false, "dial the control plane in plaintext (dev/test only, no certificates involved)")
	serverName := fs.String("server-name", agent.DefaultServerName, "TLS ServerName/SNI to verify against (ignored with -insecure)")
	pin := fs.String("pin", "", "optional \"sha256/BASE64\" SPKI pin, checked in addition to normal chain validation")
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

	token, err := resolveToken(*tokenFlag, os.Getenv("NGSTONE_TOKEN"), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ngstone: "+err.Error())
		return 1
	}
	server := resolveServer(*serverFlag, cfg)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := agent.New(agent.Config{
		ControlAddr: server,
		Token:       token,
		Subdomain:   subdomain,
		TargetURL:   targetURL,
		InstanceID:  *instanceID,

		Insecure:   *insecure,
		ServerName: *serverName,
		Pin:        *pin,
	})

	logger.Info("ngstone: starting", "control", server, "target", targetURL, "insecure", *insecure)
	if err := a.Run(ctx); err != nil {
		logger.Error("ngstone: exited with error", "err", err)
		return 1
	}
	return 0
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
	instanceID := flag.String("instance-id", "", "internal/undocumented: force a specific instance id (testing only)")

	insecure := flag.Bool("insecure", false, "dial the control plane in plaintext (dev/test only, no certificates involved)")
	serverName := flag.String("server-name", agent.DefaultServerName, "TLS ServerName/SNI to verify against (ignored with -insecure)")
	pin := flag.String("pin", "", "optional \"sha256/BASE64\" SPKI pin, checked in addition to normal chain validation (off by default)")
	showVersion := flag.Bool("version", false, "print version and exit")
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

	a := agent.New(agent.Config{
		ControlAddr: ctl,
		Token:       tok,
		Subdomain:   *subdomain,
		TargetURL:   *target,
		InstanceID:  *instanceID,

		Insecure:   *insecure,
		ServerName: *serverName,
		Pin:        *pin,
	})

	logger.Info("ngstone: starting", "control", ctl, "target", *target, "insecure", *insecure)
	if err := a.Run(ctx); err != nil {
		logger.Error("ngstone: exited with error", "err", err)
		os.Exit(1)
	}
}
