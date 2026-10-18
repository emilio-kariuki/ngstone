package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"ngstone/internal/adminapi"
	"ngstone/internal/agent"
	"ngstone/internal/config"
	"ngstone/internal/oidc"
)

const (
	doctorPass = "pass"
	doctorWarn = "warn"
	doctorFail = "fail"
	doctorSkip = "skip"
)

type doctorCheck struct {
	Name    string            `json:"name"`
	Status  string            `json:"status"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
}

type doctorReport struct {
	OK     bool          `json:"ok"`
	Checks []doctorCheck `json:"checks"`
}

type doctorOptions struct {
	Server      string
	AdminServer string
	Token       string
	AdminToken  string
	Transport   string
	ServerName  string
	Pin         string
	Timeout     time.Duration
	Insecure    bool
	JSON        bool
	LookupHost  func(context.Context, string) ([]string, error)
	DialContext func(context.Context, string, string) (net.Conn, error)
	Verify      func(context.Context, agent.Config) error
	HTTPClient  *http.Client
}

func cmdDoctor(args []string) int {
	fs := flagSet("doctor")
	opts := doctorOptions{
		Transport:  agent.TransportAuto,
		Timeout:    5 * time.Second,
		LookupHost: net.DefaultResolver.LookupHost,
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
		Verify: agent.Verify,
	}
	fs.StringVar(&opts.Server, "server", "", "control plane address override")
	fs.StringVar(&opts.AdminServer, "admin-server", os.Getenv("NGSTONE_ADMIN_SERVER"), "management API URL to check")
	fs.StringVar(&opts.Token, "token", "", "tunnel auth token override")
	fs.StringVar(&opts.AdminToken, "admin-token", os.Getenv("NGSTONE_ADMIN_TOKEN"), "management API bearer token override")
	fs.StringVar(&opts.Transport, "transport", opts.Transport, "control transport: auto, raw, or websocket")
	fs.StringVar(&opts.ServerName, "server-name", opts.ServerName, "TLS ServerName/SNI (default: control host)")
	fs.StringVar(&opts.Pin, "pin", "", "optional sha256/BASE64 SPKI pin")
	fs.DurationVar(&opts.Timeout, "timeout", opts.Timeout, "maximum time for each network check")
	fs.BoolVar(&opts.Insecure, "insecure", false, "allow plaintext control and local HTTP checks")
	fs.BoolVar(&opts.JSON, "json", false, "print machine-readable JSON")
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 0 {
		fmt.Fprintln(os.Stderr, "usage: ngstone doctor [--server address] [--admin-server URL] [--json]")
		return 2
	}
	code, report := runDoctor(opts, os.Stdout, os.Stderr)
	if opts.JSON {
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			return 1
		}
	}
	return code
}

func flagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}

func runDoctor(opts doctorOptions, out, _ io.Writer) (int, doctorReport) {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.LookupHost == nil {
		opts.LookupHost = net.DefaultResolver.LookupHost
	}
	if opts.DialContext == nil {
		opts.DialContext = (&net.Dialer{Timeout: opts.Timeout}).DialContext
	}
	if opts.Verify == nil {
		opts.Verify = agent.Verify
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{
			Timeout: opts.Timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	report := doctorReport{}
	configPath, pathErr := config.Path()
	configExists := false
	if pathErr != nil {
		report.add(doctorFail, "config", "could not resolve the ngstone config path", nil)
	} else {
		info, err := os.Stat(configPath)
		switch {
		case errors.Is(err, os.ErrNotExist):
			report.add(doctorWarn, "config", "config file does not exist yet", map[string]string{"path": configPath})
		case err != nil:
			report.add(doctorFail, "config", "could not read the ngstone config file", map[string]string{"path": configPath})
		case info.Mode().Perm()&0o077 != 0:
			configExists = true
			report.add(doctorFail, "config", "config file is readable by other users", map[string]string{"path": configPath, "mode": info.Mode().Perm().String()})
		default:
			configExists = true
			report.add(doctorPass, "config", "config file is readable and private", map[string]string{"path": configPath})
		}
	}
	cfg, err := config.Load()
	if err != nil {
		report.add(doctorFail, "config.parse", "config file could not be parsed", nil)
		cfg = config.Config{}
	} else if configExists {
		report.add(doctorPass, "config.parse", "config file parsed successfully", nil)
	}
	token := opts.Token
	if token == "" {
		token = os.Getenv("NGSTONE_TOKEN")
	}
	if token == "" {
		token = cfg.Token
	}
	if token == "" {
		report.add(doctorFail, "token", "no tunnel auth token is configured", nil)
	} else {
		report.add(doctorPass, "token", "tunnel auth token is configured", nil)
	}
	server := resolveServer(opts.Server, cfg)
	if err := agent.ValidateTransport(opts.Transport); err != nil {
		report.add(doctorFail, "transport", err.Error(), nil)
	} else {
		report.add(doctorPass, "transport", "control transport setting is valid", map[string]string{"mode": opts.Transport})
	}
	endpointCheck := checkDoctorEndpoint(opts, server)
	report.add(endpointCheck.Status, endpointCheck.Name, endpointCheck.Message, endpointCheck.Details)
	if token != "" && endpointCheck.Status != doctorFail {
		ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
		err := opts.Verify(ctx, agent.Config{
			ControlAddr: server,
			Transport:   opts.Transport,
			Token:       token,
			Insecure:    opts.Insecure,
			ServerName:  opts.ServerName,
			Pin:         opts.Pin,
		})
		cancel()
		if err == nil {
			report.add(doctorPass, "control.auth", "control plane accepted the configured token", nil)
		} else if errors.Is(err, agent.ErrBadToken) {
			report.add(doctorFail, "control.auth", "control plane rejected the configured token", nil)
		} else {
			report.add(doctorFail, "control.auth", "control plane authentication could not be completed", nil)
		}
	} else {
		report.add(doctorSkip, "control.auth", "skipped because the control endpoint or token is unavailable", nil)
	}
	if strings.TrimSpace(opts.AdminServer) == "" {
		report.add(doctorSkip, "admin.health", "set --admin-server or NGSTONE_ADMIN_SERVER to check the management API", nil)
	} else {
		check := checkAdminHealth(opts)
		report.add(check.Status, check.Name, check.Message, check.Details)
		if opts.AdminToken == "" {
			opts.AdminToken = os.Getenv("NGSTONE_ADMIN_TOKEN")
		}
		if opts.AdminToken == "" {
			report.add(doctorSkip, "admin.auth", "management bearer token is not configured; use browser OIDC login", nil)
		} else {
			check := checkAdminAuth(opts)
			report.add(check.Status, check.Name, check.Message, check.Details)
		}
	}
	oidcCheck := checkDoctorOIDC(opts)
	report.add(oidcCheck.Status, oidcCheck.Name, oidcCheck.Message, oidcCheck.Details)
	report.OK = true
	for _, check := range report.Checks {
		if check.Status == doctorFail {
			report.OK = false
			break
		}
	}
	if opts.JSON {
		return boolToExit(report.OK), report
	}
	printDoctorReport(out, report)
	return boolToExit(report.OK), report
}

func checkDoctorEndpoint(opts doctorOptions, server string) doctorCheck {
	host, _, err := net.SplitHostPort(server)
	if err != nil || host == "" {
		return doctorCheck{Status: doctorFail, Name: "control.endpoint", Message: "control plane address must include a host and port", Details: map[string]string{"address": server}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	addresses, err := opts.LookupHost(ctx, host)
	cancel()
	if err != nil {
		return doctorCheck{Status: doctorFail, Name: "control.dns", Message: "control plane hostname could not be resolved", Details: map[string]string{"host": host}}
	}
	ctx, cancel = context.WithTimeout(context.Background(), opts.Timeout)
	conn, err := opts.DialContext(ctx, "tcp", server)
	cancel()
	if err != nil {
		return doctorCheck{Status: doctorFail, Name: "control.network", Message: "control plane port is not reachable", Details: map[string]string{"address": server}}
	}
	conn.Close()
	return doctorCheck{Status: doctorPass, Name: "control.network", Message: "control plane hostname and port are reachable", Details: map[string]string{"host": host, "addresses": strings.Join(addresses, ",")}}
}

func checkAdminHealth(opts doctorOptions) doctorCheck {
	endpoint, err := doctorAdminEndpoint(opts.AdminServer, "/healthz", opts.Insecure)
	if err != nil {
		return doctorCheck{Status: doctorFail, Name: "admin.health", Message: err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return doctorCheck{Status: doctorFail, Name: "admin.health", Message: "management health request could not be created"}
	}
	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doctorCheck{Status: doctorFail, Name: "admin.health", Message: "management health endpoint is not reachable"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return doctorCheck{Status: doctorFail, Name: "admin.health", Message: "management health endpoint reported an unhealthy edge", Details: map[string]string{"status": resp.Status}}
	}
	return doctorCheck{Status: doctorPass, Name: "admin.health", Message: "management health endpoint is healthy", Details: map[string]string{"url": endpoint}}
}

func checkAdminAuth(opts doctorOptions) doctorCheck {
	endpoint, err := doctorAdminEndpoint(opts.AdminServer, adminapi.APIPrefix+"/status", opts.Insecure)
	if err != nil {
		return doctorCheck{Status: doctorFail, Name: "admin.auth", Message: err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return doctorCheck{Status: doctorFail, Name: "admin.auth", Message: "management auth request could not be created"}
	}
	req.Header.Set("Authorization", "Bearer "+opts.AdminToken)
	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doctorCheck{Status: doctorFail, Name: "admin.auth", Message: "management API could not be reached with the bearer token"}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return doctorCheck{Status: doctorFail, Name: "admin.auth", Message: "management API rejected the bearer token"}
	}
	if resp.StatusCode != http.StatusOK {
		return doctorCheck{Status: doctorFail, Name: "admin.auth", Message: "management API returned an unexpected status", Details: map[string]string{"status": resp.Status}}
	}
	return doctorCheck{Status: doctorPass, Name: "admin.auth", Message: "management bearer token was accepted"}
}

func checkDoctorOIDC(opts doctorOptions) doctorCheck {
	issuer := os.Getenv("NGSTONE_OIDC_ISSUER")
	clientID := os.Getenv("NGSTONE_OIDC_CLIENT_ID")
	redirectURL := os.Getenv("NGSTONE_OIDC_REDIRECT_URL")
	secretRaw := os.Getenv("NGSTONE_OIDC_COOKIE_SECRET")
	if issuer == "" && clientID == "" && redirectURL == "" && secretRaw == "" {
		return doctorCheck{Status: doctorSkip, Name: "oidc.config", Message: "OIDC variables are not configured in this environment"}
	}
	secret, err := oidc.ParseCookieSecret(secretRaw)
	if err != nil {
		return doctorCheck{Status: doctorFail, Name: "oidc.config", Message: "OIDC cookie secret is missing or invalid"}
	}
	err = oidc.ValidateConfig(oidc.Config{
		Issuer:        issuer,
		ClientID:      clientID,
		RedirectURL:   redirectURL,
		CookieSecret:  secret,
		AllowInsecure: opts.Insecure,
		DefaultRole:   os.Getenv("NGSTONE_OIDC_DEFAULT_ROLE"),
	})
	if err != nil {
		return doctorCheck{Status: doctorFail, Name: "oidc.config", Message: "OIDC configuration is invalid"}
	}
	return doctorCheck{Status: doctorPass, Name: "oidc.config", Message: "OIDC configuration has the required fields"}
}

func doctorAdminEndpoint(raw, path string, allowInsecure bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("management API URL is empty")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("management API server must be an http(s) URL without credentials, query, or fragment")
	}
	if u.Scheme == "http" && !allowInsecure && !doctorLoopbackHost(u.Hostname()) {
		return "", errors.New("management API server must use https outside loopback; use --insecure only for development")
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String(), nil
}

func doctorLoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "localhost" || host == "::1" {
		return true
	}
	parsed := net.ParseIP(host)
	return parsed != nil && parsed.IsLoopback()
}

func (r *doctorReport) add(status, name, message string, details map[string]string) {
	r.Checks = append(r.Checks, doctorCheck{Name: name, Status: status, Message: message, Details: details})
}

func printDoctorReport(out io.Writer, report doctorReport) {
	fmt.Fprintln(out, "ngstone doctor")
	for _, check := range report.Checks {
		fmt.Fprintf(out, "%-4s %-16s %s\n", strings.ToUpper(check.Status), check.Name, check.Message)
	}
	if report.OK {
		fmt.Fprintln(out, "\nNo blocking issues found.")
	} else {
		fmt.Fprintln(out, "\nBlocking issues found. Fix the failed checks and run doctor again.")
	}
}

func boolToExit(ok bool) int {
	if ok {
		return 0
	}
	return 1
}
