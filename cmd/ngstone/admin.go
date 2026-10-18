package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"ngstone/internal/adminapi"
	"ngstone/internal/credentials"
)

func cmdAdmin(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		printAdminUsage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "status":
		return cmdAdminStatus(args[1:])
	case "login":
		return cmdAdminLogin(args[1:])
	case "tunnels":
		return cmdAdminTunnels(args[1:])
	case "observability":
		return cmdAdminObservability(args[1:])
	case "credentials":
		return cmdAdminCredentials(args[1:])
	case "policies":
		return cmdAdminPolicies(args[1:])
	case "domains":
		return cmdAdminDomains(args[1:])
	case "screens":
		return cmdAdminScreens(args[1:])
	case "tunnel":
		return cmdAdminTunnel(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "ngstone: unknown admin subcommand %q\n", args[0])
		printAdminUsage(os.Stderr)
		return 2
	}
}

func printAdminUsage(w *os.File) {
	fmt.Fprintln(w, "usage: ngstone admin <login|status|tunnels|observability|credentials|policies|domains|screens|tunnel>")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "commands:")
	fmt.Fprintln(w, "  login                                       print the browser URL for OIDC login")
	fmt.Fprintln(w, "  status                                      show edge health and metrics")
	fmt.Fprintln(w, "  tunnels                                     list active tunnels")
	fmt.Fprintln(w, "  observability                               show per-tunnel metrics and latency")
	fmt.Fprintln(w, "  credentials issue                          issue a scoped credential")
	fmt.Fprintln(w, "  credentials list                           list credential metadata")
	fmt.Fprintln(w, "  credentials revoke <id>                    revoke one credential")
	fmt.Fprintln(w, "  policies list                              list durable traffic policies")
	fmt.Fprintln(w, "  policies apply --name NAME --file FILE     save a traffic policy")
	fmt.Fprintln(w, "  policies delete <id>                       delete an unused traffic policy")
	fmt.Fprintln(w, "  domains list                               list durable custom domains")
	fmt.Fprintln(w, "  domains add --domain NAME                  register a custom domain")
	fmt.Fprintln(w, "  domains delete <id>                        delete a custom domain")
	fmt.Fprintln(w, "  screens create [--name NAME] [--ttl TTL] [--max-viewers N]   create an ephemeral screen session")
	fmt.Fprintln(w, "  screens list                               list screen sessions")
	fmt.Fprintln(w, "  screens revoke <id>                       revoke a screen session")
	fmt.Fprintln(w, "  tunnel drain <hostname|subdomain>          gracefully drain a tunnel")
}

func cmdAdminLogin(args []string) int {
	fs, flags := newAdminFlagSet("admin login")
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 0 {
		fmt.Fprintln(os.Stderr, "usage: ngstone admin login [--server URL] [--json]")
		return 2
	}
	baseURL := strings.TrimRight(flags.server, "/")
	if !strings.Contains(baseURL, "://") {
		baseURL = "http://" + baseURL
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		fmt.Fprintln(os.Stderr, "ngstone: admin API server must be an http(s) URL without credentials, query, or fragment")
		return 2
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + adminapi.APIPrefix + "/auth/oidc/start"
	loginURL := parsed.String()
	if flags.json {
		return printAdminJSON(map[string]string{"url": loginURL, "mode": "browser"})
	}
	fmt.Printf("Open this URL in your browser to sign in with OIDC:\n%s\n", loginURL)
	fmt.Println("After login, use the same browser to open the ngstone operations dashboard.")
	return 0
}

type adminCLIFlags struct {
	server string
	token  string
	json   bool
}

func newAdminFlagSet(name string) (*flag.FlagSet, *adminCLIFlags) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	flags := &adminCLIFlags{}
	serverDefault := os.Getenv("NGSTONE_ADMIN_SERVER")
	if serverDefault == "" {
		serverDefault = adminapi.DefaultBaseURL
	}
	flags.token = os.Getenv("NGSTONE_ADMIN_TOKEN")
	fs.StringVar(&flags.server, "server", serverDefault, "management API URL (defaults to NGSTONE_ADMIN_SERVER or loopback)")
	fs.StringVar(&flags.token, "token", flags.token, "management bearer token (defaults to NGSTONE_ADMIN_TOKEN; prefer the environment)")
	fs.BoolVar(&flags.json, "json", false, "print machine-readable JSON")
	return fs, flags
}

func adminClient(flags *adminCLIFlags) (*adminapi.Client, error) {
	client, err := adminapi.NewClient(flags.server, flags.token)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func cmdAdminStatus(args []string) int {
	fs, flags := newAdminFlagSet("admin status")
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 0 {
		fmt.Fprintln(os.Stderr, "usage: ngstone admin status [--server URL] [--token TOKEN] [--json]")
		return 2
	}
	client, err := adminClient(flags)
	if err != nil {
		return printAdminClientError(err)
	}
	var status adminapi.Status
	if err := client.Get(adminapi.APIPrefix+"/status", &status); err != nil {
		return printAdminClientError(err)
	}
	if flags.json {
		return printAdminJSON(status)
	}
	health := "unhealthy"
	if status.Health.OK {
		health = "healthy"
	}
	fmt.Printf("domain: %s\n", status.Domain)
	fmt.Printf("health: %s\n", health)
	fmt.Printf("uptime: %s\n", time.Duration(status.UptimeSeconds)*time.Second)
	fmt.Printf("tunnels: %d\n", status.ActiveTunnels)
	fmt.Printf("connectors: %d\n", status.ActiveConnectors)
	fmt.Printf("requests: %d\n", status.Metrics.RequestsTotal)
	return 0
}

func cmdAdminTunnels(args []string) int {
	fs, flags := newAdminFlagSet("admin tunnels")
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 0 {
		fmt.Fprintln(os.Stderr, "usage: ngstone admin tunnels [--server URL] [--token TOKEN] [--json]")
		return 2
	}
	client, err := adminClient(flags)
	if err != nil {
		return printAdminClientError(err)
	}
	var tunnels []adminapi.Tunnel
	if err := client.Get(adminapi.APIPrefix+"/tunnels", &tunnels); err != nil {
		return printAdminClientError(err)
	}
	if flags.json {
		return printAdminJSON(tunnels)
	}
	if len(tunnels) == 0 {
		fmt.Println("no active tunnels")
		return 0
	}
	for _, tunnel := range tunnels {
		state := "offline"
		for _, connector := range tunnel.Connectors {
			if connector.Alive && connector.Healthy {
				state = "online"
				break
			}
		}
		fmt.Printf("%s\t%s\t%d connector(s)\t%s\n", tunnel.Hostname, tunnel.Kind, len(tunnel.Connectors), state)
	}
	return 0
}

func cmdAdminObservability(args []string) int {
	fs, flags := newAdminFlagSet("admin observability")
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 0 {
		fmt.Fprintln(os.Stderr, "usage: ngstone admin observability [--server URL] [--token TOKEN] [--json]")
		return 2
	}
	client, err := adminClient(flags)
	if err != nil {
		return printAdminClientError(err)
	}
	var metrics []adminapi.TunnelObservability
	if err := client.Get(adminapi.APIPrefix+"/observability/tunnels", &metrics); err != nil {
		return printAdminClientError(err)
	}
	if flags.json {
		return printAdminJSON(metrics)
	}
	if len(metrics) == 0 {
		fmt.Println("no tunnel metrics")
		return 0
	}
	for _, metric := range metrics {
		fmt.Printf("%s\t%d request(s)\tp95 %.1f ms\t%d connector(s)\t%d bytes\n", metric.Hostname, metric.RequestCount, metric.LatencyP95MS, metric.ActiveConnectors, metric.BytesTransferred)
	}
	return 0
}

func cmdAdminCredentials(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stderr, "usage: ngstone admin credentials <issue|list|revoke>")
		return 2
	}
	switch args[0] {
	case "issue":
		return cmdAdminCredentialIssue(args[1:])
	case "list":
		return cmdAdminCredentialList(args[1:])
	case "revoke":
		return cmdAdminCredentialRevoke(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "ngstone: unknown admin credentials subcommand %q\n", args[0])
		return 2
	}
}

func cmdAdminCredentialIssue(args []string) int {
	fs, flags := newAdminFlagSet("admin credentials issue")
	kind := fs.String("kind", credentials.KindHTTP, "credential kind: http, tcp, or preview")
	subdomain := fs.String("subdomain", "", "exact HTTP subdomain this credential may bind")
	remotePort := fs.Int("remote-port", 0, "exact TCP port this credential may bind")
	ttl := fs.String("ttl", "24h", "credential lifetime, up to 720h")
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 0 {
		fmt.Fprintln(os.Stderr, "usage: ngstone admin credentials issue [options]")
		return 2
	}
	if parsed, err := time.ParseDuration(*ttl); err != nil || parsed <= 0 {
		fmt.Fprintln(os.Stderr, "ngstone: ttl must be a positive duration")
		return 2
	}
	client, err := adminClient(flags)
	if err != nil {
		return printAdminClientError(err)
	}
	var issued adminapi.CredentialIssueResponse
	err = client.Post(adminapi.APIPrefix+"/credentials", adminapi.CredentialIssueRequest{
		Kind:       *kind,
		Subdomain:  *subdomain,
		RemotePort: *remotePort,
		TTL:        *ttl,
	}, &issued)
	if err != nil {
		return printAdminClientError(err)
	}
	if flags.json {
		return printAdminJSON(struct {
			credentials.Credential
			Token string `json:"token"`
		}{Credential: issued.Credential, Token: issued.Token})
	}
	fmt.Printf("credential %s issued\n", issued.Credential.ID)
	fmt.Printf("kind: %s\n", issued.Credential.Kind)
	if issued.Credential.Subdomain != "" {
		fmt.Printf("subdomain: %s\n", issued.Credential.Subdomain)
	}
	if issued.Credential.RemotePort != 0 {
		fmt.Printf("remote port: %d\n", issued.Credential.RemotePort)
	}
	fmt.Printf("expires: %s\n", issued.Credential.ExpiresAt.UTC().Format(time.RFC3339))
	fmt.Printf("token: %s\n", issued.Token)
	fmt.Fprintln(os.Stderr, "save this token now; it cannot be recovered from the edge")
	return 0
}

func cmdAdminCredentialList(args []string) int {
	fs, flags := newAdminFlagSet("admin credentials list")
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 0 {
		fmt.Fprintln(os.Stderr, "usage: ngstone admin credentials list [--server URL] [--token TOKEN] [--json]")
		return 2
	}
	client, err := adminClient(flags)
	if err != nil {
		return printAdminClientError(err)
	}
	var list []credentials.Credential
	if err := client.Get(adminapi.APIPrefix+"/credentials", &list); err != nil {
		return printAdminClientError(err)
	}
	if flags.json {
		return printAdminJSON(list)
	}
	if len(list) == 0 {
		fmt.Println("no credentials")
		return 0
	}
	for _, credential := range list {
		state := "active"
		if credential.RevokedAt != nil {
			state = "revoked"
		} else if !time.Now().Before(credential.ExpiresAt) {
			state = "expired"
		}
		fmt.Printf("%s\t%s\t%s\t%s\n", credential.ID, credential.Kind, state, credential.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return 0
}

func cmdAdminCredentialRevoke(args []string) int {
	fs, flags := newAdminFlagSet("admin credentials revoke")
	positionals, err := parsePermissive(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprintln(os.Stderr, "usage: ngstone admin credentials revoke <id> [--server URL] [--token TOKEN]")
		return 2
	}
	client, err := adminClient(flags)
	if err != nil {
		return printAdminClientError(err)
	}
	path := adminapi.APIPrefix + "/credentials/" + url.PathEscape(positionals[0])
	if err := client.Delete(path); err != nil {
		return printAdminClientError(err)
	}
	if flags.json {
		return printAdminJSON(map[string]string{"id": positionals[0], "status": "revoked"})
	}
	fmt.Printf("credential %s revoked\n", positionals[0])
	return 0
}

func cmdAdminPolicies(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stderr, "usage: ngstone admin policies <list|apply|delete>")
		return 2
	}
	switch args[0] {
	case "list":
		fs, flags := newAdminFlagSet("admin policies list")
		positionals, err := parsePermissive(fs, args[1:])
		if err != nil || len(positionals) != 0 {
			return 2
		}
		client, err := adminClient(flags)
		if err != nil {
			return printAdminClientError(err)
		}
		var list []adminapi.TrafficPolicy
		if err := client.Get(adminapi.APIPrefix+"/policies", &list); err != nil {
			return printAdminClientError(err)
		}
		if flags.json {
			return printAdminJSON(list)
		}
		for _, value := range list {
			fmt.Printf("%s\t%s\t%s\n", value.ID, value.Name, value.Digest)
		}
		return 0
	case "apply":
		fs, flags := newAdminFlagSet("admin policies apply")
		name := fs.String("name", "", "policy name")
		file := fs.String("file", "", "path to the policy JSON file")
		positionals, err := parsePermissive(fs, args[1:])
		if err != nil || len(positionals) != 0 || strings.TrimSpace(*name) == "" || strings.TrimSpace(*file) == "" {
			fmt.Fprintln(os.Stderr, "usage: ngstone admin policies apply --name NAME --file FILE [--server URL] [--token TOKEN] [--json]")
			return 2
		}
		data, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ngstone: reading policy: %v\n", err)
			return 1
		}
		client, err := adminClient(flags)
		if err != nil {
			return printAdminClientError(err)
		}
		var value adminapi.TrafficPolicy
		if err := client.Post(adminapi.APIPrefix+"/policies", adminapi.TrafficPolicyRequest{Name: *name, Policy: json.RawMessage(data)}, &value); err != nil {
			return printAdminClientError(err)
		}
		if flags.json {
			return printAdminJSON(value)
		}
		fmt.Printf("policy %s saved (%s)\n", value.Name, value.Digest)
		return 0
	case "delete":
		fs, flags := newAdminFlagSet("admin policies delete")
		positionals, err := parsePermissive(fs, args[1:])
		if err != nil || len(positionals) != 1 {
			fmt.Fprintln(os.Stderr, "usage: ngstone admin policies delete <id> [--server URL] [--token TOKEN]")
			return 2
		}
		client, err := adminClient(flags)
		if err != nil {
			return printAdminClientError(err)
		}
		if err := client.Delete(adminapi.APIPrefix + "/policies/" + url.PathEscape(positionals[0])); err != nil {
			return printAdminClientError(err)
		}
		fmt.Printf("policy %s deleted\n", positionals[0])
		return 0
	default:
		fmt.Fprintf(os.Stderr, "ngstone: unknown admin policies subcommand %q\n", args[0])
		return 2
	}
}

func cmdAdminDomains(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stderr, "usage: ngstone admin domains <list|add|delete>")
		return 2
	}
	switch args[0] {
	case "list":
		fs, flags := newAdminFlagSet("admin domains list")
		positionals, err := parsePermissive(fs, args[1:])
		if err != nil || len(positionals) != 0 {
			return 2
		}
		client, err := adminClient(flags)
		if err != nil {
			return printAdminClientError(err)
		}
		var list []adminapi.CustomDomain
		if err := client.Get(adminapi.APIPrefix+"/domains", &list); err != nil {
			return printAdminClientError(err)
		}
		if flags.json {
			return printAdminJSON(list)
		}
		for _, value := range list {
			fmt.Printf("%s\t%s\t%s\n", value.ID, value.Domain, value.Status)
		}
		return 0
	case "add":
		fs, flags := newAdminFlagSet("admin domains add")
		domain := fs.String("domain", "", "custom domain name")
		tunnelID := fs.String("tunnel-id", "", "durable tunnel id to associate")
		positionals, err := parsePermissive(fs, args[1:])
		if err != nil || len(positionals) != 0 || strings.TrimSpace(*domain) == "" {
			fmt.Fprintln(os.Stderr, "usage: ngstone admin domains add --domain NAME [--tunnel-id ID] [--server URL] [--token TOKEN] [--json]")
			return 2
		}
		client, err := adminClient(flags)
		if err != nil {
			return printAdminClientError(err)
		}
		var value adminapi.CustomDomain
		if err := client.Post(adminapi.APIPrefix+"/domains", adminapi.CustomDomainRequest{Domain: *domain, TunnelID: *tunnelID}, &value); err != nil {
			return printAdminClientError(err)
		}
		if flags.json {
			return printAdminJSON(value)
		}
		fmt.Printf("domain %s registered (%s)\n", value.Domain, value.Status)
		return 0
	case "delete":
		fs, flags := newAdminFlagSet("admin domains delete")
		positionals, err := parsePermissive(fs, args[1:])
		if err != nil || len(positionals) != 1 {
			fmt.Fprintln(os.Stderr, "usage: ngstone admin domains delete <id> [--server URL] [--token TOKEN]")
			return 2
		}
		client, err := adminClient(flags)
		if err != nil {
			return printAdminClientError(err)
		}
		if err := client.Delete(adminapi.APIPrefix + "/domains/" + url.PathEscape(positionals[0])); err != nil {
			return printAdminClientError(err)
		}
		fmt.Printf("domain %s deleted\n", positionals[0])
		return 0
	default:
		fmt.Fprintf(os.Stderr, "ngstone: unknown admin domains subcommand %q\n", args[0])
		return 2
	}
}

func cmdAdminScreens(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stderr, "usage: ngstone admin screens <create|list|revoke>")
		return 2
	}
	switch args[0] {
	case "create":
		fs, flags := newAdminFlagSet("admin screens create")
		name := fs.String("name", "", "screen session name")
		ttl := fs.String("ttl", "30m", "screen session lifetime, up to 24h")
		maxViewers := fs.Int("max-viewers", 1, "maximum viewers; values above 1 use the edge SFU")
		positionals, err := parsePermissive(fs, args[1:])
		if err != nil || len(positionals) != 0 {
			fmt.Fprintln(os.Stderr, "usage: ngstone admin screens create [--name NAME] [--ttl TTL] [--server URL] [--token TOKEN] [--json]")
			return 2
		}
		parsedTTL, err := time.ParseDuration(*ttl)
		if err != nil || parsedTTL <= 0 || parsedTTL > 24*time.Hour {
			fmt.Fprintln(os.Stderr, "ngstone: screen session ttl must be positive and no longer than 24h")
			return 2
		}
		if *maxViewers < 1 || *maxViewers > 8 {
			fmt.Fprintln(os.Stderr, "ngstone: max-viewers must be between 1 and 8")
			return 2
		}
		client, err := adminClient(flags)
		if err != nil {
			return printAdminClientError(err)
		}
		var created adminapi.ScreenSessionCreateResponse
		if err := client.Post(adminapi.APIPrefix+"/screen-sessions", adminapi.ScreenSessionRequest{Name: *name, TTL: *ttl, MaxViewers: *maxViewers}, &created); err != nil {
			return printAdminClientError(err)
		}
		if flags.json {
			return printAdminJSON(created)
		}
		fmt.Printf("screen session %s created\n", created.Session.ID)
		fmt.Printf("expires: %s\n", created.Session.ExpiresAt.UTC().Format(time.RFC3339))
		mode := "direct"
		if created.Session.SFU {
			mode = "sfu"
		}
		fmt.Printf("mode: %s (%d viewer(s))\n", mode, created.Session.MaxViewers)
		fmt.Printf("sender token: %s\n", created.SenderToken)
		fmt.Printf("viewer URL: %s\n", created.ViewerURL)
		fmt.Fprintln(os.Stderr, "save the sender token and viewer URL now; they cannot be recovered from the edge")
		return 0
	case "list":
		fs, flags := newAdminFlagSet("admin screens list")
		positionals, err := parsePermissive(fs, args[1:])
		if err != nil || len(positionals) != 0 {
			fmt.Fprintln(os.Stderr, "usage: ngstone admin screens list [--server URL] [--token TOKEN] [--json]")
			return 2
		}
		client, err := adminClient(flags)
		if err != nil {
			return printAdminClientError(err)
		}
		var list []adminapi.ScreenSession
		if err := client.Get(adminapi.APIPrefix+"/screen-sessions", &list); err != nil {
			return printAdminClientError(err)
		}
		if flags.json {
			return printAdminJSON(list)
		}
		if len(list) == 0 {
			fmt.Println("no screen sessions")
			return 0
		}
		for _, session := range list {
			mode := "direct"
			if session.SFU {
				mode = "sfu"
			}
			fmt.Printf("%s\t%s\t%s\t%s\tviewers=%d/%d\tsender=%t\texpires=%s\n", session.ID, session.Name, session.Status, mode, session.ViewerCount, session.MaxViewers, session.SenderConnected, session.ExpiresAt.UTC().Format(time.RFC3339))
		}
		return 0
	case "revoke":
		fs, flags := newAdminFlagSet("admin screens revoke")
		positionals, err := parsePermissive(fs, args[1:])
		if err != nil || len(positionals) != 1 {
			fmt.Fprintln(os.Stderr, "usage: ngstone admin screens revoke <id> [--server URL] [--token TOKEN] [--json]")
			return 2
		}
		client, err := adminClient(flags)
		if err != nil {
			return printAdminClientError(err)
		}
		if err := client.Delete(adminapi.APIPrefix + "/screen-sessions/" + url.PathEscape(positionals[0])); err != nil {
			return printAdminClientError(err)
		}
		if flags.json {
			return printAdminJSON(map[string]string{"id": positionals[0], "status": "revoked"})
		}
		fmt.Printf("screen session %s revoked\n", positionals[0])
		return 0
	default:
		fmt.Fprintf(os.Stderr, "ngstone: unknown admin screens subcommand %q\n", args[0])
		return 2
	}
}

func cmdAdminTunnel(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stderr, "usage: ngstone admin tunnel drain <hostname|subdomain>")
		return 2
	}
	if args[0] != "drain" {
		fmt.Fprintf(os.Stderr, "ngstone: unknown admin tunnel subcommand %q\n", args[0])
		return 2
	}
	fs, flags := newAdminFlagSet("admin tunnel drain")
	positionals, err := parsePermissive(fs, args[1:])
	if err != nil {
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprintln(os.Stderr, "usage: ngstone admin tunnel drain <hostname|subdomain> [--server URL] [--token TOKEN] [--json]")
		return 2
	}
	client, err := adminClient(flags)
	if err != nil {
		return printAdminClientError(err)
	}
	var drained adminapi.DrainResponse
	path := adminapi.APIPrefix + "/tunnels/" + url.PathEscape(positionals[0]) + "/drain"
	if err := client.Post(path, nil, &drained); err != nil {
		return printAdminClientError(err)
	}
	if flags.json {
		return printAdminJSON(drained)
	}
	fmt.Printf("draining %s (%d connector(s))\n", drained.Hostname, drained.Connectors)
	return 0
}

func printAdminJSON(value any) int {
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		fmt.Fprintf(os.Stderr, "ngstone: writing JSON: %v\n", err)
		return 1
	}
	return 0
}

func printAdminClientError(err error) int {
	var apiErr *adminapi.APIError
	if errors.As(err, &apiErr) && apiErr.Code != "" {
		fmt.Fprintf(os.Stderr, "ngstone: admin API %s: %s\n", apiErr.Code, apiErr.Message)
		return 1
	}
	fmt.Fprintf(os.Stderr, "ngstone: admin API: %s\n", strings.TrimSpace(err.Error()))
	return 1
}
