package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const DefaultProjectFilename = "ngstone.json"

type Project struct {
	Tunnels map[string]ProjectTunnel `json:"tunnels"`
}

type ProjectTunnel struct {
	Token              string   `json:"-"`
	BasicAuth          []string `json:"-"`
	CredentialFile     string   `json:"credential_file,omitempty"`
	ConnectorTokenFile string   `json:"connector_token_file,omitempty"`
	Kind               string   `json:"kind,omitempty"`
	Target             string   `json:"target"`
	Subdomain          string   `json:"subdomain,omitempty"`
	HostHeader         string   `json:"host_header,omitempty"`
	HTTP2              bool     `json:"http2,omitempty"`
	MultiConnector     bool     `json:"multi_connector,omitempty"`
	RemotePort         int      `json:"remote_port,omitempty"`
	TTL                string   `json:"ttl,omitempty"`
	Server             string   `json:"server,omitempty"`
	Transport          string   `json:"transport,omitempty"`
	ServerName         string   `json:"server_name,omitempty"`
	Insecure           bool     `json:"insecure,omitempty"`
	Pin                string   `json:"pin,omitempty"`
	BasicAuthFile      string   `json:"basic_auth_file,omitempty"`
	AllowCIDR          string   `json:"allow_cidr,omitempty"`
	PolicyFile         string   `json:"policy_file,omitempty"`
	ConnectorTokenEnv  string   `json:"connector_token_env,omitempty"`
	CredentialEnv      string   `json:"credential_env,omitempty"`
}

type NamedProjectTunnel struct {
	Name   string
	Tunnel ProjectTunnel
}

func FindProject(explicit string) (string, error) {
	if explicit != "" {
		info, err := os.Stat(explicit)
		if err != nil {
			return "", fmt.Errorf("project: %w", err)
		}
		if info.IsDir() {
			return "", fmt.Errorf("project: %s is a directory", explicit)
		}
		return explicit, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("project: resolving working directory: %w", err)
	}
	for _, name := range []string{DefaultProjectFilename, ".ngstone.json"} {
		path := filepath.Join(cwd, name)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("project: checking %s: %w", path, err)
		}
	}
	return "", fmt.Errorf("project: no %s or .ngstone.json found; create one or pass --file", DefaultProjectFilename)
}

func LoadProject(path string) (Project, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Project{}, fmt.Errorf("project: reading %s: %w", path, err)
	}

	var project Project
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&project); err != nil {
		return Project{}, fmt.Errorf("project: parsing %s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Project{}, fmt.Errorf("project: parsing %s: multiple JSON values", path)
		}
		return Project{}, fmt.Errorf("project: parsing %s: %w", path, err)
	}

	if err := project.Validate(); err != nil {
		return Project{}, fmt.Errorf("project: %s: %w", path, err)
	}
	return project, nil
}

func (p Project) Validate() error {
	if len(p.Tunnels) == 0 {
		return errors.New("tunnels must contain at least one tunnel")
	}
	for name, tunnel := range p.Tunnels {
		if err := validateTunnelName(name); err != nil {
			return err
		}
		if strings.TrimSpace(tunnel.Target) == "" {
			return fmt.Errorf("tunnel %q target is required", name)
		}
		kind := strings.ToLower(strings.TrimSpace(tunnel.Kind))
		if kind == "" {
			kind = "http"
		}
		if kind != "http" && kind != "tcp" {
			return fmt.Errorf("tunnel %q kind must be http or tcp", name)
		}
		if kind == "tcp" && tunnel.HostHeader != "" {
			return fmt.Errorf("tunnel %q host_header is only valid for http tunnels", name)
		}
		if kind == "tcp" && tunnel.HTTP2 {
			return fmt.Errorf("tunnel %q http2 is only valid for http tunnels", name)
		}
		if kind == "tcp" && tunnel.MultiConnector {
			return fmt.Errorf("tunnel %q multi_connector is only valid for http tunnels", name)
		}
		if tunnel.MultiConnector && strings.TrimSpace(tunnel.Subdomain) == "" {
			return fmt.Errorf("tunnel %q multi_connector requires a subdomain", name)
		}
		if tunnel.ConnectorTokenEnv != "" && tunnel.ConnectorTokenFile != "" {
			return fmt.Errorf("tunnel %q must use either connector_token_env or connector_token_file", name)
		}
		if tunnel.ConnectorTokenEnv != "" && !validEnvName(tunnel.ConnectorTokenEnv) {
			return fmt.Errorf("tunnel %q connector_token_env must be a valid environment variable name", name)
		}
		if tunnel.CredentialEnv != "" && tunnel.CredentialFile != "" {
			return fmt.Errorf("tunnel %q must use either credential_env or credential_file", name)
		}
		if tunnel.CredentialEnv != "" && !validEnvName(tunnel.CredentialEnv) {
			return fmt.Errorf("tunnel %q credential_env must be a valid environment variable name", name)
		}
		if kind == "tcp" && tunnel.BasicAuthFile != "" {
			return fmt.Errorf("tunnel %q basic_auth_file is only valid for http tunnels", name)
		}
		if kind == "tcp" && tunnel.PolicyFile != "" {
			return fmt.Errorf("tunnel %q policy_file is only valid for http tunnels", name)
		}
		if kind == "http" && tunnel.RemotePort != 0 {
			return fmt.Errorf("tunnel %q remote_port is only valid for tcp tunnels", name)
		}
		transport := strings.ToLower(strings.TrimSpace(tunnel.Transport))
		if transport != "" && transport != "auto" && transport != "raw" && transport != "tcp" && transport != "websocket" && transport != "ws" && transport != "wss" && transport != "https" {
			return fmt.Errorf("tunnel %q transport must be auto, raw, or websocket", name)
		}
		if tunnel.RemotePort < 0 || tunnel.RemotePort > 65535 {
			return fmt.Errorf("tunnel %q remote_port must be between 0 and 65535", name)
		}
		if tunnel.TTL != "" {
			ttl, err := time.ParseDuration(tunnel.TTL)
			if err != nil || ttl <= 0 {
				return fmt.Errorf("tunnel %q ttl must be a positive duration such as 2h", name)
			}
		}
		normalized := tunnel
		normalized.Kind = kind
		p.Tunnels[name] = normalized
	}
	return nil
}

func (p Project) SortedTunnels() []NamedProjectTunnel {
	names := make([]string, 0, len(p.Tunnels))
	for name := range p.Tunnels {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]NamedProjectTunnel, 0, len(names))
	for _, name := range names {
		out = append(out, NamedProjectTunnel{Name: name, Tunnel: p.Tunnels[name]})
	}
	return out
}

func (t ProjectTunnel) TTLDuration() (time.Duration, error) {
	if t.TTL == "" {
		return 0, nil
	}
	ttl, err := time.ParseDuration(t.TTL)
	if err != nil || ttl <= 0 {
		return 0, fmt.Errorf("ttl must be a positive duration such as 2h")
	}
	return ttl, nil
}

func validateTunnelName(name string) error {
	if name == "" {
		return errors.New("tunnel name cannot be empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("tunnel %q name is longer than 64 characters", name)
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return fmt.Errorf("tunnel %q name contains unsupported character %q", name, r)
	}
	return nil
}

func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (i > 0 && r >= '0' && r <= '9') || (i > 0 && r == '_') || (i == 0 && r == '_') {
			continue
		}
		return false
	}
	return true
}
