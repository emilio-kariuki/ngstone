package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"go.yaml.in/yaml/v3"
)

// TunnelsFileName is the file `ngstone start` looks for in the current
// directory before falling back to the config directory.
const TunnelsFileName = "ngstone.yml"

// TunnelsFile is the format read by `ngstone start`:
//
//	server: example.com:4443
//	tunnels:
//	  web:
//	    port: 3000
//	    subdomain: demo
//	  db:
//	    kind: tcp
//	    port: 5432
type TunnelsFile struct {
	Server     string `yaml:"server"`
	ServerName string `yaml:"server_name"`

	// Tunnels keeps the order they appear in the file.
	Tunnels []NamedTunnel `yaml:"-"`
}

// NamedTunnel is one entry under `tunnels:`.
type NamedTunnel struct {
	Name string
	Tunnel
}

// Tunnel describes one tunnel. Kind is "http" (the default) or "tcp".
type Tunnel struct {
	Kind string `yaml:"kind"`

	// The local service: Port means 127.0.0.1:Port. HTTP tunnels may give a
	// full URL instead, TCP tunnels a host:port Address.
	Port    int    `yaml:"port"`
	URL     string `yaml:"url"`
	Address string `yaml:"address"`

	// HTTP only.
	Subdomain     string   `yaml:"subdomain"`
	HostHeader    string   `yaml:"host_header"`
	BasicAuth     []string `yaml:"basic_auth"`
	BasicAuthFile string   `yaml:"basic_auth_file"`

	// TCP only.
	RemotePort int `yaml:"remote_port"`

	AllowCIDR []string `yaml:"allow_cidr"`
}

const (
	KindHTTP = "http"
	KindTCP  = "tcp"
)

var tunnelNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// TunnelsPath resolves which tunnels file to read: the explicit path when
// given, else ./ngstone.yml if it exists, else tunnels.yml in the config
// directory.
func TunnelsPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if _, err := os.Stat(TunnelsFileName); err == nil {
		return TunnelsFileName, nil
	}
	cfgPath, err := Path()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfgPath), "tunnels.yml"), nil
}

// LoadTunnels reads and validates a tunnels file.
func LoadTunnels(path string) (TunnelsFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return TunnelsFile{}, fmt.Errorf("reading tunnels file: %w", err)
	}
	f, err := ParseTunnels(data)
	if err != nil {
		return TunnelsFile{}, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// ParseTunnels decodes and validates a tunnels file. Unknown keys are
// errors, so a typo cannot silently drop a setting such as allow_cidr.
func ParseTunnels(data []byte) (TunnelsFile, error) {
	var strict struct {
		Server     string            `yaml:"server"`
		ServerName string            `yaml:"server_name"`
		Tunnels    map[string]Tunnel `yaml:"tunnels"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&strict); err != nil {
		return TunnelsFile{}, fmt.Errorf("parsing: %w", err)
	}

	// Decode again as nodes only to recover the order of the tunnels.
	var ordered struct {
		Tunnels yaml.Node `yaml:"tunnels"`
	}
	if err := yaml.Unmarshal(data, &ordered); err != nil {
		return TunnelsFile{}, fmt.Errorf("parsing: %w", err)
	}

	f := TunnelsFile{Server: strict.Server, ServerName: strict.ServerName}
	if ordered.Tunnels.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(ordered.Tunnels.Content); i += 2 {
			name := ordered.Tunnels.Content[i].Value
			f.Tunnels = append(f.Tunnels, NamedTunnel{Name: name, Tunnel: strict.Tunnels[name]})
		}
	}
	if err := f.Validate(); err != nil {
		return TunnelsFile{}, err
	}
	return f, nil
}

// Validate checks every tunnel and normalizes Kind.
func (f *TunnelsFile) Validate() error {
	if len(f.Tunnels) == 0 {
		return errors.New("no tunnels defined under \"tunnels:\"")
	}
	subdomains := map[string]string{}
	var errs []error
	for i := range f.Tunnels {
		t := &f.Tunnels[i]
		if err := t.validate(); err != nil {
			errs = append(errs, fmt.Errorf("tunnel %q: %w", t.Name, err))
			continue
		}
		if t.Subdomain != "" {
			if other, dup := subdomains[t.Subdomain]; dup {
				errs = append(errs, fmt.Errorf("tunnels %q and %q both ask for subdomain %q", other, t.Name, t.Subdomain))
			}
			subdomains[t.Subdomain] = t.Name
		}
	}
	return errors.Join(errs...)
}

func (t *NamedTunnel) validate() error {
	if !tunnelNameRE.MatchString(t.Name) {
		return errors.New("names must be 1-32 lowercase letters, digits, - or _, starting with a letter or digit")
	}
	if t.Kind == "" {
		t.Kind = KindHTTP
	}
	if t.Port != 0 && (t.Port < 1 || t.Port > 65535) {
		return fmt.Errorf("port %d is out of range", t.Port)
	}
	if t.RemotePort < 0 || t.RemotePort > 65535 {
		return fmt.Errorf("remote_port %d is out of range", t.RemotePort)
	}
	for _, c := range t.AllowCIDR {
		if _, err := netip.ParsePrefix(c); err != nil {
			return fmt.Errorf("allow_cidr %q: %v", c, err)
		}
	}

	switch t.Kind {
	case KindHTTP:
		if (t.Port == 0) == (t.URL == "") {
			return errors.New("set exactly one of port or url")
		}
		if t.URL != "" {
			u, err := url.Parse(t.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("url %q must look like http://127.0.0.1:3000", t.URL)
			}
		}
		if t.Address != "" || t.RemotePort != 0 {
			return errors.New("address and remote_port are only for kind: tcp")
		}
		if len(t.BasicAuth) > 0 && t.BasicAuthFile != "" {
			return errors.New("set basic_auth or basic_auth_file, not both")
		}
	case KindTCP:
		if (t.Port == 0) == (t.Address == "") {
			return errors.New("set exactly one of port or address")
		}
		if t.Address != "" {
			host, port, err := net.SplitHostPort(t.Address)
			if err != nil || host == "" {
				return fmt.Errorf("address %q must look like db.local:5432", t.Address)
			}
			if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("address %q has an invalid port", t.Address)
			}
		}
		if t.URL != "" || t.Subdomain != "" || t.HostHeader != "" || len(t.BasicAuth) > 0 || t.BasicAuthFile != "" {
			return errors.New("url, subdomain, host_header and basic auth are only for kind: http")
		}
	default:
		return fmt.Errorf("kind %q must be http or tcp", t.Kind)
	}
	return nil
}
