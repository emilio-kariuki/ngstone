package edge

import (
	"fmt"
	"sort"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

// DefaultDNSProvider is the ACME DNS-01 provider used when none is chosen.
const DefaultDNSProvider = "cloudflare"

// DNSEnvVar is one credential a DNS provider reads. Credentials are read
// from the environment only, never from flags: /proc/<pid>/cmdline is
// world-readable, so any local user could read a flag value with ps.
type DNSEnvVar struct {
	Name     string
	Help     string
	Optional bool
}

// dnsProviderSpec describes one supported provider. Only providers whose
// libdns implementation appends TXT values without replacing others at the
// same name, and deletes by value, are listed: the apex and wildcard
// certificates share _acme-challenge.<domain>, and their challenges can be
// live at the same time.
type dnsProviderSpec struct {
	Label string
	Env   []DNSEnvVar
	Note  string
	build func(get func(string) string) (certmagic.DNSProvider, error)
}

var dnsProviders = map[string]dnsProviderSpec{
	"cloudflare": {
		Label: "Cloudflare",
		Env: []DNSEnvVar{
			{Name: "NGSTONE_CF_API_TOKEN", Help: "API token with Zone / DNS / Edit on the zone only"},
		},
		build: func(get func(string) string) (certmagic.DNSProvider, error) {
			return &cloudflare.Provider{APIToken: get("NGSTONE_CF_API_TOKEN")}, nil
		},
	},
}

// DNSProviderNames lists the supported provider names, sorted.
func DNSProviderNames() []string {
	names := make([]string, 0, len(dnsProviders))
	for name := range dnsProviders {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// DNSProviderEnv returns the credentials the named provider reads.
func DNSProviderEnv(name string) ([]DNSEnvVar, error) {
	spec, err := lookupDNSProvider(name)
	if err != nil {
		return nil, err
	}
	return spec.Env, nil
}

// NewDNSProvider builds the named provider from credentials returned by get,
// normally os.Getenv. It fails, naming every missing variable, when a
// required credential is empty.
func NewDNSProvider(name string, get func(string) string) (certmagic.DNSProvider, error) {
	spec, err := lookupDNSProvider(name)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, v := range spec.Env {
		if !v.Optional && strings.TrimSpace(get(v.Name)) == "" {
			missing = append(missing, v.Name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("edge: DNS provider %q needs %s set in the environment", name, strings.Join(missing, ", "))
	}
	return spec.build(func(key string) string { return strings.TrimSpace(get(key)) })
}

// DescribeDNSProviders renders the supported providers and their
// credentials, for -dns-provider help.
func DescribeDNSProviders() string {
	var b strings.Builder
	for _, name := range DNSProviderNames() {
		spec := dnsProviders[name]
		fmt.Fprintf(&b, "%s (%s)\n", name, spec.Label)
		for _, v := range spec.Env {
			req := "required"
			if v.Optional {
				req = "optional"
			}
			fmt.Fprintf(&b, "    %s  %s, %s\n", v.Name, req, v.Help)
		}
		if spec.Note != "" {
			fmt.Fprintf(&b, "    note: %s\n", spec.Note)
		}
	}
	return b.String()
}

func lookupDNSProvider(name string) (dnsProviderSpec, error) {
	spec, ok := dnsProviders[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return dnsProviderSpec{}, fmt.Errorf("edge: unknown DNS provider %q; supported: %s", name, strings.Join(DNSProviderNames(), ", "))
	}
	return spec, nil
}
