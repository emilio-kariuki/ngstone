package edge

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awscredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/bunny"
	"github.com/libdns/cloudflare"
	"github.com/libdns/desec"
	"github.com/libdns/digitalocean"
	hetzner "github.com/libdns/hetzner/v2"
	"github.com/libdns/ovh"
	"github.com/libdns/route53"
	vultr "github.com/libdns/vultr/v2"
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
// live at the same time. GoDaddy, Namecheap, Porkbun, IONOS, Azure, DNSimple
// and netcup were checked and left out because their libdns modules replace
// or delete every TXT value at the name.
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
	"route53": {
		Label: "Amazon Route 53",
		Env: []DNSEnvVar{
			{Name: "NGSTONE_AWS_REGION", Help: "AWS region, for example us-east-1"},
			{Name: "NGSTONE_AWS_ACCESS_KEY_ID", Help: "access key ID of an IAM user limited to the hosted zone"},
			{Name: "NGSTONE_AWS_SECRET_ACCESS_KEY", Help: "secret access key for that IAM user"},
		},
		Note: "the IAM policy needs route53:ListHostedZonesByName, route53:ListResourceRecordSets, route53:ChangeResourceRecordSets and route53:GetChange",
		build: func(get func(string) string) (certmagic.DNSProvider, error) {
			p := &route53.Provider{
				Region:          get("NGSTONE_AWS_REGION"),
				AccessKeyId:     get("NGSTONE_AWS_ACCESS_KEY_ID"),
				SecretAccessKey: get("NGSTONE_AWS_SECRET_ACCESS_KEY"),
			}
			// The provider calls log.Fatalf if the AWS SDK config fails to
			// load on first use. Load it once here so a bad environment
			// fails at startup with a normal error instead.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := awsconfig.LoadDefaultConfig(ctx,
				awsconfig.WithRegion(p.Region),
				awsconfig.WithCredentialsProvider(awscredentials.NewStaticCredentialsProvider(p.AccessKeyId, p.SecretAccessKey, "")),
			); err != nil {
				return nil, fmt.Errorf("edge: loading AWS configuration for route53: %w", err)
			}
			return p, nil
		},
	},
	"digitalocean": {
		Label: "DigitalOcean",
		Env: []DNSEnvVar{
			{Name: "NGSTONE_DO_API_TOKEN", Help: "personal access token with domain read and write scopes"},
		},
		build: func(get func(string) string) (certmagic.DNSProvider, error) {
			return &digitalocean.Provider{APIToken: get("NGSTONE_DO_API_TOKEN")}, nil
		},
	},
	"hetzner": {
		Label: "Hetzner",
		Env: []DNSEnvVar{
			{Name: "NGSTONE_HETZNER_API_TOKEN", Help: "read and write API token of the Hetzner Console project that holds the zone"},
		},
		Note: "uses the Hetzner Console (Cloud API) DNS; zones still on the deprecated dns.hetzner.com must be migrated first",
		build: func(get func(string) string) (certmagic.DNSProvider, error) {
			return &hetzner.Provider{APIToken: get("NGSTONE_HETZNER_API_TOKEN")}, nil
		},
	},
	"vultr": {
		Label: "Vultr",
		Env: []DNSEnvVar{
			{Name: "NGSTONE_VULTR_API_KEY", Help: "API key; allow the VPS's IP in the key's access control"},
		},
		build: func(get func(string) string) (certmagic.DNSProvider, error) {
			return &vultr.Provider{APIToken: get("NGSTONE_VULTR_API_KEY")}, nil
		},
	},
	"ovh": {
		Label: "OVHcloud",
		Env: []DNSEnvVar{
			{Name: "NGSTONE_OVH_ENDPOINT", Help: "API endpoint: ovh-eu, ovh-ca or ovh-us"},
			{Name: "NGSTONE_OVH_APPLICATION_KEY", Help: "application key"},
			{Name: "NGSTONE_OVH_APPLICATION_SECRET", Help: "application secret"},
			{Name: "NGSTONE_OVH_CONSUMER_KEY", Help: "consumer key with GET, POST and DELETE on /domain/zone/*"},
		},
		build: func(get func(string) string) (certmagic.DNSProvider, error) {
			return &ovh.Provider{
				Endpoint:          get("NGSTONE_OVH_ENDPOINT"),
				ApplicationKey:    get("NGSTONE_OVH_APPLICATION_KEY"),
				ApplicationSecret: get("NGSTONE_OVH_APPLICATION_SECRET"),
				ConsumerKey:       get("NGSTONE_OVH_CONSUMER_KEY"),
			}, nil
		},
	},
	"desec": {
		Label: "deSEC",
		Env: []DNSEnvVar{
			{Name: "NGSTONE_DESEC_TOKEN", Help: "API token from desec.io/tokens"},
		},
		Note: "deSEC enforces a 3600s minimum TTL and rate limits, so issuance can take a few minutes",
		build: func(get func(string) string) (certmagic.DNSProvider, error) {
			return &desec.Provider{Token: get("NGSTONE_DESEC_TOKEN")}, nil
		},
	},
	"bunny": {
		Label: "Bunny DNS",
		Env: []DNSEnvVar{
			{Name: "NGSTONE_BUNNY_API_KEY", Help: "account API key"},
		},
		build: func(get func(string) string) (certmagic.DNSProvider, error) {
			return &bunny.Provider{AccessKey: get("NGSTONE_BUNNY_API_KEY")}, nil
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
