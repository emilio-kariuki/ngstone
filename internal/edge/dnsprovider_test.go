package edge

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/libdns/libdns"
)

// fakeDNSProvider satisfies certmagic.DNSProvider for tests that never
// reach an ACME server.
type fakeDNSProvider struct{}

func (fakeDNSProvider) AppendRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}

func (fakeDNSProvider) DeleteRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestNewDNSProviderEveryProviderBuildsWithItsCredentials(t *testing.T) {
	for _, name := range DNSProviderNames() {
		t.Run(name, func(t *testing.T) {
			vars, err := DNSProviderEnv(name)
			if err != nil {
				t.Fatalf("DNSProviderEnv: %v", err)
			}
			env := map[string]string{}
			for _, v := range vars {
				env[v.Name] = "test-value"
			}
			p, err := NewDNSProvider(name, envMap(env))
			if err != nil {
				t.Fatalf("NewDNSProvider: %v", err)
			}
			if p == nil {
				t.Fatal("NewDNSProvider returned a nil provider")
			}
		})
	}
}

func TestNewDNSProviderNamesMissingCredentials(t *testing.T) {
	for _, name := range DNSProviderNames() {
		t.Run(name, func(t *testing.T) {
			vars, _ := DNSProviderEnv(name)
			_, err := NewDNSProvider(name, envMap(nil))
			for _, v := range vars {
				if v.Optional {
					continue
				}
				if err == nil || !strings.Contains(err.Error(), v.Name) {
					t.Fatalf("error %v does not name missing required variable %s", err, v.Name)
				}
			}
		})
	}
}

func TestNewDNSProviderRejectsUnknownName(t *testing.T) {
	_, err := NewDNSProvider("not-a-provider", envMap(nil))
	if err == nil || !strings.Contains(err.Error(), "cloudflare") {
		t.Fatalf("err = %v, want an unknown-provider error listing the supported names", err)
	}
}

func TestNewDNSProviderIsCaseInsensitive(t *testing.T) {
	if _, err := NewDNSProvider("Cloudflare", envMap(map[string]string{"NGSTONE_CF_API_TOKEN": "x"})); err != nil {
		t.Fatalf("NewDNSProvider(Cloudflare): %v", err)
	}
}

// The installer keeps its own provider table so it can prompt for
// credentials before any binary is installed. This keeps the two in sync.
func TestInstallerDNSProviderTableMatchesRegistry(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/install-edge.sh")
	if err != nil {
		t.Fatalf("reading installer: %v", err)
	}
	src := string(raw)
	const open = "DNS_PROVIDER_TABLE='\n"
	start := strings.Index(src, open)
	if start < 0 {
		t.Fatal("installer has no DNS_PROVIDER_TABLE")
	}
	body := src[start+len(open):]
	end := strings.Index(body, "'")
	if end < 0 {
		t.Fatal("DNS_PROVIDER_TABLE is not terminated")
	}

	installer := map[string][]string{}
	for _, line := range strings.Split(body[:end], "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var vars []string
		for _, f := range fields[1:] {
			name, kind, ok := strings.Cut(f, ":")
			if !ok || (kind != "secret" && kind != "plain") {
				t.Fatalf("installer entry %q for %s must be VAR:secret or VAR:plain", f, fields[0])
			}
			vars = append(vars, name)
		}
		sort.Strings(vars)
		installer[fields[0]] = vars
	}

	for _, name := range DNSProviderNames() {
		env, _ := DNSProviderEnv(name)
		var want []string
		for _, v := range env {
			want = append(want, v.Name)
		}
		sort.Strings(want)
		got, ok := installer[name]
		if !ok {
			t.Errorf("installer table is missing provider %s", name)
			continue
		}
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("installer credentials for %s = %v, edge reads %v", name, got, want)
		}
		delete(installer, name)
	}
	for name := range installer {
		t.Errorf("installer lists provider %s that the edge does not support", name)
	}
}
