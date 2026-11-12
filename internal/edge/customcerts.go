package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

const customCertTag = "custom"

type customCert struct {
	cert     tls.Certificate
	file     string
	names    []string
	notAfter time.Time
}

func loadCustomCertificates(dir string, reserved func(string) bool, edgeDomain string, now time.Time) ([]customCert, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("custom certificate directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("custom certificate directory %s is not a directory", dir)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("custom certificate directory %s must not be group or world writable", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("custom certificate directory %s: %w", dir, err)
	}
	crts := map[string]bool{}
	keys := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		switch filepath.Ext(name) {
		case ".crt":
			crts[strings.TrimSuffix(name, ".crt")] = true
		case ".key":
			keys[strings.TrimSuffix(name, ".key")] = true
		}
	}
	var stems []string
	for stem := range crts {
		if !keys[stem] {
			return nil, fmt.Errorf("custom certificate %s has no matching key %s", filepath.Join(dir, stem+".crt"), filepath.Join(dir, stem+".key"))
		}
		stems = append(stems, stem)
	}
	for stem := range keys {
		if !crts[stem] {
			return nil, fmt.Errorf("custom certificate key %s has no matching certificate %s", filepath.Join(dir, stem+".key"), filepath.Join(dir, stem+".crt"))
		}
	}
	if len(stems) == 0 {
		return nil, fmt.Errorf("custom certificate directory %s contains no certificate and key pairs", dir)
	}
	sort.Strings(stems)

	owners := map[string]string{}
	var out []customCert
	for _, stem := range stems {
		crtPath := filepath.Join(dir, stem+".crt")
		keyPath := filepath.Join(dir, stem+".key")
		keyInfo, err := os.Stat(keyPath)
		if err != nil {
			return nil, fmt.Errorf("custom certificate key %s: %w", keyPath, err)
		}
		if !keyInfo.Mode().IsRegular() {
			return nil, fmt.Errorf("custom certificate key %s is not a regular file", keyPath)
		}
		if keyInfo.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("custom certificate key %s must not be group or world readable", keyPath)
		}
		pair, err := tls.LoadX509KeyPair(crtPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("custom certificate %s with key %s: %w", crtPath, keyPath, err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("custom certificate %s: parsing leaf: %w", crtPath, err)
		}
		pair.Leaf = leaf
		if len(leaf.DNSNames) == 0 {
			return nil, fmt.Errorf("custom certificate %s has no DNS names", crtPath)
		}
		if len(leaf.IPAddresses) > 0 || len(leaf.EmailAddresses) > 0 || len(leaf.URIs) > 0 {
			return nil, fmt.Errorf("custom certificate %s must not contain IP address, e-mail or URI names", crtPath)
		}
		if cn := leaf.Subject.CommonName; cn != "" && !slices.ContainsFunc(leaf.DNSNames, func(dns string) bool { return strings.EqualFold(cn, dns) }) {
			return nil, fmt.Errorf("custom certificate %s has a subject common name that is not one of its DNS names", crtPath)
		}
		if !now.Before(leaf.NotAfter) {
			return nil, fmt.Errorf("custom certificate %s expired at %s", crtPath, leaf.NotAfter.UTC().Format(time.RFC3339))
		}
		names := make([]string, 0, len(leaf.DNSNames))
		for _, raw := range leaf.DNSNames {
			name := strings.TrimSuffix(strings.ToLower(raw), ".")
			if err := checkCustomCertName(name, reserved, edgeDomain); err != nil {
				return nil, fmt.Errorf("custom certificate %s: %w", crtPath, err)
			}
			if other, dup := owners[name]; dup {
				return nil, fmt.Errorf("custom certificates %s and %s both cover %s", other, crtPath, name)
			}
			owners[name] = crtPath
			names = append(names, name)
		}
		out = append(out, customCert{cert: pair, file: crtPath, names: names, notAfter: leaf.NotAfter})
	}
	return out, nil
}

func checkCustomCertName(name string, reserved func(string) bool, edgeDomain string) error {
	if name == "" {
		return fmt.Errorf("empty DNS name")
	}
	if rest, wildcard := strings.CutPrefix(name, "*."); wildcard {
		if rest == "" || strings.Contains(rest, "*") {
			return fmt.Errorf("unsupported wildcard name %s", name)
		}
		if hostMatchesDomain(rest, edgeDomain) || hostMatchesDomain(edgeDomain, rest) {
			return fmt.Errorf("wildcard name %s overlaps the edge domain %s", name, edgeDomain)
		}
		return nil
	}
	if strings.Contains(name, "*") {
		return fmt.Errorf("unsupported wildcard name %s", name)
	}
	if reserved(name) {
		return fmt.Errorf("name %s is reserved by the edge", name)
	}
	return nil
}

func (m *TLSManager) AddCustomCertificates(ctx context.Context, certs []customCert) error {
	for _, c := range certs {
		if _, err := m.custom.CacheUnmanagedTLSCertificate(ctx, c.cert, []string{customCertTag}); err != nil {
			return fmt.Errorf("loading custom certificate %s: %w", c.file, err)
		}
		slog.Info("ngstoned: custom certificate loaded", "file", c.file, "names", c.names, "not_after", c.notAfter.UTC().Format(time.RFC3339))
	}
	return nil
}
