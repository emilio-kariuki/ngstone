package edge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"ngstone/internal/storage"
)

const customCertSecretMarker = "SECRETMARKERDONOTLEAK"

func customCertTemplate(names []string, ips []net.IP, notAfter time.Time) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		DNSNames:     names,
		IPAddresses:  ips,
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if len(names) > 0 {
		tmpl.Subject = pkix.Name{CommonName: names[0]}
	}
	return tmpl
}

func signCustomCert(t *testing.T, tmpl *x509.Certificate) (crt, key []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func customCertPEM(t *testing.T, names []string, ips []net.IP, notAfter time.Time) (crt, key []byte) {
	t.Helper()
	return signCustomCert(t, customCertTemplate(names, ips, notAfter))
}

func writeCustomTemplate(t *testing.T, dir, stem string, tmpl *x509.Certificate) {
	t.Helper()
	crt, key := signCustomCert(t, tmpl)
	if err := os.WriteFile(filepath.Join(dir, stem+".crt"), crt, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stem+".key"), key, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeCustomPair(t *testing.T, dir, stem string, names []string, notAfter time.Time) {
	t.Helper()
	crt, key := customCertPEM(t, names, nil, notAfter)
	if err := os.WriteFile(filepath.Join(dir, stem+".crt"), crt, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stem+".key"), key, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadCustomCertificates(t *testing.T) {
	valid := time.Now().Add(30 * 24 * time.Hour)
	reserved := func(name string) bool { return hostMatchesDomain(name, "example.com") }
	now := time.Now()

	cases := []struct {
		name    string
		setup   func(t *testing.T, dir string) string
		wantErr string
		want    []string
	}{
		{name: "single pair", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "app", []string{"app.example.org"}, valid)
			return dir
		}, want: []string{"app.example.org"}},
		{name: "two pairs and wildcard on another domain", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "a", []string{"a.example.org"}, valid)
			writeCustomPair(t, dir, "b", []string{"*.other.net", "b.example.org"}, valid)
			return dir
		}, want: []string{"a.example.org", "*.other.net", "b.example.org"}},
		{name: "ignores subdirectories dotfiles and other extensions", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "app", []string{"app.example.org"}, valid)
			sub := filepath.Join(dir, "sub")
			if err := os.Mkdir(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			writeCustomPair(t, sub, "nested", []string{"nested.example.org"}, valid)
			if err := os.WriteFile(filepath.Join(dir, ".hidden.crt"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "notes.pem"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return dir
		}, want: []string{"app.example.org"}},
		{name: "missing directory", setup: func(t *testing.T, dir string) string {
			return filepath.Join(dir, "missing")
		}, wantErr: "missing"},
		{name: "not a directory", setup: func(t *testing.T, dir string) string {
			file := filepath.Join(dir, "file")
			if err := os.WriteFile(file, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return file
		}, wantErr: "is not a directory"},
		{name: "group writable directory", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "app", []string{"app.example.org"}, valid)
			if err := os.Chmod(dir, 0o770); err != nil {
				t.Fatal(err)
			}
			return dir
		}, wantErr: "group or world writable"},
		{name: "world writable directory", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "app", []string{"app.example.org"}, valid)
			if err := os.Chmod(dir, 0o707); err != nil {
				t.Fatal(err)
			}
			return dir
		}, wantErr: "group or world writable"},
		{name: "orphan certificate", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "app", []string{"app.example.org"}, valid)
			if err := os.WriteFile(filepath.Join(dir, "lonely.crt"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return dir
		}, wantErr: "lonely.crt has no matching key"},
		{name: "orphan key", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "app", []string{"app.example.org"}, valid)
			if err := os.WriteFile(filepath.Join(dir, "lonely.key"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return dir
		}, wantErr: "lonely.key has no matching certificate"},
		{name: "empty directory", setup: func(t *testing.T, dir string) string {
			return dir
		}, wantErr: "contains no certificate and key pairs"},
		{name: "key readable by group", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "app", []string{"app.example.org"}, valid)
			if err := os.Chmod(filepath.Join(dir, "app.key"), 0o640); err != nil {
				t.Fatal(err)
			}
			return dir
		}, wantErr: "must not be group or world readable"},
		{name: "key readable by world", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "app", []string{"app.example.org"}, valid)
			if err := os.Chmod(filepath.Join(dir, "app.key"), 0o604); err != nil {
				t.Fatal(err)
			}
			return dir
		}, wantErr: "must not be group or world readable"},
		{name: "key symlink to a permissive file", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "app", []string{"app.example.org"}, valid)
			target := filepath.Join(t.TempDir(), "real.key")
			data, err := os.ReadFile(filepath.Join(dir, "app.key"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, data, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(dir, "app.key")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, "app.key")); err != nil {
				t.Fatal(err)
			}
			return dir
		}, wantErr: "must not be group or world readable"},
		{name: "key symlink to a private file", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "app", []string{"app.example.org"}, valid)
			target := filepath.Join(t.TempDir(), "real.key")
			if err := os.Rename(filepath.Join(dir, "app.key"), target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, "app.key")); err != nil {
				t.Fatal(err)
			}
			return dir
		}, want: []string{"app.example.org"}},
		{name: "key symlink to a directory", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "app", []string{"app.example.org"}, valid)
			if err := os.Remove(filepath.Join(dir, "app.key")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), filepath.Join(dir, "app.key")); err != nil {
				t.Fatal(err)
			}
			return dir
		}, wantErr: "is not a regular file"},
		{name: "unparsable pair", setup: func(t *testing.T, dir string) string {
			if err := os.WriteFile(filepath.Join(dir, "bad.crt"), []byte(customCertSecretMarker), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "bad.key"), []byte(customCertSecretMarker), 0o600); err != nil {
				t.Fatal(err)
			}
			return dir
		}, wantErr: "custom certificate " + "%DIR%/bad.crt with key %DIR%/bad.key"},
		{name: "no DNS names", setup: func(t *testing.T, dir string) string {
			crt, key := customCertPEM(t, nil, []net.IP{net.ParseIP("192.0.2.1")}, valid)
			if err := os.WriteFile(filepath.Join(dir, "ip.crt"), crt, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "ip.key"), key, 0o600); err != nil {
				t.Fatal(err)
			}
			return dir
		}, wantErr: "has no DNS names"},
		{name: "SAN under the edge domain", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "app", []string{"ok.example.org", "app.example.com"}, valid)
			return dir
		}, wantErr: "app.example.com is reserved"},
		{name: "SAN equal to the edge domain", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "app", []string{"example.com"}, valid)
			return dir
		}, wantErr: "example.com is reserved"},
		{name: "wildcard under the edge domain", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "app", []string{"*.apps.example.com"}, valid)
			return dir
		}, wantErr: "overlaps the edge domain"},
		{name: "wildcard equal to the edge domain", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "app", []string{"*.example.com"}, valid)
			return dir
		}, wantErr: "overlaps the edge domain"},
		{name: "wildcard parent of the edge domain", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "app", []string{"*.com"}, valid)
			return dir
		}, wantErr: "overlaps the edge domain"},
		{name: "common name naming an edge hostname", setup: func(t *testing.T, dir string) string {
			tmpl := customCertTemplate([]string{"app.example.org"}, nil, valid)
			tmpl.Subject = pkix.Name{CommonName: "victim.example.com"}
			writeCustomTemplate(t, dir, "app", tmpl)
			return dir
		}, wantErr: "subject common name that is not one of its DNS names"},
		{name: "common name not among the DNS names", setup: func(t *testing.T, dir string) string {
			tmpl := customCertTemplate([]string{"app.example.org"}, nil, valid)
			tmpl.Subject = pkix.Name{CommonName: "victim.example.net"}
			writeCustomTemplate(t, dir, "app", tmpl)
			return dir
		}, wantErr: "subject common name that is not one of its DNS names"},
		{name: "IP address name", setup: func(t *testing.T, dir string) string {
			writeCustomTemplate(t, dir, "app", customCertTemplate([]string{"app.example.org"}, []net.IP{net.ParseIP("192.0.2.1")}, valid))
			return dir
		}, wantErr: "must not contain IP address, e-mail or URI names"},
		{name: "e-mail name", setup: func(t *testing.T, dir string) string {
			tmpl := customCertTemplate([]string{"app.example.org"}, nil, valid)
			tmpl.EmailAddresses = []string{"ops@example.org"}
			writeCustomTemplate(t, dir, "app", tmpl)
			return dir
		}, wantErr: "must not contain IP address, e-mail or URI names"},
		{name: "URI name", setup: func(t *testing.T, dir string) string {
			tmpl := customCertTemplate([]string{"app.example.org"}, nil, valid)
			tmpl.URIs = []*url.URL{{Scheme: "https", Host: "victim.example.com"}}
			writeCustomTemplate(t, dir, "app", tmpl)
			return dir
		}, wantErr: "must not contain IP address, e-mail or URI names"},
		{name: "common name equal to a DNS name in another case", setup: func(t *testing.T, dir string) string {
			tmpl := customCertTemplate([]string{"a.example.org", "b.example.org"}, nil, valid)
			tmpl.Subject = pkix.Name{CommonName: "B.Example.ORG"}
			writeCustomTemplate(t, dir, "app", tmpl)
			return dir
		}, want: []string{"a.example.org", "b.example.org"}},
		{name: "empty common name", setup: func(t *testing.T, dir string) string {
			tmpl := customCertTemplate([]string{"app.example.org"}, nil, valid)
			tmpl.Subject = pkix.Name{}
			writeCustomTemplate(t, dir, "app", tmpl)
			return dir
		}, want: []string{"app.example.org"}},
		{name: "expired", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "app", []string{"app.example.org"}, now.Add(-time.Minute))
			return dir
		}, wantErr: "expired at"},
		{name: "duplicate SAN across pairs", setup: func(t *testing.T, dir string) string {
			writeCustomPair(t, dir, "a", []string{"same.example.org"}, valid)
			writeCustomPair(t, dir, "b", []string{"other.example.org", "same.example.org"}, valid)
			return dir
		}, wantErr: "both cover same.example.org"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "certs")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			target := tc.setup(t, dir)
			got, err := loadCustomCertificates(target, reserved, "example.com", now)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("loaded %d certificates, want error containing %q", len(got), tc.wantErr)
				}
				want := strings.ReplaceAll(tc.wantErr, "%DIR%", dir)
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error = %v, want it to contain %q", err, want)
				}
				if strings.Contains(err.Error(), customCertSecretMarker) || strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), "BEGIN") {
					t.Fatalf("error leaks file contents: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadCustomCertificates: %v", err)
			}
			var names []string
			for _, c := range got {
				names = append(names, c.names...)
			}
			if strings.Join(names, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("names = %v, want %v", names, tc.want)
			}
			for _, c := range got {
				if c.notAfter.IsZero() || c.file == "" || c.cert.Leaf == nil {
					t.Fatalf("incomplete customCert: %+v", c)
				}
			}
		})
	}
}

func TestNewRejectsCustomCertDirMisconfiguration(t *testing.T) {
	store, err := storage.Open(storage.Config{DSN: filepath.Join(t.TempDir(), "control.db"), EdgeID: "edge-test"})
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	dir := t.TempDir()

	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"insecure mode", Config{Domain: "example.com", Insecure: true, Storage: store, CustomCertDir: dir}, "insecure mode"},
		{"public tls config", Config{Domain: "example.com", Storage: store, CustomCertDir: dir, PublicTLSConfig: &tls.Config{}}, "public TLS config"},
		{"no durable storage", Config{Domain: "example.com", CustomCertDir: dir}, "durable storage"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := New(tc.cfg)
			if err == nil {
				t.Fatalf("New succeeded: %v", srv)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}

	if _, err := New(Config{Domain: "example.com", Storage: store, CustomCertDir: dir}); err != nil {
		t.Fatalf("New with a valid custom certificate configuration: %v", err)
	}
}

func TestCustomCertificateSNISelection(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeCustomPair(t, dir, "custom", []string{"app.example.org", "*.wild.example.net"}, time.Now().Add(24*time.Hour*30))
	certs, err := loadCustomCertificates(dir, func(name string) bool { return hostMatchesDomain(name, "example.com") }, "example.com", time.Now())
	if err != nil {
		t.Fatalf("loadCustomCertificates: %v", err)
	}

	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil }})
	t.Cleanup(cache.Stop)
	magic = certmagic.New(cache, certmagic.Config{})
	mgr := &TLSManager{magic: magic}
	if err := mgr.AddCustomCertificates(t.Context(), certs); err != nil {
		t.Fatalf("AddCustomCertificates: %v", err)
	}

	leaf := certs[0].cert.Leaf.Raw
	conn, other := net.Pipe()
	t.Cleanup(func() { conn.Close(); other.Close() })
	for _, sni := range []string{"app.example.org", "APP.example.org", "x.wild.example.net"} {
		got, err := mgr.PublicTLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: sni, Conn: conn})
		if err != nil || got == nil || string(got.Certificate[0]) != string(leaf) {
			t.Fatalf("SNI %q: cert=%v err=%v, want the custom leaf", sni, got != nil, err)
		}
	}
	for _, sni := range []string{"other.example.org", "wild.example.net", "a.b.wild.example.net", "app.example.com", ""} {
		got, err := mgr.PublicTLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: sni, Conn: conn})
		if err == nil && got != nil && string(got.Certificate[0]) == string(leaf) {
			t.Fatalf("SNI %q was served the custom leaf", sni)
		}
	}
}
