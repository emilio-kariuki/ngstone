package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadProjectWebhook(t *testing.T) {
	path := writeProject(t, `{"tunnels":{"pay":{"target":"3000","webhook":{"provider":"stripe","secret_file":"stripe.secret","path_prefix":"/stripe","tolerance":"2m"}}}}`)
	project, err := LoadProject(path)
	if err != nil {
		t.Fatalf("LoadProject: %v", err)
	}
	w := project.Tunnels["pay"].Webhook
	if w == nil || w.Provider != "stripe" || w.SecretFile != "stripe.secret" || w.PathPrefix != "/stripe" {
		t.Fatalf("webhook = %+v", w)
	}
	if d, err := w.ToleranceDuration(); err != nil || d != 2*time.Minute {
		t.Fatalf("tolerance = %v, %v", d, err)
	}
}

func TestLoadProjectRejectsBadWebhook(t *testing.T) {
	cases := map[string]string{
		`{"tunnels":{"db":{"target":"5432","kind":"tcp","webhook":{"provider":"github"}}}}`:                                       "only valid for http",
		`{"tunnels":{"web":{"target":"3000","webhook":{"provider":"paypal"}}}}`:                                                   "unknown webhook provider",
		`{"tunnels":{"web":{"target":"3000","webhook":{"provider":"github","secret":"inline"}}}}`:                                 "unknown field",
		`{"tunnels":{"web":{"target":"3000","webhook":{"provider":"github","secret_file":"a","secret_env":"B"}}}}`:                "either secret_file or secret_env",
		`{"tunnels":{"web":{"target":"3000","webhook":{"provider":"github","secret_env":"1BAD"}}}}`:                               "secret_env",
		`{"tunnels":{"web":{"target":"3000","webhook":{"provider":"slack","tolerance":"soon"}}}}`:                                 "positive duration",
		`{"tunnels":{"web":{"target":"3000","webhook":{"provider":"hmac"}}}}`:                                                     "header name",
		`{"tunnels":{"web":{"target":"3000","webhook":{"provider":"hmac","header":"X-Sig","encoding":"base32"}}}}`:                "encoding",
		`{"tunnels":{"web":{"target":"3000","webhook":{"provider":"github","path_prefix":"hooks"}}}}`:                             "start with /",
		`{"tunnels":{"web":{"target":"3000","webhook":{"provider":"github","header":"X-Hub-Signature-256","prefix":"sha256="}}}}`: "apply only",
	}
	for data, want := range cases {
		_, err := LoadProject(writeProject(t, data))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("LoadProject(%s) error = %v, want containing %q", data, err, want)
		}
	}
}

func TestParseTunnelsWebhook(t *testing.T) {
	f, err := ParseTunnels([]byte(`
tunnels:
  hooks:
    port: 3000
    webhook:
      provider: hmac
      header: X-Shopify-Hmac-Sha256
      encoding: base64
      secret_env: SHOPIFY_SECRET
`))
	if err != nil {
		t.Fatalf("ParseTunnels: %v", err)
	}
	w := f.Tunnels[0].Webhook
	if w == nil || w.Provider != "hmac" || w.Header != "X-Shopify-Hmac-Sha256" || w.Encoding != "base64" || w.SecretEnv != "SHOPIFY_SECRET" {
		t.Fatalf("webhook = %+v", w)
	}

	_, err = ParseTunnels([]byte(`
tunnels:
  db:
    kind: tcp
    port: 5432
    webhook:
      provider: github
`))
	if err == nil || !strings.Contains(err.Error(), "only valid for http") {
		t.Fatalf("tcp webhook error = %v", err)
	}
}
