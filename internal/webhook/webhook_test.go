package webhook

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	githubDocSecret    = "It's a Secret to Everybody"
	githubDocBody      = "Hello, World!"
	githubDocSignature = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"

	slackDocSecret    = "8f742231b10e8888abcd99yyyzzz85a5"
	slackDocTimestamp = "1531420618"
	slackDocBody      = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c"
	slackDocSignature = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503"

	stripeSecret    = "whsec_test_secret"
	stripeTimestamp = int64(1700000000)
	stripeBody      = `{"id":"evt_test","object":"event"}`
	stripeV1        = "8042376f6ca064adbe037642a718227dfd59047137eb49497a54c49eb0cfb724"

	hmacBase64Secret    = "shpss_secret"
	hmacBase64Body      = `{"id":1}`
	hmacBase64Signature = "xocA3LkeJ/RvNrkxep1EUtFHuj7rIoIqZYaLU26LyPQ="

	hmacHexSecret    = "generic"
	hmacHexBody      = "payload"
	hmacHexSignature = "a5e0dd0887cd879caf06082250abf4862c246cdad52845d437f9d1b9d53b02ae"
)

func headers(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return h
}

func TestVerify(t *testing.T) {
	stripeNow := time.Unix(stripeTimestamp, 0)
	slackNow := time.Unix(1531420618, 0)
	tests := []struct {
		name    string
		cfg     Config
		header  http.Header
		body    string
		now     time.Time
		wantErr error
	}{
		{
			name:   "github documented vector",
			cfg:    Config{Provider: ProviderGitHub, Secret: githubDocSecret},
			header: headers(GitHubSignatureHeader, githubDocSignature),
			body:   githubDocBody,
		},
		{
			name:    "github tampered body",
			cfg:     Config{Provider: ProviderGitHub, Secret: githubDocSecret},
			header:  headers(GitHubSignatureHeader, githubDocSignature),
			body:    githubDocBody + "!",
			wantErr: ErrInvalidSignature,
		},
		{
			name:    "github wrong secret",
			cfg:     Config{Provider: ProviderGitHub, Secret: "other"},
			header:  headers(GitHubSignatureHeader, githubDocSignature),
			body:    githubDocBody,
			wantErr: ErrInvalidSignature,
		},
		{
			name:    "github missing header",
			cfg:     Config{Provider: ProviderGitHub, Secret: githubDocSecret},
			header:  headers("X-Hub-Signature", "sha1=0000"),
			body:    githubDocBody,
			wantErr: ErrMissingSignature,
		},
		{
			name:    "github sha1 style value",
			cfg:     Config{Provider: ProviderGitHub, Secret: githubDocSecret},
			header:  headers(GitHubSignatureHeader, "sha1=757107ea0eb2509fc211221cce984b8a37570b6d"),
			body:    githubDocBody,
			wantErr: ErrMalformedSignature,
		},
		{
			name:    "github duplicated header",
			cfg:     Config{Provider: ProviderGitHub, Secret: githubDocSecret},
			header:  headers(GitHubSignatureHeader, githubDocSignature, GitHubSignatureHeader, githubDocSignature),
			body:    githubDocBody,
			wantErr: ErrMalformedSignature,
		},
		{
			name:   "slack documented vector",
			cfg:    Config{Provider: ProviderSlack, Secret: slackDocSecret},
			header: headers(SlackSignatureHeader, slackDocSignature, SlackTimestampHeader, slackDocTimestamp),
			body:   slackDocBody,
			now:    slackNow.Add(4 * time.Minute),
		},
		{
			name:    "slack replay outside window",
			cfg:     Config{Provider: ProviderSlack, Secret: slackDocSecret},
			header:  headers(SlackSignatureHeader, slackDocSignature, SlackTimestampHeader, slackDocTimestamp),
			body:    slackDocBody,
			now:     slackNow.Add(6 * time.Minute),
			wantErr: ErrTimestampOutOfRange,
		},
		{
			name:   "slack custom window",
			cfg:    Config{Provider: ProviderSlack, Secret: slackDocSecret, Tolerance: time.Hour},
			header: headers(SlackSignatureHeader, slackDocSignature, SlackTimestampHeader, slackDocTimestamp),
			body:   slackDocBody,
			now:    slackNow.Add(30 * time.Minute),
		},
		{
			name:    "slack timestamp swapped",
			cfg:     Config{Provider: ProviderSlack, Secret: slackDocSecret},
			header:  headers(SlackSignatureHeader, slackDocSignature, SlackTimestampHeader, "1531420619"),
			body:    slackDocBody,
			now:     slackNow,
			wantErr: ErrInvalidSignature,
		},
		{
			name:    "slack missing timestamp",
			cfg:     Config{Provider: ProviderSlack, Secret: slackDocSecret},
			header:  headers(SlackSignatureHeader, slackDocSignature),
			body:    slackDocBody,
			now:     slackNow,
			wantErr: ErrMissingSignature,
		},
		{
			name:    "slack non numeric timestamp",
			cfg:     Config{Provider: ProviderSlack, Secret: slackDocSecret},
			header:  headers(SlackSignatureHeader, slackDocSignature, SlackTimestampHeader, "-1531420618"),
			body:    slackDocBody,
			now:     slackNow,
			wantErr: ErrMalformedSignature,
		},
		{
			name:   "stripe v1",
			cfg:    Config{Provider: ProviderStripe, Secret: stripeSecret},
			header: headers(StripeSignatureHeader, "t=1700000000,v1="+stripeV1),
			body:   stripeBody,
			now:    stripeNow,
		},
		{
			name:   "stripe several v1 and v0 with spaces",
			cfg:    Config{Provider: ProviderStripe, Secret: stripeSecret},
			header: headers(StripeSignatureHeader, "t=1700000000, v1=00"+stripeV1[2:]+", v1="+stripeV1+", v0=6ffbb59b2300aae63f272406069a9788598b792a944a07aba816edb039989a39,"),
			body:   stripeBody,
			now:    stripeNow.Add(-time.Minute),
		},
		{
			name:    "stripe tampered body",
			cfg:     Config{Provider: ProviderStripe, Secret: stripeSecret},
			header:  headers(StripeSignatureHeader, "t=1700000000,v1="+stripeV1),
			body:    strings.Replace(stripeBody, "evt_test", "evt_evil", 1),
			now:     stripeNow,
			wantErr: ErrInvalidSignature,
		},
		{
			name:    "stripe expired",
			cfg:     Config{Provider: ProviderStripe, Secret: stripeSecret},
			header:  headers(StripeSignatureHeader, "t=1700000000,v1="+stripeV1),
			body:    stripeBody,
			now:     stripeNow.Add(5*time.Minute + time.Second),
			wantErr: ErrTimestampOutOfRange,
		},
		{
			name:    "stripe future timestamp",
			cfg:     Config{Provider: ProviderStripe, Secret: stripeSecret},
			header:  headers(StripeSignatureHeader, "t=1700000000,v1="+stripeV1),
			body:    stripeBody,
			now:     stripeNow.Add(-10 * time.Minute),
			wantErr: ErrTimestampOutOfRange,
		},
		{
			name:    "stripe v0 only",
			cfg:     Config{Provider: ProviderStripe, Secret: stripeSecret},
			header:  headers(StripeSignatureHeader, "t=1700000000,v0="+stripeV1),
			body:    stripeBody,
			now:     stripeNow,
			wantErr: ErrMissingSignature,
		},
		{
			name:    "stripe no timestamp",
			cfg:     Config{Provider: ProviderStripe, Secret: stripeSecret},
			header:  headers(StripeSignatureHeader, "v1="+stripeV1),
			body:    stripeBody,
			now:     stripeNow,
			wantErr: ErrMalformedSignature,
		},
		{
			name:    "stripe timestamp moved",
			cfg:     Config{Provider: ProviderStripe, Secret: stripeSecret},
			header:  headers(StripeSignatureHeader, "t=1700000001,v1="+stripeV1),
			body:    stripeBody,
			now:     stripeNow,
			wantErr: ErrInvalidSignature,
		},
		{
			name:    "stripe missing header",
			cfg:     Config{Provider: ProviderStripe, Secret: stripeSecret},
			body:    stripeBody,
			now:     stripeNow,
			wantErr: ErrMissingSignature,
		},
		{
			name:   "hmac hex",
			cfg:    Config{Provider: ProviderHMAC, Secret: hmacHexSecret, Header: "x-signature"},
			header: headers("X-Signature", strings.ToUpper(hmacHexSignature)),
			body:   hmacHexBody,
		},
		{
			name:   "hmac hex with prefix",
			cfg:    Config{Provider: ProviderHMAC, Secret: hmacHexSecret, Header: "X-Signature", Prefix: "sha256="},
			header: headers("X-Signature", "sha256="+hmacHexSignature),
			body:   hmacHexBody,
		},
		{
			name:    "hmac prefix missing",
			cfg:     Config{Provider: ProviderHMAC, Secret: hmacHexSecret, Header: "X-Signature", Prefix: "sha256="},
			header:  headers("X-Signature", hmacHexSignature),
			body:    hmacHexBody,
			wantErr: ErrMalformedSignature,
		},
		{
			name:   "hmac base64",
			cfg:    Config{Provider: ProviderHMAC, Secret: hmacBase64Secret, Header: "X-Shopify-Hmac-Sha256", Encoding: EncodingBase64},
			header: headers("X-Shopify-Hmac-Sha256", hmacBase64Signature),
			body:   hmacBase64Body,
		},
		{
			name:    "hmac base64 tampered",
			cfg:     Config{Provider: ProviderHMAC, Secret: hmacBase64Secret, Header: "X-Shopify-Hmac-Sha256", Encoding: EncodingBase64},
			header:  headers("X-Shopify-Hmac-Sha256", hmacBase64Signature),
			body:    `{"id":2}`,
			wantErr: ErrInvalidSignature,
		},
		{
			name:    "hmac wrong encoding",
			cfg:     Config{Provider: ProviderHMAC, Secret: hmacBase64Secret, Header: "X-Shopify-Hmac-Sha256"},
			header:  headers("X-Shopify-Hmac-Sha256", hmacBase64Signature),
			body:    hmacBase64Body,
			wantErr: ErrMalformedSignature,
		},
		{
			name:    "hmac truncated signature",
			cfg:     Config{Provider: ProviderHMAC, Secret: hmacHexSecret, Header: "X-Signature"},
			header:  headers("X-Signature", hmacHexSignature[:32]),
			body:    hmacHexBody,
			wantErr: ErrMalformedSignature,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := New(tt.cfg)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if tt.header == nil {
				tt.header = http.Header{}
			}
			err = v.Verify(tt.header, []byte(tt.body), tt.now)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Verify = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignHelpersMatchDocumentedVectors(t *testing.T) {
	if got := GitHubSignature(githubDocSecret, []byte(githubDocBody)); got != githubDocSignature {
		t.Fatalf("GitHubSignature = %s", got)
	}
	if got := SlackSignature(slackDocSecret, 1531420618, []byte(slackDocBody)); got != slackDocSignature {
		t.Fatalf("SlackSignature = %s", got)
	}
	if got := StripeSignature(stripeSecret, stripeTimestamp, []byte(stripeBody)); got != "t=1700000000,v1="+stripeV1 {
		t.Fatalf("StripeSignature = %s", got)
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		want    Config
		wantErr string
	}{
		{name: "missing provider", cfg: Config{Secret: "s"}, wantErr: "provider"},
		{name: "unknown provider", cfg: Config{Provider: "paypal", Secret: "s"}, wantErr: "unknown webhook provider"},
		{name: "missing secret", cfg: Config{Provider: "github"}, wantErr: "secret"},
		{name: "secret too long", cfg: Config{Provider: "github", Secret: strings.Repeat("s", MaxSecretBytes+1)}, wantErr: "longer"},
		{name: "relative path", cfg: Config{Provider: "github", Secret: "s", PathPrefix: "hooks"}, wantErr: "start with /"},
		{name: "tolerance on github", cfg: Config{Provider: "github", Secret: "s", Tolerance: time.Minute}, wantErr: "tolerance"},
		{name: "negative tolerance", cfg: Config{Provider: "stripe", Secret: "s", Tolerance: -time.Second}, wantErr: "negative"},
		{name: "huge tolerance", cfg: Config{Provider: "stripe", Secret: "s", Tolerance: 48 * time.Hour}, wantErr: "at most"},
		{name: "header on stripe", cfg: Config{Provider: "stripe", Secret: "s", Header: "X-Sig"}, wantErr: "apply only"},
		{name: "hmac without header", cfg: Config{Provider: "hmac", Secret: "s"}, wantErr: "header name"},
		{name: "hmac bad header", cfg: Config{Provider: "hmac", Secret: "s", Header: "X Sig"}, wantErr: "invalid"},
		{name: "hmac bad encoding", cfg: Config{Provider: "hmac", Secret: "s", Header: "X-Sig", Encoding: "base32"}, wantErr: "encoding"},
		{name: "hmac prefix with space", cfg: Config{Provider: "hmac", Secret: "s", Header: "X-Sig", Prefix: "sha256 "}, wantErr: "prefix"},
		{
			name: "stripe defaults",
			cfg:  Config{Provider: " Stripe ", Secret: "s", PathPrefix: "/hooks//stripe/"},
			want: Config{Provider: "stripe", Secret: "s", PathPrefix: "/hooks/stripe/", Tolerance: DefaultTolerance},
		},
		{
			name: "root prefix means everything",
			cfg:  Config{Provider: "github", Secret: "s", PathPrefix: "/"},
			want: Config{Provider: "github", Secret: "s"},
		},
		{
			name: "hmac defaults",
			cfg:  Config{Provider: "hmac", Secret: "s", Header: "x-signature"},
			want: Config{Provider: "hmac", Secret: "s", Header: "X-Signature", Encoding: EncodingHex},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.Normalize()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Normalize error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			if got != tt.want {
				t.Fatalf("Normalize = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestMatches(t *testing.T) {
	tests := []struct {
		prefix string
		path   string
		want   bool
	}{
		{"", "/anything", true},
		{"/webhooks", "/webhooks", true},
		{"/webhooks", "/webhooks/", true},
		{"/webhooks", "/webhooks/stripe", true},
		{"/webhooks", "/webhooksfoo", false},
		{"/webhooks", "/other", false},
		{"/webhooks", "/other/../webhooks/stripe", true},
		{"/webhooks", "//webhooks/stripe", true},
		{"/webhooks", "/WebHooks/stripe", true},
		{"/webhooks", "", false},
		{"/webhooks/", "/webhooks", true},
		{"/webhooks/", "/webhooks/x", true},
		{"/webhooks/", "/webhooksx", false},
	}
	for _, tt := range tests {
		v, err := New(Config{Provider: ProviderGitHub, Secret: "s", PathPrefix: tt.prefix})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if got := v.Matches(tt.path); got != tt.want {
			t.Errorf("prefix %q path %q: Matches = %v, want %v", tt.prefix, tt.path, got, tt.want)
		}
	}
}

func TestEqual(t *testing.T) {
	a, _ := New(Config{Provider: ProviderGitHub, Secret: "one"})
	b, _ := New(Config{Provider: "GitHub", Secret: "one"})
	c, _ := New(Config{Provider: ProviderGitHub, Secret: "two"})
	d, _ := New(Config{Provider: ProviderGitHub, Secret: "one", PathPrefix: "/hooks"})
	if !a.Equal(b) {
		t.Fatal("equal configs compare unequal")
	}
	if a.Equal(c) || a.Equal(d) || a.Equal(nil) {
		t.Fatal("different configs compare equal")
	}
	var none *Verifier
	if !none.Equal(nil) {
		t.Fatal("nil verifiers compare unequal")
	}
}
