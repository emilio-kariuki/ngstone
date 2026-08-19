package policy

import (
	"net/http"
	"net/url"
	"testing"
)

func TestParseAndDecideFirstMatchWins(t *testing.T) {
	p, err := Parse([]byte(`{
  "default_action": "deny",
  "rules": [
    {"path_prefix": "/api", "action": "allow"},
    {"method": "POST", "path_prefix": "/api/private", "action": "deny"}
  ]
}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	cases := []struct {
		name    string
		method  string
		path    string
		allowed bool
	}{
		{name: "allowed prefix", method: http.MethodGet, path: "/api/users", allowed: true},
		{name: "first match wins", method: http.MethodPost, path: "/api/private", allowed: true},
		{name: "prefix boundary", method: http.MethodGet, path: "/apian", allowed: false},
		{name: "default deny", method: http.MethodGet, path: "/health", allowed: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptestRequest(tc.method, tc.path)
			if got := p.Decide(r).Allowed; got != tc.allowed {
				t.Fatalf("allowed = %v, want %v", got, tc.allowed)
			}
		})
	}
}

func TestHeaderPresenceAndValueMatching(t *testing.T) {
	p, err := Parse([]byte(`{
  "rules": [
    {"header": "X-Preview", "header_value": "yes", "action": "allow"},
    {"header": "X-Internal", "action": "deny"}
  ]
}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	withValue := httptestRequest(http.MethodGet, "/")
	withValue.Header.Set("x-preview", "yes")
	if !p.Decide(withValue).Allowed {
		t.Fatal("matching header value was denied")
	}

	wrongValue := httptestRequest(http.MethodGet, "/")
	wrongValue.Header.Set("X-Preview", "no")
	if !p.Decide(wrongValue).Allowed {
		t.Fatal("unmatched header rule should fall through to the default allow")
	}

	present := httptestRequest(http.MethodGet, "/")
	present.Header.Set("X-Internal", "1")
	if p.Decide(present).Allowed {
		t.Fatal("header-presence rule allowed a matching request")
	}
}

func TestPathMatchingNormalizesTraversal(t *testing.T) {
	p, err := Parse([]byte(`{"default_action":"allow","rules":[{"action":"deny","path_prefix":"/admin"}]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Decide(httptestRequest(http.MethodGet, "/admin/../admin/settings")).Allowed {
		t.Fatal("normalized traversal path bypassed the admin deny rule")
	}
}

func TestParseRejectsUnknownFieldsAndInvalidRules(t *testing.T) {
	cases := []string{
		`{"rules":[],"unknown":true}`,
		`{"default_action":"drop","rules":[]}`,
		`{"rules":[{"action":"deny","path_prefix":"api"}]}`,
		`{"rules":[{"action":"deny","header_value":"x"}]}`,
	}
	for _, input := range cases {
		if _, err := Parse([]byte(input)); err == nil {
			t.Fatalf("Parse(%s) succeeded, want error", input)
		}
	}
}

func TestDigestIsStableAfterNormalization(t *testing.T) {
	a, err := Parse([]byte(`{"default_action":"ALLOW","rules":[{"action":"DENY","method":"get"}]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	b, err := Parse([]byte(`{"rules":[{"method":"GET","action":"deny"}],"default_action":"allow"}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if a.Digest() != b.Digest() {
		t.Fatalf("digests differ: %q != %q", a.Digest(), b.Digest())
	}
}

func httptestRequest(method, path string) *http.Request {
	return &http.Request{Method: method, URL: mustParseURL(path), Header: make(http.Header)}
}

func mustParseURL(path string) *url.URL {
	u, err := url.Parse(path)
	if err != nil {
		panic(err)
	}
	return u
}
