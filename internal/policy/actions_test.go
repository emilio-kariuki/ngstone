package policy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestLegacyPolicyEncodingIsUnchanged(t *testing.T) {
	p, err := Parse([]byte(`{"default_action":"deny","rules":[{"action":"allow","method":"get","path_prefix":"/api/"},{"action":"deny","header":"x-internal","header_value":"1"}]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"default_action":"deny","rules":[{"action":"allow","method":"GET","path_prefix":"/api"},{"action":"deny","header":"X-Internal","header_value":"1"}]}`
	if string(data) != want {
		t.Fatalf("encoding = %s, want %s", data, want)
	}
}

func TestTransformRulesApplyInOrderAndDoNotDecide(t *testing.T) {
	p, err := Parse([]byte(`{
  "default_action": "deny",
  "rules": [
    {"action": "transform", "request_headers": {"set": {"x-env": "prod"}, "add": {"X-Tag": "all"}, "remove": ["x-debug"]}},
    {"action": "allow", "path_prefix": "/api"},
    {"action": "transform", "path_prefix": "/api", "request_headers": {"set": {"X-Env": "api"}, "add": {"X-Tag": "api"}}, "response_headers": {"set": {"Cache-Control": "no-store"}, "remove": ["Server"]}},
    {"action": "transform", "path_prefix": "/other", "request_headers": {"set": {"X-Other": "1"}}}
  ]
}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	r := httptestRequest(http.MethodGet, "/api/users")
	r.Header.Set("X-Debug", "1")
	d := p.Decide(r)
	if !d.Allowed {
		t.Fatal("request was not allowed")
	}
	d.ApplyRequestHeaders(r.Header)
	if got := r.Header.Get("X-Env"); got != "api" {
		t.Fatalf("X-Env = %q, want api", got)
	}
	if got := r.Header.Values("X-Tag"); !reflect.DeepEqual(got, []string{"all", "api"}) {
		t.Fatalf("X-Tag = %q", got)
	}
	if r.Header.Get("X-Debug") != "" || r.Header.Get("X-Other") != "" {
		t.Fatalf("unexpected headers: %v", r.Header)
	}

	resp := http.Header{"Server": {"app"}, "Content-Type": {"text/plain"}}
	d.ApplyResponseHeaders(resp)
	if resp.Get("Server") != "" || resp.Get("Cache-Control") != "no-store" || resp.Get("Content-Type") != "text/plain" {
		t.Fatalf("response headers = %v", resp)
	}

	denied := httptestRequest(http.MethodGet, "/private")
	denied.Header.Set("X-Debug", "1")
	dd := p.Decide(denied)
	if dd.Allowed {
		t.Fatal("default deny allowed a request")
	}
	dd.ApplyRequestHeaders(denied.Header)
	if denied.Header.Get("X-Env") != "" || denied.Header.Get("X-Debug") != "1" {
		t.Fatal("transforms applied to a denied request")
	}
}

func TestRedirectFirstMatchWinsAndSubstitutesPath(t *testing.T) {
	p, err := Parse([]byte(`{
  "rules": [
    {"action": "allow", "path_prefix": "/old/keep"},
    {"action": "redirect", "path_prefix": "/old", "redirect_url": "/new$path", "redirect_status": 308},
    {"action": "redirect", "path_prefix": "/docs", "redirect_url": "https://docs.example.com${path}"},
    {"action": "redirect", "path_prefix": "/slash", "redirect_url": "/$path"},
    {"action": "redirect", "path_prefix": "/bare", "redirect_url": "$path"},
    {"action": "deny", "path_prefix": "/old"}
  ]
}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cases := []struct {
		target string
		url    string
		status int
	}{
		{target: "/old/a/b", url: "/new/a/b", status: 308},
		{target: "/old", url: "/new", status: 308},
		{target: "/old/", url: "/new/", status: 308},
		{target: "/old/a%20b?x=1&y=2", url: "/new/a%20b?x=1&y=2", status: 308},
		{target: "/old/../old/x", url: "/new/x", status: 308},
		{target: "/docs/guide", url: "https://docs.example.com/guide", status: http.StatusFound},
		{target: "/slash//evil.example", url: "/evil.example", status: http.StatusFound},
		{target: "/bare", url: "/", status: http.StatusFound},
		{target: "/bare/x", url: "/x", status: http.StatusFound},
	}
	for _, tc := range cases {
		d := p.Decide(httptestRequest(http.MethodGet, tc.target))
		if d.Allowed || d.RedirectURL != tc.url || d.RedirectStatus != tc.status {
			t.Fatalf("%s: decision = %+v, want redirect %d %s", tc.target, d, tc.status, tc.url)
		}
	}
	if d := p.Decide(httptestRequest(http.MethodGet, "/old/keep/1")); !d.Allowed || d.RedirectURL != "" {
		t.Fatalf("earlier allow rule did not win: %+v", d)
	}
	if d := p.Decide(httptestRequest(http.MethodGet, "/elsewhere")); !d.Allowed || d.RedirectURL != "" {
		t.Fatalf("unmatched request = %+v", d)
	}
}

func TestRedirectQueryIsNotAppendedWhenTargetHasQuery(t *testing.T) {
	p, err := Parse([]byte(`{"rules":[
  {"action":"redirect","path_prefix":"/login","redirect_url":"https://idp.example/authorize?client_id=abc&redirect_uri=https://safe.example/cb"},
  {"action":"redirect","path_prefix":"/go","redirect_url":"https://idp.example/authorize?next=$path"},
  {"action":"redirect","path_prefix":"/plain","redirect_url":"https://example.com/landing"}
]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cases := []struct{ target, want string }{
		{"/login?redirect_uri=https://evil.example/cb&client_id=evil", "https://idp.example/authorize?client_id=abc&redirect_uri=https://safe.example/cb"},
		{"/go/a&redirect_uri=https:%2F%2Fevil.example", "https://idp.example/authorize?next=%2Fa%26redirect_uri%3Dhttps%3A%2Fevil.example"},
		{"/plain/x?next=1", "https://example.com/landing?next=1"},
	}
	for _, tc := range cases {
		if got := p.Decide(httptestRequest(http.MethodGet, tc.target)).RedirectURL; got != tc.want {
			t.Fatalf("%s: RedirectURL = %q, want %q", tc.target, got, tc.want)
		}
	}
}

func TestRedirectDoesNotExpandVisitorText(t *testing.T) {
	p, err := Parse([]byte(`{"rules":[{"action":"redirect","path_prefix":"/old","redirect_url":"/new${path}"}]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := p.Decide(httptestRequest(http.MethodGet, "/old/$path")).RedirectURL; got != "/new/$path" {
		t.Fatalf("RedirectURL = %q, want /new/$path", got)
	}
}

func TestValidationRejectsReservedAndInvalidActions(t *testing.T) {
	reserved := []string{
		"Host", "Connection", "Keep-Alive", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
		"Content-Length", "Authorization", "Forwarded", "X-Forwarded-For", "X-Forwarded-Proto", "x-forwarded-host",
		"X-Real-IP", "X-Ngstone-Request-ID", "X-Ngstone-Client-Addr",
	}
	for _, name := range reserved {
		for _, side := range []string{"request_headers", "response_headers"} {
			for _, op := range []string{`{"set":{"` + name + `":"x"}}`, `{"add":{"` + name + `":"x"}}`, `{"remove":["` + name + `"]}`} {
				input := `{"rules":[{"action":"transform","` + side + `":` + op + `}]}`
				if _, err := Parse([]byte(input)); err == nil {
					t.Fatalf("Parse(%s) succeeded, want error", input)
				}
			}
		}
	}

	invalid := []string{
		`{"default_action":"redirect","rules":[]}`,
		`{"default_action":"transform","rules":[]}`,
		`{"rules":[{"action":"transform"}]}`,
		`{"rules":[{"action":"transform","request_headers":{}}]}`,
		`{"rules":[{"action":"transform","request_headers":{"set":{"X-A":"1","x-a":"2"}}}]}`,
		`{"rules":[{"action":"transform","request_headers":{"set":{"X-A":"line\nbreak"}}}]}`,
		`{"rules":[{"action":"transform","request_headers":{"set":{"Bad Name":"1"}}}]}`,
		`{"rules":[{"action":"transform","request_headers":{"unknown":{"X-A":"1"}}}]}`,
		`{"rules":[{"action":"allow","request_headers":{"set":{"X-A":"1"}}}]}`,
		`{"rules":[{"action":"deny","response_headers":{"set":{"X-A":"1"}}}]}`,
		`{"rules":[{"action":"allow","redirect_url":"/x"}]}`,
		`{"rules":[{"action":"transform","redirect_status":301,"request_headers":{"set":{"X-A":"1"}}}]}`,
		`{"rules":[{"action":"redirect"}]}`,
		`{"rules":[{"action":"redirect","redirect_url":"/x","redirect_status":303}]}`,
		`{"rules":[{"action":"redirect","redirect_url":"relative"}]}`,
		`{"rules":[{"action":"redirect","redirect_url":"//evil.example/x"}]}`,
		`{"rules":[{"action":"redirect","redirect_url":"javascript:alert(1)"}]}`,
		`{"rules":[{"action":"redirect","redirect_url":"https://$path"}]}`,
		`{"rules":[{"action":"redirect","redirect_url":"/x#frag"}]}`,
		`{"rules":[{"action":"redirect","redirect_url":"https://user@example.com/"}]}`,
		`{"rules":[{"action":"redirect","path_prefix":"/old","redirect_url":"https:/$path"}]}`,
		`{"rules":[{"action":"redirect","path_prefix":"/old","redirect_url":"https://new$path@evil.example/"}]}`,
		`{"rules":[{"action":"redirect","path_prefix":"/old","redirect_url":"https://new$path.evil.example/"}]}`,
		`{"rules":[],"cors":{}}`,
		`{"rules":[],"cors":{"allowed_origins":["*"],"allow_credentials":true}}`,
		`{"rules":[],"cors":{"allowed_origins":["*","https://a.example"]}}`,
		`{"rules":[],"cors":{"allowed_origins":["https://a.example/path"]}}`,
		`{"rules":[],"cors":{"allowed_origins":["null"]}}`,
		`{"rules":[],"cors":{"allowed_origins":["ftp://a.example"]}}`,
		`{"rules":[],"cors":{"allowed_origins":["https://a.example"],"max_age":-1}}`,
		`{"rules":[],"cors":{"allowed_origins":["https://a.example"],"max_age":90000}}`,
		`{"rules":[],"cors":{"allowed_origins":["https://a.example"],"allowed_methods":["GE T"]}}`,
		`{"rules":[],"cors":{"allowed_origins":["https://a.example"],"allowed_headers":["*","X-A"]}}`,
		`{"rules":[{"action":"transform","response_headers":{"set":{"Access-Control-Allow-Origin":"*"}}}],"cors":{"allowed_origins":["https://a.example"]}}`,
	}
	for _, input := range invalid {
		if _, err := Parse([]byte(input)); err == nil {
			t.Fatalf("Parse(%s) succeeded, want error", input)
		}
	}

	if _, err := Parse([]byte(`{"rules":[{"action":"transform","response_headers":{"set":{"Access-Control-Allow-Origin":"*"}}}]}`)); err != nil {
		t.Fatalf("Access-Control-* response header without cors was rejected: %v", err)
	}

	for _, target := range []string{
		"https://new.example$path",
		"https://new.example/base$path",
		"https://new.example/x?next=$path",
		"https://new.example/",
	} {
		input := `{"rules":[{"action":"redirect","path_prefix":"/old","redirect_url":"` + target + `"}]}`
		if _, err := Parse([]byte(input)); err != nil {
			t.Fatalf("Parse(%s): %v", input, err)
		}
	}
}

func TestRedirectHostIsPinnedForHostileRequestPaths(t *testing.T) {
	p, err := Parse([]byte(`{"rules":[{"action":"redirect","path_prefix":"/old","redirect_url":"https://new.example$path"}]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, target := range []string{"/old/evil.example/phish", "/old//evil.example", "/old/@evil.example", "/old/%2F%2Fevil.example"} {
		d := p.Decide(httptestRequest(http.MethodGet, target))
		location, err := url.Parse(d.RedirectURL)
		if err != nil || location.Host != "new.example" || location.User != nil {
			t.Fatalf("%s: RedirectURL = %q, want host new.example", target, d.RedirectURL)
		}
	}
}

func TestValidateIsIdempotentForNewFields(t *testing.T) {
	input := `{
  "rules": [
    {"action": "transform", "request_headers": {"set": {"x-a": "1"}, "remove": ["x-b"]}, "response_headers": {"add": {"x-c": "2"}}},
    {"action": "REDIRECT", "path_prefix": "/old/", "redirect_url": "/new$path"}
  ],
  "cors": {"allowed_origins": ["HTTPS://App.Example:443"], "allowed_methods": ["get", "put"], "allowed_headers": ["content-type"], "exposed_headers": ["x-total"], "allow_credentials": true, "max_age": 600}
}`
	first, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	second, err := Parse(encoded)
	if err != nil {
		t.Fatalf("Parse(round trip): %v", err)
	}
	if first.Digest() != second.Digest() {
		t.Fatalf("digest changed after round trip: %s", encoded)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("round trip differs:\n%#v\n%#v", first, second)
	}
	for _, want := range []string{`"X-A":"1"`, `"remove":["X-B"]`, `"redirect_status":302`, `"https://app.example"`, `"allowed_methods":["GET","PUT"]`, `"Content-Type"`, `"X-Total"`} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("encoded policy %s missing %s", encoded, want)
		}
	}
}

func TestCORSPreflight(t *testing.T) {
	p, err := Parse([]byte(`{"default_action":"deny","rules":[],"cors":{"allowed_origins":["https://app.example"],"allowed_methods":["GET","PUT"],"allowed_headers":["Content-Type","X-Token"],"allow_credentials":true,"max_age":600}}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	preflight := func(origin, method string) (http.Header, bool) {
		r := httptestRequest(http.MethodOptions, "/api")
		r.Header.Set("Origin", origin)
		r.Header.Set("Access-Control-Request-Method", method)
		r.Header.Set("Access-Control-Request-Headers", "content-type")
		return p.Preflight(r)
	}

	h, ok := preflight("https://app.example", "PUT")
	if !ok {
		t.Fatal("preflight was not answered")
	}
	want := map[string]string{
		"Access-Control-Allow-Origin":      "https://app.example",
		"Access-Control-Allow-Credentials": "true",
		"Access-Control-Allow-Methods":     "GET, PUT",
		"Access-Control-Allow-Headers":     "Content-Type, X-Token",
		"Access-Control-Max-Age":           "600",
	}
	for name, value := range want {
		if got := h.Get(name); got != value {
			t.Fatalf("%s = %q, want %q", name, got, value)
		}
	}
	if !varyContains(h, "Origin") {
		t.Fatalf("Vary = %q", h.Values("Vary"))
	}

	if h, ok := preflight("https://evil.example", "PUT"); !ok || h.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("disallowed origin got %v (answered=%v)", h, ok)
	}
	if h, ok := preflight("https://app.example", "DELETE"); !ok || h.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("disallowed method got %v (answered=%v)", h, ok)
	}

	plain := httptestRequest(http.MethodOptions, "/api")
	if _, ok := p.Preflight(plain); ok {
		t.Fatal("OPTIONS without Origin was treated as a preflight")
	}
	var none *Policy
	if _, ok := none.Preflight(plain); ok {
		t.Fatal("nil policy answered a preflight")
	}
}

func TestCORSWildcardReflectsRequestedHeaders(t *testing.T) {
	p, err := Parse([]byte(`{"rules":[],"cors":{"allowed_origins":["*"],"allowed_headers":["*"]}}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := httptestRequest(http.MethodOptions, "/")
	r.Header.Set("Origin", "https://any.example")
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Header.Set("Access-Control-Request-Headers", "X-One, x-two")
	h, ok := p.Preflight(r)
	if !ok || h.Get("Access-Control-Allow-Origin") != "*" || h.Get("Access-Control-Allow-Headers") != "x-one, x-two" || h.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("preflight headers = %v", h)
	}
	if got := h.Get("Access-Control-Allow-Methods"); got != "GET, HEAD, POST" {
		t.Fatalf("default methods = %q", got)
	}
}

func TestCORSResponseHeadersReplaceUpstreamValues(t *testing.T) {
	p, err := Parse([]byte(`{"rules":[],"cors":{"allowed_origins":["https://app.example"],"exposed_headers":["X-Total"],"allow_credentials":true}}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := httptestRequest(http.MethodGet, "/")
	r.Header.Set("Origin", "https://app.example")
	d := p.Decide(r)
	resp := http.Header{"Access-Control-Allow-Origin": {"*"}, "Access-Control-Max-Age": {"1"}, "Vary": {"Accept-Encoding"}}
	d.ApplyResponseHeaders(resp)
	if got := resp.Values("Access-Control-Allow-Origin"); !reflect.DeepEqual(got, []string{"https://app.example"}) {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
	if resp.Get("Access-Control-Allow-Credentials") != "true" || resp.Get("Access-Control-Expose-Headers") != "X-Total" || resp.Get("Access-Control-Max-Age") != "" {
		t.Fatalf("response headers = %v", resp)
	}
	if got := resp.Values("Vary"); !reflect.DeepEqual(got, []string{"Accept-Encoding", "Origin"}) {
		t.Fatalf("Vary = %q", got)
	}

	other := httptestRequest(http.MethodGet, "/")
	other.Header.Set("Origin", "https://evil.example")
	od := p.Decide(other)
	resp = http.Header{"Access-Control-Allow-Origin": {"*"}}
	od.ApplyResponseHeaders(resp)
	if resp.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("disallowed origin kept CORS headers: %v", resp)
	}
}

func TestCORSWildcardResponseIsCacheSafe(t *testing.T) {
	p, err := Parse([]byte(`{"rules":[],"cors":{"allowed_origins":["*"]}}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, origin := range []string{"", "https://any.example"} {
		r := httptestRequest(http.MethodGet, "/")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		d := p.Decide(r)
		resp := http.Header{"Access-Control-Allow-Origin": {"https://other.example"}}
		d.ApplyResponseHeaders(resp)
		if got := resp.Values("Access-Control-Allow-Origin"); !reflect.DeepEqual(got, []string{"*"}) {
			t.Fatalf("origin %q: Access-Control-Allow-Origin = %q, want *", origin, got)
		}
		if len(resp.Values("Vary")) != 0 {
			t.Fatalf("origin %q: wildcard response varies: %q", origin, resp.Values("Vary"))
		}
	}
}

func TestCORSStripsEveryUpstreamAccessControlHeader(t *testing.T) {
	p, err := Parse([]byte(`{"rules":[],"cors":{"allowed_origins":["https://app.example"]}}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := httptestRequest(http.MethodGet, "/")
	r.Header.Set("Origin", "https://evil.example")
	d := p.Decide(r)
	resp := http.Header{
		"Access-Control-Allow-Private-Network": {"true"},
		"Access-Control-Allow-Origin":          {"*"},
		"Access-Control-Custom":                {"x"},
		"Content-Type":                         {"text/plain"},
	}
	d.ApplyResponseHeaders(resp)
	for name := range resp {
		if strings.HasPrefix(name, "Access-Control-") {
			t.Fatalf("upstream %s survived: %v", name, resp)
		}
	}
	if resp.Get("Content-Type") != "text/plain" {
		t.Fatalf("response headers = %v", resp)
	}
}

func TestValidationRejectsCORSValuesThatCanNeverMatch(t *testing.T) {
	invalid := []string{
		`{"rules":[],"cors":{"allowed_origins":["https://a.example"],"allowed_methods":["*"]}}`,
		`{"rules":[],"cors":{"allowed_origins":["https://a.example"],"allowed_methods":["GET","P*"]}}`,
		`{"rules":[],"cors":{"allowed_origins":["https://*.example.com"]}}`,
		`{"rules":[],"cors":{"allowed_origins":["https://a.example","*.example.com"]}}`,
		`{"rules":[],"cors":{"allowed_origins":["https://a.example"],"allowed_headers":["X-*"]}}`,
		`{"rules":[],"cors":{"allowed_origins":["https://a.example"],"allowed_headers":["Content-Type","*-Id"]}}`,
		`{"rules":[],"cors":{"allowed_origins":["https://a.example"],"exposed_headers":["X-*"]}}`,
	}
	for _, input := range invalid {
		if _, err := Parse([]byte(input)); err == nil {
			t.Fatalf("Parse(%s) succeeded, want error", input)
		}
	}
	if _, err := Parse([]byte(`{"rules":[],"cors":{"allowed_origins":["*"],"allowed_headers":["*"]}}`)); err != nil {
		t.Fatalf("bare wildcard origin rejected: %v", err)
	}
}

func TestValidationLimits(t *testing.T) {
	removeList := func(n int) string {
		names := make([]string, n)
		for i := range names {
			names[i] = fmt.Sprintf(`"X-H%d"`, i)
		}
		return strings.Join(names, ",")
	}
	originList := func(n int) string {
		origins := make([]string, n)
		for i := range origins {
			origins[i] = fmt.Sprintf(`"https://a%d.example"`, i)
		}
		return strings.Join(origins, ",")
	}
	headerList := func(n int) string {
		names := make([]string, n)
		for i := range names {
			names[i] = fmt.Sprintf(`"X-E%d"`, i)
		}
		return strings.Join(names, ",")
	}
	redirectURL := func(n int) string {
		prefix := "https://example.com/"
		return prefix + strings.Repeat("a", n-len(prefix))
	}
	cases := []struct {
		name  string
		build func(over bool) string
	}{
		{"header actions", func(over bool) string {
			n := maxHeaderActions
			if over {
				n++
			}
			return `{"rules":[{"action":"transform","request_headers":{"remove":[` + removeList(n) + `]}}]}`
		}},
		{"cors origins", func(over bool) string {
			n := maxCORSEntries
			if over {
				n++
			}
			return `{"rules":[],"cors":{"allowed_origins":[` + originList(n) + `]}}`
		}},
		{"cors exposed headers", func(over bool) string {
			n := maxCORSEntries
			if over {
				n++
			}
			return `{"rules":[],"cors":{"allowed_origins":["https://a.example"],"exposed_headers":[` + headerList(n) + `]}}`
		}},
		{"redirect url", func(over bool) string {
			n := maxRedirectURL
			if over {
				n++
			}
			return `{"rules":[{"action":"redirect","redirect_url":"` + redirectURL(n) + `"}]}`
		}},
		{"header value", func(over bool) string {
			n := maxHeaderValue
			if over {
				n++
			}
			return `{"rules":[{"action":"transform","request_headers":{"set":{"X-A":"` + strings.Repeat("a", n) + `"}}}]}`
		}},
	}
	for _, tc := range cases {
		if _, err := Parse([]byte(tc.build(false))); err != nil {
			t.Fatalf("%s: value at the limit rejected: %v", tc.name, err)
		}
		if _, err := Parse([]byte(tc.build(true))); err == nil {
			t.Fatalf("%s: value over the limit accepted", tc.name)
		}
	}
}
