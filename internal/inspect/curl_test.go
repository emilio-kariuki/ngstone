package inspect

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestBuildCurlRedactsSensitiveHeaders(t *testing.T) {
	ex := &Exchange{
		Kind: KindHTTP,
		Req: CapturedReq{
			Method: "POST",
			URL:    "https://public.example.test/orders?q=one two",
			Header: http.Header{
				"Authorization": {"Bearer secret"},
				"Content-Type":  {"application/json"},
				"X-Request-ID":  {"req-1"},
			},
			Body: []byte(`{"name":"O'Reilly"}`),
		},
	}

	command, err := BuildCurl(ex, CurlOptions{})
	if err != nil {
		t.Fatalf("BuildCurl: %v", err)
	}
	if strings.Contains(command, "Bearer secret") {
		t.Fatalf("curl command leaked authorization: %s", command)
	}
	for _, want := range []string{"curl", "--request 'POST'", "[REDACTED]", "Content-Type: application/json", "'\"'\"'"} {
		if !strings.Contains(command, want) {
			t.Fatalf("curl command %q does not contain %q", command, want)
		}
	}

	withSensitive, err := BuildCurl(ex, CurlOptions{IncludeSensitive: true})
	if err != nil {
		t.Fatalf("BuildCurl with sensitive headers: %v", err)
	}
	if !strings.Contains(withSensitive, "Bearer secret") {
		t.Fatalf("curl command did not include authorization when requested: %s", withSensitive)
	}
}

func TestBuildCurlCanTargetLocalAppAndPreserveHost(t *testing.T) {
	ex := &Exchange{
		Kind: KindHTTP,
		Req: CapturedReq{
			Method: "GET",
			URL:    "https://demo.example.test/orders",
			Header: http.Header{},
		},
	}
	target, err := url.Parse("http://127.0.0.1:3000")
	if err != nil {
		t.Fatal(err)
	}
	command, err := BuildCurl(ex, CurlOptions{Target: target})
	if err != nil {
		t.Fatalf("BuildCurl: %v", err)
	}
	if !strings.Contains(command, "http://127.0.0.1:3000/orders") || !strings.Contains(command, "Host: demo.example.test") {
		t.Fatalf("curl command did not target local app with original host: %s", command)
	}
}

func TestBuildCurlRejectsTruncatedAndUpgradeRequests(t *testing.T) {
	truncated := &Exchange{Kind: KindHTTP, Req: CapturedReq{URL: "http://example.test", Truncated: true}}
	if _, err := BuildCurl(truncated, CurlOptions{}); err != ErrTruncatedBody {
		t.Fatalf("truncated error = %v, want %v", err, ErrTruncatedBody)
	}
	upgrade := &Exchange{Kind: KindUpgrade, Req: CapturedReq{URL: "http://example.test"}}
	if _, err := BuildCurl(upgrade, CurlOptions{}); err != ErrNotReplayable {
		t.Fatalf("upgrade error = %v, want %v", err, ErrNotReplayable)
	}
}
