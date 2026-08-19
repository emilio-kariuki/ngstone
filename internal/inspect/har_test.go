package inspect

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMarshalHARRedactsSensitiveHeadersAndPreservesBodies(t *testing.T) {
	start := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	exchange := &Exchange{
		ID:       "exchange-1",
		Tunnel:   "web",
		Kind:     KindHTTP,
		Start:    start,
		Duration: 1500 * time.Millisecond,
		Req: CapturedReq{
			Method: "POST",
			URL:    "https://demo.example.test/items?a=2&a=1",
			Proto:  "HTTP/1.1",
			Header: http.Header{
				"Authorization": {"Bearer secret"},
				"Content-Type":  {"application/json"},
			},
			Body:     []byte(`{"name":"one"}`),
			BodySize: 14,
		},
		Resp: CapturedResp{
			Status: 201,
			Proto:  "HTTP/1.1",
			Header: http.Header{
				"Content-Type": {"application/json"},
				"Set-Cookie":   {"session=secret"},
			},
			Body:     []byte(`{"ok":true}`),
			BodySize: 11,
		},
	}

	data, err := MarshalHAR([]*Exchange{exchange}, HAROptions{})
	if err != nil {
		t.Fatalf("MarshalHAR: %v", err)
	}
	var doc struct {
		Log struct {
			Entries []struct {
				Comment string `json:"comment"`
				Request struct {
					Headers  []harHeader    `json:"headers"`
					PostData *harPostData   `json:"postData"`
					Query    []harNameValue `json:"queryString"`
				} `json:"request"`
				Response struct {
					Headers []harHeader `json:"headers"`
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal HAR: %v", err)
	}
	if len(doc.Log.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(doc.Log.Entries))
	}
	entry := doc.Log.Entries[0]
	if len(entry.Request.Query) != 2 || entry.Request.Query[0].Value != "2" || entry.Request.Query[1].Value != "1" {
		t.Fatalf("query = %+v", entry.Request.Query)
	}
	if entry.Request.PostData == nil || entry.Request.PostData.Text != `{"name":"one"}` {
		t.Fatalf("post data = %+v", entry.Request.PostData)
	}
	if entry.Comment != "tunnel: web" {
		t.Fatalf("comment = %q, want tunnel metadata", entry.Comment)
	}
	for _, header := range entry.Request.Headers {
		if strings.EqualFold(header.Name, "Authorization") && header.Value != "[REDACTED]" {
			t.Fatalf("authorization header = %q", header.Value)
		}
	}
	for _, header := range entry.Response.Headers {
		if strings.EqualFold(header.Name, "Set-Cookie") && header.Value != "[REDACTED]" {
			t.Fatalf("set-cookie header = %q", header.Value)
		}
	}

	data, err = MarshalHAR([]*Exchange{exchange}, HAROptions{IncludeSensitive: true})
	if err != nil {
		t.Fatalf("MarshalHAR with sensitive headers: %v", err)
	}
	if !strings.Contains(string(data), "Bearer secret") {
		t.Fatal("sensitive header was not included when requested")
	}
}

func TestMarshalHARUsesBase64ForBinaryBodies(t *testing.T) {
	exchange := &Exchange{
		Start: time.Now(),
		Req: CapturedReq{
			Method: "POST",
			URL:    "https://example.test/upload",
			Header: http.Header{"Content-Type": {"application/octet-stream"}},
			Body:   []byte{0, 1, 2},
		},
		Resp: CapturedResp{Status: http.StatusOK},
	}
	data, err := MarshalHAR([]*Exchange{exchange}, HAROptions{})
	if err != nil {
		t.Fatalf("MarshalHAR: %v", err)
	}
	if !strings.Contains(string(data), `"encoding": "base64"`) {
		t.Fatalf("HAR = %s, want base64 encoding", data)
	}
}

func TestWriteHARCreatesProtectedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.har")
	if err := WriteHAR(path, nil, HAROptions{}); err != nil {
		t.Fatalf("WriteHAR: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat HAR: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("HAR mode = %o, want 600", info.Mode().Perm())
	}
}
