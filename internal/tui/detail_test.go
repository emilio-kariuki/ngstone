package tui

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"strings"
	"testing"

	"ngstone/internal/inspect"
)

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func TestBuildDetailGzipDecodesToReadableText(t *testing.T) {
	plaintext := `{"message":"hello world"}`
	compressed := gzipBytes(t, []byte(plaintext))

	ex := &inspect.Exchange{
		Kind: inspect.KindHTTP,
		Req: inspect.CapturedReq{
			Method: "GET",
			URL:    "https://example.com/api",
			Header: http.Header{},
		},
		Resp: inspect.CapturedResp{
			Status: 200,
			Header: http.Header{"Content-Encoding": []string{"gzip"}},
			Body:   compressed,
		},
	}

	out := buildDetail(ex)

	if !strings.Contains(out, plaintext) {
		t.Fatalf("expected detail to contain decoded plaintext %q, got:\n%s", plaintext, out)
	}
	if strings.Contains(out, string(compressed)) {
		t.Fatalf("expected detail to not contain raw gzip bytes")
	}
}

func TestBuildDetailBinaryRendersHexPreview(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xC3, 0x28}

	ex := &inspect.Exchange{
		Kind: inspect.KindHTTP,
		Req: inspect.CapturedReq{
			Method: "GET",
			URL:    "https://example.com/binary",
			Header: http.Header{},
		},
		Resp: inspect.CapturedResp{
			Status: 200,
			Header: http.Header{"Content-Type": []string{"application/octet-stream"}},
			Body:   data,
		},
	}

	out := buildDetail(ex)
	want := hexPreview(data, 512)

	if !strings.Contains(out, want) {
		t.Fatalf("expected detail to contain hex dump %q, got:\n%s", want, out)
	}
}

func TestBuildDetailUpgradeShowsByteCountsNoBody(t *testing.T) {
	ex := &inspect.Exchange{
		Kind: inspect.KindUpgrade,
		Req: inspect.CapturedReq{
			Method: "GET",
			URL:    "https://example.com/ws",
			Header: http.Header{},
		},
		BytesClientToApp: 1024,
		BytesAppToClient: 2048,
	}

	out := buildDetail(ex)

	if !strings.Contains(out, "WS") {
		t.Fatalf("expected detail to mention WS, got:\n%s", out)
	}
	wantC2A := "client -> app: " + fmtBytes(1024)
	wantA2C := "app -> client: " + fmtBytes(2048)
	if !strings.Contains(out, wantC2A) {
		t.Fatalf("expected detail to contain %q, got:\n%s", wantC2A, out)
	}
	if !strings.Contains(out, wantA2C) {
		t.Fatalf("expected detail to contain %q, got:\n%s", wantA2C, out)
	}
	if strings.Contains(out, "BODY") {
		t.Fatalf("expected detail to not contain a BODY section, got:\n%s", out)
	}
}
