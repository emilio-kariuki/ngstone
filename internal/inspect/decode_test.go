package inspect

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"net/http"
	"strings"
	"testing"
)

func hdr(kv ...string) http.Header {
	h := make(http.Header)
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func TestDecodeGzip(t *testing.T) {
	const want = `{"a":1}`
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(want))
	zw.Close()

	got := Decode(hdr("Content-Encoding", "gzip", "Content-Type", "application/json"), buf.Bytes())
	if !got.Decoded || got.Err != "" {
		t.Fatalf("decode failed: %+v", got)
	}
	if string(got.Data) != want {
		t.Fatalf("data = %q", got.Data)
	}
	if got.Binary {
		t.Fatal("json marked binary")
	}
}

func TestDecodeZlibDeflate(t *testing.T) {
	const want = "plain deflate text"
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	zw.Write([]byte(want))
	zw.Close()

	got := Decode(hdr("Content-Encoding", "deflate"), buf.Bytes())
	if !got.Decoded || string(got.Data) != want {
		t.Fatalf("zlib deflate: %+v", got)
	}
}

func TestDecodeRawDeflate(t *testing.T) {
	const want = "raw deflate text"
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	fw.Write([]byte(want))
	fw.Close()

	got := Decode(hdr("Content-Encoding", "deflate"), buf.Bytes())
	if !got.Decoded || string(got.Data) != want {
		t.Fatalf("raw deflate: %+v", got)
	}
}

func TestDecodeBrotliReportedUndecodable(t *testing.T) {
	raw := []byte{0x1b, 0x2e, 0x00, 0x00}
	got := Decode(hdr("Content-Encoding", "br"), raw)
	if got.Decoded {
		t.Fatal("br should not be reported as decoded")
	}
	if !strings.Contains(got.Err, "br") {
		t.Fatalf("Err = %q", got.Err)
	}
	if !bytes.Equal(got.Data, raw) {
		t.Fatal("br data should pass through untouched")
	}
}

func TestDecodeIdentity(t *testing.T) {
	got := Decode(hdr("Content-Type", "text/plain"), []byte("hello"))
	if !got.Decoded || string(got.Data) != "hello" || got.Binary {
		t.Fatalf("%+v", got)
	}
}

func TestDecodeCorruptGzipReportsError(t *testing.T) {
	got := Decode(hdr("Content-Encoding", "gzip"), []byte("not gzip at all"))
	if got.Decoded || got.Err == "" {
		t.Fatalf("expected a decode error, got %+v", got)
	}
}

func TestDecodeCapsDecompressedSize(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	chunk := bytes.Repeat([]byte("a"), 64<<10)
	for i := 0; i < (MaxDecodedSize/len(chunk))+4; i++ {
		zw.Write(chunk)
	}
	zw.Close()

	got := Decode(hdr("Content-Encoding", "gzip"), buf.Bytes())
	if !got.Decoded {
		t.Fatalf("decode failed: %+v", got.Err)
	}
	if len(got.Data) != MaxDecodedSize {
		t.Fatalf("decoded size = %d, want %d", len(got.Data), MaxDecodedSize)
	}
	if !got.Truncated {
		t.Fatal("oversized decode not marked truncated")
	}
}

func TestIsBinary(t *testing.T) {
	cases := []struct {
		name  string
		ctype string
		data  []byte
		want  bool
	}{
		{"utf8 text", "text/plain", []byte("héllo wörld"), false},
		{"json", "application/json", []byte(`{"k":"v"}`), false},
		{"png content type", "image/png", []byte("\x89PNG\r\n\x1a\n"), true},
		{"nul byte", "text/plain", []byte("ab\x00cd"), true},
		{"invalid utf8", "", []byte{0xff, 0xfe, 0x41, 0x42}, true},
		{"empty", "application/octet-stream", nil, false},
		{"truncated rune", "text/plain", []byte("abc\xc3"), false},
		{"octet stream but text", "application/octet-stream", []byte("plain"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsBinary(tc.ctype, tc.data); got != tc.want {
				t.Fatalf("IsBinary(%q) = %v, want %v", tc.ctype, got, tc.want)
			}
		})
	}
}
