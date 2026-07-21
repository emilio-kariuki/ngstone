package inspect

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"
)

const MaxDecodedSize = 4 << 20

type DecodedBody struct {
	Data      []byte
	Encoding  string
	Decoded   bool
	Binary    bool
	Truncated bool
	Err       string
}

func Decode(header http.Header, raw []byte) DecodedBody {
	enc := ""
	if header != nil {
		enc = strings.ToLower(strings.TrimSpace(header.Get("Content-Encoding")))
	}
	ctype := ""
	if header != nil {
		ctype = header.Get("Content-Type")
	}

	out := DecodedBody{Data: raw, Encoding: enc}

	switch enc {
	case "", "identity":
		out.Decoded = true
	case "gzip", "x-gzip":
		data, trunc, err := decompress(raw, newGzipReader)
		if err != nil {
			out.Err = "gzip decode failed: " + err.Error()
		} else {
			out.Data = data
			out.Decoded = true
			out.Truncated = trunc
		}
	case "deflate":
		data, trunc, err := decompress(raw, newDeflateReader)
		if err != nil {
			out.Err = "deflate decode failed: " + err.Error()
		} else {
			out.Data = data
			out.Decoded = true
			out.Truncated = trunc
		}
	default:
		out.Err = "unsupported content-encoding: " + enc
	}

	out.Binary = IsBinary(ctype, out.Data)
	return out
}

func newGzipReader(r io.Reader) (io.Reader, error) { return gzip.NewReader(r) }

func newDeflateReader(r io.Reader) (io.Reader, error) {
	buf, err := io.ReadAll(io.LimitReader(r, MaxDecodedSize+1))
	if err != nil {
		return nil, err
	}
	if zr, err := zlib.NewReader(bytes.NewReader(buf)); err == nil {
		return zr, nil
	}
	return flate.NewReader(bytes.NewReader(buf)), nil
}

func decompress(raw []byte, mk func(io.Reader) (io.Reader, error)) ([]byte, bool, error) {
	r, err := mk(bytes.NewReader(raw))
	if err != nil {
		return nil, false, err
	}
	if c, ok := r.(io.Closer); ok {
		defer c.Close()
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxDecodedSize+1))
	if err != nil && len(data) == 0 {
		return nil, false, err
	}
	truncated := false
	if len(data) > MaxDecodedSize {
		data = data[:MaxDecodedSize]
		truncated = true
	}
	return data, truncated, nil
}

var binaryTypes = []string{
	"image/",
	"video/",
	"audio/",
	"font/",
	"application/octet-stream",
	"application/pdf",
	"application/zip",
	"application/gzip",
	"application/wasm",
	"application/x-protobuf",
	"application/grpc",
}

func IsBinary(contentType string, data []byte) bool {
	if len(data) == 0 {
		return false
	}

	base := contentType
	if base != "" {
		if parsed, _, err := mime.ParseMediaType(contentType); err == nil {
			base = parsed
		}
		base = strings.ToLower(base)
		for _, p := range binaryTypes {
			if strings.HasPrefix(base, p) {
				return true
			}
		}
	}

	sample := data
	if len(sample) > 1024 {
		sample = sample[:1024]
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return true
	}
	return !utf8.Valid(trimPartialRune(sample))
}

func trimPartialRune(b []byte) []byte {
	for i := 0; i < utf8.UTFMax && i < len(b); i++ {
		cut := len(b) - i
		if r, size := utf8.DecodeLastRune(b[:cut]); r != utf8.RuneError || size > 1 {
			return b[:cut]
		}
	}
	return b
}
