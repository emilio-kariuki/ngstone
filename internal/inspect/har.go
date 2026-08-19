package inspect

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ngstone/internal/version"
)

type HAROptions struct {
	IncludeSensitive bool
}

type harLog struct {
	Version string     `json:"version"`
	Creator harCreator `json:"creator"`
	Entries []harEntry `json:"entries"`
}

type harCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type harDocument struct {
	Log harLog `json:"log"`
}

type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
	Comment         string      `json:"comment,omitempty"`
}

type harRequest struct {
	Method      string         `json:"method"`
	URL         string         `json:"url"`
	HTTPVersion string         `json:"httpVersion"`
	Headers     []harHeader    `json:"headers"`
	QueryString []harNameValue `json:"queryString"`
	Cookies     []harCookie    `json:"cookies"`
	HeadersSize int            `json:"headersSize"`
	BodySize    int64          `json:"bodySize"`
	PostData    *harPostData   `json:"postData,omitempty"`
}

type harResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []harHeader `json:"headers"`
	Cookies     []harCookie `json:"cookies"`
	Content     harContent  `json:"content"`
	RedirectURL string      `json:"redirectURL"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int64       `json:"bodySize"`
}

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harPostData struct {
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text"`
	Encoding string `json:"encoding,omitempty"`
}

type harContent struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

var sensitiveHARHeaders = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
	"set-cookie":          {},
	"x-api-key":           {},
}

func MarshalHAR(exchanges []*Exchange, opts HAROptions) ([]byte, error) {
	entries := make([]harEntry, 0, len(exchanges))
	for _, exchange := range exchanges {
		if exchange == nil {
			continue
		}
		entries = append(entries, makeHAREntry(exchange, opts))
	}
	doc := harDocument{
		Log: harLog{
			Version: "1.2",
			Creator: harCreator{Name: "ngstone", Version: version.Version},
			Entries: entries,
		},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func WriteHAR(path string, exchanges []*Exchange, opts HAROptions) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("inspect: HAR output path is required")
	}
	data, err := MarshalHAR(exchanges, opts)
	if err != nil {
		return fmt.Errorf("inspect: encoding HAR: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("inspect: creating HAR temp file: %w", err)
	}
	tmpPath := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("inspect: protecting HAR file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("inspect: writing HAR file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("inspect: closing HAR file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("inspect: replacing %s: %w", path, err)
	}
	renamed = true
	return nil
}

func makeHAREntry(exchange *Exchange, opts HAROptions) harEntry {
	reqProto := exchange.Req.Proto
	if reqProto == "" {
		reqProto = "HTTP/1.1"
	}
	respProto := exchange.Resp.Proto
	if respProto == "" {
		respProto = "HTTP/1.1"
	}

	requestBody := makeHARBody(exchange.Req.Body, exchange.Req.Header)
	responseBody := makeHARContent(exchange.Resp.Body, exchange.Resp.BodySize, exchange.Resp.Header)
	comment := ""
	if exchange.Req.Truncated || exchange.Resp.Truncated {
		comment = "one or more captured bodies were truncated at the inspector limit"
	}
	if exchange.Err != "" {
		if comment != "" {
			comment += "; "
		}
		comment += exchange.Err
	}
	if exchange.Tunnel != "" {
		if comment != "" {
			comment += "; "
		}
		comment += "tunnel: " + exchange.Tunnel
	}

	return harEntry{
		StartedDateTime: exchange.Start.UTC().Format(time.RFC3339Nano),
		Time:            float64(exchange.Duration) / float64(time.Millisecond),
		Request: harRequest{
			Method:      exchange.Req.Method,
			URL:         exchange.Req.URL,
			HTTPVersion: reqProto,
			Headers:     harHeaders(exchange.Req.Header, opts),
			QueryString: harQuery(exchange.Req.URL),
			Cookies:     []harCookie{},
			HeadersSize: -1,
			BodySize:    exchange.Req.BodySize,
			PostData:    requestBody,
		},
		Response: harResponse{
			Status:      exchange.Resp.Status,
			StatusText:  http.StatusText(exchange.Resp.Status),
			HTTPVersion: respProto,
			Headers:     harHeaders(exchange.Resp.Header, opts),
			Cookies:     []harCookie{},
			Content:     responseBody,
			RedirectURL: exchange.Resp.Header.Get("Location"),
			HeadersSize: -1,
			BodySize:    exchange.Resp.BodySize,
		},
		Comment: comment,
	}
}

func harHeaders(header http.Header, opts HAROptions) []harHeader {
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]harHeader, 0, len(header))
	for _, key := range keys {
		values := header.Values(key)
		if len(values) == 0 {
			values = []string{""}
		}
		for _, value := range values {
			if !opts.IncludeSensitive {
				if _, ok := sensitiveHARHeaders[strings.ToLower(key)]; ok {
					value = "[REDACTED]"
				}
			}
			out = append(out, harHeader{Name: key, Value: value})
		}
	}
	return out
}

func harQuery(raw string) []harNameValue {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return []harNameValue{}
	}
	values := u.Query()
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]harNameValue, 0)
	for _, key := range keys {
		for _, value := range values[key] {
			out = append(out, harNameValue{Name: key, Value: value})
		}
	}
	return out
}

func makeHARBody(body []byte, header http.Header) *harPostData {
	if len(body) == 0 {
		return nil
	}
	text, encoding := harText(body, header)
	return &harPostData{
		MimeType: header.Get("Content-Type"),
		Text:     text,
		Encoding: encoding,
	}
}

func makeHARContent(body []byte, size int64, header http.Header) harContent {
	content := harContent{
		Size:     size,
		MimeType: header.Get("Content-Type"),
	}
	if len(body) > 0 {
		content.Text, content.Encoding = harText(body, header)
	}
	return content
}

func harText(body []byte, header http.Header) (string, string) {
	if IsBinary(header.Get("Content-Type"), body) {
		return base64.StdEncoding.EncodeToString(body), "base64"
	}
	return string(body), ""
}
