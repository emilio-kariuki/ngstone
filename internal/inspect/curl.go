package inspect

import (
	"errors"
	"net/url"
	"sort"
	"strings"
)

type CurlOptions struct {
	IncludeSensitive bool
	Target           *url.URL
}

func BuildCurl(ex *Exchange, opts CurlOptions) (string, error) {
	if ex == nil {
		return "", ErrNotFound
	}
	if ex.Kind == KindUpgrade {
		return "", ErrNotReplayable
	}
	if ex.Req.Truncated {
		return "", ErrTruncatedBody
	}

	method := ex.Req.Method
	if method == "" {
		method = "GET"
	}
	rawURL := ex.Req.URL
	u, err := url.Parse(rawURL)
	if err != nil || u.String() == "" {
		return "", errors.New("inspect: captured request URL is invalid")
	}
	header := sanitizeHeader(ex.Req.Header)
	if opts.Target != nil {
		originalHost := u.Host
		u.Scheme = opts.Target.Scheme
		u.Host = opts.Target.Host
		if originalHost != "" {
			header.Set("Host", originalHost)
		}
	}

	lines := []string{"curl --request " + shellQuote(method) + " --url " + shellQuote(u.String())}
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values := header.Values(key)
		if len(values) == 0 {
			values = []string{""}
		}
		for _, value := range values {
			if !opts.IncludeSensitive && isSensitiveHeader(key) {
				value = "[REDACTED]"
			}
			lines = append(lines, "  --header "+shellQuote(key+": "+value))
		}
	}
	if len(ex.Req.Body) > 0 {
		lines = append(lines, "  --data-raw "+shellQuote(string(ex.Req.Body)))
	}
	return strings.Join(lines, " \\\n"), nil
}

func isSensitiveHeader(key string) bool {
	_, ok := sensitiveHARHeaders[strings.ToLower(key)]
	return ok
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
