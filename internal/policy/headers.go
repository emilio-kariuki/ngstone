package policy

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/net/http/httpguts"
)

const maxHeaderActions = 32

type HeaderActions struct {
	Set    map[string]string `json:"set,omitempty"`
	Add    map[string]string `json:"add,omitempty"`
	Remove []string          `json:"remove,omitempty"`
}

var reservedHeaders = map[string]string{
	"connection":          "hop-by-hop",
	"keep-alive":          "hop-by-hop",
	"proxy-connection":    "hop-by-hop",
	"proxy-authenticate":  "hop-by-hop",
	"proxy-authorization": "hop-by-hop",
	"te":                  "hop-by-hop",
	"trailer":             "hop-by-hop",
	"trailers":            "hop-by-hop",
	"transfer-encoding":   "hop-by-hop",
	"upgrade":             "hop-by-hop",
	"http2-settings":      "hop-by-hop",
	"host":                "owned by the edge",
	"content-length":      "owned by the edge",
	"authorization":       "owned by the edge",
	"forwarded":           "owned by the edge",
	"x-real-ip":           "owned by the edge",
}

var reservedHeaderPrefixes = []string{"x-forwarded-", "x-ngstone-"}

func reservedHeaderReason(name string, cors bool) string {
	lower := strings.ToLower(name)
	if reason, ok := reservedHeaders[lower]; ok {
		return reason
	}
	for _, prefix := range reservedHeaderPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return "owned by the edge"
		}
	}
	if cors && strings.HasPrefix(lower, "access-control-") {
		return "owned by the cors option"
	}
	return ""
}

func (r *Rule) validateTransform(cors bool) error {
	if r.Action != ActionTransform {
		if r.RequestHeaders != nil || r.ResponseHeaders != nil {
			return errors.New("request_headers and response_headers require action transform")
		}
		return nil
	}
	if r.RequestHeaders == nil && r.ResponseHeaders == nil {
		return errors.New("transform requires request_headers or response_headers")
	}
	if r.RequestHeaders != nil {
		if err := r.RequestHeaders.validate(false); err != nil {
			return fmt.Errorf("request_headers: %w", err)
		}
	}
	if r.ResponseHeaders != nil {
		if err := r.ResponseHeaders.validate(cors); err != nil {
			return fmt.Errorf("response_headers: %w", err)
		}
	}
	return nil
}

func (a *HeaderActions) validate(cors bool) error {
	if len(a.Set) == 0 && len(a.Add) == 0 && len(a.Remove) == 0 {
		return errors.New("must contain set, add or remove")
	}
	if len(a.Set)+len(a.Add)+len(a.Remove) > maxHeaderActions {
		return fmt.Errorf("too many header actions (max %d)", maxHeaderActions)
	}
	var err error
	if a.Set, err = canonicalHeaderMap("set", a.Set, cors); err != nil {
		return err
	}
	if a.Add, err = canonicalHeaderMap("add", a.Add, cors); err != nil {
		return err
	}
	for i, name := range a.Remove {
		canonical, err := checkHeaderName(name, cors)
		if err != nil {
			return fmt.Errorf("remove: %w", err)
		}
		a.Remove[i] = canonical
	}
	return nil
}

func canonicalHeaderMap(field string, values map[string]string, cors bool) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(values))
	for name, value := range values {
		canonical, err := checkHeaderName(name, cors)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		if _, dup := out[canonical]; dup {
			return nil, fmt.Errorf("%s: header %q is listed more than once", field, canonical)
		}
		if len(value) > maxHeaderValue || !httpguts.ValidHeaderFieldValue(value) {
			return nil, fmt.Errorf("%s: value for %q is invalid or exceeds %d bytes", field, canonical, maxHeaderValue)
		}
		out[canonical] = value
	}
	return out, nil
}

func checkHeaderName(name string, cors bool) (string, error) {
	if strings.TrimSpace(name) != name || !validToken(name) {
		return "", fmt.Errorf("header name %q is invalid", name)
	}
	canonical := http.CanonicalHeaderKey(name)
	if reason := reservedHeaderReason(canonical, cors); reason != "" {
		return "", fmt.Errorf("header %q cannot be changed: %s", canonical, reason)
	}
	return canonical, nil
}

func (a *HeaderActions) apply(h http.Header) {
	for _, name := range a.Remove {
		h.Del(name)
	}
	for name, value := range a.Set {
		h.Set(name, value)
	}
	for name, value := range a.Add {
		h.Add(name, value)
	}
}
