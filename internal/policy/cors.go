package policy

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	maxCORSEntries = 64
	maxCORSMaxAge  = 86400
	corsWildcard   = "*"
)

var defaultCORSMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost}

type CORS struct {
	AllowedOrigins   []string `json:"allowed_origins"`
	AllowedMethods   []string `json:"allowed_methods,omitempty"`
	AllowedHeaders   []string `json:"allowed_headers,omitempty"`
	ExposedHeaders   []string `json:"exposed_headers,omitempty"`
	AllowCredentials bool     `json:"allow_credentials,omitempty"`
	MaxAge           int      `json:"max_age,omitempty"`
}

func (c *CORS) validate() error {
	if len(c.AllowedOrigins) == 0 {
		return errors.New("allowed_origins must not be empty")
	}
	if len(c.AllowedOrigins) > maxCORSEntries || len(c.AllowedMethods) > maxCORSEntries || len(c.AllowedHeaders) > maxCORSEntries || len(c.ExposedHeaders) > maxCORSEntries {
		return fmt.Errorf("lists may hold at most %d entries", maxCORSEntries)
	}
	for i, origin := range c.AllowedOrigins {
		if origin == corsWildcard {
			if len(c.AllowedOrigins) != 1 {
				return errors.New(`allowed_origins "*" cannot be combined with other origins`)
			}
			if c.AllowCredentials {
				return errors.New(`allowed_origins "*" cannot be combined with allow_credentials`)
			}
			continue
		}
		if strings.Contains(origin, corsWildcard) {
			return fmt.Errorf("allowed_origins entry %q cannot contain \"*\"; use \"*\" alone or exact origins", origin)
		}
		normalized, ok := normalizeOrigin(origin)
		if !ok {
			return fmt.Errorf("allowed_origins entry %q must be \"*\" or scheme://host[:port]", origin)
		}
		c.AllowedOrigins[i] = normalized
	}
	for i, method := range c.AllowedMethods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if strings.Contains(method, corsWildcard) {
			return fmt.Errorf("allowed_methods entry %q cannot contain \"*\"; list methods explicitly", c.AllowedMethods[i])
		}
		if !validToken(method) {
			return fmt.Errorf("allowed_methods entry %q is invalid", c.AllowedMethods[i])
		}
		c.AllowedMethods[i] = method
	}
	for i, name := range c.AllowedHeaders {
		if name == corsWildcard {
			if len(c.AllowedHeaders) != 1 {
				return errors.New(`allowed_headers "*" cannot be combined with other headers`)
			}
			continue
		}
		if !validToken(name) {
			return fmt.Errorf("allowed_headers entry %q is invalid", name)
		}
		c.AllowedHeaders[i] = http.CanonicalHeaderKey(name)
	}
	for i, name := range c.ExposedHeaders {
		if !validToken(name) {
			return fmt.Errorf("exposed_headers entry %q is invalid", name)
		}
		c.ExposedHeaders[i] = http.CanonicalHeaderKey(name)
	}
	if c.MaxAge < 0 || c.MaxAge > maxCORSMaxAge {
		return fmt.Errorf("max_age must be between 0 and %d seconds", maxCORSMaxAge)
	}
	return nil
}

func normalizeOrigin(origin string) (string, bool) {
	if origin == "" || containsControl(origin) || strings.ContainsAny(origin, " \\") {
		return "", false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.HasSuffix(origin, "#") {
		return "", false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", false
	}
	port := parsed.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return "", false
		}
		host += ":" + port
	}
	return scheme + "://" + host, true
}

func (c *CORS) wildcard() bool {
	return len(c.AllowedOrigins) == 1 && c.AllowedOrigins[0] == corsWildcard
}

func (c *CORS) originAllowed(origin string) bool {
	if origin == "" {
		return false
	}
	if c.wildcard() {
		return true
	}
	normalized, ok := normalizeOrigin(origin)
	if !ok {
		return false
	}
	for _, allowed := range c.AllowedOrigins {
		if allowed == normalized {
			return true
		}
	}
	return false
}

func (c *CORS) methods() []string {
	if len(c.AllowedMethods) == 0 {
		return defaultCORSMethods
	}
	return c.AllowedMethods
}

func IsPreflight(r *http.Request) bool {
	return r != nil && r.Method == http.MethodOptions && r.Header.Get("Origin") != "" && r.Header.Get("Access-Control-Request-Method") != ""
}

func (p *Policy) Preflight(r *http.Request) (http.Header, bool) {
	if p == nil || p.CORS == nil || !IsPreflight(r) {
		return nil, false
	}
	c := p.CORS
	h := make(http.Header)
	h.Add("Vary", "Origin")
	h.Add("Vary", "Access-Control-Request-Method")
	h.Add("Vary", "Access-Control-Request-Headers")
	origin := r.Header.Get("Origin")
	if !c.originAllowed(origin) {
		return h, true
	}
	requested := strings.ToUpper(strings.TrimSpace(r.Header.Get("Access-Control-Request-Method")))
	methodAllowed := false
	for _, method := range c.methods() {
		if method == requested {
			methodAllowed = true
			break
		}
	}
	if !methodAllowed {
		return h, true
	}
	c.setOrigin(h, origin)
	h.Set("Access-Control-Allow-Methods", strings.Join(c.methods(), ", "))
	if headers := c.preflightHeaders(r); headers != "" {
		h.Set("Access-Control-Allow-Headers", headers)
	}
	if c.MaxAge > 0 {
		h.Set("Access-Control-Max-Age", strconv.Itoa(c.MaxAge))
	}
	return h, true
}

func (c *CORS) preflightHeaders(r *http.Request) string {
	if len(c.AllowedHeaders) == 1 && c.AllowedHeaders[0] == corsWildcard {
		var names []string
		for _, value := range r.Header.Values("Access-Control-Request-Headers") {
			for _, name := range strings.Split(value, ",") {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				if !validToken(name) {
					return ""
				}
				names = append(names, strings.ToLower(name))
			}
		}
		return strings.Join(names, ", ")
	}
	return strings.Join(c.AllowedHeaders, ", ")
}

func (c *CORS) setOrigin(h http.Header, origin string) {
	if c.wildcard() {
		h.Set("Access-Control-Allow-Origin", corsWildcard)
	} else {
		h.Set("Access-Control-Allow-Origin", origin)
	}
	if c.AllowCredentials {
		h.Set("Access-Control-Allow-Credentials", "true")
	}
}

func (c *CORS) applyResponse(h http.Header, origin string) {
	for name := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "Access-Control-") {
			delete(h, name)
		}
	}
	if !c.wildcard() && !varyContains(h, "Origin") {
		h.Add("Vary", "Origin")
	}
	if !c.wildcard() && !c.originAllowed(origin) {
		return
	}
	c.setOrigin(h, origin)
	if len(c.ExposedHeaders) > 0 {
		h.Set("Access-Control-Expose-Headers", strings.Join(c.ExposedHeaders, ", "))
	}
}

func varyContains(h http.Header, name string) bool {
	for _, value := range h.Values("Vary") {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "*" || strings.EqualFold(part, name) {
				return true
			}
		}
	}
	return false
}
