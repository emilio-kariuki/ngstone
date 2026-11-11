package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	pathpkg "path"
	"strings"
	"unicode"
)

const (
	maxRules       = 64
	maxPathPrefix  = 2048
	maxHeaderValue = 4096
	maxPolicyBytes = 48 << 10
)

const (
	ActionAllow     = "allow"
	ActionDeny      = "deny"
	ActionRedirect  = "redirect"
	ActionTransform = "transform"
)

type Policy struct {
	DefaultAction string `json:"default_action,omitempty"`
	Rules         []Rule `json:"rules"`
	CORS          *CORS  `json:"cors,omitempty"`
}

type Rule struct {
	Action          string         `json:"action"`
	Method          string         `json:"method,omitempty"`
	PathPrefix      string         `json:"path_prefix,omitempty"`
	Header          string         `json:"header,omitempty"`
	HeaderValue     string         `json:"header_value,omitempty"`
	RedirectURL     string         `json:"redirect_url,omitempty"`
	RedirectStatus  int            `json:"redirect_status,omitempty"`
	RequestHeaders  *HeaderActions `json:"request_headers,omitempty"`
	ResponseHeaders *HeaderActions `json:"response_headers,omitempty"`
}

type Decision struct {
	Allowed        bool
	RedirectURL    string
	RedirectStatus int

	request  []*HeaderActions
	response []*HeaderActions
	cors     *CORS
	origin   string
}

func LoadFile(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxPolicyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(data) > maxPolicyBytes {
		return nil, fmt.Errorf("policy file exceeds %d bytes", maxPolicyBytes)
	}
	parsed, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return parsed, nil
}

func Parse(data []byte) (*Policy, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var parsed Policy
	if err := decoder.Decode(&parsed); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("multiple JSON values")
		}
		return nil, err
	}
	if err := parsed.Validate(); err != nil {
		return nil, err
	}
	return &parsed, nil
}

func (p *Policy) Validate() error {
	if p == nil {
		return errors.New("policy is nil")
	}

	p.DefaultAction = strings.ToLower(strings.TrimSpace(p.DefaultAction))
	if p.DefaultAction == "" {
		p.DefaultAction = "allow"
	}
	if p.DefaultAction != ActionAllow && p.DefaultAction != ActionDeny {
		return fmt.Errorf("default_action must be allow or deny")
	}
	if p.CORS != nil {
		if err := p.CORS.validate(); err != nil {
			return fmt.Errorf("cors: %w", err)
		}
	}
	if len(p.Rules) > maxRules {
		return fmt.Errorf("too many rules (max %d)", maxRules)
	}

	for i := range p.Rules {
		rule := &p.Rules[i]
		rule.Action = strings.ToLower(strings.TrimSpace(rule.Action))
		if !validAction(rule.Action) {
			return fmt.Errorf("rule %d action must be allow, deny, redirect or transform", i+1)
		}

		rule.Method = strings.ToUpper(strings.TrimSpace(rule.Method))
		if rule.Method != "" && !validToken(rule.Method) {
			return fmt.Errorf("rule %d method is invalid", i+1)
		}

		if len(rule.PathPrefix) > maxPathPrefix {
			return fmt.Errorf("rule %d path_prefix exceeds %d bytes", i+1, maxPathPrefix)
		}
		if rule.PathPrefix != "" && (rule.PathPrefix[0] != '/' || containsControl(rule.PathPrefix)) {
			return fmt.Errorf("rule %d path_prefix must be an absolute URL path", i+1)
		}
		if rule.PathPrefix != "" {
			rule.PathPrefix = normalizePath(rule.PathPrefix)
		}

		if rule.Header != "" {
			if strings.TrimSpace(rule.Header) != rule.Header || !validToken(rule.Header) {
				return fmt.Errorf("rule %d header name is invalid", i+1)
			}
			rule.Header = http.CanonicalHeaderKey(rule.Header)
		}
		if len(rule.HeaderValue) > maxHeaderValue || strings.ContainsAny(rule.HeaderValue, "\r\n") {
			return fmt.Errorf("rule %d header_value is invalid or exceeds %d bytes", i+1, maxHeaderValue)
		}
		if rule.Header == "" && rule.HeaderValue != "" {
			return fmt.Errorf("rule %d header_value requires header", i+1)
		}
		if err := rule.validateRedirect(); err != nil {
			return fmt.Errorf("rule %d %w", i+1, err)
		}
		if err := rule.validateTransform(p.CORS != nil); err != nil {
			return fmt.Errorf("rule %d %w", i+1, err)
		}
	}

	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("encoding policy: %w", err)
	}
	if len(data) > maxPolicyBytes {
		return fmt.Errorf("policy exceeds %d bytes", maxPolicyBytes)
	}
	return nil
}

func (p *Policy) Digest() string {
	if p == nil {
		return ""
	}
	data, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (p *Policy) Decide(r *http.Request) Decision {
	if p == nil {
		return Decision{Allowed: true}
	}
	decision := Decision{Allowed: p.DefaultAction != ActionDeny}
	decided := false
	for i := range p.Rules {
		rule := &p.Rules[i]
		if !ruleMatches(*rule, r) {
			continue
		}
		if rule.Action == ActionTransform {
			if rule.RequestHeaders != nil {
				decision.request = append(decision.request, rule.RequestHeaders)
			}
			if rule.ResponseHeaders != nil {
				decision.response = append(decision.response, rule.ResponseHeaders)
			}
			continue
		}
		if decided {
			continue
		}
		decided = true
		switch rule.Action {
		case ActionRedirect:
			decision.Allowed = false
			decision.RedirectURL = rule.redirectTarget(r)
			decision.RedirectStatus = rule.RedirectStatus
			if decision.RedirectStatus == 0 {
				decision.RedirectStatus = defaultRedirectStatus
			}
		default:
			decision.Allowed = rule.Action == ActionAllow
		}
	}
	if !decision.Allowed {
		decision.request = nil
		decision.response = nil
	}
	if p.CORS != nil && r != nil {
		decision.cors = p.CORS
		decision.origin = r.Header.Get("Origin")
	}
	return decision
}

func (d *Decision) ApplyRequestHeaders(h http.Header) {
	for _, actions := range d.request {
		actions.apply(h)
	}
}

func (d *Decision) ApplyResponseHeaders(h http.Header) {
	for _, actions := range d.response {
		actions.apply(h)
	}
	d.ApplyCORS(h)
}

func (d *Decision) ApplyCORS(h http.Header) {
	if d.cors != nil {
		d.cors.applyResponse(h, d.origin)
	}
}

func (d *Decision) TransformsResponse() bool {
	return len(d.response) > 0 || d.cors != nil
}

func ruleMatches(rule Rule, r *http.Request) bool {
	if r == nil {
		return false
	}
	if rule.Method != "" && r.Method != rule.Method {
		return false
	}
	if rule.PathPrefix != "" && (r.URL == nil || !pathMatches(r.URL.Path, rule.PathPrefix)) {
		return false
	}
	if rule.Header != "" {
		values := r.Header.Values(rule.Header)
		if len(values) == 0 {
			return false
		}
		if rule.HeaderValue != "" {
			matched := false
			for _, value := range values {
				if value == rule.HeaderValue {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}
	return true
}

func pathMatches(path, prefix string) bool {
	path = normalizePath(path)
	prefix = normalizePath(prefix)
	if path == prefix {
		return true
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return strings.HasSuffix(prefix, "/") || (len(path) > len(prefix) && path[len(prefix)] == '/')
}

func normalizePath(value string) string {
	if value == "" {
		return "/"
	}
	cleaned := pathpkg.Clean(value)
	if !strings.HasPrefix(cleaned, "/") {
		return "/" + cleaned
	}
	return cleaned
}

func validAction(action string) bool {
	switch action {
	case ActionAllow, ActionDeny, ActionRedirect, ActionTransform:
		return true
	}
	return false
}

func validToken(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		switch r {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		default:
			return false
		}
	}
	return true
}

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
