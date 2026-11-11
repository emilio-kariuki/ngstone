package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	ProviderStripe = "stripe"
	ProviderGitHub = "github"
	ProviderSlack  = "slack"
	ProviderHMAC   = "hmac"

	EncodingHex    = "hex"
	EncodingBase64 = "base64"

	DefaultTolerance = 5 * time.Minute
	MaxTolerance     = 24 * time.Hour

	MaxSecretBytes     = 4096
	MaxHeaderNameBytes = 128
	MaxPrefixBytes     = 64
	MaxPathPrefixBytes = 1024

	StripeSignatureHeader = "Stripe-Signature"
	GitHubSignatureHeader = "X-Hub-Signature-256"
	SlackSignatureHeader  = "X-Slack-Signature"
	SlackTimestampHeader  = "X-Slack-Request-Timestamp"
)

var (
	ErrMissingSignature    = errors.New("missing signature")
	ErrMalformedSignature  = errors.New("malformed signature")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrTimestampOutOfRange = errors.New("timestamp outside tolerance")
)

var Providers = []string{ProviderStripe, ProviderGitHub, ProviderSlack, ProviderHMAC}

type Config struct {
	Provider   string
	Secret     string
	PathPrefix string
	Header     string
	Encoding   string
	Prefix     string
	Tolerance  time.Duration
}

func (c Config) Normalize() (Config, error) {
	c.Provider = strings.ToLower(strings.TrimSpace(c.Provider))
	switch c.Provider {
	case ProviderStripe, ProviderGitHub, ProviderSlack, ProviderHMAC:
	case "":
		return c, errors.New("webhook verification needs a provider")
	default:
		return c, fmt.Errorf("unknown webhook provider %q (want %s)", c.Provider, strings.Join(Providers, ", "))
	}
	if c.Secret == "" {
		return c, errors.New("webhook verification needs a non-empty secret")
	}
	if len(c.Secret) > MaxSecretBytes {
		return c, fmt.Errorf("webhook secret is longer than %d bytes", MaxSecretBytes)
	}
	if c.PathPrefix != "" {
		if !strings.HasPrefix(c.PathPrefix, "/") {
			return c, errors.New("webhook path prefix must start with /")
		}
		if len(c.PathPrefix) > MaxPathPrefixBytes {
			return c, fmt.Errorf("webhook path prefix is longer than %d bytes", MaxPathPrefixBytes)
		}
		if strings.ContainsAny(c.PathPrefix, "%?#") {
			return c, errors.New("webhook path prefix must not contain %, ? or #")
		}
		c.PathPrefix = path.Clean(c.PathPrefix)
		if c.PathPrefix == "/" {
			c.PathPrefix = ""
		}
	}
	if c.Tolerance < 0 {
		return c, errors.New("webhook tolerance must not be negative")
	}
	if c.Tolerance > MaxTolerance {
		return c, fmt.Errorf("webhook tolerance must be at most %s", MaxTolerance)
	}
	if c.Tolerance != 0 && (c.Tolerance < time.Second || c.Tolerance%time.Second != 0) {
		return c, errors.New("webhook tolerance must be a whole number of seconds")
	}
	switch c.Provider {
	case ProviderStripe, ProviderSlack:
		if c.Tolerance == 0 {
			c.Tolerance = DefaultTolerance
		}
	default:
		if c.Tolerance != 0 {
			return c, fmt.Errorf("webhook tolerance applies only to the %s and %s providers", ProviderStripe, ProviderSlack)
		}
	}
	if c.Provider != ProviderHMAC {
		if c.Header != "" || c.Encoding != "" || c.Prefix != "" {
			return c, fmt.Errorf("webhook header, encoding and prefix apply only to the %s provider", ProviderHMAC)
		}
		return c, nil
	}
	c.Header = strings.TrimSpace(c.Header)
	if c.Header == "" {
		return c, errors.New("the hmac webhook provider needs a signature header name")
	}
	if len(c.Header) > MaxHeaderNameBytes || !validHeaderName(c.Header) {
		return c, fmt.Errorf("invalid webhook signature header name %q", c.Header)
	}
	c.Header = textproto.CanonicalMIMEHeaderKey(c.Header)
	c.Encoding = strings.ToLower(strings.TrimSpace(c.Encoding))
	switch c.Encoding {
	case "":
		c.Encoding = EncodingHex
	case EncodingHex, EncodingBase64:
	default:
		return c, fmt.Errorf("webhook signature encoding must be %s or %s", EncodingHex, EncodingBase64)
	}
	if len(c.Prefix) > MaxPrefixBytes {
		return c, fmt.Errorf("webhook signature prefix is longer than %d bytes", MaxPrefixBytes)
	}
	for _, r := range c.Prefix {
		if r < 0x21 || r > 0x7e {
			return c, errors.New("webhook signature prefix must be printable ASCII without spaces")
		}
	}
	return c, nil
}

func validHeaderName(name string) bool {
	for i := 0; i < len(name); i++ {
		ch := name[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", ch) >= 0:
		default:
			return false
		}
	}
	return name != ""
}

type Verifier struct {
	cfg    Config
	secret []byte
}

func New(c Config) (*Verifier, error) {
	normalized, err := c.Normalize()
	if err != nil {
		return nil, err
	}
	return &Verifier{cfg: normalized, secret: []byte(normalized.Secret)}, nil
}

func (v *Verifier) Provider() string {
	if v == nil {
		return ""
	}
	return v.cfg.Provider
}

func (v *Verifier) PathPrefix() string {
	if v == nil {
		return ""
	}
	return v.cfg.PathPrefix
}

func (v *Verifier) Equal(o *Verifier) bool {
	if v == nil || o == nil {
		return v == nil && o == nil
	}
	a, b := v.cfg, o.cfg
	a.Secret, b.Secret = "", ""
	secretsEqual := subtle.ConstantTimeCompare(sha256Sum(v.secret), sha256Sum(o.secret)) == 1
	return a == b && secretsEqual
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func (v *Verifier) Matches(requestPath string) bool {
	if v == nil {
		return false
	}
	prefix := v.cfg.PathPrefix
	if prefix == "" {
		return true
	}
	if strings.Contains(strings.ToLower(requestPath), "%2f") {
		return true
	}
	decoded, err := url.PathUnescape(requestPath)
	if err != nil || !strings.HasPrefix(decoded, "/") {
		return true
	}
	for i := 0; i < len(decoded); i++ {
		if ch := decoded[i]; ch < 0x20 || ch >= 0x7f || ch == '\\' || ch == ';' || ch == '%' {
			return true
		}
	}
	if decoded != "/" {
		for _, seg := range strings.Split(strings.TrimSuffix(decoded[1:], "/"), "/") {
			if seg == "" || seg == "." || seg == ".." {
				return true
			}
		}
	}
	return strings.Contains(strings.ToLower(decoded)+"/", strings.ToLower(prefix))
}

func (v *Verifier) Verify(h http.Header, body []byte, now time.Time) error {
	if v == nil {
		return nil
	}
	switch v.cfg.Provider {
	case ProviderStripe:
		return v.verifyStripe(h, body, now)
	case ProviderGitHub:
		return v.verifyGitHub(h, body)
	case ProviderSlack:
		return v.verifySlack(h, body, now)
	case ProviderHMAC:
		return v.verifyHMAC(h, body)
	}
	return ErrInvalidSignature
}

func (v *Verifier) CheckHeaders(h http.Header) error {
	err := v.Verify(h, nil, time.Time{})
	if errors.Is(err, ErrMissingSignature) || errors.Is(err, ErrMalformedSignature) {
		return err
	}
	return nil
}

func (v *Verifier) mac(parts ...[]byte) []byte {
	m := hmac.New(sha256.New, v.secret)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

func singleHeader(h http.Header, name string) (string, error) {
	values := h.Values(name)
	if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
		return "", ErrMissingSignature
	}
	if len(values) > 1 {
		return "", ErrMalformedSignature
	}
	return strings.TrimSpace(values[0]), nil
}

func withinTolerance(ts int64, now time.Time, tolerance time.Duration) bool {
	delta := now.Unix() - ts
	if delta < 0 {
		delta = -delta
	}
	return delta <= int64(tolerance/time.Second)
}

func parseUnix(s string) (int64, bool) {
	if s == "" || len(s) > 12 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

func (v *Verifier) verifyStripe(h http.Header, body []byte, now time.Time) error {
	header, err := singleHeader(h, StripeSignatureHeader)
	if err != nil {
		return err
	}
	var timestamp string
	var candidates [][]byte
	for _, item := range strings.Split(header, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			return ErrMalformedSignature
		}
		switch key {
		case "t":
			if timestamp != "" {
				return ErrMalformedSignature
			}
			timestamp = value
		case "v1":
			decoded, err := hex.DecodeString(value)
			if err != nil || len(decoded) != sha256.Size {
				continue
			}
			candidates = append(candidates, decoded)
		}
	}
	ts, ok := parseUnix(timestamp)
	if !ok {
		return ErrMalformedSignature
	}
	if len(candidates) == 0 {
		return ErrMissingSignature
	}
	expected := v.mac([]byte(timestamp), []byte("."), body)
	match := 0
	for _, candidate := range candidates {
		match |= subtle.ConstantTimeCompare(expected, candidate)
	}
	if match != 1 {
		return ErrInvalidSignature
	}
	if !withinTolerance(ts, now, v.cfg.Tolerance) {
		return ErrTimestampOutOfRange
	}
	return nil
}

func (v *Verifier) verifyGitHub(h http.Header, body []byte) error {
	header, err := singleHeader(h, GitHubSignatureHeader)
	if err != nil {
		return err
	}
	encoded, ok := cutPrefixFold(header, "sha256=")
	if !ok {
		return ErrMalformedSignature
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != sha256.Size {
		return ErrMalformedSignature
	}
	if !hmac.Equal(v.mac(body), decoded) {
		return ErrInvalidSignature
	}
	return nil
}

func (v *Verifier) verifySlack(h http.Header, body []byte, now time.Time) error {
	signature, err := singleHeader(h, SlackSignatureHeader)
	if err != nil {
		return err
	}
	timestamp, err := singleHeader(h, SlackTimestampHeader)
	if err != nil {
		return err
	}
	ts, ok := parseUnix(timestamp)
	if !ok {
		return ErrMalformedSignature
	}
	encoded, ok := cutPrefixFold(signature, "v0=")
	if !ok {
		return ErrMalformedSignature
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != sha256.Size {
		return ErrMalformedSignature
	}
	if !hmac.Equal(v.mac([]byte("v0:"), []byte(timestamp), []byte(":"), body), decoded) {
		return ErrInvalidSignature
	}
	if !withinTolerance(ts, now, v.cfg.Tolerance) {
		return ErrTimestampOutOfRange
	}
	return nil
}

func (v *Verifier) verifyHMAC(h http.Header, body []byte) error {
	header, err := singleHeader(h, v.cfg.Header)
	if err != nil {
		return err
	}
	encoded := header
	if v.cfg.Prefix != "" {
		var ok bool
		encoded, ok = cutPrefixFold(header, v.cfg.Prefix)
		if !ok {
			return ErrMalformedSignature
		}
	}
	decoded, ok := decodeSignature(encoded, v.cfg.Encoding)
	if !ok || len(decoded) != sha256.Size {
		return ErrMalformedSignature
	}
	if !hmac.Equal(v.mac(body), decoded) {
		return ErrInvalidSignature
	}
	return nil
}

func decodeSignature(s, encoding string) ([]byte, bool) {
	if encoding == EncodingHex {
		decoded, err := hex.DecodeString(s)
		return decoded, err == nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if decoded, err := enc.DecodeString(s); err == nil {
			return decoded, true
		}
	}
	return nil, false
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return "", false
	}
	return s[len(prefix):], true
}

func (c Config) String() string {
	return "webhook(" + c.Provider + ", secret redacted)"
}

func (c Config) GoString() string {
	return c.String()
}
