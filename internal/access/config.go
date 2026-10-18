package access

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxCredentials = 64
	MaxCIDRs       = 64
	MaxRealmBytes  = 256
	DefaultRealm   = "ngstone"
)

type Config struct {
	BasicAuthSHA256 []string `json:"basic_auth_sha256,omitempty"`
	BasicAuthRealm  string   `json:"basic_auth_realm,omitempty"`
	AllowCIDRs      []string `json:"allow_cidrs,omitempty"`
}

func Normalize(c Config) (Config, error) {
	if len(c.BasicAuthSHA256) > MaxCredentials || len(c.AllowCIDRs) > MaxCIDRs {
		return Config{}, fmt.Errorf("access: at most %d credentials and %d CIDRs are allowed", MaxCredentials, MaxCIDRs)
	}
	c.BasicAuthSHA256 = slices.Clone(c.BasicAuthSHA256)
	c.AllowCIDRs = slices.Clone(c.AllowCIDRs)
	for i, digest := range c.BasicAuthSHA256 {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 {
			return Config{}, fmt.Errorf("access: invalid basic_auth_sha256 digest")
		}
		c.BasicAuthSHA256[i] = hex.EncodeToString(decoded)
	}
	for i, cidr := range c.AllowCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return Config{}, fmt.Errorf("access: invalid allow_cidrs entry %q: %w", cidr, err)
		}
		c.AllowCIDRs[i] = prefix.Masked().String()
	}
	slices.Sort(c.BasicAuthSHA256)
	slices.Sort(c.AllowCIDRs)
	if len(c.BasicAuthSHA256) == 0 && len(c.AllowCIDRs) == 0 && c.BasicAuthRealm == "" {
		return Config{}, nil
	}
	var realm strings.Builder
	for _, r := range c.BasicAuthRealm {
		if r != '"' && r != '\\' && unicode.IsPrint(r) {
			realm.WriteRune(r)
		}
	}
	c.BasicAuthRealm = realm.String()
	if len(c.BasicAuthRealm) > MaxRealmBytes {
		c.BasicAuthRealm = c.BasicAuthRealm[:MaxRealmBytes]
		for !utf8.ValidString(c.BasicAuthRealm) {
			c.BasicAuthRealm = c.BasicAuthRealm[:len(c.BasicAuthRealm)-1]
		}
	}
	if c.BasicAuthRealm == "" {
		c.BasicAuthRealm = DefaultRealm
	}
	return c, nil
}

func CanonicalJSON(raw string) (string, error) {
	var c Config
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return "", fmt.Errorf("access: invalid configuration JSON: %w", err)
	}
	c, err := Normalize(c)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(c)
	return string(data), err
}

func CanonicalCIDRsJSON(raw string) (string, error) {
	var cidrs []string
	if err := json.Unmarshal([]byte(raw), &cidrs); err != nil {
		return "", fmt.Errorf("access: invalid CIDR JSON: %w", err)
	}
	c, err := Normalize(Config{AllowCIDRs: cidrs})
	if err != nil {
		return "", err
	}
	if c.AllowCIDRs == nil {
		c.AllowCIDRs = []string{}
	}
	data, err := json.Marshal(c.AllowCIDRs)
	return string(data), err
}
