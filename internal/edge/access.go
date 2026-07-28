package edge

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	"ngstone/internal/proto"
)

const (
	maxAccessCreds   = 64
	maxAccessCIDRs   = 64
	maxRealmLen      = 256
	defaultAuthRealm = "ngstone"
)

type accessControl struct {
	basicDigests [][32]byte
	realm        string
	allow        []netip.Prefix
}

func buildAccessControl(bind proto.Bind) (*accessControl, error) {
	if len(bind.BasicAuthSHA256) == 0 && bind.BasicAuthRealm == "" && len(bind.AllowCIDRs) == 0 {
		return nil, nil
	}

	if len(bind.BasicAuthSHA256) > maxAccessCreds {
		return nil, fmt.Errorf("edge: too many basic auth credentials (max %d)", maxAccessCreds)
	}
	if len(bind.AllowCIDRs) > maxAccessCIDRs {
		return nil, fmt.Errorf("edge: too many allow_cidrs entries (max %d)", maxAccessCIDRs)
	}

	ac := &accessControl{}

	for _, s := range bind.BasicAuthSHA256 {
		raw, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("edge: invalid basic_auth_sha256 digest %q: %w", s, err)
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf("edge: invalid basic_auth_sha256 digest %q: must be 32 bytes", s)
		}
		var digest [32]byte
		copy(digest[:], raw)
		ac.basicDigests = append(ac.basicDigests, digest)
	}

	for _, c := range bind.AllowCIDRs {
		prefix, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("edge: invalid allow_cidrs entry %q: %w", c, err)
		}
		ac.allow = append(ac.allow, prefix)
	}

	ac.realm = truncateRealm(sanitizeRealm(bind.BasicAuthRealm), maxRealmLen)
	if ac.realm == "" {
		ac.realm = defaultAuthRealm
	}

	return ac, nil
}

func sanitizeRealm(realm string) string {
	var b strings.Builder
	for _, r := range realm {
		if r == '"' || r == '\\' || !unicode.IsPrint(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func truncateRealm(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	b := s[:maxBytes]
	for len(b) > 0 {
		r, size := utf8.DecodeLastRuneInString(b)
		if r != utf8.RuneError || size != 1 {
			break
		}
		b = b[:len(b)-1]
	}
	return b
}

func prefixesContain(ps []netip.Prefix, ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (ac *accessControl) allowIP(ip netip.Addr) bool {
	if ac == nil || len(ac.allow) == 0 {
		return true
	}
	return prefixesContain(ac.allow, ip)
}

func (ac *accessControl) checkBasicAuth(r *http.Request) bool {
	if ac == nil || len(ac.basicDigests) == 0 {
		return true
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	sum := sha256.Sum256([]byte(user + ":" + pass))
	var match int
	for _, d := range ac.basicDigests {
		match |= subtle.ConstantTimeCompare(sum[:], d[:])
	}
	return match == 1
}

func (ac *accessControl) hasBasicAuth() bool {
	return ac != nil && len(ac.basicDigests) > 0
}

func (ac *accessControl) authRealm() string {
	if ac == nil || ac.realm == "" {
		return defaultAuthRealm
	}
	return ac.realm
}

func (ac *accessControl) prefixes() []netip.Prefix {
	if ac == nil {
		return nil
	}
	return ac.allow
}
