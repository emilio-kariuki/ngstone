package edge

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"slices"

	"ngstone/internal/access"
	"ngstone/internal/proto"
)

const (
	maxAccessCreds   = access.MaxCredentials
	maxAccessCIDRs   = access.MaxCIDRs
	maxRealmLen      = access.MaxRealmBytes
	defaultAuthRealm = access.DefaultRealm
)

type accessControl struct {
	basicDigests [][32]byte
	realm        string
	allow        []netip.Prefix
	login        *visitorLoginRule
}

type visitorLoginRule struct {
	emails  []string
	domains []string
}

func buildAccessControl(bind proto.Bind) (*accessControl, error) {
	if len(bind.BasicAuthSHA256) == 0 && bind.BasicAuthRealm == "" && len(bind.AllowCIDRs) == 0 && bind.OIDC == nil {
		return nil, nil
	}

	canonical, err := access.Normalize(access.Config{BasicAuthSHA256: bind.BasicAuthSHA256, BasicAuthRealm: bind.BasicAuthRealm, AllowCIDRs: bind.AllowCIDRs})
	if err != nil {
		return nil, err
	}
	ac := &accessControl{realm: canonical.BasicAuthRealm}
	for _, encoded := range canonical.BasicAuthSHA256 {
		raw, err := hex.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("edge: decode access digest: %w", err)
		}
		ac.basicDigests = append(ac.basicDigests, [32]byte(raw))
	}
	for _, cidr := range canonical.AllowCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("edge: decode access CIDR: %w", err)
		}
		ac.allow = append(ac.allow, prefix)
	}
	if bind.OIDC != nil {
		emails, domains, err := access.NormalizeLogin(bind.OIDC.AllowEmails, bind.OIDC.AllowDomains)
		if err != nil {
			return nil, err
		}
		ac.login = &visitorLoginRule{emails: emails, domains: domains}
	}
	return ac, nil
}

func (ac *accessControl) loginRule() *visitorLoginRule {
	if ac == nil {
		return nil
	}
	return ac.login
}

func (rule *visitorLoginRule) allows(email string, verified bool) bool {
	return rule != nil && access.LoginAllows(rule.emails, rule.domains, email, verified)
}

func visitorLoginRuleEqual(a, b *visitorLoginRule) bool {
	if a == nil || b == nil {
		return a == b
	}
	return slices.Equal(a.emails, b.emails) && slices.Equal(a.domains, b.domains)
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
