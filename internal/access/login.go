package access

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	MaxLoginEmails  = 64
	MaxLoginDomains = 64
	maxLoginEntry   = 254
)

func NormalizeLogin(emails, domains []string) ([]string, []string, error) {
	if len(emails) > MaxLoginEmails || len(domains) > MaxLoginDomains {
		return nil, nil, fmt.Errorf("access: at most %d allowed emails and %d allowed domains are permitted", MaxLoginEmails, MaxLoginDomains)
	}
	outEmails := make([]string, 0, len(emails))
	for _, raw := range emails {
		email := strings.ToLower(strings.TrimSpace(raw))
		local, domain, ok := strings.Cut(email, "@")
		if !ok || local == "" || !validLoginDomain(domain) || len(email) > maxLoginEntry || strings.ContainsAny(local, " \t\r\n\"<>,;") {
			return nil, nil, fmt.Errorf("access: invalid allowed email %q", raw)
		}
		outEmails = append(outEmails, email)
	}
	outDomains := make([]string, 0, len(domains))
	for _, raw := range domains {
		domain := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "@")
		if !validLoginDomain(domain) {
			return nil, nil, fmt.Errorf("access: invalid allowed email domain %q", raw)
		}
		outDomains = append(outDomains, domain)
	}
	slices.Sort(outEmails)
	slices.Sort(outDomains)
	return slices.Compact(outEmails), slices.Compact(outDomains), nil
}

func LoginAllows(emails, domains []string, email string, verified bool) bool {
	for i := 0; i < len(email); i++ {
		if email[i] >= utf8.RuneSelf {
			return false
		}
	}
	if len(emails) == 0 && len(domains) == 0 {
		return true
	}
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndexByte(email, '@')
	if !verified || at <= 0 || at == len(email)-1 {
		return false
	}
	if slices.Contains(emails, email) {
		return true
	}
	return slices.Contains(domains, email[at+1:])
}

func validLoginDomain(domain string) bool {
	if domain == "" || len(domain) > maxLoginEntry || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return false
	}
	for _, r := range domain {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}
