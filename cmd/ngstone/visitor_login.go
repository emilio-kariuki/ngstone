package main

import (
	"fmt"
	"strings"

	"ngstone/internal/access"
	"ngstone/internal/proto"
)

func parseOIDCLogin(enabled bool, emails, domains []string) (*proto.OIDCLogin, error) {
	splitEmails := splitLoginList(emails)
	splitDomains := splitLoginList(domains)
	if !enabled {
		if len(splitEmails) > 0 || len(splitDomains) > 0 {
			return nil, fmt.Errorf("--oidc-allow-email and --oidc-allow-domain require --oidc")
		}
		return nil, nil
	}
	normalizedEmails, normalizedDomains, err := access.NormalizeLogin(splitEmails, splitDomains)
	if err != nil {
		return nil, fmt.Errorf("invalid OIDC visitor login: %w", err)
	}
	login := &proto.OIDCLogin{}
	if len(normalizedEmails) > 0 {
		login.AllowEmails = normalizedEmails
	}
	if len(normalizedDomains) > 0 {
		login.AllowDomains = normalizedDomains
	}
	return login, nil
}

func splitLoginList(values []string) []string {
	var out []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}
