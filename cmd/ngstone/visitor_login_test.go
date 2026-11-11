package main

import (
	"slices"
	"testing"
)

func TestParseOIDCLogin(t *testing.T) {
	login, err := parseOIDCLogin(false, nil, nil)
	if err != nil || login != nil {
		t.Fatalf("disabled = %+v, %v", login, err)
	}
	if _, err := parseOIDCLogin(false, []string{"a@example.org"}, nil); err == nil {
		t.Fatal("allow list without --oidc must be rejected")
	}
	login, err = parseOIDCLogin(true, nil, nil)
	if err != nil || login == nil || len(login.AllowEmails) != 0 || len(login.AllowDomains) != 0 {
		t.Fatalf("open login = %+v, %v", login, err)
	}
	login, err = parseOIDCLogin(true, []string{"B@example.org, a@example.org", "a@example.org"}, []string{"Corp.Example"})
	if err != nil {
		t.Fatalf("parseOIDCLogin: %v", err)
	}
	if !slices.Equal(login.AllowEmails, []string{"a@example.org", "b@example.org"}) || !slices.Equal(login.AllowDomains, []string{"corp.example"}) {
		t.Fatalf("login = %+v", login)
	}
	if _, err := parseOIDCLogin(true, []string{"nope"}, nil); err == nil {
		t.Fatal("invalid email must be rejected")
	}
}
