package access

import (
	"slices"
	"testing"
)

func TestNormalizeLoginCanonicalizesAndRejectsInvalidEntries(t *testing.T) {
	emails, domains, err := NormalizeLogin([]string{" Bob@Example.org ", "bob@example.org", "amy@x.io"}, []string{"@Corp.Example", "corp.example"})
	if err != nil {
		t.Fatalf("NormalizeLogin: %v", err)
	}
	if !slices.Equal(emails, []string{"amy@x.io", "bob@example.org"}) || !slices.Equal(domains, []string{"corp.example"}) {
		t.Fatalf("emails=%v domains=%v", emails, domains)
	}
	for _, bad := range [][2][]string{
		{{"no-at"}, nil},
		{{"@example.org"}, nil},
		{{"a@b@c"}, nil},
		{{"a b@example.org"}, nil},
		{nil, {"exa mple.org"}},
		{nil, {".example.org"}},
		{nil, {""}},
	} {
		if _, _, err := NormalizeLogin(bad[0], bad[1]); err == nil {
			t.Errorf("NormalizeLogin(%q, %q) succeeded", bad[0], bad[1])
		}
	}
	tooMany := make([]string, MaxLoginEmails+1)
	for i := range tooMany {
		tooMany[i] = "a@example.org"
	}
	if _, _, err := NormalizeLogin(tooMany, nil); err == nil {
		t.Fatal("NormalizeLogin accepted too many emails")
	}
}

func TestLoginAllows(t *testing.T) {
	emails := []string{"bob@example.org"}
	domains := []string{"corp.example"}
	cases := []struct {
		email    string
		verified bool
		want     bool
	}{
		{"bob@example.org", true, true},
		{"BOB@example.org", true, true},
		{"amy@corp.example", true, true},
		{"amy@sub.corp.example", true, false},
		{"amy@corp.example.evil", true, false},
		{"bob@example.org", false, false},
		{"", true, false},
	}
	for _, tc := range cases {
		if got := LoginAllows(emails, domains, tc.email, tc.verified); got != tc.want {
			t.Errorf("LoginAllows(%q, %v) = %v, want %v", tc.email, tc.verified, got, tc.want)
		}
	}
	if !LoginAllows(nil, nil, "", false) {
		t.Fatal("an empty allow list must accept any authenticated visitor")
	}
}

func TestLoginAllowsRejectsNonASCIIEmails(t *testing.T) {
	cases := []struct {
		name    string
		emails  []string
		domains []string
		email   string
	}{
		{"dotted capital I folds to i in the domain", nil, []string{"gmail.com"}, "x@gmaİl.com"},
		{"kelvin sign folds to k in the local part", []string{"kim@example.org"}, nil, "Kim@example.org"},
		{"non-ASCII email with an empty rule", nil, nil, "Kim@example.org"},
	}
	for _, tc := range cases {
		if LoginAllows(tc.emails, tc.domains, tc.email, true) {
			t.Errorf("%s: LoginAllows(%q) = true, want false", tc.name, tc.email)
		}
	}
	if !LoginAllows([]string{"kim@example.org"}, nil, "Kim@example.org", true) {
		t.Error("ASCII mixed-case email must still match")
	}
}
