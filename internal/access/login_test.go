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
