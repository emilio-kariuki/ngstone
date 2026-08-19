package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIssueValidateAndListNeverStorePlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	issued, err := store.IssueAt(Spec{Kind: KindHTTP, Subdomain: "Demo"}, 2*time.Hour, now)
	if err != nil {
		t.Fatalf("IssueAt: %v", err)
	}
	if issued.Token == "" || !strings.HasPrefix(issued.Token, "nst_") {
		t.Fatalf("token = %q, want an nst token", issued.Token)
	}
	if issued.Credential.Subdomain != "demo" {
		t.Fatalf("subdomain = %q, want demo", issued.Credential.Subdomain)
	}
	got, err := store.Validate(issued.Token, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.ID != issued.Credential.ID || !got.ExpiresAt.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("validated credential = %+v, want %+v", got, issued.Credential)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(data), issued.Token) {
		t.Fatalf("credential file contains the plaintext token")
	}
	if len(string(data)) < len(issued.Token) {
		t.Fatalf("credential file unexpectedly short")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("credential file mode = %o, want 600", info.Mode().Perm())
	}
	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].ID != issued.Credential.ID {
		t.Fatalf("List = %+v, want one credential %s", list, issued.Credential.ID)
	}
}

func TestCredentialExpiryAndIndependentRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	first, err := store.IssueAt(Spec{Subdomain: "one"}, time.Hour, now)
	if err != nil {
		t.Fatalf("first IssueAt: %v", err)
	}
	second, err := store.IssueAt(Spec{Subdomain: "two"}, time.Hour, now)
	if err != nil {
		t.Fatalf("second IssueAt: %v", err)
	}
	if err := store.RevokeAt(first.Credential.ID, now.Add(10*time.Minute)); err != nil {
		t.Fatalf("RevokeAt: %v", err)
	}
	if _, err := store.Validate(first.Token, now.Add(20*time.Minute)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked Validate error = %v, want ErrRevoked", err)
	}
	active, err := store.Active(first.Credential.ID, now.Add(20*time.Minute))
	if err != nil {
		t.Fatalf("Active revoked: %v", err)
	}
	if active {
		t.Fatalf("revoked credential is active")
	}
	if _, err := store.Validate(second.Token, now.Add(20*time.Minute)); err != nil {
		t.Fatalf("independent credential Validate: %v", err)
	}
	if _, err := store.Validate(second.Token, now.Add(2*time.Hour)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired Validate error = %v, want ErrExpired", err)
	}
}

func TestCredentialOwnerScoping(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	first, err := store.Issue(Spec{Subdomain: "one", OwnerID: "team-a"}, time.Hour)
	if err != nil {
		t.Fatalf("first Issue: %v", err)
	}
	second, err := store.Issue(Spec{Subdomain: "two", OwnerID: "team-b"}, time.Hour)
	if err != nil {
		t.Fatalf("second Issue: %v", err)
	}
	list, err := store.ListForOwner("team-a")
	if err != nil {
		t.Fatalf("ListForOwner: %v", err)
	}
	if len(list) != 1 || list[0].ID != first.Credential.ID {
		t.Fatalf("team-a credentials = %+v", list)
	}
	if err := store.RevokeForOwner(first.Credential.ID, "team-b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-owner revoke error = %v, want ErrNotFound", err)
	}
	if _, err := store.Validate(first.Token, time.Now()); err != nil {
		t.Fatalf("cross-owner revoke changed credential: %v", err)
	}
	if err := store.RevokeForOwner(first.Credential.ID, "team-a"); err != nil {
		t.Fatalf("owner revoke: %v", err)
	}
	if _, err := store.Validate(first.Token, time.Now()); !errors.Is(err, ErrRevoked) {
		t.Fatalf("owner-revoked credential error = %v, want ErrRevoked", err)
	}
	if _, err := store.Validate(second.Token, time.Now()); err != nil {
		t.Fatalf("other owner's credential error = %v", err)
	}
}

func TestCredentialScopeValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	cases := []struct {
		name string
		spec Spec
		want string
	}{
		{name: "http", spec: Spec{Kind: KindHTTP, Subdomain: "demo"}, want: ""},
		{name: "tcp", spec: Spec{Kind: KindTCP, RemotePort: 15432}, want: ""},
		{name: "missing subdomain", spec: Spec{Kind: KindHTTP}, want: "a valid HTTP subdomain is required"},
		{name: "bad subdomain", spec: Spec{Kind: KindHTTP, Subdomain: "www"}, want: "a valid HTTP subdomain is required"},
		{name: "tcp port missing", spec: Spec{Kind: KindTCP}, want: "TCP credentials require a remote port"},
		{name: "unknown kind", spec: Spec{Kind: "udp", Subdomain: "demo"}, want: "kind must be"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.IssueAt(tc.spec, time.Hour, time.Now())
			if tc.want == "" {
				if err != nil {
					t.Fatalf("IssueAt: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("IssueAt error = %v, want substring %q", err, tc.want)
			}
		})
	}
	if !ValidateSubdomain("demo-1") || ValidateSubdomain("Demo") || ValidateSubdomain("api-edge") {
		t.Fatalf("ValidateSubdomain did not enforce the edge naming rules")
	}
}

func TestConcurrentIssueDoesNotLoseCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	const n = 8
	tokens := make(chan string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			local, err := Open(path)
			if err != nil {
				t.Errorf("Open %d: %v", i, err)
				return
			}
			issued, err := local.Issue(Spec{Subdomain: "demo-" + string(rune('a'+i))}, time.Hour)
			if err != nil {
				t.Errorf("Issue %d: %v", i, err)
				return
			}
			tokens <- issued.Token
		}(i)
	}
	wg.Wait()
	close(tokens)
	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != n {
		t.Fatalf("List returned %d credentials, want %d", len(list), n)
	}
	for token := range tokens {
		if _, err := store.Validate(token, time.Now()); err != nil {
			t.Fatalf("Validate concurrent token: %v", err)
		}
	}
}

func TestOpenRejectsInsecureFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"credentials":[]}`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "must not be group or world readable") {
		t.Fatalf("Open error = %v, want insecure-mode error", err)
	}
}
