package edge

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"unicode/utf8"

	"ngstone/internal/proto"
)

func digestFor(user, pass string) string {
	sum := sha256.Sum256([]byte(user + ":" + pass))
	return hex.EncodeToString(sum[:])
}

func TestBuildAccessControlEmptyBind(t *testing.T) {
	ac, err := buildAccessControl(proto.Bind{})
	if err != nil {
		t.Fatalf("buildAccessControl: %v", err)
	}
	if ac != nil {
		t.Fatalf("got %+v, want nil accessControl for an open tunnel", ac)
	}
}

func TestBuildAccessControlInvalidDigestHex(t *testing.T) {
	if _, err := buildAccessControl(proto.Bind{BasicAuthSHA256: []string{"not-hex-zz"}}); err == nil {
		t.Fatal("expected error for non-hex digest")
	}
}

func TestBuildAccessControlDigestWrongLength(t *testing.T) {
	raw := make([]byte, 16)
	if _, err := buildAccessControl(proto.Bind{BasicAuthSHA256: []string{hex.EncodeToString(raw)}}); err == nil {
		t.Fatal("expected error for wrong-length digest")
	}
}

func TestBuildAccessControlMalformedCIDR(t *testing.T) {
	for _, c := range []string{"10.0.0.0/33", "notacidr"} {
		if _, err := buildAccessControl(proto.Bind{AllowCIDRs: []string{c}}); err == nil {
			t.Fatalf("expected error for malformed CIDR %q", c)
		}
	}
}

func TestBuildAccessControlTooManyCreds(t *testing.T) {
	digests := make([]string, maxAccessCreds+1)
	for i := range digests {
		digests[i] = digestFor("u", "p")
	}
	if _, err := buildAccessControl(proto.Bind{BasicAuthSHA256: digests}); err == nil {
		t.Fatal("expected error for too many basic auth credentials")
	}
}

func TestBuildAccessControlTooManyCIDRs(t *testing.T) {
	cidrs := make([]string, maxAccessCIDRs+1)
	for i := range cidrs {
		cidrs[i] = "10.0.0.0/8"
	}
	if _, err := buildAccessControl(proto.Bind{AllowCIDRs: cidrs}); err == nil {
		t.Fatal("expected error for too many allow_cidrs entries")
	}
}

func TestBuildAccessControlRealmDefault(t *testing.T) {
	ac, err := buildAccessControl(proto.Bind{BasicAuthSHA256: []string{digestFor("u", "p")}})
	if err != nil {
		t.Fatalf("buildAccessControl: %v", err)
	}
	if ac.realm != defaultAuthRealm {
		t.Fatalf("realm = %q, want %q", ac.realm, defaultAuthRealm)
	}
}

func TestBuildAccessControlRealmSanitization(t *testing.T) {
	ac, err := buildAccessControl(proto.Bind{
		BasicAuthSHA256: []string{digestFor("u", "p")},
		BasicAuthRealm:  "he\"llo\\wor\x00ld",
	})
	if err != nil {
		t.Fatalf("buildAccessControl: %v", err)
	}
	if ac.realm != "helloworld" {
		t.Fatalf("realm = %q, want %q", ac.realm, "helloworld")
	}
}

func TestAllowIPNilReceiver(t *testing.T) {
	var ac *accessControl
	if !ac.allowIP(netip.MustParseAddr("1.2.3.4")) {
		t.Fatal("nil accessControl should allow all IPs")
	}
}

func TestAllowIPEmptyAllowList(t *testing.T) {
	ac := &accessControl{}
	if !ac.allowIP(netip.MustParseAddr("1.2.3.4")) {
		t.Fatal("empty allow list should allow all IPs")
	}
}

func TestAllowIPv4InRange(t *testing.T) {
	ac := &accessControl{allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	if !ac.allowIP(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("expected 10.1.2.3 to be allowed by 10.0.0.0/8")
	}
}

func TestAllowIPv4OutOfRange(t *testing.T) {
	ac := &accessControl{allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	if ac.allowIP(netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("expected 192.168.1.1 to be rejected by 10.0.0.0/8")
	}
}

func TestAllowIPv6InRange(t *testing.T) {
	ac := &accessControl{allow: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}}
	if !ac.allowIP(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("expected 2001:db8::1 to be allowed by 2001:db8::/32")
	}
}

func TestAllowIPMappedV4InV6ClientAddr(t *testing.T) {
	ac := &accessControl{allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	mapped := netip.MustParseAddr("::ffff:10.1.2.3")
	if !ac.allowIP(mapped) {
		t.Fatal("expected 4-in-6 mapped address to match v4 prefix via Unmap")
	}
}

func TestAllowIPv4NotMatchUnrelatedV6Prefix(t *testing.T) {
	ac := &accessControl{allow: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}}
	if ac.allowIP(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("expected v4 addr to not match unrelated v6 prefix")
	}
}

func TestCheckBasicAuthNilReceiver(t *testing.T) {
	var ac *accessControl
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if !ac.checkBasicAuth(req) {
		t.Fatal("nil accessControl should allow all requests")
	}
}

func TestCheckBasicAuthNoDigests(t *testing.T) {
	ac := &accessControl{}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if !ac.checkBasicAuth(req) {
		t.Fatal("accessControl with no digests should allow all requests")
	}
}

func TestCheckBasicAuthMissingHeader(t *testing.T) {
	digest := sha256.Sum256([]byte("user:pass"))
	ac := &accessControl{basicDigests: [][32]byte{digest}}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if ac.checkBasicAuth(req) {
		t.Fatal("expected request without Authorization header to be rejected")
	}
}

func TestCheckBasicAuthWrongUser(t *testing.T) {
	digest := sha256.Sum256([]byte("user:pass"))
	ac := &accessControl{basicDigests: [][32]byte{digest}}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.SetBasicAuth("wronguser", "pass")
	if ac.checkBasicAuth(req) {
		t.Fatal("expected wrong user to be rejected")
	}
}

func TestCheckBasicAuthWrongPass(t *testing.T) {
	digest := sha256.Sum256([]byte("user:pass"))
	ac := &accessControl{basicDigests: [][32]byte{digest}}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.SetBasicAuth("user", "wrongpass")
	if ac.checkBasicAuth(req) {
		t.Fatal("expected wrong pass to be rejected")
	}
}

func TestCheckBasicAuthCorrect(t *testing.T) {
	digest := sha256.Sum256([]byte("user:pass"))
	ac := &accessControl{basicDigests: [][32]byte{digest}}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.SetBasicAuth("user", "pass")
	if !ac.checkBasicAuth(req) {
		t.Fatal("expected correct credentials to be accepted")
	}
}

func TestCheckBasicAuthMultiCredential(t *testing.T) {
	creds := [][2]string{
		{"alice", "a-pass"},
		{"bob", "b-pass"},
		{"carol", "c-pass"},
	}
	ac := &accessControl{}
	for _, c := range creds {
		ac.basicDigests = append(ac.basicDigests, sha256.Sum256([]byte(c[0]+":"+c[1])))
	}

	for _, c := range creds {
		req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.SetBasicAuth(c[0], c[1])
		if !ac.checkBasicAuth(req) {
			t.Fatalf("expected credential %s to be accepted", c[0])
		}
	}

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.SetBasicAuth("dave", "wrong")
	if ac.checkBasicAuth(req) {
		t.Fatal("expected an unknown 4th credential to be rejected")
	}
}

func TestTruncateRealmASCIIOverCap(t *testing.T) {
	realm := strings.Repeat("a", 500)
	got := truncateRealm(realm, maxRealmLen)
	if len(got) != maxRealmLen {
		t.Fatalf("truncateRealm ascii len = %d, want %d", len(got), maxRealmLen)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("truncateRealm ascii result is not valid UTF-8: %q", got)
	}
}

func TestTruncateRealmMultiByteRunesStaysValidUTF8(t *testing.T) {
	realm := strings.Repeat("é", 200)
	got := truncateRealm(realm, maxRealmLen)
	if len(got) > maxRealmLen {
		t.Fatalf("truncateRealm multi-byte len = %d, want <= %d", len(got), maxRealmLen)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("truncateRealm multi-byte result is not valid UTF-8 (likely a partial rune): %q", got)
	}
}

func TestTruncateRealmEmojiStaysValidUTF8(t *testing.T) {
	realm := strings.Repeat("😀", 200)
	got := truncateRealm(realm, maxRealmLen)
	if len(got) > maxRealmLen {
		t.Fatalf("truncateRealm emoji len = %d, want <= %d", len(got), maxRealmLen)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("truncateRealm emoji result is not valid UTF-8 (likely a partial rune): %q", got)
	}
}

func TestHasBasicAuthNilReceiver(t *testing.T) {
	var ac *accessControl
	if ac.hasBasicAuth() {
		t.Fatal("nil accessControl should report hasBasicAuth = false")
	}
}

func TestHasBasicAuthOnlyCIDRs(t *testing.T) {
	ac := &accessControl{allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	if ac.hasBasicAuth() {
		t.Fatal("accessControl with only CIDRs should report hasBasicAuth = false")
	}
}

func TestHasBasicAuthWithDigests(t *testing.T) {
	ac := &accessControl{basicDigests: [][32]byte{sha256.Sum256([]byte("user:pass"))}}
	if !ac.hasBasicAuth() {
		t.Fatal("accessControl with digests should report hasBasicAuth = true")
	}
}
