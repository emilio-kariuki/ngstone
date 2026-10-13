package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"ngstone/internal/proto"
)

func TestShareSecretAndLinkRoundTrip(t *testing.T) {
	secret, hash, err := NewShareSecret()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(secret))
	if hex.EncodeToString(sum[:]) != hash {
		t.Fatalf("hash does not match the secret the link carries")
	}
	if strings.ContainsAny(secret, "+/=") {
		t.Fatalf("secret %q is not base64url without padding", secret)
	}

	link := ShareLink("example.com:4443", secret)
	if !strings.HasPrefix(link, "ngstone://example.com:4443/s/") {
		t.Fatalf("link = %q", link)
	}
	addr, got, err := ParseShareLink(link)
	if err != nil {
		t.Fatalf("ParseShareLink: %v", err)
	}
	if addr != "example.com:4443" || got != secret {
		t.Fatalf("parsed (%q, %q), want (example.com:4443, %q)", addr, got, secret)
	}

	another, _, _ := NewShareSecret()
	if another == secret {
		t.Fatalf("two minted secrets are equal")
	}
}

func TestParseShareLinkRejectsMalformed(t *testing.T) {
	secret, _, _ := NewShareSecret()
	bad := []string{
		"",
		"https://example.com:4443/s/" + secret,
		"ngstone://example.com/s/" + secret,
		"ngstone:///s/" + secret,
		"ngstone://example.com:4443/" + secret,
		"ngstone://example.com:4443/s/",
		"ngstone://example.com:4443/s/short",
		"ngstone://example.com:4443/s/" + secret + "/extra",
		"ngstone://example.com:4443/s/" + strings.Repeat("!", 43),
	}
	for _, l := range bad {
		if _, _, err := ParseShareLink(l); err == nil {
			t.Errorf("ParseShareLink(%q) accepted a malformed link", l)
		}
	}
	if _, got, err := ParseShareLink("  ngstone://example.com:4443/s/" + secret + "\n"); err != nil || got != secret {
		t.Fatalf("surrounding whitespace should be tolerated: %v", err)
	}
}

func TestPresetPort(t *testing.T) {
	if PresetPort("postgres") != 5432 || PresetPort("mysql") != 3306 || PresetPort("redis") != 6379 || PresetPort("tcp") != 0 {
		t.Fatalf("preset ports wrong")
	}
}

func TestFormatShareEvent(t *testing.T) {
	at := time.Date(2026, 1, 2, 14, 5, 11, 0, time.Local).UnixMilli()
	cases := []struct {
		ev   proto.ShareEvent
		want []string
	}{
		{proto.ShareEvent{Event: proto.ShareEventConnectorJoined, AtMS: at, ConnectorID: "c1", ClientAddr: "203.0.113.9:1234"}, []string{"14:05:11", "connector joined", "203.0.113.9", "c1"}},
		{proto.ShareEvent{Event: proto.ShareEventConnOpen, AtMS: at, ConnectorID: "c1", ConnID: 3, ClientAddr: "203.0.113.9:1234"}, []string{"conn #3", "open", "via c1"}},
		{proto.ShareEvent{Event: proto.ShareEventConnClose, AtMS: at, ConnID: 3, DurationMS: 247_000, BytesUp: 12 << 20, BytesDown: 512}, []string{"conn #3", "closed", "4m07s", "12.0 MiB up", "512 B down"}},
		{proto.ShareEvent{Event: proto.ShareEventConnRejected, AtMS: at, ClientAddr: "198.51.100.1:5", Reason: "max_conns"}, []string{"rejected", "198.51.100.1", "max_conns"}},
		{proto.ShareEvent{Event: proto.ShareEventClosed, AtMS: at, Reason: "expired"}, []string{"share closed", "expired"}},
	}
	for _, tc := range cases {
		line := FormatShareEvent(tc.ev)
		for _, w := range tc.want {
			if !strings.Contains(line, w) {
				t.Errorf("%s: line %q lacks %q", tc.ev.Event, line, w)
			}
		}
	}
}
