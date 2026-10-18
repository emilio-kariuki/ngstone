package edge

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeScreenTURNURLs(t *testing.T) {
	urls, err := normalizeScreenTURNURLs([]string{
		"turn:turn.example.com:3478?transport=udp",
		"turns:turn.example.com:5349",
		"stun:stun.example.com:3478",
		"turn:turn.example.com:3478?transport=udp",
	}, "shared-secret")
	if err != nil {
		t.Fatalf("normalize TURN URLs: %v", err)
	}
	if len(urls) != 3 {
		t.Fatalf("normalized URLs = %v, want three unique URLs", urls)
	}
	if _, err := normalizeScreenTURNURLs([]string{"turn:turn.example.com:3478"}, ""); err == nil {
		t.Fatal("TURN URL without a shared secret was accepted")
	}
	if _, err := normalizeScreenTURNURLs([]string{"https://turn.example.com"}, "secret"); err == nil {
		t.Fatal("non-ICE URL was accepted")
	}
}

func TestScreenICEServersUseShortLivedScopedCredentials(t *testing.T) {
	expiresAt := time.Unix(1_900_000_000, 0).UTC()
	servers := screenICEServers([]string{
		"turn:turn.example.com:3478",
		"stun:stun.example.com:3478",
	}, "shared-secret", "session-id", expiresAt)
	if len(servers) != 2 {
		t.Fatalf("ICE servers = %+v", servers)
	}
	if servers[0].Username != "1900000000:session-id" || servers[0].Credential == "" {
		t.Fatalf("TURN credentials = %+v", servers[0])
	}
	if servers[1].Username != "" || servers[1].Credential != "" {
		t.Fatalf("STUN server unexpectedly received credentials = %+v", servers[1])
	}
	if strings.Contains(servers[0].Credential, "shared-secret") {
		t.Fatal("TURN credential exposed the shared secret")
	}
}

func TestScreenRegistrySupportsMultipleViewersInSFUMode(t *testing.T) {
	registry := newScreenRegistry()
	issued, err := registry.createWithOptions("owner", "demo", time.Minute, 3, func(id string) string {
		return "https://example.com/_ngstone/screen/" + id
	})
	if err != nil {
		t.Fatalf("create SFU screen session: %v", err)
	}
	sender := &screenPeer{}
	if _, _, err := registry.attach(issued.Session.ID, screenRoleSender, sender); err != nil {
		t.Fatalf("attach sender: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, _, err := registry.attach(issued.Session.ID, screenRoleViewer, &screenPeer{}); err != nil {
			t.Fatalf("attach viewer %d: %v", i, err)
		}
	}
	if registry.available(issued.Session.ID, screenRoleViewer) {
		t.Fatal("SFU registry reported a fourth viewer slot")
	}
	item, err := registry.get(issued.Session.ID, "owner", false)
	if err != nil {
		t.Fatalf("get SFU session: %v", err)
	}
	if !item.SFU || item.MaxViewers != 3 || item.ViewerCount != 3 || !item.ViewerConnected || item.Status != "active" {
		t.Fatalf("SFU session snapshot = %+v", item)
	}
}
