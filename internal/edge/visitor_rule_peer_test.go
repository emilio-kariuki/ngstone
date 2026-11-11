package edge

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"ngstone/internal/storage"
)

func leaseRemoteTunnel(t *testing.T, e *peerEdge, host, kind, accessJSON string) {
	t.Helper()
	_, err := e.store.AcquireLease(context.Background(), storage.LeaseRequest{
		Hostname:   host,
		Kind:       kind,
		EdgeID:     e.id,
		OwnerID:    "owner",
		InstanceID: "inst-" + e.id,
		SessionID:  "sess-" + e.id + "-" + host,
		AccessJSON: accessJSON,
		ExpiresAt:  time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("acquire lease %s on %s: %v", host, e.id, err)
	}
}

func TestVisitorRuleForHostFallsBackToStorage(t *testing.T) {
	const host = "app.example.com"
	cases := []struct {
		name      string
		kind      string
		access    string
		seed      bool
		expirePee bool
		noPeers   bool
		closeDB   bool
		corrupt   bool
		wantFound bool
		wantRule  bool
		check     func(t *testing.T, rule *visitorLoginRule)
	}{
		{name: "rule allowing a domain", kind: "http", access: `{"visitor_login":{"allow_domains":["corp.example"]}}`, seed: true, wantFound: true, wantRule: true, check: func(t *testing.T, rule *visitorLoginRule) {
			if !rule.allows("a@corp.example", true) {
				t.Fatal("rule rejects a@corp.example")
			}
			if rule.allows("a@evil.example", true) {
				t.Fatal("rule allows a@evil.example")
			}
		}},
		{name: "wall without lists", kind: "http", access: `{"visitor_login":{}}`, seed: true, wantFound: true, wantRule: true, check: func(t *testing.T, rule *visitorLoginRule) {
			if !rule.allows("anyone@anywhere.example", true) {
				t.Fatal("rule without lists rejects a verified email")
			}
		}},
		{name: "no wall", kind: "http", access: `{}`, seed: true, wantFound: true},
		{name: "no live lease", kind: "http", access: `{"visitor_login":{}}`},
		{name: "expired peer row", kind: "http", access: `{"visitor_login":{}}`, seed: true, expirePee: true},
		{name: "tls tunnel", kind: "tls", access: `{"visitor_login":{}}`, seed: true},
		{name: "peers disabled", kind: "http", access: `{"visitor_login":{}}`, seed: true, noPeers: true},
		{name: "storage lookup error", kind: "http", access: `{"visitor_login":{}}`, seed: true, closeDB: true},
		{name: "corrupt access json", kind: "http", access: `{"visitor_login":{}}`, seed: true, corrupt: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc := newPeerCluster(t)
			a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
			registerPeers(t, a, b)
			if tc.seed {
				leaseRemoteTunnel(t, b, host, tc.kind, tc.access)
			}
			if tc.expirePee {
				peer := b.record()
				peer.ExpiresAt = time.Now().Add(-time.Minute)
				if err := b.store.UpsertEdgePeer(context.Background(), peer); err != nil {
					t.Fatalf("expire peer: %v", err)
				}
			}
			if tc.noPeers {
				a.srv.peers = nil
			}
			if tc.corrupt {
				db, err := sql.Open("sqlite", "file:"+pc.dsn+"?_pragma=busy_timeout(5000)")
				if err != nil {
					t.Fatalf("open database: %v", err)
				}
				defer db.Close()
				if _, err := db.Exec(`UPDATE tunnels SET access_json = $1 WHERE hostname = $2`, "{not json", host); err != nil {
					t.Fatalf("corrupt access_json: %v", err)
				}
			}
			if tc.closeDB {
				a.store.Close()
			}
			lookups := metricDelta(metricPeerApexRuleLookups)
			logs := &lockedBuffer{}
			prevLogger := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
			defer slog.SetDefault(prevLogger)
			rule, found := a.srv.visitorRuleForHost(context.Background(), host)
			if logged := strings.Contains(logs.String(), "lookup host access"); logged != tc.closeDB {
				t.Fatalf("storage error logged = %v, want %v; logs: %s", logged, tc.closeDB, logs.String())
			}
			if found != tc.wantFound || (rule != nil) != tc.wantRule {
				t.Fatalf("visitorRuleForHost = %+v, %v; want rule=%v found=%v", rule, found, tc.wantRule, tc.wantFound)
			}
			if tc.check != nil {
				tc.check(t, rule)
			}
			wantLookups := int64(0)
			if tc.wantRule {
				wantLookups = 1
			}
			if got := lookups(); got != wantLookups {
				t.Fatalf("apex rule lookups = %d, want %d", got, wantLookups)
			}
		})
	}
}

func TestVisitorCallbackMintsTicketForTunnelLeasedOnAnotherEdge(t *testing.T) {
	const host = "app.example.com"
	idp := newFakeVisitorIdP(t)
	pc := newPeerCluster(t)
	a, b := pc.edge(t, "edge-a"), pc.edge(t, "edge-b")
	registerPeers(t, a, b)
	leaseRemoteTunnel(t, b, host, "http", `{"visitor_login":{"allow_domains":["example.org"]}}`)

	s := newVisitorTestServer(t, idp)
	s.storage = a.store
	s.cfg.PeerAddr = a.srv.cfg.PeerAddr
	s.peers = a.srv.peers

	for _, tc := range []struct {
		email string
		code  int
	}{
		{"alice@example.org", http.StatusFound},
		{"mallory@evil.example", http.StatusForbidden},
	} {
		idp.setUser(tc.email, true)
		sealed, err := s.visitor.codec.Encode(visitorToken{Purpose: visitorPurposeReturn, Host: host, Path: "/", Binding: "bind", ExpiresAt: time.Now().Add(time.Minute)})
		if err != nil {
			t.Fatalf("seal return: %v", err)
		}
		startURL := "http://example.com" + visitorStartPath + "?" + url.Values{"return": {sealed}}.Encode()
		start := visitorRequest(t, s, http.MethodGet, startURL, htmlAccept())
		if start.Code != http.StatusFound {
			t.Fatalf("start status = %d, body=%s", start.Code, start.Body.String())
		}
		var stateCookie *http.Cookie
		for _, cookie := range start.Result().Cookies() {
			if strings.HasPrefix(strings.TrimPrefix(cookie.Name, visitorCookieHostPrefix), visitorStateCookiePrefix) {
				stateCookie = cookie
			}
		}
		authorize, err := http.NewRequest(http.MethodGet, start.Header().Get("Location"), nil)
		if err != nil {
			t.Fatalf("authorize request: %v", err)
		}
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Do(authorize)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		resp.Body.Close()
		callback := visitorRequest(t, s, http.MethodGet, resp.Header.Get("Location"), htmlAccept(), stateCookie)
		if callback.Code != tc.code {
			t.Fatalf("%s: callback status = %d, want %d; body=%s", tc.email, callback.Code, tc.code, callback.Body.String())
		}
		if tc.code == http.StatusFound {
			finish, err := url.Parse(callback.Header().Get("Location"))
			if err != nil || finish.Host != host || finish.Path != visitorFinishPath || finish.Query().Get("ticket") == "" {
				t.Fatalf("finish redirect = %q", callback.Header().Get("Location"))
			}
		} else if !strings.Contains(callback.Body.String(), "Access denied") {
			t.Fatalf("body = %q, want the access-denied page", callback.Body.String())
		}
	}
}
