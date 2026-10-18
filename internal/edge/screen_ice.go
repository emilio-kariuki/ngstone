package edge

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	defaultScreenMaxViewers = 8
	maxScreenTURNURLs       = 16
	DefaultScreenMaxViewers = defaultScreenMaxViewers
)

type screenICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

type screenSignalConfig struct {
	ICEServers []screenICEServer `json:"ice_servers"`
	Mode       string            `json:"mode"`
	MaxViewers int               `json:"max_viewers"`
}

func normalizeScreenTURNURLs(raw []string, sharedSecret string) ([]string, error) {
	if len(raw) > maxScreenTURNURLs {
		return nil, fmt.Errorf("screen TURN URL count must not exceed %d", maxScreenTURNURLs)
	}
	urls := make([]string, 0, len(raw))
	hasTURN := false
	seen := make(map[string]struct{}, len(raw))
	for _, value := range raw {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.ContainsAny(value, "\r\n\t ") {
			return nil, fmt.Errorf("screen TURN URL %q contains whitespace", value)
		}
		parsed, err := url.Parse(value)
		if err != nil {
			return nil, fmt.Errorf("invalid screen ICE URL %q: %w", value, err)
		}
		scheme := strings.ToLower(parsed.Scheme)
		switch scheme {
		case "turn", "turns", "stun", "stuns":
		default:
			return nil, fmt.Errorf("screen ICE URL %q must use turn, turns, stun, or stuns", value)
		}
		if parsed.User != nil || parsed.Fragment != "" || (parsed.Host == "" && parsed.Opaque == "") {
			return nil, fmt.Errorf("screen ICE URL %q must not contain credentials or a fragment", value)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		urls = append(urls, value)
		if scheme == "turn" || scheme == "turns" {
			hasTURN = true
		}
	}
	if hasTURN && strings.TrimSpace(sharedSecret) == "" {
		return nil, errors.New("screen TURN shared secret is required when TURN URLs are configured")
	}
	return urls, nil
}

func screenICEServers(urls []string, sharedSecret, sessionID string, expiresAt time.Time) []screenICEServer {
	if len(urls) == 0 {
		return []screenICEServer{}
	}
	username := fmt.Sprintf("%d:%s", expiresAt.Unix(), sessionID)
	mac := hmac.New(sha1.New, []byte(sharedSecret))
	_, _ = mac.Write([]byte(username))
	credential := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	servers := make([]screenICEServer, 0, len(urls))
	for _, value := range urls {
		server := screenICEServer{URLs: []string{value}}
		parsed, err := url.Parse(value)
		if err == nil && (strings.EqualFold(parsed.Scheme, "turn") || strings.EqualFold(parsed.Scheme, "turns")) {
			server.Username = username
			server.Credential = credential
		}
		servers = append(servers, server)
	}
	return servers
}

func screenSignalConfigFor(session *screenSession, turnURLs []string, turnSecret string) screenSignalConfig {
	mode := "direct"
	if session != nil && session.SFU {
		mode = "sfu"
	}
	config := screenSignalConfig{Mode: mode, MaxViewers: 1}
	if session != nil {
		config.MaxViewers = session.MaxViewers
		config.ICEServers = screenICEServers(turnURLs, turnSecret, session.ID, session.ExpiresAt)
	}
	if config.ICEServers == nil {
		config.ICEServers = []screenICEServer{}
	}
	return config
}
