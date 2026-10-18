package adminapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ngstone/internal/credentials"
)

const (
	DefaultBaseURL = "http://127.0.0.1:4041"
	APIPrefix      = "/api/v1"
)

type CredentialIssueRequest struct {
	Kind       string `json:"kind,omitempty"`
	Subdomain  string `json:"subdomain,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	TTL        string `json:"ttl,omitempty"`
}

type CredentialIssueResponse struct {
	Credential credentials.Credential `json:"credential"`
	Token      string                 `json:"token"`
}

type ScreenSessionRequest struct {
	Name       string `json:"name,omitempty"`
	TTL        string `json:"ttl,omitempty"`
	MaxViewers int    `json:"max_viewers,omitempty"`
}

type ScreenSession struct {
	ID              string    `json:"id"`
	Name            string    `json:"name,omitempty"`
	OwnerID         string    `json:"owner_id"`
	Status          string    `json:"status"`
	ViewerURL       string    `json:"viewer_url"`
	MaxViewers      int       `json:"max_viewers"`
	ViewerCount     int       `json:"viewer_count"`
	SFU             bool      `json:"sfu"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	SenderConnected bool      `json:"sender_connected"`
	ViewerConnected bool      `json:"viewer_connected"`
}

type ScreenSessionCreateResponse struct {
	Session     ScreenSession `json:"session"`
	SenderToken string        `json:"sender_token"`
	ViewerToken string        `json:"viewer_token"`
	ViewerURL   string        `json:"viewer_url"`
}

type TrafficPolicyRequest struct {
	Name    string          `json:"name"`
	OwnerID string          `json:"owner_id,omitempty"`
	Policy  json.RawMessage `json:"policy"`
}

type TrafficPolicy struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	OwnerID   string          `json:"owner_id"`
	Digest    string          `json:"digest"`
	Policy    json.RawMessage `json:"policy"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type TunnelObservability struct {
	TunnelID          string           `json:"tunnel_id"`
	Name              string           `json:"name,omitempty"`
	Hostname          string           `json:"hostname"`
	Kind              string           `json:"kind,omitempty"`
	Port              int              `json:"port,omitempty"`
	OwnerID           string           `json:"owner_id,omitempty"`
	Status            string           `json:"status,omitempty"`
	RequestCount      int64            `json:"request_count"`
	LatencyP50MS      float64          `json:"latency_p50_ms"`
	LatencyP95MS      float64          `json:"latency_p95_ms"`
	LatencyP99MS      float64          `json:"latency_p99_ms"`
	StatusCodes       map[string]int64 `json:"status_codes"`
	ActiveConnectors  int              `json:"active_connectors"`
	Reconnects        int64            `json:"reconnects"`
	BytesIn           int64            `json:"bytes_in"`
	BytesOut          int64            `json:"bytes_out"`
	BytesTransferred  int64            `json:"bytes_transferred"`
	CredentialExpired int64            `json:"credential_expired"`
	CredentialRevoked int64            `json:"credential_revoked"`
	UpdatedAt         time.Time        `json:"updated_at"`
}

type CustomDomainRequest struct {
	Domain   string `json:"domain"`
	TunnelID string `json:"tunnel_id,omitempty"`
	OwnerID  string `json:"owner_id,omitempty"`
	Status   string `json:"status,omitempty"`
}

type CustomDomain struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	TunnelID  string    `json:"tunnel_id,omitempty"`
	OwnerID   string    `json:"owner_id"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type DrainResponse struct {
	Hostname   string `json:"hostname"`
	Connectors int    `json:"connectors"`
}

type Status struct {
	GeneratedAt      time.Time `json:"generated_at"`
	StartedAt        time.Time `json:"started_at,omitempty"`
	UptimeSeconds    int64     `json:"uptime_seconds"`
	Domain           string    `json:"domain"`
	PublicScheme     string    `json:"public_scheme"`
	Listeners        Listeners `json:"listeners"`
	LoopbackOnly     bool      `json:"loopback_only"`
	Health           Health    `json:"health"`
	Metrics          Metrics   `json:"metrics"`
	ActiveTunnels    int       `json:"active_tunnels"`
	ActiveConnectors int       `json:"active_connectors"`
	Tunnels          []Tunnel  `json:"tunnels"`
	Events           []Event   `json:"events"`
}

type Listeners struct {
	Control string `json:"control"`
	Public  string `json:"public"`
	Ops     string `json:"ops"`
}

type Health struct {
	OK       bool        `json:"ok"`
	Apex     Certificate `json:"apex_cert,omitempty"`
	Wildcard Certificate `json:"wildcard_cert,omitempty"`
}

type Certificate struct {
	Domain   string `json:"domain"`
	NotAfter string `json:"not_after,omitempty"`
	Error    string `json:"error,omitempty"`
}

type Metrics struct {
	RequestsTotal            int64 `json:"requests_total"`
	Responses4xx             int64 `json:"responses_4xx"`
	Responses5xx             int64 `json:"responses_5xx"`
	BytesTotal               int64 `json:"bytes_total"`
	ActiveSessions           int64 `json:"active_sessions"`
	ActiveUpgrades           int64 `json:"active_upgrades"`
	RejectedRateLimited      int64 `json:"rejected_rate_limited"`
	RejectedGlobalCap        int64 `json:"rejected_global_cap"`
	RejectedSessionCap       int64 `json:"rejected_session_cap"`
	Rejected413              int64 `json:"rejected_413"`
	RejectedForbiddenCIDR    int64 `json:"rejected_forbidden_cidr"`
	RejectedUnauthorized     int64 `json:"rejected_unauthorized"`
	RejectedTrafficPolicy    int64 `json:"rejected_traffic_policy"`
	RejectedUpgradeCap       int64 `json:"rejected_upgrade_cap"`
	TCPRejectedGlobalCap     int64 `json:"tcp_rejected_global_cap"`
	TCPRejectedBindCap       int64 `json:"tcp_rejected_bind_cap"`
	TCPRejectedRateLimited   int64 `json:"tcp_rejected_rate_limited"`
	TCPRejectedForbiddenCIDR int64 `json:"tcp_rejected_forbidden_cidr"`
}

type Tunnel struct {
	ID               string      `json:"id,omitempty"`
	Name             string      `json:"name,omitempty"`
	Kind             string      `json:"kind"`
	Hostname         string      `json:"hostname"`
	Port             int         `json:"port,omitempty"`
	OwnerID          string      `json:"owner_id,omitempty"`
	Status           string      `json:"status,omitempty"`
	EdgeID           string      `json:"edge_id,omitempty"`
	Durable          bool        `json:"durable,omitempty"`
	BoundAt          time.Time   `json:"bound_at"`
	HTTP2            bool        `json:"http2"`
	MultiConnector   bool        `json:"multi_connector"`
	AccessRestricted bool        `json:"access_restricted"`
	PolicyEnabled    bool        `json:"policy_enabled"`
	Connectors       []Connector `json:"connectors"`
}

type Connector struct {
	SessionID      string    `json:"session_id"`
	InstanceID     string    `json:"instance_id"`
	Remote         string    `json:"remote,omitempty"`
	BoundAt        time.Time `json:"bound_at"`
	Alive          bool      `json:"alive"`
	Healthy        bool      `json:"healthy"`
	ActiveStreams  int64     `json:"active_streams"`
	StreamCapacity int64     `json:"stream_capacity"`
}

type Event struct {
	At      time.Time         `json:"at"`
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
}

type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e == nil {
		return "admin API error"
	}
	if e.Message == "" {
		return fmt.Sprintf("admin API request failed with status %d", e.Status)
	}
	return e.Message
}

type Client struct {
	baseURL    url.URL
	token      string
	httpClient *http.Client
}

func NewClient(rawURL, token string) (*Client, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		rawURL = DefaultBaseURL
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("admin API server must be an http(s) URL without credentials, query, or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return &Client{
		baseURL: *u,
		token:   strings.TrimSpace(token),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *Client) Get(path string, output any) error {
	return c.request(http.MethodGet, path, nil, output)
}

func (c *Client) Post(path string, input, output any) error {
	return c.request(http.MethodPost, path, input, output)
}

func (c *Client) Delete(path string) error {
	return c.request(http.MethodDelete, path, nil, nil)
}

func (c *Client) request(method, path string, input, output any) error {
	if c == nil {
		return errors.New("admin API client is nil")
	}
	if path == "" || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") {
		return errors.New("admin API path must be an absolute path without query or fragment")
	}
	u := c.baseURL
	u.Path = strings.TrimRight(c.baseURL.Path, "/") + path
	var body io.Reader
	if input != nil {
		var buf bytes.Buffer
		encoder := json.NewEncoder(&buf)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(input); err != nil {
			return fmt.Errorf("encoding admin API request: %w", err)
		}
		body = &buf
	}
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return fmt.Errorf("creating admin API request: %w", err)
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("admin API request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return decodeAPIError(resp)
	}
	if output == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 4<<20))
	if err := decoder.Decode(&envelope); err != nil {
		return fmt.Errorf("decoding admin API response: %w", err)
	}
	if len(envelope.Data) == 0 {
		return errors.New("admin API response did not contain data")
	}
	if err := json.Unmarshal(envelope.Data, output); err != nil {
		return fmt.Errorf("decoding admin API data: %w", err)
	}
	return nil
}

func decodeAPIError(resp *http.Response) error {
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 64<<10))
	if err := decoder.Decode(&envelope); err != nil {
		return &APIError{Status: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
	}
	message := envelope.Error.Message
	if message == "" {
		message = http.StatusText(resp.StatusCode)
	}
	return &APIError{Status: resp.StatusCode, Code: envelope.Error.Code, Message: message}
}
