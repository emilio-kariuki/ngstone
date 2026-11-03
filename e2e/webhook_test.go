package e2e

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ngstone/internal/webhook"
)

type webhookOrigin struct {
	mu     sync.Mutex
	bodies []string
}

func (o *webhookOrigin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	if strings.HasPrefix(r.URL.Path, "/__ngstone_ready") {
		io.WriteString(w, "origin-ok")
		return
	}
	o.mu.Lock()
	o.bodies = append(o.bodies, r.URL.Path+" "+string(data))
	o.mu.Unlock()
	io.WriteString(w, "origin-ok")
}

func (o *webhookOrigin) received() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.bodies...)
}

func postWebhook(t *testing.T, publicAddr, hostname, path, body string, headers map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+publicAddr+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Host = hostname
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST %s%s: %v", hostname, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

func expectWebhook(t *testing.T, label string, status int, body string, wantStatus int, wantBody string) {
	t.Helper()
	if status != wantStatus || !strings.Contains(body, wantBody) {
		t.Fatalf("%s: status=%d body=%q, want %d containing %q", label, status, body, wantStatus, wantBody)
	}
}

func TestWebhookVerificationStripeViaPortFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess end-to-end test in -short mode")
	}
	edgeBin, agentBin := buildBinaries(t)
	origin := &webhookOrigin{}
	app := httptest.NewServer(origin)
	defer app.Close()

	token := "e2e-webhook-token"
	domain := "hooks.example.com"
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)
	_, edgeLog := startEdge(t, edgeBin, controlAddr, publicAddr, token, domain)

	home := t.TempDir()
	secret := "whsec_e2e_" + sha256Hex(t.Name())[:24]
	secretPath := filepath.Join(home, "stripe.secret")
	if err := os.WriteFile(secretPath, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	agentOut := &syncBuf{}
	cmd := exec.Command(agentBin, "port", app.URL,
		"--server", controlAddr, "--insecure", "--token", token, "--subdomain", "pay", "--json",
		"--verify-webhook", "stripe", "--verify-webhook-secret-file", secretPath, "--verify-webhook-path", "/stripe", "--verify-webhook-tolerance", "2m")
	cmd.Env = append(os.Environ(), "XDG_RUNTIME_DIR="+filepath.Join(home, "run"), "XDG_CONFIG_HOME="+filepath.Join(home, "cfg"))
	cmd.Stdout = io.MultiWriter(os.Stderr, agentOut)
	cmd.Stderr = io.MultiWriter(os.Stderr, agentOut)
	p := newManagedProc(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ngstone port: %v", err)
	}
	t.Cleanup(p.killAndWait)
	host := "pay." + domain
	waitBound(t, publicAddr, host)

	body := `{"id":"evt_e2e","type":"invoice.paid"}`
	now := time.Now().Unix()
	valid := webhook.StripeSignature(secret, now, []byte(body))

	status, resp := postWebhook(t, publicAddr, host, "/stripe/events", body, map[string]string{webhook.StripeSignatureHeader: valid})
	expectWebhook(t, "valid", status, resp, http.StatusOK, "origin-ok")

	status, resp = postWebhook(t, publicAddr, host, "/stripe/events", strings.Replace(body, "invoice.paid", "invoice.voided", 1), map[string]string{webhook.StripeSignatureHeader: valid})
	expectWebhook(t, "tampered", status, resp, http.StatusUnauthorized, "invalid signature")

	expired := webhook.StripeSignature(secret, now-int64((10*time.Minute)/time.Second), []byte(body))
	status, resp = postWebhook(t, publicAddr, host, "/stripe/events", body, map[string]string{webhook.StripeSignatureHeader: expired})
	expectWebhook(t, "expired", status, resp, http.StatusUnauthorized, "timestamp outside tolerance")

	wrongKey := webhook.StripeSignature("whsec_wrong", now, []byte(body))
	status, resp = postWebhook(t, publicAddr, host, "/stripe/events", body, map[string]string{webhook.StripeSignatureHeader: wrongKey})
	expectWebhook(t, "wrong secret", status, resp, http.StatusUnauthorized, "invalid signature")

	status, resp = postWebhook(t, publicAddr, host, "/stripe/events", body, nil)
	expectWebhook(t, "unsigned", status, resp, http.StatusUnauthorized, "missing signature")

	status, resp = postWebhook(t, publicAddr, host, "/health", "ping", nil)
	expectWebhook(t, "outside prefix", status, resp, http.StatusOK, "origin-ok")

	got := origin.received()
	want := []string{"/stripe/events " + body, "/health ping"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("origin received %q, want %q", got, want)
	}

	p.killAndWait()
	for name, out := range map[string]string{"agent output": agentOut.String(), "edge log": edgeLog.String()} {
		if strings.Contains(out, secret) {
			t.Fatalf("%s exposes the webhook secret:\n%s", name, out)
		}
	}
}

func TestWebhookVerificationGitHubAndSlackViaTunnelsFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess end-to-end test in -short mode")
	}
	edgeBin, agentBin := buildBinaries(t)
	origin := &webhookOrigin{}
	app := httptest.NewServer(origin)
	defer app.Close()

	token := "e2e-webhook-start-token"
	domain := "hooks-start.example.com"
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)
	startEdge(t, edgeBin, controlAddr, publicAddr, token, domain)

	home := t.TempDir()
	githubSecret := "gh-e2e-" + sha256Hex("github")[:16]
	slackSecret := "slack-e2e-" + sha256Hex("slack")[:16]
	if err := os.WriteFile(filepath.Join(home, "github.secret"), []byte(githubSecret), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	cfgPath := filepath.Join(home, "ngstone.yml")
	yml := fmt.Sprintf(`server: %s
tunnels:
  gh:
    url: %s
    subdomain: gh
    webhook:
      provider: github
      secret_file: github.secret
  slack:
    url: %s
    subdomain: slack
    webhook:
      provider: slack
      secret_env: E2E_SLACK_SIGNING_SECRET
      tolerance: 1m
`, controlAddr, app.URL, app.URL)
	if err := os.WriteFile(cfgPath, []byte(yml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command(agentBin, "start", "--config", cfgPath, "--no-tui", "--insecure", "--token", token)
	cmd.Env = append(os.Environ(), "XDG_RUNTIME_DIR="+filepath.Join(home, "run"), "XDG_CONFIG_HOME="+filepath.Join(home, "cfg"), "E2E_SLACK_SIGNING_SECRET="+slackSecret)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	p := newManagedProc(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(p.killAndWait)
	ghHost, slackHost := "gh."+domain, "slack."+domain
	waitStatus(t, publicAddr, ghHost, "/", http.StatusUnauthorized, 15*time.Second)
	waitStatus(t, publicAddr, slackHost, "/", http.StatusUnauthorized, 15*time.Second)

	ghBody := `{"zen":"Keep it logically awesome."}`
	status, resp := postWebhook(t, publicAddr, ghHost, "/github", ghBody, map[string]string{webhook.GitHubSignatureHeader: webhook.GitHubSignature(githubSecret, []byte(ghBody))})
	expectWebhook(t, "github valid", status, resp, http.StatusOK, "origin-ok")
	status, resp = postWebhook(t, publicAddr, ghHost, "/github", ghBody+" ", map[string]string{webhook.GitHubSignatureHeader: webhook.GitHubSignature(githubSecret, []byte(ghBody))})
	expectWebhook(t, "github tampered", status, resp, http.StatusUnauthorized, "invalid signature")

	slackBody := "token=abc&command=%2Fdeploy&text=prod"
	now := time.Now().Unix()
	ts := fmt.Sprint(now)
	status, resp = postWebhook(t, publicAddr, slackHost, "/slack/commands", slackBody, map[string]string{
		webhook.SlackSignatureHeader: webhook.SlackSignature(slackSecret, now, []byte(slackBody)),
		webhook.SlackTimestampHeader: ts,
	})
	expectWebhook(t, "slack valid", status, resp, http.StatusOK, "origin-ok")

	old := now - 300
	status, resp = postWebhook(t, publicAddr, slackHost, "/slack/commands", slackBody, map[string]string{
		webhook.SlackSignatureHeader: webhook.SlackSignature(slackSecret, old, []byte(slackBody)),
		webhook.SlackTimestampHeader: fmt.Sprint(old),
	})
	expectWebhook(t, "slack replayed", status, resp, http.StatusUnauthorized, "timestamp outside tolerance")

	status, resp = postWebhook(t, publicAddr, slackHost, "/slack/commands", strings.Replace(slackBody, "prod", "staging", 1), map[string]string{
		webhook.SlackSignatureHeader: webhook.SlackSignature(slackSecret, now, []byte(slackBody)),
		webhook.SlackTimestampHeader: ts,
	})
	expectWebhook(t, "slack tampered", status, resp, http.StatusUnauthorized, "invalid signature")

	got := origin.received()
	want := []string{"/github " + ghBody, "/slack/commands " + slackBody}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("origin received %q, want %q", got, want)
	}
}
