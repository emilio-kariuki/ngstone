package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ngstone/internal/config"
	"ngstone/internal/webhook"
)

type webhookFlags struct {
	provider   string
	secretFile string
	pathPrefix string
	header     string
	encoding   string
	prefix     string
	tolerance  time.Duration
}

func (wf *webhookFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&wf.provider, "verify-webhook", "", "verify webhook signatures at the edge before forwarding: "+strings.Join(webhook.Providers, ", "))
	fs.StringVar(&wf.secretFile, "verify-webhook-secret-file", "", "file holding the webhook signing secret (defaults to $"+config.DefaultWebhookSecretEnv+")")
	fs.StringVar(&wf.pathPrefix, "verify-webhook-path", "", "only verify requests whose path contains this path at a segment boundary (empty = every request)")
	fs.StringVar(&wf.header, "verify-webhook-header", "", "signature header for --verify-webhook hmac")
	fs.StringVar(&wf.encoding, "verify-webhook-encoding", "", "signature encoding for --verify-webhook hmac: hex or base64 (default hex)")
	fs.StringVar(&wf.prefix, "verify-webhook-prefix", "", "signature prefix for --verify-webhook hmac, such as sha256=")
	fs.DurationVar(&wf.tolerance, "verify-webhook-tolerance", 0, "timestamp tolerance for stripe and slack (default 5m)")
}

func (wf *webhookFlags) set() bool {
	return wf.secretFile != "" || wf.pathPrefix != "" || wf.header != "" || wf.encoding != "" || wf.prefix != "" || wf.tolerance != 0
}

func resolveWebhookFlags(wf *webhookFlags, envSecret string) (*webhook.Config, error) {
	if wf.provider == "" {
		if wf.set() {
			return nil, errors.New("--verify-webhook-* options need --verify-webhook <provider>")
		}
		return nil, nil
	}
	secret := envSecret
	if wf.secretFile != "" {
		var err error
		secret, err = readWebhookSecretFile(wf.secretFile, false)
		if err != nil {
			return nil, err
		}
	}
	if secret == "" {
		return nil, fmt.Errorf("--verify-webhook needs a secret: pass --verify-webhook-secret-file or set %s", config.DefaultWebhookSecretEnv)
	}
	cfg := webhook.Config{
		Provider:   wf.provider,
		Secret:     secret,
		PathPrefix: wf.pathPrefix,
		Header:     wf.header,
		Encoding:   wf.encoding,
		Prefix:     wf.prefix,
		Tolerance:  wf.tolerance,
	}
	normalized, err := cfg.Normalize()
	if err != nil {
		return nil, err
	}
	return &normalized, nil
}

func resolveProjectWebhook(w *config.TunnelWebhook, projectDir string) (*webhook.Config, error) {
	if w == nil {
		return nil, nil
	}
	var secret string
	switch {
	case w.SecretFile != "":
		path := w.SecretFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(projectDir, path)
		}
		var err error
		secret, err = readWebhookSecretFile(path, true)
		if err != nil {
			return nil, err
		}
	default:
		name := w.SecretEnv
		if name == "" {
			name = config.DefaultWebhookSecretEnv
		}
		secret = os.Getenv(name)
		if secret == "" {
			return nil, fmt.Errorf("webhook secret environment variable %s is empty", name)
		}
	}
	tolerance, err := w.ToleranceDuration()
	if err != nil {
		return nil, err
	}
	normalized, err := w.Config(secret, tolerance).Normalize()
	if err != nil {
		return nil, err
	}
	return &normalized, nil
}

func readWebhookSecretFile(path string, strict bool) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("reading webhook secret file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("webhook secret file must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		if strict {
			return "", fmt.Errorf("webhook secret file %s must be readable only by its owner (chmod 600)", path)
		}
		fmt.Fprintf(os.Stderr, "ngstone: warning: %s is group/world readable; consider chmod 600 to protect the webhook secret\n", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading webhook secret file: %w", err)
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", fmt.Errorf("webhook secret file %s is empty", path)
	}
	return secret, nil
}
