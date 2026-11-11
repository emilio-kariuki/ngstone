package config

import (
	"errors"
	"fmt"
	"time"

	"ngstone/internal/webhook"
)

const DefaultWebhookSecretEnv = "NGSTONE_WEBHOOK_SECRET"

type TunnelWebhook struct {
	Provider   string `json:"provider" yaml:"provider"`
	SecretFile string `json:"secret_file,omitempty" yaml:"secret_file"`
	SecretEnv  string `json:"secret_env,omitempty" yaml:"secret_env"`
	PathPrefix string `json:"path_prefix,omitempty" yaml:"path_prefix"`
	Header     string `json:"header,omitempty" yaml:"header"`
	Encoding   string `json:"encoding,omitempty" yaml:"encoding"`
	Prefix     string `json:"prefix,omitempty" yaml:"prefix"`
	Tolerance  string `json:"tolerance,omitempty" yaml:"tolerance"`
}

func (w *TunnelWebhook) Validate(kind string, http2, oidc bool) error {
	if w == nil {
		return nil
	}
	if kind != KindHTTP {
		return errors.New("webhook verification is only valid for http tunnels")
	}
	if http2 {
		return errors.New("webhook verification cannot be combined with http2")
	}
	if oidc {
		return errors.New("webhook verification cannot be combined with oidc visitor login")
	}
	if w.SecretFile != "" && w.SecretEnv != "" {
		return errors.New("webhook must use either secret_file or secret_env")
	}
	if w.SecretEnv != "" && !validEnvName(w.SecretEnv) {
		return errors.New("webhook secret_env must be a valid environment variable name")
	}
	tolerance, err := w.ToleranceDuration()
	if err != nil {
		return err
	}
	_, err = w.Config("placeholder", tolerance).Normalize()
	return err
}

func (w *TunnelWebhook) ToleranceDuration() (time.Duration, error) {
	if w == nil || w.Tolerance == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(w.Tolerance)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("webhook tolerance must be a positive duration such as 5m")
	}
	return d, nil
}

func (w *TunnelWebhook) Config(secret string, tolerance time.Duration) webhook.Config {
	return webhook.Config{
		Provider:   w.Provider,
		Secret:     secret,
		PathPrefix: w.PathPrefix,
		Header:     w.Header,
		Encoding:   w.Encoding,
		Prefix:     w.Prefix,
		Tolerance:  tolerance,
	}
}
