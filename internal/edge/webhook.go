package edge

import (
	"bytes"
	"errors"
	"expvar"
	"io"
	"net/http"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/webhook"
)

var metricRejectedWebhook = expvar.NewInt("ngstoned_rejected_webhook_signature_total")

func buildWebhookVerifier(bind proto.Bind) (*webhook.Verifier, error) {
	if bind.Webhook == nil {
		return nil, nil
	}
	if bind.Webhook.ToleranceSeconds < 0 || bind.Webhook.ToleranceSeconds > int64(webhook.MaxTolerance/time.Second) {
		return nil, errors.New("webhook tolerance is out of range")
	}
	return webhook.New(webhook.Config{
		Provider:   bind.Webhook.Provider,
		Secret:     bind.Webhook.Secret,
		PathPrefix: bind.Webhook.PathPrefix,
		Header:     bind.Webhook.Header,
		Encoding:   bind.Webhook.Encoding,
		Prefix:     bind.Webhook.Prefix,
		Tolerance:  time.Duration(bind.Webhook.ToleranceSeconds) * time.Second,
	})
}

func webhookBodyLimit(limits LimitsConfig) int64 {
	if limits.MaxBodyBytes > 0 && limits.MaxBodyBytes < webhook.MaxBodyBytes {
		return limits.MaxBodyBytes
	}
	return webhook.MaxBodyBytes
}

func verifyWebhookRequest(w http.ResponseWriter, r *http.Request, v *webhook.Verifier, limit int64, now time.Time) bool {
	if v == nil || !v.Matches(r.URL.Path) {
		return true
	}
	if r.ContentLength > limit {
		metricRejected413.Add(1)
		http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
		return false
	}
	var body []byte
	if r.Body != nil && r.Body != http.NoBody {
		data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
		if err != nil {
			writeWebhookBodyError(w, r, err)
			return false
		}
		if int64(len(data)) > limit {
			metricRejected413.Add(1)
			w.Header().Set("Connection", "close")
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return false
		}
		body = data
	}
	if err := v.Verify(r.Header, body, now); err != nil {
		metricRejectedWebhook.Add(1)
		http.Error(w, "webhook signature rejected: "+err.Error(), http.StatusUnauthorized)
		return false
	}
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	if len(body) == 0 {
		r.Body = http.NoBody
		r.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
		return true
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	return true
}

func writeWebhookBodyError(w http.ResponseWriter, r *http.Request, err error) {
	var maxBytesErr *http.MaxBytesError
	switch {
	case errors.As(err, &maxBytesErr):
		metricRejected413.Add(1)
		http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
	case errors.Is(err, errClientIdle):
		metricRejectedClientIdle.Add(1)
		if r.ProtoMajor == 1 {
			w.Header().Set("Connection", "close")
		}
		writeError(w, http.StatusRequestTimeout)
	default:
		http.Error(w, "could not read request body", http.StatusBadRequest)
	}
}
