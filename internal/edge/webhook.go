package edge

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/webhook"
)

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
	return min(limits.WebhookMaxBodyBytes, limits.MaxBodyBytes)
}

func verifyWebhookRequest(w http.ResponseWriter, r *http.Request, v *webhook.Verifier, limit int64, budget *byteBudget, now time.Time) (release func(), ok bool) {
	if v == nil || !v.Matches(r.URL.EscapedPath()) {
		return func() {}, true
	}
	if err := v.CheckHeaders(r.Header); err != nil {
		rejectWebhookSignature(w, err)
		return func() {}, false
	}
	if r.ContentLength > limit {
		metricRejected413.Add(1)
		http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
		return func() {}, false
	}
	body, release, ok := readWebhookBody(w, r, limit, budget)
	if !ok {
		return func() {}, false
	}
	if err := v.Verify(r.Header, body, now); err != nil {
		release()
		rejectWebhookSignature(w, err)
		return func() {}, false
	}
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	if len(body) == 0 {
		r.Body = http.NoBody
		r.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
		return release, true
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	return release, true
}

func readWebhookBody(w http.ResponseWriter, r *http.Request, limit int64, budget *byteBudget) ([]byte, func(), bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, func() {}, true
	}
	size := r.ContentLength
	if size < 0 {
		size = limit
	}
	release, ok := budget.reserve(size)
	if !ok {
		metricRejectedWebhookBuffer.Add(1)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "webhook verification is busy", http.StatusServiceUnavailable)
		return nil, nil, false
	}
	buf := make([]byte, size)
	n, err := io.ReadFull(r.Body, buf)
	if err != nil && (r.ContentLength >= 0 || (!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF))) {
		release()
		writeWebhookBodyError(w, r, err)
		return nil, nil, false
	}
	if n == len(buf) {
		var probe [1]byte
		m, err := io.ReadFull(r.Body, probe[:])
		if m > 0 {
			release()
			metricRejected413.Add(1)
			if r.ProtoMajor == 1 {
				w.Header().Set("Connection", "close")
			}
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return nil, nil, false
		}
		if err != nil && !errors.Is(err, io.EOF) {
			release()
			writeWebhookBodyError(w, r, err)
			return nil, nil, false
		}
	}
	return buf[:n], release, true
}

func rejectWebhookSignature(w http.ResponseWriter, err error) {
	metricRejectedWebhook.Add(1)
	http.Error(w, "webhook signature rejected: "+err.Error(), http.StatusUnauthorized)
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
