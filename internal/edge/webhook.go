package edge

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/webhook"
)

func buildWebhookVerifier(bind proto.Bind) (*webhook.Verifier, error) {
	if bind.Webhook == nil {
		return nil, nil
	}
	if bind.HTTP2 {
		return nil, errors.New("webhook verification cannot be combined with HTTP/2 tunnels")
	}
	if bind.OIDC != nil {
		return nil, errors.New("webhook verification cannot be combined with visitor login")
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
		release()
		return release, true
	}
	r.Body = &releasingBody{reader: bytes.NewReader(body), release: release}
	return release, true
}

type releasingBody struct {
	mu      sync.Mutex
	reader  *bytes.Reader
	release func()
}

func (b *releasingBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.reader == nil {
		return 0, io.EOF
	}
	n, err := b.reader.Read(p)
	if err != nil {
		b.drop()
	}
	return n, err
}

func (b *releasingBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.drop()
	return nil
}

func (b *releasingBody) drop() {
	b.reader = nil
	b.release()
}

func readWebhookBody(w http.ResponseWriter, r *http.Request, limit int64, budget *byteBudget) ([]byte, func(), bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, func() {}, true
	}
	size := r.ContentLength
	if size < 0 {
		size = limit
	}
	if ib, ok := r.Body.(*idleBody); ok && ib.idle > 0 {
		ib.until = time.Now().Add(ib.idle)
		defer func() { ib.until = time.Time{} }()
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
