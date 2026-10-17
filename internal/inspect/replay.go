package inspect

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrTruncatedBody = errors.New("inspect: captured request body was truncated, replay unavailable")
	ErrNotFound      = errors.New("inspect: exchange not found")
	ErrNotReplayable = errors.New("inspect: exchange is not replayable")
)

type Overrides struct {
	Method string
	URL    string
	Header http.Header
	Body   []byte
}

var hopByHop = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func sanitizeHeader(src http.Header) http.Header {
	h := src.Clone()
	if h == nil {
		h = make(http.Header)
	}
	for _, v := range h.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if tok = strings.TrimSpace(tok); tok != "" {
				h.Del(tok)
			}
		}
	}
	for _, k := range hopByHop {
		h.Del(k)
	}
	h.Del("Content-Length")
	h.Del("Host")
	return h
}

func Replay(ctx context.Context, ex *Exchange, target *url.URL, rt http.RoundTripper, ov *Overrides) (*Exchange, error) {
	if ex == nil {
		return nil, ErrNotFound
	}
	if ex.Kind == KindUpgrade {
		return nil, ErrNotReplayable
	}
	if rt == nil {
		rt = http.DefaultTransport
	}

	body := ex.Req.Body
	if ov != nil && ov.Body != nil {
		body = ov.Body
	} else if ex.Req.Truncated {
		return nil, ErrTruncatedBody
	}

	method := ex.Req.Method
	if ov != nil && ov.Method != "" {
		method = ov.Method
	}
	if method == "" {
		method = http.MethodGet
	}

	raw := ex.Req.URL
	if ov != nil && ov.URL != "" {
		raw = ov.URL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	host := u.Host
	if target != nil {
		u.Scheme = target.Scheme
		u.Host = target.Host
		if u.Scheme == "" {
			u.Scheme = "http"
		}
	}
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	if host == "" {
		host = u.Host
	}

	header := ex.Req.Header
	if ov != nil && ov.Header != nil {
		header = ov.Header
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = sanitizeHeader(header)
	req.Host = host
	req.ContentLength = int64(len(body))
	if len(body) == 0 {
		req.Body = http.NoBody
	}

	out := &Exchange{
		ID:       newID(),
		ReqID:    ex.ReqID,
		Tunnel:   ex.Tunnel,
		Kind:     KindHTTP,
		Start:    start,
		Replayed: true,
		ReplayOf: ex.ID,
		Req: CapturedReq{
			Method:   method,
			URL:      req.URL.String(),
			Proto:    req.Proto,
			Header:   req.Header.Clone(),
			Body:     append([]byte(nil), body...),
			BodySize: int64(len(body)),
		},
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		out.Duration = time.Since(start)
		out.Err = err.Error()
		return out, err
	}
	defer resp.Body.Close()

	cb := &capBuf{}
	buf := make([]byte, 32*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			cb.add(buf[:n])
		}
		if rerr != nil {
			if rerr != io.EOF {
				out.Err = rerr.Error()
			}
			break
		}
	}
	rbody, rsize, rtrunc := cb.snapshot()

	out.Duration = time.Since(start)
	out.Resp = CapturedResp{
		Status:    resp.StatusCode,
		Proto:     resp.Proto,
		Header:    resp.Header.Clone(),
		Body:      rbody,
		BodySize:  rsize,
		Truncated: rtrunc,
	}
	return out, nil
}

func (s *Store) Replay(ctx context.Context, id string, target *url.URL, rt http.RoundTripper, ov *Overrides) (*Exchange, error) {
	src, ok := s.Get(id)
	if !ok {
		return nil, ErrNotFound
	}
	out, err := Replay(ctx, src, target, rt, ov)
	if out != nil {
		s.Add(out)
	}
	return out, err
}
