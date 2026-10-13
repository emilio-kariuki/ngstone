package tui

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"ngstone/internal/inspect"
)

func replayThroughForm(t *testing.T, ex *inspect.Exchange, edit func(*editFormModel)) (gotBody []byte, gotHeader http.Header, err error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotHeader = r.Header.Clone()
	}))
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)

	f := newEditForm()
	f.populate(ex)
	if edit != nil {
		edit(&f)
	}
	_, err = inspect.Replay(context.Background(), ex, target, nil, f.overrides())
	return gotBody, gotHeader, err
}

func multipartExchange() *inspect.Exchange {
	body := []byte("--b\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n\tx\x00y\r\n--b--\r\n")
	return &inspect.Exchange{
		ID:   "1",
		Kind: inspect.KindHTTP,
		Req: inspect.CapturedReq{
			Method:   http.MethodPost,
			URL:      "http://app.example.com/upload",
			Header:   http.Header{"Content-Type": {"multipart/form-data; boundary=b"}, "X-Trace": {"a\tb"}},
			Body:     body,
			BodySize: int64(len(body)),
		},
	}
}

// Opening the editor and saving without edits must replay the exact captured
// bytes; the textarea's sanitizer used to turn CRLF into blank lines, tabs
// into spaces and drop control bytes.
func TestEditFormUneditedReplayKeepsCapturedBytes(t *testing.T) {
	ex := multipartExchange()
	got, hdr, err := replayThroughForm(t, ex, nil)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if string(got) != string(ex.Req.Body) {
		t.Fatalf("replayed body = %q, want the captured %q", got, ex.Req.Body)
	}
	if hdr.Get("X-Trace") != "a\tb" {
		t.Fatalf("replayed X-Trace = %q, want the captured %q", hdr.Get("X-Trace"), "a\tb")
	}
}

// A body the textarea cannot hold faithfully is locked: typing is ignored and
// the captured bytes are replayed.
func TestEditFormLossyBodyIsLocked(t *testing.T) {
	ex := multipartExchange()
	got, _, err := replayThroughForm(t, ex, func(f *editFormModel) {
		f.focus = editFocusBody
		f.applyFocus()
		*f, _ = f.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("zzz")})
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if string(got) != string(ex.Req.Body) {
		t.Fatalf("replayed body = %q, want the captured %q", got, ex.Req.Body)
	}
}

// Editing a truncated capture must not replay the 256 KiB prefix as if it
// were the whole body; it fails the same way plain replay does.
func TestEditFormTruncatedBodyKeepsReplayGuard(t *testing.T) {
	ex := &inspect.Exchange{
		ID:   "2",
		Kind: inspect.KindHTTP,
		Req: inspect.CapturedReq{
			Method:    http.MethodPost,
			URL:       "http://app.example.com/big",
			Body:      []byte("prefix only"),
			BodySize:  1 << 20,
			Truncated: true,
		},
	}
	_, _, err := replayThroughForm(t, ex, func(f *editFormModel) {
		f.focus = editFocusBody
		f.applyFocus()
		*f, _ = f.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("!")})
	})
	if !errors.Is(err, inspect.ErrTruncatedBody) {
		t.Fatalf("replay err = %v, want ErrTruncatedBody", err)
	}
}

// Real edits to a plain text body are still applied.
func TestEditFormEditedTextBodyIsSent(t *testing.T) {
	ex := &inspect.Exchange{
		ID:   "3",
		Kind: inspect.KindHTTP,
		Req: inspect.CapturedReq{
			Method: http.MethodPost,
			URL:    "http://app.example.com/json",
			Header: http.Header{"Content-Type": {"application/json"}},
			Body:   []byte(`{"a":1}`),
		},
	}
	got, _, err := replayThroughForm(t, ex, func(f *editFormModel) {
		f.body.SetValue(`{"a":2}`)
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if string(got) != `{"a":2}` {
		t.Fatalf("replayed body = %q, want the edited body", got)
	}
}
