package inspect

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReplayFileRoundTripIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.json")
	want := &Exchange{
		ID:    "source",
		Start: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
		Kind:  KindHTTP,
		Req: CapturedReq{
			Method:   "POST",
			URL:      "https://example.test/items",
			Header:   http.Header{"Content-Type": {"application/json"}},
			Body:     []byte(`{"name":"test"}`),
			BodySize: 16,
		},
	}
	if err := SaveReplay(path, want); err != nil {
		t.Fatalf("SaveReplay: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat replay file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("replay file mode = %o, want 600", got)
	}
	got, err := LoadReplay(path)
	if err != nil {
		t.Fatalf("LoadReplay: %v", err)
	}
	if got.Req.Method != want.Req.Method || got.Req.URL != want.Req.URL || string(got.Req.Body) != string(want.Req.Body) {
		t.Fatalf("loaded request = %+v, want %+v", got.Req, want.Req)
	}
	if got.Req.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("loaded headers = %v", got.Req.Header)
	}
}

func TestSaveReplayRejectsUnsupportedRequests(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.json")
	if err := SaveReplay(path, &Exchange{Kind: KindUpgrade}); err != ErrNotReplayable {
		t.Fatalf("upgrade error = %v, want %v", err, ErrNotReplayable)
	}
	if err := SaveReplay(path, &Exchange{Kind: KindHTTP, Req: CapturedReq{URL: "https://example.test", Truncated: true}}); err != ErrTruncatedBody {
		t.Fatalf("truncated error = %v, want %v", err, ErrTruncatedBody)
	}
}
