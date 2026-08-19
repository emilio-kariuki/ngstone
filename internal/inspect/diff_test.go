package inspect

import (
	"net/http"
	"strings"
	"testing"
)

func TestDiffResponsesReportsStatusHeadersAndBodyChanges(t *testing.T) {
	original := &Exchange{
		ID: "original",
		Resp: CapturedResp{
			Status: 200,
			Header: http.Header{"Content-Type": {"application/json"}},
			Body:   []byte("{\n  \"ok\": true\n}"),
		},
	}
	replay := &Exchange{
		ID: "replay",
		Resp: CapturedResp{
			Status: 500,
			Header: http.Header{"Content-Type": {"text/plain"}},
			Body:   []byte("failed"),
		},
	}

	diff, err := DiffResponses(original, replay)
	if err != nil {
		t.Fatalf("DiffResponses: %v", err)
	}
	for _, want := range []string{"@@ STATUS @@", "- 200 OK", "+ 500 Internal Server Error", "@@ HEADERS @@", "@@ BODY @@", "+ failed"} {
		if !strings.Contains(diff, want) {
			t.Fatalf("diff %q does not contain %q", diff, want)
		}
	}
}

func TestDiffResponsesReportsNoDifference(t *testing.T) {
	ex := &Exchange{ID: "same", Resp: CapturedResp{Status: 204, Header: http.Header{}, Body: []byte("done")}}
	diff, err := DiffResponses(ex, ex.Clone())
	if err != nil {
		t.Fatalf("DiffResponses: %v", err)
	}
	if !strings.Contains(diff, "(no response differences)") {
		t.Fatalf("diff = %q, want no-difference message", diff)
	}
}
