package tui

import (
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"

	"ngstone/internal/inspect"
)

func TestTruncatePathRuneSafety(t *testing.T) {
	inputs := []struct {
		name  string
		input string
	}{
		{"accented", "/api/café/orders"},
		{"cjk", "/ユーザー/list"},
		{"emoji", "/emoji/🚀/go"},
	}

	for _, c := range inputs {
		for width := 1; width <= 12; width++ {
			out := truncatePath(c.input, width)
			if !utf8.ValidString(out) {
				t.Errorf("%s: truncatePath(%q, %d) = %q, not valid UTF-8", c.name, c.input, width, out)
			}
			if w := lipgloss.Width(out); w > width {
				t.Errorf("%s: truncatePath(%q, %d) width = %d, want <= %d", c.name, c.input, width, w, width)
			}
		}
	}
}

func TestPadRightPadLeftCellSafety(t *testing.T) {
	cases := []struct {
		name  string
		input string
		width int
	}{
		{"accented fits", "café", 10},
		{"accented overflows", "café ordering system", 10},
		{"cjk fits", "ユーザー", 10},
		{"cjk overflows", "ユーザー一覧ページ", 6},
		{"emoji overflows", "🚀🚀🚀🚀🚀", 6},
	}

	for _, c := range cases {
		right := padRight(c.input, c.width)
		if !utf8.ValidString(right) {
			t.Errorf("%s: padRight(%q, %d) = %q, not valid UTF-8", c.name, c.input, c.width, right)
		}
		if w := lipgloss.Width(right); w != c.width {
			t.Errorf("%s: padRight(%q, %d) width = %d, want %d", c.name, c.input, c.width, w, c.width)
		}

		left := padLeft(c.input, c.width)
		if !utf8.ValidString(left) {
			t.Errorf("%s: padLeft(%q, %d) = %q, not valid UTF-8", c.name, c.input, c.width, left)
		}
		if w := lipgloss.Width(left); w != c.width {
			t.Errorf("%s: padLeft(%q, %d) width = %d, want %d", c.name, c.input, c.width, w, c.width)
		}
	}
}

func TestRenderRowNonASCIIPathsStayAligned(t *testing.T) {
	paths := []string{
		"https://example.com/api/café/orders",
		"https://example.com/ユーザー/list",
		"https://example.com/emoji/🚀/go",
	}
	widths := []int{30, 40, 60, 80}

	for _, p := range paths {
		ex := &inspect.Exchange{
			Kind: inspect.KindHTTP,
			Req: inspect.CapturedReq{
				Method: "GET",
				URL:    p,
				Header: http.Header{},
			},
			Resp: inspect.CapturedResp{Status: 200},
		}
		for _, w := range widths {
			row := renderRow(ex, w, false, false)
			if !utf8.ValidString(row) {
				t.Errorf("path=%q width=%d: rendered row is not valid UTF-8: %q", p, w, row)
			}
			if got := lipgloss.Width(row); got != w {
				t.Errorf("path=%q width=%d: lipgloss.Width(row) = %d, want %d", p, w, got, w)
			}
		}
	}
}

func TestRowPathHidesHostKeepsPath(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"absolute path only", "http://plain-juniper-54.ngstone.site/_next/static/chunks/_1anvha4._.js", "/_next/static/chunks/_1anvha4._.js"},
		{"absolute with query", "https://example.com/api/orders?id=7", "/api/orders?id=7"},
		{"root no path", "http://example.com", "/"},
		{"root with slash", "http://example.com/", "/"},
		{"already relative", "/_next/static/chunks/_1anvha4._.js", "/_next/static/chunks/_1anvha4._.js"},
	}
	for _, c := range cases {
		if got := rowPath(c.in); got != c.want {
			t.Errorf("%s: rowPath(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestRowPathMalformedFallsBackToRawWithoutPanic(t *testing.T) {
	malformed := []string{
		"http://[::1:bad",
		"://not-a-url",
		"%zz-invalid-escape",
	}
	for _, raw := range malformed {
		var got string
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("rowPath(%q) panicked: %v", raw, r)
				}
			}()
			got = rowPath(raw)
		}()
		if got != raw {
			t.Errorf("rowPath(%q) = %q, want raw fallback %q", raw, got, raw)
		}
	}
}

func TestRenderRowShowsPathNotFullURL(t *testing.T) {
	ex := &inspect.Exchange{
		Kind: inspect.KindHTTP,
		Req: inspect.CapturedReq{
			Method: "GET",
			URL:    "http://plain-juniper-54.ngstone.site/_next/static/chunks/_1anvha4._.js",
			Header: http.Header{},
		},
		Resp: inspect.CapturedResp{Status: 200},
	}
	row := renderRow(ex, 100, false, false)
	if strings.Contains(row, "plain-juniper-54") {
		t.Errorf("row still shows host: %q", row)
	}
	if !strings.Contains(row, "/_next/static/chunks/_1anvha4._.js") {
		t.Errorf("row missing path: %q", row)
	}
}

func TestRenderRowMalformedURLDoesNotPanicOrBlank(t *testing.T) {
	ex := &inspect.Exchange{
		Kind: inspect.KindHTTP,
		Req: inspect.CapturedReq{
			Method: "GET",
			URL:    "http://[::1:bad",
			Header: http.Header{},
		},
		Resp: inspect.CapturedResp{Status: 200},
	}
	var row string
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("renderRow panicked on malformed URL: %v", r)
			}
		}()
		row = renderRow(ex, 60, false, false)
	}()
	if strings.TrimSpace(row) == "" {
		t.Errorf("expected non-blank row for malformed URL, got %q", row)
	}
}

func TestListHeaderAlignsWithDataRow(t *testing.T) {
	ex := &inspect.Exchange{
		Kind: inspect.KindHTTP,
		Req: inspect.CapturedReq{
			Method: "GET",
			URL:    "https://example.com/api/orders?id=7",
			Header: http.Header{},
		},
		Resp: inspect.CapturedResp{Status: 200},
	}
	for _, w := range []int{30, 40, 60, 80, 100} {
		header := renderListHeader(w)
		row := renderRow(ex, w, false, false)
		if hw, rw := lipgloss.Width(header), lipgloss.Width(row); hw != rw {
			t.Errorf("width=%d: header width %d != row width %d", w, hw, rw)
		}
	}
}

func TestListHeaderContainsColumnLabels(t *testing.T) {
	header := renderListHeader(80)
	for _, want := range []string{"METHOD", "PATH", "STATUS", "TIME"} {
		if !strings.Contains(header, want) {
			t.Errorf("header %q missing column label %q", header, want)
		}
	}
}

func TestViewIncludesListHeader(t *testing.T) {
	m := newTestModel(t, []*inspect.Exchange{
		mkExchange("a", "GET", "https://example.com/api/orders", 200),
	})
	view := m.View()
	for _, want := range []string{"METHOD", "PATH", "STATUS", "TIME"} {
		if !strings.Contains(view, want) {
			t.Errorf("expected view to contain column label %q, view:\n%s", want, view)
		}
	}
}

func TestFilterMatchesPathNotHost(t *testing.T) {
	m := newTestModel(t, []*inspect.Exchange{
		mkExchange("a", "GET", "https://tenant-one.ngstone.site/api/orders", 200),
		mkExchange("b", "GET", "https://tenant-one.ngstone.site/api/users", 200),
	})

	m.filterQuery = "tenant-one"
	m.rebuildRows()
	if len(m.rows) != 0 {
		t.Fatalf("expected host substring to match nothing, got %d rows", len(m.rows))
	}

	m.filterQuery = "orders"
	m.rebuildRows()
	if len(m.rows) != 1 {
		t.Fatalf("expected path substring to match 1 row, got %d", len(m.rows))
	}
}

func TestRenderRowReplayGlyphsStayAligned(t *testing.T) {
	ex := &inspect.Exchange{
		Kind:     inspect.KindHTTP,
		Replayed: true,
		Req: inspect.CapturedReq{
			Method: "GET",
			URL:    "https://example.com/api/orders",
			Header: http.Header{},
		},
		Resp: inspect.CapturedResp{Status: 200},
	}

	for _, w := range []int{30, 40, 60} {
		row := renderRow(ex, w, false, false)
		if !utf8.ValidString(row) {
			t.Errorf("width=%d: replayed row not valid UTF-8: %q", w, row)
		}
		if got := lipgloss.Width(row); got != w {
			t.Errorf("width=%d: replayed row width = %d, want %d", w, got, w)
		}

		replayingRow := renderRow(ex, w, false, true)
		if !utf8.ValidString(replayingRow) {
			t.Errorf("width=%d: in-flight row not valid UTF-8: %q", w, replayingRow)
		}
		if got := lipgloss.Width(replayingRow); got != w {
			t.Errorf("width=%d: in-flight row width = %d, want %d", w, got, w)
		}
	}
}
