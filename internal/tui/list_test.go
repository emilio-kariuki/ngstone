package tui

import (
	"net/http"
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
