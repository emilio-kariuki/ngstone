package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"ngstone/internal/inspect"
)

const (
	methodColWidth = 9
	statusColWidth = 5
	timeColWidth   = 11
)

const (
	glyphReplayed  = "↺"
	glyphReplaying = "~"
)

func rowMethod(ex *inspect.Exchange) string {
	if ex.Kind == inspect.KindUpgrade {
		return "WS"
	}
	return ex.Req.Method
}

func rowMarker(ex *inspect.Exchange, replaying bool) string {
	switch {
	case replaying:
		return glyphReplaying
	case ex.Replayed:
		return glyphReplayed
	default:
		return ""
	}
}

func rowStatusCol(ex *inspect.Exchange) string {
	if ex.Resp.Status == 0 {
		if ex.Err != "" {
			return "ERR"
		}
		return "..."
	}
	return fmt.Sprintf("%d", ex.Resp.Status)
}

func rowTimeCol(ex *inspect.Exchange) string {
	if ex.Kind == inspect.KindUpgrade {
		return fmtBytes(ex.BytesClientToApp) + "/" + fmtBytes(ex.BytesAppToClient)
	}
	if ex.Resp.Status == 0 {
		return "-"
	}
	return ex.Duration.Round(time.Millisecond).String()
}

func fmtBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for n1 := n / unit; n1 >= unit; n1 /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func runeCellWidth(r rune) int {
	return lipgloss.Width(string(r))
}

func truncateCells(s string, width int) string {
	if width <= 0 {
		return ""
	}
	var b strings.Builder
	acc := 0
	for _, r := range s {
		rw := runeCellWidth(r)
		if acc+rw > width {
			break
		}
		b.WriteRune(r)
		acc += rw
	}
	for acc < width {
		b.WriteByte(' ')
		acc++
	}
	return b.String()
}

func padRight(s string, width int) string {
	if width <= 0 {
		return ""
	}
	w := lipgloss.Width(s)
	if w >= width {
		return truncateCells(s, width)
	}
	return s + strings.Repeat(" ", width-w)
}

func padLeft(s string, width int) string {
	if width <= 0 {
		return ""
	}
	w := lipgloss.Width(s)
	if w >= width {
		return truncateCells(s, width)
	}
	return strings.Repeat(" ", width-w) + s
}

func truncatePath(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}
	budget := width - 1
	var b strings.Builder
	acc := 0
	for _, r := range s {
		rw := runeCellWidth(r)
		if acc+rw > budget {
			break
		}
		b.WriteRune(r)
		acc += rw
	}
	return b.String() + "…"
}

func renderRow(ex *inspect.Exchange, width int, selected bool, replaying bool) string {
	method := rowMethod(ex)
	marker := rowMarker(ex, replaying)
	methodField := padRight(marker+method, methodColWidth)
	statusField := padLeft(rowStatusCol(ex), statusColWidth)
	timeField := padLeft(rowTimeCol(ex), timeColWidth)

	prefix := "  "
	if selected {
		prefix = "> "
	}

	pathWidth := width - len(prefix) - methodColWidth - statusColWidth - timeColWidth
	if pathWidth < 0 {
		pathWidth = 0
	}
	path := padRight(truncatePath(ex.Req.URL, pathWidth), pathWidth)

	line := prefix +
		methodStyle(method).Render(methodField) +
		path +
		statusStyle(ex.Resp.Status).Render(statusField) +
		timeField

	if selected {
		return selectedRowStyle.Render(line)
	}
	return line
}

func visibleRowWindow(total, height, cursor int) (start, end int) {
	if height <= 0 {
		return 0, 0
	}
	if total <= height {
		return 0, total
	}
	start = cursor - height/2
	if start < 0 {
		start = 0
	}
	end = start + height
	if end > total {
		end = total
		start = end - height
		if start < 0 {
			start = 0
		}
	}
	return start, end
}

func renderList(m *Model) string {
	if m.listHeight <= 0 {
		return ""
	}
	start, end := visibleRowWindow(len(m.rows), m.listHeight, m.cursor)
	lines := make([]string, 0, m.listHeight)
	for i := start; i < end; i++ {
		ex := m.rows[i]
		_, replaying := m.replaying[ex.ID]
		lines = append(lines, renderRow(ex, m.width, i == m.cursor, replaying))
	}
	for len(lines) < m.listHeight {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}
