package tui

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"ngstone/internal/inspect"
)

func testKey(s string) tea.KeyMsg {
	switch s {
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

func newTestModel(t *testing.T, exchanges []*inspect.Exchange) Model {
	t.Helper()
	store := inspect.NewStore()
	for _, ex := range exchanges {
		store.Add(ex)
	}
	m := New(Options{Store: store})
	m.width = 100
	m.height = 40
	m.recomputeLayout()
	return m
}

func mkExchange(id, method, path string, status int) *inspect.Exchange {
	return &inspect.Exchange{
		ID:   id,
		Kind: inspect.KindHTTP,
		Req: inspect.CapturedReq{
			Method: method,
			URL:    path,
			Header: http.Header{},
		},
		Resp: inspect.CapturedResp{
			Status: status,
			Header: http.Header{},
		},
	}
}

func TestExchangeMsgAppendsAndKeepsSelection(t *testing.T) {
	m := newTestModel(t, []*inspect.Exchange{
		mkExchange("a", "GET", "/a", 200),
		mkExchange("b", "GET", "/b", 200),
	})

	if len(m.rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(m.rows))
	}

	m.cursor = 1
	m.selectedID = m.rows[1].ID
	selectedBefore := m.selectedID

	newEx := mkExchange("c", "POST", "/c", 201)
	updated, _ := m.Update(exchangeMsg{ex: newEx})
	m2 := updated.(Model)

	if got := len(m2.all); got != 3 {
		t.Fatalf("expected 3 total exchanges, got %d", got)
	}
	if m2.totalSeen != 3 {
		t.Fatalf("expected totalSeen 3, got %d", m2.totalSeen)
	}
	if m2.rows[0].ID != "c" {
		t.Fatalf("expected newest row at top, got %s", m2.rows[0].ID)
	}
	if m2.selectedID != selectedBefore {
		t.Fatalf("expected selectedID to remain %s, got %s", selectedBefore, m2.selectedID)
	}
	if m2.cursor < 0 || m2.cursor >= len(m2.rows) || m2.rows[m2.cursor].ID != selectedBefore {
		t.Fatalf("expected cursor to point at row %s, cursor=%d rows=%v", selectedBefore, m2.cursor, rowIDs(m2.rows))
	}
}

func rowIDs(rows []*inspect.Exchange) []string {
	ids := make([]string, len(rows))
	for i, ex := range rows {
		ids[i] = ex.ID
	}
	return ids
}

func TestNavigationBounds(t *testing.T) {
	m := newTestModel(t, []*inspect.Exchange{
		mkExchange("a", "GET", "/a", 200),
		mkExchange("b", "GET", "/b", 200),
		mkExchange("c", "GET", "/c", 200),
	})

	if m.cursor != 0 {
		t.Fatalf("expected initial cursor 0, got %d", m.cursor)
	}

	updated, _ := m.handleKey(testKey("up"))
	if updated.cursor != 0 {
		t.Fatalf("up at top should be no-op, cursor=%d", updated.cursor)
	}

	updated, _ = updated.handleKey(testKey("down"))
	if updated.cursor != 1 {
		t.Fatalf("expected cursor 1 after one down, got %d", updated.cursor)
	}

	updated, _ = updated.handleKey(testKey("down"))
	if updated.cursor != 2 {
		t.Fatalf("expected cursor 2 after two downs, got %d", updated.cursor)
	}

	updated, _ = updated.handleKey(testKey("down"))
	if updated.cursor != 2 {
		t.Fatalf("down at bottom should be no-op, cursor=%d", updated.cursor)
	}

	updated, _ = updated.handleKey(testKey("up"))
	if updated.cursor != 1 {
		t.Fatalf("expected cursor 1 after one up from bottom, got %d", updated.cursor)
	}
}

func TestFilterNarrowsRows(t *testing.T) {
	m := newTestModel(t, []*inspect.Exchange{
		mkExchange("a", "GET", "/foo", 200),
		mkExchange("b", "POST", "/bar", 500),
		mkExchange("c", "GET", "/baz", 404),
	})

	if len(m.rows) != 3 {
		t.Fatalf("expected 3 rows initially, got %d", len(m.rows))
	}

	m.filterQuery = "GET"
	m.rebuildRows()
	if len(m.rows) != 2 {
		t.Fatalf("expected 2 rows for method filter, got %d", len(m.rows))
	}

	m.filterQuery = "5xx"
	m.rebuildRows()
	if len(m.rows) != 1 {
		t.Fatalf("expected 1 row for status-class filter, got %d", len(m.rows))
	}

	m.filterQuery = "baz"
	m.rebuildRows()
	if len(m.rows) != 1 {
		t.Fatalf("expected 1 row for substring filter, got %d", len(m.rows))
	}

	m.filterQuery = ""
	m.rebuildRows()
	if len(m.rows) != 3 {
		t.Fatalf("expected 3 rows after clearing filter, got %d", len(m.rows))
	}
}

func TestResizeToTinySizeDoesNotPanic(t *testing.T) {
	m := newTestModel(t, []*inspect.Exchange{
		mkExchange("a", "GET", "/foo", 200),
	})

	updated, _ := m.Update(tea.WindowSizeMsg{Width: 1, Height: 1})
	m2 := updated.(Model)

	_ = m2.View()
}

func TestAllBoundedAtRingSizeWithoutReconcile(t *testing.T) {
	m := newTestModel(t, nil)

	total := inspect.RingSize + 50
	for i := 0; i < total; i++ {
		ex := mkExchange(fmt.Sprintf("id-%d", i), "GET", fmt.Sprintf("/r/%d", i), 200)
		updated, _ := m.Update(exchangeMsg{ex: ex})
		m = updated.(Model)
	}

	if len(m.all) != inspect.RingSize {
		t.Fatalf("expected m.all bounded to %d, got %d", inspect.RingSize, len(m.all))
	}

	wantOldest := fmt.Sprintf("id-%d", total-inspect.RingSize)
	wantNewest := fmt.Sprintf("id-%d", total-1)
	if m.all[0].ID != wantOldest {
		t.Fatalf("expected oldest retained entry %s, got %s", wantOldest, m.all[0].ID)
	}
	if m.all[len(m.all)-1].ID != wantNewest {
		t.Fatalf("expected newest retained entry %s, got %s", wantNewest, m.all[len(m.all)-1].ID)
	}
}

func TestResizeThenNormalViewDoesNotPanic(t *testing.T) {
	m := newTestModel(t, []*inspect.Exchange{
		mkExchange("a", "GET", "/foo", 200),
	})

	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m2 := updated.(Model)

	if m2.width != 120 || m2.height != 40 {
		t.Fatalf("expected width/height updated, got %d/%d", m2.width, m2.height)
	}

	_ = m2.View()
}

func TestDiffShortcutFindsReplayPair(t *testing.T) {
	original := mkExchange("original", "GET", "/items", 200)
	original.Resp.Body = []byte("one")
	replay := mkExchange("replay", "GET", "/items", 500)
	replay.Replayed = true
	replay.ReplayOf = original.ID
	replay.Resp.Body = []byte("two")
	m := newTestModel(t, []*inspect.Exchange{original, replay})
	m.cursor = 0
	m.selectedID = m.rows[0].ID
	updated, _ := m.handleKey(testKey("d"))
	if updated.diffText == "" {
		t.Fatal("diff shortcut did not render a response diff")
	}
	if !strings.Contains(updated.diffText, "500") {
		t.Fatalf("diff = %q, want replay status", updated.diffText)
	}
}
