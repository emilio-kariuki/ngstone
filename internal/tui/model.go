package tui

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"ngstone/internal/inspect"
)

type focusTarget int

const (
	focusList focusTarget = iota
	focusDetail
)

const (
	minWidth  = 40
	minHeight = 8

	headerHeight  = 3
	footerHeight  = 1
	logPaneHeight = 6
)

type Model struct {
	store    *inspect.Store
	target   *url.URL
	rt       http.RoundTripper
	statusCh <-chan StatusEvent
	logs     *LogRing

	sub   <-chan *inspect.Exchange
	unsub func()

	all  []*inspect.Exchange
	rows []*inspect.Exchange

	selectedID string
	cursor     int

	filterActive bool
	filterInput  textinput.Model
	filterQuery  string

	focus      focusTarget
	detailVP   viewport.Model
	listHeight int

	status      StatusEvent
	tunnels     []Tunnel
	statuses    map[string]StatusEvent
	lastLatency time.Duration
	totalSeen   int

	showLogs bool
	showHelp bool

	editing  bool
	editForm editFormModel

	replaying map[string]struct{}

	width, height int

	err      string
	notice   string
	diffText string
}

type exchangeMsg struct{ ex *inspect.Exchange }
type subClosedMsg struct{}
type statusMsg struct{ ev StatusEvent }
type reconcileMsg struct{ t time.Time }
type replayResultMsg struct {
	sourceID string
	ex       *inspect.Exchange
	err      error
}

func New(opts Options) Model {
	sub, unsub := opts.Store.Subscribe()

	fi := textinput.New()
	fi.Placeholder = "method, 2xx/3xx/4xx/5xx, or substring"

	m := Model{
		store:       opts.Store,
		target:      opts.Target,
		rt:          opts.RT,
		statusCh:    opts.Status,
		logs:        opts.Logs,
		sub:         sub,
		unsub:       unsub,
		filterInput: fi,
		detailVP:    viewport.New(0, 0),
		replaying:   make(map[string]struct{}),
		editForm:    newEditForm(),
		tunnels:     opts.Tunnels,
		statuses:    make(map[string]StatusEvent),
	}

	m.all = opts.Store.List()
	m.totalSeen = len(m.all)
	m.rebuildRows()

	return m
}

func waitForExchange(ch <-chan *inspect.Exchange) tea.Cmd {
	return func() tea.Msg {
		ex, ok := <-ch
		if !ok {
			return subClosedMsg{}
		}
		return exchangeMsg{ex}
	}
}

func waitForStatus(ch <-chan StatusEvent) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return nil
		}
		return statusMsg{ev}
	}
}

func tickReconcile() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg { return reconcileMsg{t} })
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(waitForExchange(m.sub), waitForStatus(m.statusCh), tickReconcile())
}

func (m *Model) rebuildRows() {
	newest := make([]*inspect.Exchange, 0, len(m.all))
	for i := len(m.all) - 1; i >= 0; i-- {
		newest = append(newest, m.all[i])
	}
	filtered := newest
	if m.filterQuery != "" {
		filtered = filtered[:0:0]
		for _, ex := range newest {
			if matchFilter(m.filterQuery, ex) {
				filtered = append(filtered, ex)
			}
		}
	}
	m.rows = filtered
	m.reconcileCursor()
}

func (m *Model) reconcileCursor() {
	if len(m.rows) == 0 {
		m.selectedID = ""
		m.cursor = 0
		return
	}
	for i, ex := range m.rows {
		if ex.ID == m.selectedID {
			m.cursor = i
			return
		}
	}
	if m.cursor >= len(m.rows) {
		m.cursor = len(m.rows) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	m.selectedID = m.rows[m.cursor].ID
}

// headerLines is the header's height: three lines for one tunnel, or two
// plus one per tunnel when several run in one process.
func (m Model) headerLines() int {
	if len(m.tunnels) > 0 {
		return 2 + len(m.tunnels)
	}
	return headerHeight
}

// replayTarget picks where an exchange is replayed: the target of the
// tunnel that captured it, or the single tunnel's target.
func (m Model) replayTarget(ex *inspect.Exchange) (*url.URL, http.RoundTripper) {
	if ex != nil && ex.Tunnel != "" {
		for _, t := range m.tunnels {
			if t.Name == ex.Tunnel {
				return t.Target, t.RT
			}
		}
	}
	return m.target, m.rt
}

func (m *Model) recomputeLayout() {
	avail := m.height - m.headerLines() - footerHeight
	if avail < 0 {
		avail = 0
	}
	if m.showLogs {
		avail -= logPaneHeight
		if avail < 0 {
			avail = 0
		}
	}
	avail -= listHeaderRows
	if avail < 0 {
		avail = 0
	}
	listH := avail / 2
	detailH := avail - listH
	if listH < 0 {
		listH = 0
	}
	if detailH < 0 {
		detailH = 0
	}
	m.listHeight = listH
	m.detailVP.Width = max(0, m.width-2)
	m.detailVP.Height = detailH
}

func (m Model) selectedExchange() *inspect.Exchange {
	if m.cursor < 0 || m.cursor >= len(m.rows) {
		return nil
	}
	return m.rows[m.cursor]
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case exchangeMsg:
		return m.handleExchange(msg.ex)
	case subClosedMsg:
		return m, nil
	case statusMsg:
		if msg.ev.Tunnel != "" {
			m.statuses[msg.ev.Tunnel] = msg.ev
		} else {
			m.status = msg.ev
		}
		return m, waitForStatus(m.statusCh)
	case reconcileMsg:
		m.all = m.store.List()
		if len(m.all) > m.totalSeen {
			m.totalSeen = len(m.all)
		}
		m.rebuildRows()
		return m, tickReconcile()
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.recomputeLayout()
		m.filterInput.Width = max(0, m.width-4)
		m.editForm.setWidth(max(0, m.width-4))
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	case replayResultMsg:
		delete(m.replaying, msg.sourceID)
		if msg.err != nil {
			m.err = msg.err.Error()
		} else {
			m.err = ""
		}
		return m, nil
	}
	return m, nil
}

func (m Model) handleExchange(ex *inspect.Exchange) (Model, tea.Cmd) {
	found := false
	for i, e := range m.all {
		if e.ID == ex.ID {
			m.all[i] = ex
			found = true
			break
		}
	}
	if !found {
		m.all = append(m.all, ex)
		m.totalSeen++
		m.trimAll()
	}
	if ex.Kind == inspect.KindHTTP && ex.Resp.Status != 0 {
		m.lastLatency = ex.Duration
	}
	delete(m.replaying, ex.ID)
	m.rebuildRows()
	return m, waitForExchange(m.sub)
}

func (m *Model) trimAll() {
	if len(m.all) <= inspect.RingSize {
		return
	}
	excess := len(m.all) - inspect.RingSize
	copy(m.all, m.all[excess:])
	for i := inspect.RingSize; i < len(m.all); i++ {
		m.all[i] = nil
	}
	m.all = m.all[:inspect.RingSize]
}

func (m Model) handleKey(msg tea.KeyMsg) (Model, tea.Cmd) {
	if m.filterActive {
		return m.handleFilterKey(msg)
	}
	if m.editing {
		return m.handleEditKey(msg)
	}

	switch msg.String() {
	case "up", "k", "down", "j", "pgup", "pgdown":
		return m.handleNavKey(msg)
	case "tab":
		if m.focus == focusList {
			m.focus = focusDetail
		} else {
			m.focus = focusList
		}
	case "r":
		return m.handleReplayKey()
	case "c":
		return m.handleCurlKey(false)
	case "C":
		return m.handleCurlKey(true)
	case "d":
		return m.handleDiffKey()
	case "s":
		return m.handleSaveKey()
	case "e":
		if ex := m.selectedExchange(); ex != nil && ex.Kind != inspect.KindUpgrade {
			m.editing = true
			m.editForm.populate(ex)
		}
	case "/":
		m.filterActive = true
		m.filterInput.SetValue(m.filterQuery)
		m.filterInput.CursorEnd()
		m.filterInput.Focus()
	case "l":
		m.showLogs = !m.showLogs
		m.recomputeLayout()
	case "?":
		m.showHelp = !m.showHelp
	case "q", "ctrl+c":
		return m, tea.Quit
	}
	return m, nil
}

func (m Model) handleNavKey(msg tea.KeyMsg) (Model, tea.Cmd) {
	m.diffText = ""
	if m.focus == focusDetail {
		var cmd tea.Cmd
		m.detailVP, cmd = m.detailVP.Update(msg)
		return m, cmd
	}
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
			m.selectedID = m.rows[m.cursor].ID
		}
	case "down", "j":
		if m.cursor < len(m.rows)-1 {
			m.cursor++
			m.selectedID = m.rows[m.cursor].ID
		}
	}
	return m, nil
}

func (m Model) handleReplayKey() (Model, tea.Cmd) {
	ex := m.selectedExchange()
	if ex == nil || ex.Kind == inspect.KindUpgrade {
		return m, nil
	}
	if _, busy := m.replaying[ex.ID]; busy {
		return m, nil
	}
	m.replaying[ex.ID] = struct{}{}
	target, rt := m.replayTarget(ex)
	return m, replayCmd(m.store, target, rt, ex.ID, nil)
}

func (m Model) handleFilterKey(msg tea.KeyMsg) (Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		m.filterQuery = strings.TrimSpace(m.filterInput.Value())
		m.filterActive = false
		m.diffText = ""
		m.rebuildRows()
		return m, nil
	case "esc":
		m.filterActive = false
		return m, nil
	}
	var cmd tea.Cmd
	m.filterInput, cmd = m.filterInput.Update(msg)
	return m, cmd
}

func (m Model) handleEditKey(msg tea.KeyMsg) (Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.editing = false
		return m, nil
	case "ctrl+s":
		sourceID := m.editForm.sourceID
		ov := m.editForm.overrides()
		m.editing = false
		m.diffText = ""
		m.replaying[sourceID] = struct{}{}
		source, _ := m.store.Get(sourceID)
		target, rt := m.replayTarget(source)
		return m, replayCmd(m.store, target, rt, sourceID, ov)
	}
	var cmd tea.Cmd
	m.editForm, cmd = m.editForm.Update(msg)
	return m, cmd
}

func (m Model) handleCurlKey(includeSensitive bool) (Model, tea.Cmd) {
	ex := m.selectedExchange()
	if ex == nil {
		return m, nil
	}
	command, err := inspect.BuildCurl(ex, inspect.CurlOptions{IncludeSensitive: includeSensitive})
	if err != nil {
		m.err = err.Error()
		return m, nil
	}
	if err := copyToClipboard(command); err != nil {
		m.err = "copy cURL failed: " + err.Error() + "; command: " + command
		return m, nil
	}
	m.err = ""
	if includeSensitive {
		m.notice = "copied cURL with sensitive headers"
	} else {
		m.notice = "copied redacted cURL; press C to include sensitive headers"
	}
	return m, nil
}

func (m Model) handleDiffKey() (Model, tea.Cmd) {
	if m.diffText != "" {
		m.diffText = ""
		return m, nil
	}
	ex := m.selectedExchange()
	if ex == nil || ex.Kind == inspect.KindUpgrade {
		return m, nil
	}
	original, replay := m.replayPair(ex)
	if original == nil || replay == nil {
		m.err = "no replay response found; press r first"
		return m, nil
	}
	diff, err := inspect.DiffResponses(original, replay)
	if err != nil {
		m.err = err.Error()
		return m, nil
	}
	m.err = ""
	m.diffText = diff
	m.notice = "response diff shown; press d or move selection to close"
	return m, nil
}

func (m Model) replayPair(ex *inspect.Exchange) (*inspect.Exchange, *inspect.Exchange) {
	if ex == nil {
		return nil, nil
	}
	if ex.ReplayOf != "" {
		original, ok := m.store.Get(ex.ReplayOf)
		if ok {
			return original, ex
		}
	}
	for i := len(m.all) - 1; i >= 0; i-- {
		candidate := m.all[i]
		if candidate != nil && candidate.ReplayOf == ex.ID {
			return ex, candidate
		}
	}
	return nil, nil
}

func (m Model) handleSaveKey() (Model, tea.Cmd) {
	ex := m.selectedExchange()
	if ex == nil {
		return m, nil
	}
	path := fmt.Sprintf("ngstone-replay-%s.json", ex.ID)
	if err := inspect.SaveReplay(path, ex); err != nil {
		m.err = "save replay failed: " + err.Error()
		return m, nil
	}
	m.err = ""
	m.notice = "saved replay file " + path
	return m, nil
}

func (m Model) View() string {
	if m.width < minWidth || m.height < minHeight {
		return "ngstone: terminal too small\n"
	}

	sections := []string{m.renderHeader()}

	if m.editing {
		sections = append(sections, m.editForm.View())
	} else if m.filterActive {
		sections = append(sections, "Filter: "+m.filterInput.View())
	}

	sections = append(sections, renderListHeader(m.width))
	sections = append(sections, renderList(&m))

	if m.diffText != "" {
		m.detailVP.SetContent(m.diffText)
	} else {
		m.detailVP.SetContent(buildDetail(m.selectedExchange()))
	}
	sections = append(sections, m.detailVP.View())

	if m.showLogs && m.logs != nil {
		sections = append(sections, m.renderLogPane())
	}

	if m.showHelp {
		sections = append(sections, m.renderHelp())
	} else {
		sections = append(sections, m.renderFooter())
	}

	if m.err != "" {
		sections = append(sections, errorStyle.Render(m.err))
	}
	if m.notice != "" {
		sections = append(sections, helpStyle.Render(m.notice))
	}

	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

func (m Model) renderHeader() string {
	title := headerTitleStyle.Render("ngstone")
	hint := "(Ctrl+C quit)"
	gap := m.width - len("ngstone") - len(hint)
	if gap < 1 {
		gap = 1
	}
	line1 := title + strings.Repeat(" ", gap) + hint

	state := m.status.State
	if state == "" {
		state = "connecting"
	}
	line2 := fmt.Sprintf("Session %s   Latency %s", stateStyle(state).Render(state), m.lastLatency.Round(time.Millisecond))

	fwdURL := m.status.URL
	if fwdURL == "" {
		fwdURL = "connecting..."
	}
	target := ""
	if m.target != nil {
		target = m.target.String()
	}

	inFlight := 0
	for _, ex := range m.all {
		if ex.Kind == inspect.KindHTTP && ex.Resp.Status == 0 && ex.Err == "" {
			inFlight++
		}
		if ex.Kind == inspect.KindUpgrade && ex.Err == "" {
			inFlight++
		}
	}

	if len(m.tunnels) > 0 {
		return m.renderTunnelsHeader(line1, inFlight)
	}

	line3 := fmt.Sprintf("Forwarding %s -> %s   %d total · %d in-flight", fwdURL, target, m.totalSeen, inFlight)

	return lipgloss.JoinVertical(lipgloss.Left, line1, line2, line3)
}

func (m Model) renderTunnelsHeader(line1 string, inFlight int) string {
	online := 0
	nameWidth := 0
	for _, t := range m.tunnels {
		if m.statuses[t.Name].State == "online" {
			online++
		}
		nameWidth = max(nameWidth, len(t.Name))
	}
	lines := []string{
		line1,
		fmt.Sprintf("%d of %d tunnels online   Latency %s   %d total · %d in-flight",
			online, len(m.tunnels), m.lastLatency.Round(time.Millisecond), m.totalSeen, inFlight),
	}
	for _, t := range m.tunnels {
		st := m.statuses[t.Name]
		state := st.State
		if state == "" {
			state = "connecting"
		}
		fwd := st.URL
		if fwd == "" {
			fwd = "…"
		}
		target := ""
		if t.Target != nil {
			target = t.Target.String()
		}
		line := fmt.Sprintf("%-*s  %s  %s -> %s", nameWidth, t.Name, stateStyle(state).Render(fmt.Sprintf("%-12s", state)), fwd, target)
		if st.Err != nil && state != "online" {
			line += "  " + st.Err.Error()
		}
		lines = append(lines, line)
	}
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func (m Model) renderFooter() string {
	return footerStyle.Render("↑↓ select   r replay   e edit   c cURL   d diff   s save   / filter   l logs   q quit   ? help")
}

func (m Model) renderHelp() string {
	h := help.New()
	h.Width = m.width
	h.ShowAll = true
	return h.View(keys)
}

func (m Model) renderLogPane() string {
	lines := m.logs.Lines()
	if len(lines) > logPaneHeight {
		lines = lines[len(lines)-logPaneHeight:]
	}
	for len(lines) < logPaneHeight {
		lines = append([]string{""}, lines...)
	}
	return strings.Join(lines, "\n")
}
