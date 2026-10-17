package tui

import (
	"net/http"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"ngstone/internal/inspect"
)

const (
	editFocusMethod = iota
	editFocusURL
	editFocusHeaders
	editFocusBody
	editFocusCount
)

type editFormModel struct {
	sourceID string
	method   textinput.Model
	url      textinput.Model
	headers  textarea.Model
	body     textarea.Model
	focus    int

	// The textarea sanitizes what it holds (CR and LF each become a newline,
	// tabs become spaces, control bytes and invalid UTF-8 are dropped, and it
	// caps the line count), so its value is not a faithful copy of the
	// captured bytes. The *Init fields hold the value as loaded: a field left
	// unchanged is sent as no override, so replay uses the captured bytes. A
	// field the textarea cannot hold faithfully is locked instead of edited.
	headersInit   string
	headersLocked bool
	bodyInit      string
	bodyLocked    bool
	bodyNote      string
}

const (
	noteBodyTruncated = "(captured body was truncated, so it cannot be edited or replayed)"
	noteBodyLossy     = "(body has bytes the editor cannot preserve, such as binary data, tabs or CR; it is replayed unchanged)"
)

func newEditForm() editFormModel {
	method := textinput.New()
	method.Placeholder = "GET"
	u := textinput.New()
	u.Placeholder = "https://..."
	headers := textarea.New()
	headers.Placeholder = "key: value"
	body := textarea.New()
	return editFormModel{
		method:  method,
		url:     u,
		headers: headers,
		body:    body,
	}
}

func headersToLines(h http.Header) string {
	if len(h) == 0 {
		return ""
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		for _, v := range h[k] {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func parseHeaderLines(s string) http.Header {
	h := make(http.Header)
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if key == "" {
			continue
		}
		h.Add(key, val)
	}
	return h
}

func (f *editFormModel) populate(ex *inspect.Exchange) {
	f.sourceID = ex.ID
	f.method.SetValue(ex.Req.Method)
	f.url.SetValue(ex.Req.URL)
	headerText := headersToLines(ex.Req.Header)
	f.headers.SetValue(headerText)
	f.headersInit = f.headers.Value()
	f.headersLocked = f.headersInit != headerText

	f.body.SetValue(string(ex.Req.Body))
	f.bodyInit = f.body.Value()
	f.bodyLocked, f.bodyNote = false, ""
	switch {
	case ex.Req.Truncated:
		f.bodyLocked, f.bodyNote = true, noteBodyTruncated
	case f.bodyInit != string(ex.Req.Body):
		f.bodyLocked, f.bodyNote = true, noteBodyLossy
	}

	f.focus = editFocusMethod
	f.applyFocus()
}

func (f *editFormModel) applyFocus() {
	f.method.Blur()
	f.url.Blur()
	f.headers.Blur()
	f.body.Blur()
	switch f.focus {
	case editFocusMethod:
		f.method.Focus()
	case editFocusURL:
		f.url.Focus()
	case editFocusHeaders:
		f.headers.Focus()
	case editFocusBody:
		f.body.Focus()
	}
}

func (f *editFormModel) setWidth(w int) {
	if w < 0 {
		w = 0
	}
	f.method.Width = w
	f.url.Width = w
	f.headers.SetWidth(w)
	f.body.SetWidth(w)
}

func (f editFormModel) Update(msg tea.Msg) (editFormModel, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		switch keyMsg.String() {
		case "tab":
			f.focus = (f.focus + 1) % editFocusCount
			f.applyFocus()
			return f, nil
		case "shift+tab":
			f.focus = (f.focus - 1 + editFocusCount) % editFocusCount
			f.applyFocus()
			return f, nil
		}
	}

	var cmd tea.Cmd
	switch f.focus {
	case editFocusMethod:
		f.method, cmd = f.method.Update(msg)
	case editFocusURL:
		f.url, cmd = f.url.Update(msg)
	case editFocusHeaders:
		if !f.headersLocked {
			f.headers, cmd = f.headers.Update(msg)
		}
	case editFocusBody:
		if !f.bodyLocked {
			f.body, cmd = f.body.Update(msg)
		}
	}
	return f, cmd
}

func (f editFormModel) overrides() *inspect.Overrides {
	ov := &inspect.Overrides{
		Method: strings.TrimSpace(f.method.Value()),
		URL:    strings.TrimSpace(f.url.Value()),
	}
	// A nil Header or Body tells Replay to use the captured bytes, which also
	// keeps its ErrTruncatedBody guard in force for truncated captures.
	if !f.headersLocked && f.headers.Value() != f.headersInit {
		ov.Header = parseHeaderLines(f.headers.Value())
	}
	if !f.bodyLocked && f.body.Value() != f.bodyInit {
		ov.Body = []byte(f.body.Value())
	}
	return ov
}

func (f editFormModel) View() string {
	var b strings.Builder
	b.WriteString("Method: ")
	b.WriteString(f.method.View())
	b.WriteString("\n")
	b.WriteString("URL: ")
	b.WriteString(f.url.View())
	b.WriteString("\n")
	b.WriteString("Headers:")
	if f.headersLocked {
		b.WriteString(" (cannot be edited without changing them; replayed unchanged)")
	}
	b.WriteString("\n")
	b.WriteString(f.headers.View())
	b.WriteString("\n")
	b.WriteString("Body:")
	if f.bodyNote != "" {
		b.WriteString(" ")
		b.WriteString(f.bodyNote)
	}
	b.WriteString("\n")
	b.WriteString(f.body.View())
	return b.String()
}
