package tui

import (
	"context"
	"log/slog"
	"strings"
	"sync"
)

type LogRing struct {
	mu    sync.Mutex
	lines []string
	cap   int
	start int
	count int
	level slog.Leveler
}

func NewLogRing(capacity int) *LogRing {
	if capacity <= 0 {
		capacity = 500
	}
	return &LogRing{
		lines: make([]string, capacity),
		cap:   capacity,
	}
}

func (r *LogRing) Enabled(ctx context.Context, level slog.Level) bool {
	if r.level == nil {
		return true
	}
	return level >= r.level.Level()
}

func (r *LogRing) Handle(ctx context.Context, rec slog.Record) error {
	return (&logRingHandler{ring: r}).Handle(ctx, rec)
}

func (r *LogRing) WithAttrs(attrs []slog.Attr) slog.Handler {
	return (&logRingHandler{ring: r}).WithAttrs(attrs)
}

func (r *LogRing) WithGroup(name string) slog.Handler {
	return (&logRingHandler{ring: r}).WithGroup(name)
}

func (r *LogRing) Lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, r.count)
	for i := 0; i < r.count; i++ {
		out[i] = r.lines[(r.start+i)%r.cap]
	}
	return out
}

func (r *LogRing) push(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := (r.start + r.count) % r.cap
	r.lines[idx] = line
	if r.count < r.cap {
		r.count++
	} else {
		r.start = (r.start + 1) % r.cap
	}
}

type logRingHandler struct {
	ring   *LogRing
	prefix string
	group  string
}

func (h *logRingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.ring.Enabled(ctx, level)
}

func (h *logRingHandler) Handle(ctx context.Context, rec slog.Record) error {
	var b strings.Builder
	b.WriteString(rec.Time.Format("15:04:05"))
	b.WriteByte(' ')
	b.WriteString(rec.Level.String())
	b.WriteByte(' ')
	b.WriteString(rec.Message)
	b.WriteString(h.prefix)
	rec.Attrs(func(a slog.Attr) bool {
		b.WriteByte(' ')
		if h.group != "" {
			b.WriteString(h.group)
			b.WriteByte('.')
		}
		b.WriteString(a.Key)
		b.WriteByte('=')
		b.WriteString(a.Value.String())
		return true
	})
	h.ring.push(b.String())
	return nil
}

func (h *logRingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	return &logRingHandler{
		ring:   h.ring,
		prefix: h.prefix + formatAttrsWithGroup(h.group, attrs),
		group:  h.group,
	}
}

func (h *logRingHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	g := name
	if h.group != "" {
		g = h.group + "." + name
	}
	return &logRingHandler{ring: h.ring, prefix: h.prefix, group: g}
}

func formatAttrsWithGroup(group string, attrs []slog.Attr) string {
	var b strings.Builder
	for _, a := range attrs {
		b.WriteByte(' ')
		if group != "" {
			b.WriteString(group)
			b.WriteByte('.')
		}
		b.WriteString(a.Key)
		b.WriteByte('=')
		b.WriteString(a.Value.String())
	}
	return b.String()
}
