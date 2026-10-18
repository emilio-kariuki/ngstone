package edge

import (
	"context"
	"sync"
	"time"

	"ngstone/internal/storage"
)

type opsEvent struct {
	At      time.Time         `json:"at"`
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
}

type eventRing struct {
	mu       sync.RWMutex
	capacity int
	entries  []opsEvent
}

func newEventRing(capacity int) *eventRing {
	if capacity < 1 {
		capacity = 1
	}
	return &eventRing{capacity: capacity}
}

func (r *eventRing) add(level, message string, fields map[string]string) {
	if r == nil {
		return
	}
	entry := opsEvent{At: time.Now().UTC(), Level: level, Message: message}
	if len(fields) > 0 {
		entry.Fields = make(map[string]string, len(fields))
		for key, value := range fields {
			entry.Fields[key] = value
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) == r.capacity {
		copy(r.entries, r.entries[1:])
		r.entries[len(r.entries)-1] = entry
		return
	}
	r.entries = append(r.entries, entry)
}

func (r *eventRing) snapshot() []opsEvent {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]opsEvent, len(r.entries))
	for i, entry := range r.entries {
		out[i] = entry
		if entry.Fields != nil {
			out[i].Fields = make(map[string]string, len(entry.Fields))
			for key, value := range entry.Fields {
				out[i].Fields[key] = value
			}
		}
	}
	return out
}

func (s *Server) recordEvent(level, message string, fields map[string]string) {
	if s == nil {
		return
	}
	if s.events == nil {
		s.events = newEventRing(200)
	}
	s.events.add(level, message, fields)
	if s.storage != nil {
		event := storage.AuditEvent{
			EdgeID:       s.storage.EdgeID(),
			Action:       message,
			ResourceType: "edge_event",
			ResourceID:   fields["hostname"],
			Metadata:     fields,
			CreatedAt:    time.Now().UTC(),
		}
		if s.auditCh != nil {
			select {
			case s.auditCh <- event:
			default:
			}
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = s.storage.RecordAudit(ctx, event)
		cancel()
	}
}

func (s *Server) auditLoop() {
	defer s.auditWG.Done()
	for {
		select {
		case event := <-s.auditCh:
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = s.storage.RecordAudit(ctx, event)
			cancel()
		case <-s.auditStop:
			for {
				select {
				case event := <-s.auditCh:
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					_ = s.storage.RecordAudit(ctx, event)
					cancel()
				default:
					return
				}
			}
		}
	}
}

func (s *Server) stopAudit() {
	if s == nil || s.auditStop == nil {
		return
	}
	close(s.auditStop)
	s.auditWG.Wait()
	s.auditStop = nil
	s.auditCh = nil
}
