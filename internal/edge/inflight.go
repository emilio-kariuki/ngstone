package edge

import (
	"sync"
	"time"
)

// inflightTracker counts a session's in-flight streams so a drain can wait
// for them. It replaces a sync.WaitGroup because here an Add can legitimately
// run concurrently with Wait: a request routed just before the session was
// unrouted still reaches DialContext after the drain has begun, and a
// WaitGroup panics (taking the whole edge down) when an Add from zero races a
// blocked Wait.
type inflightTracker struct {
	mu   sync.Mutex
	n    int
	idle chan struct{} // closed when n returns to zero; nil whenever n == 0
}

func (t *inflightTracker) Add(delta int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.n == 0 && delta > 0 {
		t.idle = make(chan struct{})
	}
	t.n += delta
	if t.n < 0 {
		panic("edge: negative in-flight stream count")
	}
	if t.n == 0 && t.idle != nil {
		close(t.idle)
		t.idle = nil
	}
}

func (t *inflightTracker) Done() { t.Add(-1) }

// Wait blocks until no streams are in flight.
func (t *inflightTracker) Wait() { t.waitUntil(nil) }

// waitTimeout waits until no streams are in flight or d elapses, and reports
// whether the count drained.
func (t *inflightTracker) waitTimeout(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	return t.waitUntil(timer.C)
}

func (t *inflightTracker) waitUntil(timeout <-chan time.Time) bool {
	for {
		t.mu.Lock()
		idle := t.idle
		t.mu.Unlock()
		if idle == nil {
			return true
		}
		select {
		case <-idle:
			// Re-check: a straggler may have started a new stream since.
		case <-timeout:
			return false
		}
	}
}
