package edge

import (
	"sync/atomic"
	"testing"
	"time"
)

// A sync.WaitGroup panics under exactly this pattern ("WaitGroup is reused
// before previous Wait has returned"): streams starting and finishing while a
// drain is waiting. The tracker must tolerate it.
func TestInflightTrackerAddConcurrentWithWait(t *testing.T) {
	var tr inflightTracker
	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			tr.Add(1)
			tr.Done()
		}
	}()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		tr.Wait()
		tr.waitTimeout(time.Millisecond)
	}
	stop.Store(true)
	<-done
}

func TestInflightTrackerWaitTimeout(t *testing.T) {
	var tr inflightTracker
	if !tr.waitTimeout(10 * time.Millisecond) {
		t.Fatal("waitTimeout on an idle tracker reported not drained")
	}

	tr.Add(1)
	start := time.Now()
	if tr.waitTimeout(50 * time.Millisecond) {
		t.Fatal("waitTimeout reported drained with a stream still in flight")
	}
	if time.Since(start) < 50*time.Millisecond {
		t.Fatal("waitTimeout returned before its timeout")
	}

	go func() {
		time.Sleep(20 * time.Millisecond)
		tr.Done()
	}()
	if !tr.waitTimeout(2 * time.Second) {
		t.Fatal("waitTimeout did not observe the count returning to zero")
	}
}

// A stream that starts while a drain is waiting keeps the drain waiting until
// that stream finishes too.
func TestInflightTrackerWaitCoversLateStarter(t *testing.T) {
	var tr inflightTracker
	tr.Add(1)

	drained := make(chan struct{})
	go func() {
		tr.Wait()
		close(drained)
	}()

	tr.Add(1) // late starter
	tr.Done() // first stream finishes; one is still in flight

	select {
	case <-drained:
		t.Fatal("Wait returned while the late stream was still in flight")
	case <-time.After(50 * time.Millisecond):
	}

	tr.Done()
	select {
	case <-drained:
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not return after the last stream finished")
	}
}

func TestInflightTrackerNegativePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Done without Add did not panic")
		}
	}()
	var tr inflightTracker
	tr.Done()
}
