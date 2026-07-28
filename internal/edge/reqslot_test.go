package edge

import "testing"

func TestReqSlotNeverUpgradedReleaseFreesRequestBudget(t *testing.T) {
	const n = 3
	srv := &Server{globalSem: newGlobalSemaphore(n), upgradeSem: newGlobalSemaphore(5)}
	as := &AgentSession{streamSem: newGlobalSemaphore(n), upgradeStreamSem: newGlobalSemaphore(5)}

	if !srv.globalSem.tryAcquire() {
		t.Fatal("setup: global acquire failed")
	}
	if !as.tryAcquireStream() {
		t.Fatal("setup: stream acquire failed")
	}

	slot := newReqSlot(srv, as)
	slot.release()

	for i := 0; i < n; i++ {
		if !srv.globalSem.tryAcquire() {
			t.Fatalf("global slot %d/%d not re-acquirable after release", i+1, n)
		}
	}
	for i := 0; i < n; i++ {
		if !as.tryAcquireStream() {
			t.Fatalf("stream slot %d/%d not re-acquirable after release", i+1, n)
		}
	}

	for i := 0; i < 5; i++ {
		if !srv.upgradeSem.tryAcquire() {
			t.Fatalf("upgrade sem slot %d/5 unavailable; a never-upgraded release must not touch the upgrade budget", i+1)
		}
	}
	for i := 0; i < 5; i++ {
		if !as.tryAcquireUpgrade() {
			t.Fatalf("per-session upgrade slot %d/5 unavailable; a never-upgraded release must not touch the upgrade budget", i+1)
		}
	}
}

func TestReqSlotReclassifyFreesRequestBudgetAndConsumesUpgradeBudget(t *testing.T) {
	srv := &Server{globalSem: newGlobalSemaphore(1), upgradeSem: newGlobalSemaphore(1)}
	as := &AgentSession{streamSem: newGlobalSemaphore(1), upgradeStreamSem: newGlobalSemaphore(1)}

	if !srv.globalSem.tryAcquire() {
		t.Fatal("setup: global acquire failed")
	}
	if !as.tryAcquireStream() {
		t.Fatal("setup: stream acquire failed")
	}

	baseline := metricActiveUpgrades.Value()

	slot := newReqSlot(srv, as)
	if !slot.reclassify() {
		t.Fatal("reclassify() should succeed when both upgrade budgets are available")
	}

	if !srv.globalSem.tryAcquire() {
		t.Fatal("global request slot should be freed immediately after reclassify()")
	}
	if !as.tryAcquireStream() {
		t.Fatal("per-session stream slot should be freed immediately after reclassify()")
	}
	if srv.upgradeSem.tryAcquire() {
		t.Fatal("global upgrade slot should be fully consumed after reclassify()")
	}
	if as.tryAcquireUpgrade() {
		t.Fatal("per-session upgrade slot should be fully consumed after reclassify()")
	}

	if got, want := metricActiveUpgrades.Value(), baseline+1; got != want {
		t.Fatalf("ngstoned_active_upgrades = %d, want baseline+1 = %d", got, want)
	}

	slot.release()

	if got, want := metricActiveUpgrades.Value(), baseline; got != want {
		t.Fatalf("ngstoned_active_upgrades after release = %d, want back to baseline %d", got, want)
	}
	if !srv.upgradeSem.tryAcquire() {
		t.Fatal("global upgrade slot should be freed after release()")
	}
}

func TestReqSlotReleaseTwiceDoesNotDoubleFree(t *testing.T) {
	srv := &Server{globalSem: newGlobalSemaphore(1)}
	as := &AgentSession{streamSem: newGlobalSemaphore(1)}

	if !srv.globalSem.tryAcquire() {
		t.Fatal("setup: global acquire failed")
	}
	if !as.tryAcquireStream() {
		t.Fatal("setup: stream acquire failed")
	}

	slot := newReqSlot(srv, as)
	slot.release()

	if !srv.globalSem.tryAcquire() {
		t.Fatal("expected to re-acquire the slot freed by the first release()")
	}
	if !as.tryAcquireStream() {
		t.Fatal("expected to re-acquire the stream slot freed by the first release()")
	}

	slot.release()

	if srv.globalSem.tryAcquire() {
		t.Fatal("a second release() call freed a global slot that a later acquirer already holds; release() must be idempotent")
	}
	if as.tryAcquireStream() {
		t.Fatal("a second release() call freed a stream slot that a later acquirer already holds; release() must be idempotent")
	}
}

func TestReqSlotReclassifyAfterReleaseReturnsFalseAndConsumesNothing(t *testing.T) {
	srv := &Server{globalSem: newGlobalSemaphore(1), upgradeSem: newGlobalSemaphore(1)}
	as := &AgentSession{streamSem: newGlobalSemaphore(1), upgradeStreamSem: newGlobalSemaphore(1)}

	if !srv.globalSem.tryAcquire() {
		t.Fatal("setup: global acquire failed")
	}
	if !as.tryAcquireStream() {
		t.Fatal("setup: stream acquire failed")
	}

	slot := newReqSlot(srv, as)
	slot.release()

	if slot.reclassify() {
		t.Fatal("reclassify() after release() must return false")
	}
	if !srv.upgradeSem.tryAcquire() {
		t.Fatal("reclassify() after release() must not consume the global upgrade budget")
	}
	if !as.tryAcquireUpgrade() {
		t.Fatal("reclassify() after release() must not consume the per-session upgrade budget")
	}
}

func TestReqSlotReclassifyTwiceIsIdempotent(t *testing.T) {
	srv := &Server{globalSem: newGlobalSemaphore(1), upgradeSem: newGlobalSemaphore(2)}
	as := &AgentSession{streamSem: newGlobalSemaphore(1), upgradeStreamSem: newGlobalSemaphore(2)}

	if !srv.globalSem.tryAcquire() {
		t.Fatal("setup: global acquire failed")
	}
	if !as.tryAcquireStream() {
		t.Fatal("setup: stream acquire failed")
	}

	slot := newReqSlot(srv, as)
	if !slot.reclassify() {
		t.Fatal("first reclassify() should succeed")
	}
	if slot.reclassify() {
		t.Fatal("second reclassify() must return false")
	}

	acquiredGlobal := 0
	for i := 0; i < 2; i++ {
		if srv.upgradeSem.tryAcquire() {
			acquiredGlobal++
		}
	}
	if acquiredGlobal != 1 {
		t.Fatalf("global upgrade sem: %d of 2 slots acquirable after two reclassify() calls, want exactly 1 consumed", acquiredGlobal)
	}

	acquiredSession := 0
	for i := 0; i < 2; i++ {
		if as.tryAcquireUpgrade() {
			acquiredSession++
		}
	}
	if acquiredSession != 1 {
		t.Fatalf("per-session upgrade sem: %d of 2 slots acquirable after two reclassify() calls, want exactly 1 consumed", acquiredSession)
	}
}

func TestReqSlotReclassifyFailsWhenGlobalUpgradeBudgetExhausted(t *testing.T) {
	srv := &Server{globalSem: newGlobalSemaphore(1), upgradeSem: newGlobalSemaphore(0)}
	as := &AgentSession{streamSem: newGlobalSemaphore(1), upgradeStreamSem: newGlobalSemaphore(1)}

	if !srv.globalSem.tryAcquire() {
		t.Fatal("setup: global acquire failed")
	}
	if !as.tryAcquireStream() {
		t.Fatal("setup: stream acquire failed")
	}

	slot := newReqSlot(srv, as)
	if slot.reclassify() {
		t.Fatal("reclassify() must fail when the global upgrade budget is exhausted")
	}

	if !as.tryAcquireUpgrade() {
		t.Fatal("per-session upgrade budget must not have been consumed when the global upgrade acquire failed first")
	}
	as.releaseUpgrade()

	slot.release()

	if !srv.globalSem.tryAcquire() {
		t.Fatal("request-scoped global budget should be freed by release() after a failed reclassify()")
	}
	if srv.globalSem.tryAcquire() {
		t.Fatal("request-scoped global budget was double-freed")
	}
	if !as.tryAcquireStream() {
		t.Fatal("request-scoped stream budget should be freed by release() after a failed reclassify()")
	}
}

func TestReqSlotReclassifyUnwindsGlobalUpgradeWhenPerSessionExhausted(t *testing.T) {
	srv := &Server{globalSem: newGlobalSemaphore(1), upgradeSem: newGlobalSemaphore(3)}
	as := &AgentSession{streamSem: newGlobalSemaphore(1), upgradeStreamSem: newGlobalSemaphore(0)}

	if !srv.globalSem.tryAcquire() {
		t.Fatal("setup: global acquire failed")
	}
	if !as.tryAcquireStream() {
		t.Fatal("setup: stream acquire failed")
	}

	slot := newReqSlot(srv, as)
	if slot.reclassify() {
		t.Fatal("reclassify() must fail when the per-session upgrade budget is exhausted")
	}

	acquired := 0
	for i := 0; i < 3; i++ {
		if srv.upgradeSem.tryAcquire() {
			acquired++
		}
	}
	if acquired != 3 {
		t.Fatalf("global upgrade sem: %d of 3 slots acquirable after a failed reclassify(), want 3; the global upgrade acquire must be unwound when the per-session acquire fails", acquired)
	}
}
