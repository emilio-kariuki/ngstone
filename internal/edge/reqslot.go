package edge

import "sync"

type reqSlot struct {
	srv *Server
	as  *AgentSession

	mu        sync.Mutex
	released  bool
	onUpgrade bool
}

func newReqSlot(srv *Server, as *AgentSession) *reqSlot {
	return &reqSlot{srv: srv, as: as}
}

func (sl *reqSlot) reclassify() bool {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	if sl.released || sl.onUpgrade {
		return false
	}
	if !sl.srv.upgradeSem.tryAcquire() {
		return false
	}
	if !sl.as.tryAcquireUpgrade() {
		sl.srv.upgradeSem.release()
		return false
	}

	sl.srv.globalSem.release()
	sl.as.releaseStream()
	sl.onUpgrade = true
	metricActiveUpgrades.Add(1)
	return true
}

func (sl *reqSlot) release() {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	if sl.released {
		return
	}
	sl.released = true

	if sl.onUpgrade {
		sl.srv.upgradeSem.release()
		sl.as.releaseUpgrade()
		metricActiveUpgrades.Add(-1)
		return
	}
	sl.srv.globalSem.release()
	sl.as.releaseStream()
}
