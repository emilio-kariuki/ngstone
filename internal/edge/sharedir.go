package edge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"sync"
	"time"

	"ngstone/internal/storage"
)

func shareDirKey(digest []byte) string {
	h := sha256.New()
	h.Write([]byte("ngstone-share-directory\x00"))
	h.Write(digest)
	return hex.EncodeToString(h.Sum(nil))
}

func (r *shareRegistry) holds(hash [32]byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur, ok := r.byHash[hash]
	return ok && !cur.closed && !cur.unpublished
}

func (r *shareRegistry) registered(hash [32]byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur, ok := r.byHash[hash]
	return ok && !cur.closed
}

func (r *shareRegistry) markPublished(sh *share) {
	r.mu.Lock()
	defer r.mu.Unlock()
	sh.unpublished = false
}

func (r *shareRegistry) expiry(sh *share) time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return sh.expiresAt
}

func (r *shareRegistry) live() []*share {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*share, 0, len(r.byID))
	for _, sh := range r.byID {
		if !sh.closed && !sh.unpublished {
			out = append(out, sh)
		}
	}
	return out
}

func (s *Server) publishShare(sh *share) error {
	if f := s.peers.beforePublish; f != nil {
		f()
	}
	ctx, cancel := context.WithTimeout(context.Background(), peerDeleteTimeout)
	defer cancel()
	return s.peers.store.PublishShare(ctx, shareDirKey(sh.secretHash[:]), sh.id, s.peers.selfID, sh.ownerID, s.shares.expiry(sh))
}

func (s *Server) withdrawShare(sh *share) {
	key := shareDirKey(sh.secretHash[:])
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), peerDeleteTimeout)
		defer cancel()
		slogStorageError("withdraw share", s.peers.store.WithdrawShare(ctx, key, s.peers.selfID))
	}()
}

func (s *Server) revokeRemoteShare(shareID, ownerID string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), peerDeleteTimeout)
	defer cancel()
	revoked, err := s.peers.store.RevokeShare(ctx, shareID, ownerID, time.Now())
	slogStorageError("revoke share", err)
	return err == nil && revoked
}

func (s *Server) shareNotFoundMessage() string {
	if s.peers == nil {
		return "no such live share"
	}
	return "no such live share on edge " + s.peers.selfID
}

func (p *peerForwarder) republishShares() {
	for _, sh := range p.srv.shares.live() {
		slogStorageError("publish share", p.srv.publishShare(sh))
	}
}

func (p *peerForwarder) purgeShares(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, peerDeleteTimeout)
	defer cancel()
	slogStorageError("purge edge shares", p.store.PurgeEdgeShares(cctx, p.selfID))
}

func (p *peerForwarder) syncShares(ctx context.Context, now time.Time) {
	cctx, cancel := context.WithTimeout(ctx, peerLookupTimeout)
	defer cancel()
	if err := p.store.DeleteExpiredShares(cctx, now); err != nil {
		slogStorageError("delete expired shares", err)
	}
	ids, err := p.store.RevokedShares(cctx, p.selfID, now, 256)
	if err != nil {
		slogStorageError("list revoked shares", err)
		return
	}
	for _, id := range ids {
		if sh, ok := p.srv.shares.byShareID(id); ok {
			p.srv.closeShare(sh, "revoked")
		}
	}
}

type readErrTracker struct {
	r   io.Reader
	err error
}

func (t *readErrTracker) Read(b []byte) (int, error) {
	n, err := t.r.Read(b)
	if err != nil {
		t.err = err
	}
	return n, err
}

func (p *peerForwarder) routeControl(ctx context.Context, conn net.Conn, ip string, releaseUnauth func()) (net.Conn, bool) {
	tracker := &readErrTracker{r: conn}
	captured, secret, ok := sniffShareSecret(tracker)
	if !ok && tracker.err != nil {
		conn.Close()
		return nil, true
	}
	local := &replayConn{Conn: conn, buf: captured}
	if !ok {
		return local, false
	}
	s := p.srv
	hash := shareSecretHash(secret)
	if s.shares.holds(hash) {
		return local, false
	}
	src, valid := peerClientAddrPort(conn.RemoteAddr())
	if !valid {
		return local, false
	}
	if _, err := proxyProtoV1Line(src); err != nil {
		return local, false
	}
	if !s.authLimiter.allowed(ip) || !s.perIPLimiter.allow(ip) {
		return local, false
	}
	key := shareDirKey(hash[:])
	missKey := "share:" + key
	if _, miss := p.misses.Get(missKey); miss {
		return local, false
	}
	if !p.lookupSem.tryAcquire() {
		metricPeerRejectedLookupCap.Add(1)
		return local, false
	}
	metricPeerLookups.Add(1)
	lctx, cancel := context.WithTimeout(ctx, peerLookupTimeout)
	owner, found, err := p.store.LookupShareEdge(lctx, key, p.selfID, time.Now())
	cancel()
	p.lookupSem.release()
	if err != nil {
		metricPeerLookupErrors.Add(1)
		slogStorageError("lookup share edge", err)
		return local, false
	}
	if !found {
		p.misses.Add(missKey, struct{}{})
		return local, false
	}
	release, ok := p.reserve(ip)
	if !ok {
		return local, false
	}
	defer release()
	if !p.beginSplice() {
		return local, false
	}
	defer p.splices.Done()
	upstream, _ := p.connect("", &ownerEntry{peers: []storage.EdgePeer{owner}}, peerFrame{kind: peerFrameControl, src: src, payload: captured})
	if upstream == nil {
		metricPeerForwardFailed.Add(1)
		return local, false
	}
	defer upstream.Close()
	defer conn.Close()
	releaseUnauth()
	if conn.SetDeadline(time.Time{}) != nil {
		return nil, true
	}
	metricActivePeerForwards.Add(1)
	defer metricActivePeerForwards.Add(-1)
	metricPeerControlForwarded.Add(1)
	splice(conn, upstream, s.limitsOrDefault().TCPIdleTimeout, peerHalfCloseGrace)
	return nil, true
}

func (s *Server) admitForwardedControl(ctx context.Context, pc net.Conn) {
	if !s.unauthSem.tryAcquire() {
		writePeerStatus(pc, peerStatusNotOwner)
		pc.Close()
		return
	}
	var once sync.Once
	release := func() { once.Do(s.unauthSem.release) }
	if !s.acceptControl() {
		release()
		writePeerStatus(pc, peerStatusNotOwner)
		pc.Close()
		return
	}
	defer s.controlConns.Done()
	defer release()
	if !writePeerStatus(pc, peerStatusAccept) {
		pc.Close()
		return
	}
	metricPeerAcceptedConns.Add(1)
	s.handleControlConnTransport(ctx, pc, release, false, true)
}
