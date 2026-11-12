package edge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"ngstone/internal/proto"
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
		if err := f(); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), peerDeleteTimeout)
	defer cancel()
	return s.peers.store.PublishShare(ctx, shareDirKey(sh.secretHash[:]), sh.id, s.peers.selfID, sh.ownerID, s.shares.expiry(sh))
}

func (s *Server) reassertShare(sh *share) error {
	if f := s.peers.beforePublish; f != nil {
		if err := f(); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), peerDeleteTimeout)
	defer cancel()
	return s.peers.store.ReassertShare(ctx, shareDirKey(sh.secretHash[:]), sh.id, s.peers.selfID, sh.ownerID, s.shares.expiry(sh))
}

func (s *Server) withdrawShare(sh *share) {
	key := shareDirKey(sh.secretHash[:])
	s.peers.withdraws.Add(1)
	go func() {
		defer s.peers.withdraws.Done()
		if f := s.peers.beforeWithdraw; f != nil {
			f()
		}
		ctx, cancel := context.WithTimeout(context.Background(), peerDeleteTimeout)
		defer cancel()
		slogStorageError("withdraw share", s.peers.store.WithdrawShare(ctx, key, s.peers.selfID, sh.id))
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

func (p *peerForwarder) reassertShares() {
	s := p.srv
	for _, sh := range s.shares.live() {
		err := s.reassertShare(sh)
		switch {
		case err == nil:
			if _, live := s.shares.byShareID(sh.id); !live {
				s.withdrawShare(sh)
			}
		case errors.Is(err, storage.ErrShareTaken):
			s.closeShare(sh, proto.ShareReasonTaken)
		case errors.Is(err, storage.ErrShareMoved):
			s.closeShare(sh, proto.ShareReasonMoved)
		default:
			slogStorageError("reassert share", err)
			metricShareDirectoryErrors.Add(1)
		}
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
			p.srv.closeShare(sh, proto.ShareReasonRevoked)
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

func (p *peerForwarder) routeControl(ctx context.Context, conn net.Conn, ip string, releaseUnauth, leave func()) (net.Conn, bool) {
	tracker := &readErrTracker{r: conn}
	captured, secret, ok := sniffShareSecret(tracker)
	if !ok && tracker.err != nil {
		slog.Warn("edge: auth attempt", "ip", ip, "result", "no_auth_message", "err", tracker.err)
		conn.Close()
		return nil, true
	}
	local := &replayConn{Conn: conn, buf: captured}
	if !ok {
		return local, false
	}
	hash := shareSecretHash(secret)
	src, key, eligible := p.controlForwardable(conn, ip, hash)
	if !eligible {
		return local, false
	}
	owner, found, ok := p.lookupShareHolder(ctx, key)
	if !ok {
		return p.forwardFailed(conn)
	}
	if !found {
		return local, false
	}
	return p.spliceControl(ctx, conn, ip, src, captured, owner, releaseUnauth, leave)
}

func (p *peerForwarder) controlForwardable(conn net.Conn, ip string, hash [32]byte) (src netip.AddrPort, key string, ok bool) {
	s := p.srv
	if s.shares.holds(hash) {
		return src, "", false
	}
	src, valid := peerClientAddrPort(conn.RemoteAddr())
	if !valid {
		return src, "", false
	}
	if _, err := proxyProtoV1Line(src); err != nil {
		return src, "", false
	}
	if !s.authLimiter.allowed(ip) || !s.perIPLimiter.allow(ip) {
		return src, "", false
	}
	key = shareDirKey(hash[:])
	if _, miss := p.misses.Get("share:" + key); miss {
		return src, "", false
	}
	return src, key, true
}

func (p *peerForwarder) lookupShareHolder(ctx context.Context, key string) (owner storage.EdgePeer, found, ok bool) {
	if !p.lookupSem.tryAcquire() {
		metricPeerRejectedLookupCap.Add(1)
		return owner, false, false
	}
	metricPeerLookups.Add(1)
	lctx, cancel := context.WithTimeout(ctx, peerLookupTimeout)
	owner, found, err := p.store.LookupShareEdge(lctx, key, p.selfID, time.Now())
	cancel()
	p.lookupSem.release()
	if err != nil {
		metricPeerLookupErrors.Add(1)
		slogStorageError("lookup share edge", err)
		return owner, false, false
	}
	if !found {
		p.misses.Add("share:"+key, struct{}{})
	}
	return owner, found, true
}

func (p *peerForwarder) spliceControl(ctx context.Context, conn net.Conn, ip string, src netip.AddrPort, captured []byte, owner storage.EdgePeer, releaseUnauth, leave func()) (net.Conn, bool) {
	release, ok := p.reserve(ip)
	if !ok {
		return p.forwardFailed(conn)
	}
	defer release()
	if !p.beginSplice() {
		return p.forwardFailed(conn)
	}
	defer p.splices.Done()
	upstream, _ := p.connect("", &ownerEntry{peers: []storage.EdgePeer{owner}}, peerFrame{kind: peerFrameControl, src: src, payload: captured})
	if upstream == nil {
		metricPeerForwardFailed.Add(1)
		return p.forwardFailed(conn)
	}
	defer upstream.Close()
	defer conn.Close()
	releaseUnauth()
	leave()
	if conn.SetDeadline(time.Time{}) != nil {
		return nil, true
	}
	metricActivePeerForwards.Add(1)
	defer metricActivePeerForwards.Add(-1)
	metricPeerControlForwarded.Add(1)
	p.spliceUntilDone(ctx, conn, upstream)
	return nil, true
}

func (p *peerForwarder) forwardFailed(conn net.Conn) (net.Conn, bool) {
	metricControlForwardFailed.Add(1)
	conn.Close()
	return nil, true
}

func (s *Server) admitForwardedControl(ctx context.Context, pc net.Conn) {
	if !s.unauthSem.tryAcquire() {
		writePeerStatus(pc, peerStatusNotOwner)
		pc.Close()
		return
	}
	releaseAddr, ok := s.acquireUnauthAddr(pc.RemoteAddr())
	if !ok {
		s.unauthSem.release()
		writePeerStatus(pc, peerStatusNotOwner)
		pc.Close()
		return
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			releaseAddr()
			s.unauthSem.release()
		})
	}
	if !s.acceptControl() {
		release()
		writePeerStatus(pc, peerStatusNotOwner)
		pc.Close()
		return
	}
	leave := sync.OnceFunc(s.controlConns.Done)
	defer leave()
	defer release()
	if !writePeerStatus(pc, peerStatusAccept) {
		pc.Close()
		return
	}
	metricPeerAcceptedConns.Add(1)
	s.handleControlConnTransport(ctx, pc, release, controlTransport{forwarded: true, leave: leave, name: "peer"})
}
