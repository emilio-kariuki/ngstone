package edge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"ngstone/internal/proto"
	"ngstone/internal/storage"
	"ngstone/internal/tunnel"
)

const (
	remoteAdminBudget  = 3 * time.Second
	remoteListMaxEdges = 32
	remoteListFanout   = 4
	remoteListCacheTTL = 2 * time.Second
	adminAuthRequestID = 1
	adminRequestID     = 3
	adminGoodbyeID     = 5
)

var errAdminRejected = errors.New("edge: holder rejected the operator credential")

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

func (p *peerForwarder) routeControl(ctx context.Context, conn net.Conn, ip string, deadline time.Time, releaseUnauth, leave func()) (net.Conn, bool) {
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
	return p.spliceControl(ctx, conn, ip, src, captured, owner, deadline, releaseUnauth, leave)
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

func (p *peerForwarder) spliceControl(ctx context.Context, conn net.Conn, ip string, src netip.AddrPort, captured []byte, owner storage.EdgePeer, deadline time.Time, releaseUnauth, leave func()) (net.Conn, bool) {
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
	if upstream.SetReadDeadline(deadline) != nil {
		return nil, true
	}
	reply, authed := sniffAuthReply(upstream)
	if authed {
		releaseUnauth()
	}
	if len(reply) > 0 {
		conn.SetWriteDeadline(deadline)
		conn.Write(reply)
	}
	if !authed {
		metricPeerForwardFailed.Add(1)
		return nil, true
	}
	leave()
	if conn.SetDeadline(time.Time{}) != nil || upstream.SetReadDeadline(time.Time{}) != nil {
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

func (s *Server) admitForwardedControl(ctx context.Context, pc net.Conn, origin authOrigin) {
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
	name := "peer"
	if origin == authForwardedAdmin {
		name = "peer-admin"
	}
	s.handleControlConnTransport(ctx, pc, release, controlTransport{origin: origin, leave: leave, name: name})
}

type remoteShareCache struct {
	at        time.Time
	shares    []proto.ShareInfo
	unreached []string
}

func (s *Server) remoteShareHolder(as *AgentSession, shareID string) (storage.EdgePeer, bool) {
	if s.peers == nil || as.viaPeer || as.relayToken == "" {
		return storage.EdgePeer{}, false
	}
	p := s.peers
	if !p.lookupSem.tryAcquire() {
		metricPeerRejectedLookupCap.Add(1)
		return storage.EdgePeer{}, false
	}
	metricPeerLookups.Add(1)
	ctx, cancel := context.WithTimeout(context.Background(), peerLookupTimeout)
	holder, found, err := p.store.LookupShareEdgeByID(ctx, shareID, durableOwnerID(as), p.selfID, time.Now())
	cancel()
	p.lookupSem.release()
	if err != nil {
		metricPeerLookupErrors.Add(1)
		slogStorageError("lookup share edge by id", err)
		return storage.EdgePeer{}, false
	}
	return holder, found
}

func (p *peerForwarder) adminCall(as *AgentSession, holder storage.EdgePeer, req proto.Msg, budget time.Time) (proto.Msg, peerOutcome, error) {
	if !as.Remote.IsValid() {
		return proto.Msg{}, peerDown, errors.New("edge: operator address unknown")
	}
	release, ok := p.reserve(as.Remote.Addr().Unmap().String())
	if !ok {
		return proto.Msg{}, peerDown, errors.New("edge: peer forward capacity reached")
	}
	type result struct {
		msg     proto.Msg
		outcome peerOutcome
		err     error
	}
	done := make(chan result, 1)
	go func() {
		defer release()
		msg, outcome, err := p.adminExchange(as, holder, req, budget)
		done <- result{msg, outcome, err}
	}()
	timer := time.NewTimer(time.Until(budget))
	defer timer.Stop()
	select {
	case r := <-done:
		return r.msg, r.outcome, r.err
	case <-timer.C:
		return proto.Msg{}, peerDown, errors.New("edge: holder did not answer in time")
	}
}

func (p *peerForwarder) adminExchange(as *AgentSession, holder storage.EdgePeer, req proto.Msg, budget time.Time) (proto.Msg, peerOutcome, error) {
	pc, outcome := p.attempt(holder, peerFrame{kind: peerFrameAdmin, src: as.Remote})
	if pc == nil {
		return proto.Msg{}, outcome, errors.New("edge: holder unreachable")
	}
	if err := pc.SetDeadline(budget); err != nil {
		pc.Close()
		return proto.Msg{}, peerDown, err
	}
	sess, err := tunnel.Client(pc)
	if err != nil {
		pc.Close()
		return proto.Msg{}, peerDown, err
	}
	defer sess.Close("admin call done")
	ctrl := sess.Control()
	if err := ctrl.Write(proto.TypeAuth, adminAuthRequestID, proto.Auth{Token: as.relayToken, ProtoVersions: proto.SupportedVersions}); err != nil {
		return proto.Msg{}, peerDown, err
	}
	reply, err := readAdminReply(ctrl, adminAuthRequestID)
	if err != nil {
		return proto.Msg{}, peerDown, err
	}
	if reply.Type != proto.TypeAuthOK {
		return proto.Msg{}, peerDown, errAdminRejected
	}
	var payload any
	if len(req.Data) > 0 {
		payload = req.Data
	}
	if err := ctrl.Write(req.Type, adminRequestID, payload); err != nil {
		return proto.Msg{}, peerDown, err
	}
	reply, err = readAdminReply(ctrl, adminRequestID)
	if err != nil {
		return proto.Msg{}, peerDown, err
	}
	switch reply.Type {
	case proto.TypeShareOK, proto.TypeSharesOK, proto.TypeKickOK, proto.TypeShareErr, proto.TypeError:
	default:
		return proto.Msg{}, peerDown, errors.New("edge: unexpected admin reply " + reply.Type)
	}
	ctrl.Write(proto.TypeGoodbye, adminGoodbyeID, nil)
	return reply, peerOK, nil
}

func readAdminReply(ctrl *proto.Conn, id uint64) (proto.Msg, error) {
	for {
		m, err := ctrl.Read()
		if err != nil {
			return proto.Msg{}, err
		}
		if m.Type == proto.TypeGoodbye {
			return proto.Msg{}, errors.New("edge: holder is draining")
		}
		if m.Type == proto.TypePing || m.ID != id {
			continue
		}
		return m, nil
	}
}

func (s *Server) forwardShareAdmin(as *AgentSession, ctrl *proto.Conn, id uint64, typ, shareID string, payload any) bool {
	holder, ok := s.remoteShareHolder(as, shareID)
	if !ok {
		return false
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	as.remoteShares = nil
	reply, outcome, err := s.peers.adminCall(as, holder, proto.Msg{Type: typ, Data: data}, time.Now().Add(remoteAdminBudget))
	if err != nil {
		reason, suffix := "unreachable", "which did not answer"
		switch {
		case outcome == peerSkew:
			reason, suffix = "skew", "which runs an older ngstoned"
		case errors.Is(err, errAdminRejected):
			reason, suffix = "rejected_token", "which rejected this session's token"
		}
		slog.Info("edge: remote share admin", "op", typ, "share_id", shareID, "holder_edge", holder.EdgeID, "session", as.ID, "owner", durableOwnerID(as), "outcome", reason)
		msg := "share " + shareID + " is on edge " + holder.EdgeID + " " + suffix
		if typ == proto.TypeShareUpdate {
			ctrl.Write(proto.TypeShareErr, id, proto.ShareErr{Code: proto.CodeShareNotFound, Message: msg})
		} else {
			ctrl.Write(proto.TypeError, id, proto.Error{Code: proto.CodeShareNotFound, Message: msg})
		}
		return true
	}
	slog.Info("edge: remote share admin", "op", typ, "share_id", shareID, "holder_edge", holder.EdgeID, "session", as.ID, "owner", durableOwnerID(as), "outcome", reply.Type)
	var out any
	if len(reply.Data) > 0 {
		out = reply.Data
	}
	ctrl.Write(reply.Type, id, out)
	return true
}

func (s *Server) groupShares(as *AgentSession) (shares []proto.ShareInfo, unreached []string, ok bool) {
	if s.peers == nil || as.viaPeer || as.relayToken == "" {
		return nil, nil, false
	}
	if c := as.remoteShares; c != nil && time.Since(c.at) < remoteListCacheTTL {
		return c.shares, c.unreached, true
	}
	p := s.peers
	if !p.lookupSem.tryAcquire() {
		metricPeerRejectedLookupCap.Add(1)
		return nil, nil, false
	}
	metricPeerLookups.Add(1)
	ctx, cancel := context.WithTimeout(context.Background(), remoteAdminBudget)
	defer cancel()
	budget, _ := ctx.Deadline()
	edges, err := p.store.ShareEdgesForOwner(ctx, durableOwnerID(as), p.selfID, time.Now(), remoteListMaxEdges)
	p.lookupSem.release()
	if err != nil {
		metricPeerLookupErrors.Add(1)
		slogStorageError("list share edges", err)
		return nil, nil, false
	}
	type result struct {
		shares []proto.ShareInfo
		err    error
	}
	results := make([]result, len(edges))
	sem := make(chan struct{}, remoteListFanout)
	var wg sync.WaitGroup
	for i, e := range edges {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i].err = ctx.Err()
				return
			}
			reply, _, err := p.adminCall(as, e, proto.Msg{Type: proto.TypeListShares}, budget)
			if err == nil && reply.Type != proto.TypeSharesOK {
				err = errors.New("edge: unexpected list reply " + reply.Type)
			}
			if err == nil {
				var body proto.SharesOK
				if body, err = proto.Decode[proto.SharesOK](reply); err == nil {
					for j := range body.Shares {
						body.Shares[j].Edge = e.EdgeID
						body.Shares[j].Mine = false
					}
					results[i].shares = body.Shares
				}
			}
			results[i].err = err
		}()
	}
	wg.Wait()
	for i, r := range results {
		if r.err != nil {
			unreached = append(unreached, edges[i].EdgeID)
			continue
		}
		shares = append(shares, r.shares...)
	}
	sort.Strings(unreached)
	as.remoteShares = &remoteShareCache{at: time.Now(), shares: shares, unreached: unreached}
	return shares, unreached, true
}
