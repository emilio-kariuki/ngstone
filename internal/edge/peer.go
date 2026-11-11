package edge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sync/singleflight"

	"ngstone/internal/storage"
)

const (
	peerALPN1 = "ngstone-peer-1"
	peerALPN2 = "ngstone-peer-2"

	peerFrameSNI     byte = 0x01
	peerFrameTCP     byte = 0x02
	peerFrameControl byte = 0x03

	peerStatusAccept   byte = 0x00
	peerStatusNotOwner byte = 0x01

	peerDialTimeout        = 2 * time.Second
	peerStatusTimeout      = 2 * time.Second
	peerAcceptTimeout      = 5 * time.Second
	peerLookupTimeout      = 2 * time.Second
	peerDeleteTimeout      = 3 * time.Second
	peerPinRefreshInterval = time.Second

	maxPeerHandshakes = 64
	maxPeerLookups    = 8
	maxPeerForwards   = 1024

	peerOwnerCacheSize = 10000
	peerOwnerCacheTTL  = 30 * time.Second
	peerMissCacheSize  = 4096
	peerMissCacheTTL   = 2 * time.Second
	peerDownCacheSize  = 256
	peerDownCacheTTL   = 5 * time.Second

	peerHalfCloseGrace = 5 * time.Second

	peerTCPPollInterval = 2 * time.Second
)

var (
	errPeerResumed    = errors.New("edge: peer session resumption is not allowed")
	errPeerALPN       = errors.New("edge: peer ALPN mismatch")
	errPeerNoCert     = errors.New("edge: peer presented no certificate")
	errPeerUnknownPin = errors.New("edge: peer key is not registered")
	errPeerPinChanged = errors.New("edge: peer key does not match the registered pin")
)

type peerForwardedKey struct{}

func peerForwarded(ctx context.Context) bool {
	v, _ := ctx.Value(peerForwardedKey{}).(bool)
	return v
}

func peerConnContext(ctx context.Context, c net.Conn) context.Context {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	if rc, ok := c.(*replayConn); ok && rc.forwarded {
		return context.WithValue(ctx, peerForwardedKey{}, true)
	}
	return ctx
}

type peerIdentity struct {
	cert tls.Certificate
	pin  string
}

func newPeerIdentity() (peerIdentity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return peerIdentity{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return peerIdentity{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ngstone-peer"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return peerIdentity{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return peerIdentity{}, err
	}
	return peerIdentity{
		cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf},
		pin:  spkiPin(leaf),
	}, nil
}

func spkiPin(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

type ownerEntry struct {
	peers    []storage.EdgePeer
	resolved time.Time
}

type peerForwarder struct {
	srv    *Server
	store  *storage.Store
	selfID string
	addr   string
	id     peerIdentity

	owners   *expirable.LRU[string, *ownerEntry]
	ownersMu sync.Mutex
	misses   *expirable.LRU[string, struct{}]
	down     *expirable.LRU[string, time.Time]

	tcpOwners atomic.Pointer[map[int][]storage.EdgePeer]
	tcpFresh  atomic.Int64

	pins        atomic.Pointer[map[string]time.Time]
	lastRefresh atomic.Int64
	lookups     singleflight.Group
	pinFlights  singleflight.Group

	handshakeSem *globalSemaphore
	lookupSem    *globalSemaphore
	forwardSem   *globalSemaphore

	spliceMu sync.Mutex
	draining bool
	splices  sync.WaitGroup

	ln     net.Listener
	public *sniListener
}

func newPeerForwarder(s *Server) (*peerForwarder, error) {
	id, err := newPeerIdentity()
	if err != nil {
		return nil, fmt.Errorf("edge: generating peer identity: %w", err)
	}
	return &peerForwarder{
		srv:          s,
		store:        s.storage,
		selfID:       s.storage.EdgeID(),
		addr:         s.cfg.PeerAddr,
		id:           id,
		owners:       expirable.NewLRU[string, *ownerEntry](peerOwnerCacheSize, nil, peerOwnerCacheTTL),
		misses:       expirable.NewLRU[string, struct{}](peerMissCacheSize, nil, peerMissCacheTTL),
		down:         expirable.NewLRU[string, time.Time](peerDownCacheSize, nil, peerDownCacheTTL),
		handshakeSem: newGlobalSemaphore(maxPeerHandshakes),
		lookupSem:    newGlobalSemaphore(maxPeerLookups),
		forwardSem:   newGlobalSemaphore(maxPeerForwards),
	}, nil
}

func (p *peerForwarder) knownPin(pin string) bool {
	set := p.pins.Load()
	if set == nil {
		return false
	}
	expiresAt, ok := (*set)[pin]
	return ok && time.Now().Before(expiresAt)
}

func peerKnownALPN(proto string) bool {
	return proto == peerALPN2 || proto == peerALPN1
}

func (p *peerForwarder) serverTLS() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{p.id.cert},
		ClientAuth:             tls.RequireAnyClientCert,
		NextProtos:             []string{peerALPN2, peerALPN1},
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.DidResume {
				return errPeerResumed
			}
			if !peerKnownALPN(cs.NegotiatedProtocol) {
				return errPeerALPN
			}
			if len(cs.PeerCertificates) == 0 {
				return errPeerNoCert
			}
			pin := spkiPin(cs.PeerCertificates[0])
			if p.knownPin(pin) {
				return nil
			}
			p.refreshPins()
			if p.knownPin(pin) {
				return nil
			}
			return errPeerUnknownPin
		},
	}
}

func (p *peerForwarder) clientTLS(wantPin string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{p.id.cert},
		InsecureSkipVerify: true,
		ServerName:         "ngstone-peer",
		NextProtos:         []string{peerALPN2, peerALPN1},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.DidResume {
				return errPeerResumed
			}
			if !peerKnownALPN(cs.NegotiatedProtocol) {
				return errPeerALPN
			}
			if len(cs.PeerCertificates) == 0 {
				return errPeerNoCert
			}
			if subtle.ConstantTimeCompare([]byte(spkiPin(cs.PeerCertificates[0])), []byte(wantPin)) != 1 {
				return errPeerPinChanged
			}
			return nil
		},
	}
}

func (p *peerForwarder) refreshPins() {
	p.pinFlights.Do("pins", func() (any, error) {
		now := time.Now()
		if now.UnixNano()-p.lastRefresh.Load() < int64(peerPinRefreshInterval) {
			return nil, nil
		}
		p.lastRefresh.Store(now.UnixNano())
		ctx, cancel := context.WithTimeout(context.Background(), peerLookupTimeout)
		defer cancel()
		peers, err := p.store.LiveEdgePeers(ctx, now)
		if err != nil {
			slogStorageError("refresh edge peer pins", err)
			return nil, nil
		}
		set := make(map[string]time.Time, len(peers))
		for _, peer := range peers {
			set[peer.SPKISHA256] = peer.ExpiresAt
		}
		p.pins.Store(&set)
		return nil, nil
	})
}

func (p *peerForwarder) leaseTTL() time.Duration {
	if ttl := p.srv.cfg.LeaseTTL; ttl > 0 {
		return ttl
	}
	return storage.DefaultLeaseTTL
}

func (p *peerForwarder) heartbeat(ctx context.Context) error {
	ttl := p.leaseTTL()
	p.purgeShares(ctx)
	p.beat(ctx, ttl)
	p.republishShares()
	ticker := time.NewTicker(ttl / 3)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			p.beat(ctx, ttl)
		}
	}
}

func (p *peerForwarder) beat(ctx context.Context, ttl time.Duration) {
	now := time.Now()
	cctx, cancel := context.WithTimeout(ctx, peerLookupTimeout)
	err := p.store.UpsertEdgePeer(cctx, storage.EdgePeer{
		EdgeID:     p.selfID,
		PeerAddr:   p.addr,
		SPKISHA256: p.id.pin,
		ExpiresAt:  now.Add(ttl),
	})
	cancel()
	if ctx.Err() != nil {
		return
	}
	slogStorageError("upsert edge peer", err)
	p.refreshPins()
	p.syncShares(ctx, now)
}

func (p *peerForwarder) stop() {
	if p == nil {
		return
	}
	p.spliceMu.Lock()
	p.draining = true
	p.spliceMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), peerDeleteTimeout)
	defer cancel()
	slogStorageError("purge edge shares", p.store.PurgeEdgeShares(ctx, p.selfID))
	slogStorageError("delete edge peer", p.store.DeleteEdgePeer(ctx, p.selfID))
	if p.ln != nil {
		p.ln.Close()
	}
	if p.srv.tcpMgr != nil {
		p.srv.tcpMgr.reconcileRemote(nil, p.forwardTCP)
	}
}

func (p *peerForwarder) beginSplice() bool {
	p.spliceMu.Lock()
	defer p.spliceMu.Unlock()
	if p.draining {
		return false
	}
	p.splices.Add(1)
	return true
}

func (p *peerForwarder) waitSplices(ctx context.Context) {
	if p == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		p.splices.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

type peerConn struct {
	*tls.Conn
	remote net.Addr
}

func (c *peerConn) RemoteAddr() net.Addr { return c.remote }

func (p *peerForwarder) acceptLoop(ctx context.Context) error {
	backoff := 5 * time.Millisecond
	for {
		c, err := p.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			slog.Warn("edge: peer accept error", "err", err, "backoff", backoff)
			t := time.NewTimer(backoff)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				return nil
			}
			backoff = min(backoff*2, time.Second)
			continue
		}
		backoff = 5 * time.Millisecond
		go p.serveConn(ctx, c)
	}
}

func (p *peerForwarder) serveConn(ctx context.Context, c net.Conn) {
	if !p.handshakeSem.tryAcquire() {
		c.Close()
		return
	}
	held := true
	defer func() {
		if held {
			p.handshakeSem.release()
		}
	}()
	if err := c.SetDeadline(time.Now().Add(peerAcceptTimeout)); err != nil {
		c.Close()
		return
	}
	tc := tls.Server(c, p.serverTLS())
	if err := tc.HandshakeContext(ctx); err != nil {
		metricPeerRejectedAuth.Add(1)
		slog.Debug("edge: peer handshake rejected", "remote", c.RemoteAddr().String(), "err", err)
		c.Close()
		return
	}
	kind := peerFrameSNI
	var tcpPort int
	if tc.ConnectionState().NegotiatedProtocol == peerALPN2 {
		var head [1]byte
		if _, err := io.ReadFull(tc, head[:]); err != nil {
			slog.Debug("edge: peer frame header unreadable", "remote", c.RemoteAddr().String(), "err", err)
			tc.Close()
			return
		}
		kind = head[0]
		switch kind {
		case peerFrameSNI, peerFrameControl:
		case peerFrameTCP:
			var port [2]byte
			if _, err := io.ReadFull(tc, port[:]); err != nil {
				slog.Debug("edge: peer frame port unreadable", "remote", c.RemoteAddr().String(), "err", err)
				tc.Close()
				return
			}
			tcpPort = int(binary.BigEndian.Uint16(port[:]))
		default:
			slog.Debug("edge: peer frame of unknown type", "remote", c.RemoteAddr().String(), "type", kind)
			tc.Close()
			return
		}
	}
	remote, err := readProxyProtoHeader(tc, nil)
	if err != nil || remote == nil {
		slog.Debug("edge: peer connection without a client address", "remote", c.RemoteAddr().String(), "err", err)
		tc.Close()
		return
	}
	if kind == peerFrameTCP {
		p.serveTCP(tc, tcpPort, remote, func() {
			held = false
			p.handshakeSem.release()
		})
		return
	}
	if kind == peerFrameControl {
		held = false
		p.handshakeSem.release()
		p.srv.admitForwardedControl(ctx, &peerConn{Conn: tc, remote: remote})
		return
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		tc.Close()
		return
	}
	held = false
	p.handshakeSem.release()
	metricPeerAcceptedConns.Add(1)
	p.public.classifyForwarded(&peerConn{Conn: tc, remote: remote})
}

func (p *peerForwarder) serveTCP(tc *tls.Conn, port int, remote net.Addr, releaseHandshake func()) {
	mgr := p.srv.tcpMgr
	if mgr == nil || port < mgr.lo || port > mgr.hi {
		writePeerStatus(tc, peerStatusNotOwner)
		tc.Close()
		return
	}
	fwd, ok := mgr.acceptForwarded(port, &peerConn{Conn: tc, remote: remote})
	if !ok {
		writePeerStatus(tc, peerStatusNotOwner)
		tc.Close()
		return
	}
	if !writePeerStatus(tc, peerStatusAccept) || tc.SetDeadline(time.Time{}) != nil {
		fwd.abort()
		return
	}
	releaseHandshake()
	metricPeerAcceptedConns.Add(1)
	fwd.serve()
}

func writePeerStatus(c net.Conn, status byte) bool {
	_, err := c.Write([]byte{status})
	return err == nil
}

func (p *peerForwarder) eligible(host string) bool {
	host = normalizeHost(host)
	label, ok := strings.CutSuffix(host, "."+normalizeHost(p.srv.cfg.Domain))
	if !ok || !validSubdomain(label) {
		return false
	}
	return !p.srv.visitor.servesHost(host)
}

type lookupResult int

const (
	lookupFound lookupResult = iota
	lookupNone
	lookupRefused
)

var errPeerLookupCap = errors.New("edge: peer lookup capacity reached")

func (p *peerForwarder) queryOwners(key string) ([]storage.EdgePeer, error) {
	if !p.lookupSem.tryAcquire() {
		metricPeerRejectedLookupCap.Add(1)
		return nil, errPeerLookupCap
	}
	defer p.lookupSem.release()
	metricPeerLookups.Add(1)
	ctx, cancel := context.WithTimeout(context.Background(), peerLookupTimeout)
	defer cancel()
	return p.store.LookupHostOwners(ctx, key, p.selfID, time.Now())
}

func (p *peerForwarder) lookupOnce(key string) (any, error) {
	if entry, ok := p.owners.Get(key); ok {
		return entry, nil
	}
	if _, miss := p.misses.Get(key); miss {
		return (*ownerEntry)(nil), nil
	}
	owners, err := p.queryOwners(key)
	if err != nil {
		return nil, err
	}
	if len(owners) == 0 {
		p.misses.Add(key, struct{}{})
		return (*ownerEntry)(nil), nil
	}
	entry := &ownerEntry{peers: owners, resolved: time.Now()}
	p.ownersMu.Lock()
	p.owners.Add(key, entry)
	p.ownersMu.Unlock()
	return entry, nil
}

func (p *peerForwarder) resolve(key string) (*ownerEntry, lookupResult) {
	v, err, _ := p.lookups.Do(key, func() (any, error) { return p.lookupOnce(key) })
	if err != nil {
		if !errors.Is(err, errPeerLookupCap) {
			metricPeerLookupErrors.Add(1)
			slogStorageError("lookup host owners", err)
		}
		return nil, lookupRefused
	}
	entry, ok := v.(*ownerEntry)
	if !ok {
		metricPeerLookupErrors.Add(1)
		return nil, lookupRefused
	}
	if entry == nil {
		return nil, lookupNone
	}
	return entry, lookupFound
}

func (p *peerForwarder) candidates(key string) (*ownerEntry, lookupResult) {
	if entry, ok := p.owners.Get(key); ok {
		return entry, lookupFound
	}
	if _, miss := p.misses.Get(key); miss {
		return nil, lookupNone
	}
	return p.resolve(key)
}

func (p *peerForwarder) refresh(key string, used *ownerEntry) (*ownerEntry, lookupResult) {
	p.ownersMu.Lock()
	cur, ok := p.owners.Peek(key)
	if ok && cur != used {
		p.ownersMu.Unlock()
		return cur, lookupFound
	}
	if ok {
		p.owners.Remove(key)
	}
	p.ownersMu.Unlock()
	return p.candidates(key)
}

func peerClientAddrPort(a net.Addr) (netip.AddrPort, bool) {
	if t, ok := a.(*net.TCPAddr); ok {
		ap := t.AddrPort()
		return ap, ap.IsValid()
	}
	ap, err := netip.ParseAddrPort(a.String())
	return ap, err == nil
}

type peerOutcome int

const (
	peerOK peerOutcome = iota
	peerDown
	peerStale
	peerSkew
)

type peerFrame struct {
	kind    byte
	port    uint16
	src     netip.AddrPort
	payload []byte
}

func (f peerFrame) encode(alpn string) ([]byte, bool) {
	if alpn != peerALPN2 && (alpn != peerALPN1 || f.kind != peerFrameSNI) {
		return nil, false
	}
	line, err := proxyProtoV1Line(f.src)
	if err != nil {
		return nil, false
	}
	buf := make([]byte, 0, 3+len(line)+len(f.payload))
	if alpn == peerALPN2 {
		buf = append(buf, f.kind)
		if f.kind == peerFrameTCP {
			buf = binary.BigEndian.AppendUint16(buf, f.port)
		}
	}
	buf = append(buf, line...)
	return append(buf, f.payload...), true
}

func (p *peerForwarder) attempt(owner storage.EdgePeer, frame peerFrame) (*tls.Conn, peerOutcome) {
	dialer := net.Dialer{Timeout: peerDialTimeout}
	raw, err := dialer.Dial("tcp", owner.PeerAddr)
	if err != nil {
		if _, marked := p.down.Peek(owner.PeerAddr); !marked {
			p.down.Add(owner.PeerAddr, time.Now())
		}
		slog.Debug("edge: peer dial failed", "owner", owner.EdgeID, "err", err)
		return nil, peerDown
	}
	tc := tls.Client(raw, p.clientTLS(owner.SPKISHA256))
	ctx, cancel := context.WithTimeout(context.Background(), peerDialTimeout)
	err = tc.HandshakeContext(ctx)
	cancel()
	if err != nil {
		raw.Close()
		slog.Debug("edge: peer handshake failed", "owner", owner.EdgeID, "err", err)
		return nil, peerStale
	}
	payload, ok := frame.encode(tc.ConnectionState().NegotiatedProtocol)
	if !ok {
		tc.Close()
		metricPeerVersionSkew.Add(1)
		slog.Debug("edge: peer owner cannot carry this frame", "owner", owner.EdgeID, "kind", frame.kind, "alpn", tc.ConnectionState().NegotiatedProtocol)
		return nil, peerSkew
	}
	var status [1]byte
	err = tc.SetDeadline(time.Now().Add(peerStatusTimeout))
	if err == nil {
		_, err = tc.Write(payload)
	}
	if err == nil {
		_, err = io.ReadFull(tc, status[:])
	}
	if err == nil {
		err = tc.SetDeadline(time.Time{})
	}
	if err != nil {
		tc.Close()
		slog.Debug("edge: peer status failed", "owner", owner.EdgeID, "err", err)
		return nil, peerStale
	}
	switch status[0] {
	case peerStatusAccept:
		return tc, peerOK
	case peerStatusNotOwner:
		metricPeerForwardStale.Add(1)
	}
	tc.Close()
	slog.Debug("edge: peer refused forward", "owner", owner.EdgeID, "status", status[0])
	return nil, peerStale
}

func (p *peerForwarder) local(client *replayConn) {
	p.public.deliver(client)
}

func (p *peerForwarder) pick(owners []storage.EdgePeer, failed storage.EdgePeer) (storage.EdgePeer, bool) {
	for _, owner := range owners {
		if owner.EdgeID == failed.EdgeID && owner.PeerAddr == failed.PeerAddr && owner.SPKISHA256 == failed.SPKISHA256 {
			continue
		}
		if _, down := p.down.Get(owner.PeerAddr); down {
			continue
		}
		return owner, true
	}
	return storage.EdgePeer{}, false
}

func (p *peerForwarder) predatesDown(entry *ownerEntry) bool {
	for _, owner := range entry.peers {
		if at, ok := p.down.Peek(owner.PeerAddr); ok && entry.resolved.Before(at) {
			return true
		}
	}
	return false
}

func (p *peerForwarder) connect(key string, entry *ownerEntry, frame peerFrame) (upstream *tls.Conn, noOwner bool) {
	var failed storage.EdgePeer
	resolved := key == ""
	reresolve := func() (found, noOwner bool) {
		resolved = true
		fresh, res := p.refresh(key, entry)
		switch res {
		case lookupNone:
			return false, true
		case lookupRefused:
			return false, false
		}
		entry = fresh
		return true, false
	}
	for attempt := 0; attempt < 2; attempt++ {
		owner, ok := p.pick(entry.peers, failed)
		if !ok {
			if resolved || (time.Since(entry.resolved) <= peerDownCacheTTL && !p.predatesDown(entry)) {
				return nil, false
			}
			found, none := reresolve()
			if !found {
				return nil, none
			}
			if owner, ok = p.pick(entry.peers, failed); !ok {
				return nil, false
			}
		}
		upstream, outcome := p.attempt(owner, frame)
		if upstream != nil {
			return upstream, false
		}
		failed = owner
		if outcome == peerStale && attempt == 0 && !resolved {
			found, none := reresolve()
			if !found {
				return nil, none
			}
		}
	}
	return nil, false
}

func (p *peerForwarder) reserve(ip string) (func(), bool) {
	if !p.forwardSem.tryAcquire() {
		metricPeerRejectedForwardCap.Add(1)
		return nil, false
	}
	releaseIP, ok := p.srv.perIP.acquire(ip)
	if !ok {
		p.forwardSem.release()
		metricRejectedPerIPCap.Add(1)
		return nil, false
	}
	return func() {
		releaseIP()
		p.forwardSem.release()
	}, true
}

func peerPayload(client *replayConn) (peerFrame, bool) {
	src, ok := peerClientAddrPort(client.RemoteAddr())
	if !ok {
		return peerFrame{}, false
	}
	if _, err := proxyProtoV1Line(src); err != nil {
		return peerFrame{}, false
	}
	return peerFrame{kind: peerFrameSNI, src: src, payload: client.buf}, true
}

func (p *peerForwarder) forward(client *replayConn, host string) {
	key := strings.ToLower(host)
	ip := remoteIP(client)
	if !p.srv.perIPLimiter.allow(ip) {
		metricRejectedRateLimited.Add(1)
		client.Close()
		return
	}
	entry, res := p.candidates(key)
	switch res {
	case lookupRefused:
		client.Close()
		return
	case lookupNone:
		p.local(client)
		return
	}
	release, ok := p.reserve(ip)
	if !ok {
		client.Close()
		return
	}
	defer release()
	frame, ok := peerPayload(client)
	if !ok {
		slog.Debug("edge: peer forward without a client address", "host", host)
		client.Close()
		return
	}
	upstream, noOwner := p.connect(key, entry, frame)
	switch {
	case noOwner:
		p.local(client)
	case upstream == nil:
		metricPeerForwardFailed.Add(1)
		slog.Debug("edge: peer forward failed", "host", host, "client", frame.src.String())
		client.Close()
	default:
		p.run(client.Conn, upstream, metricPeerForwardedConns)
	}
}

func (p *peerForwarder) run(client net.Conn, upstream *tls.Conn, forwarded *expvar.Int) {
	if !p.beginSplice() {
		upstream.Close()
		client.Close()
		return
	}
	metricActivePeerForwards.Add(1)
	forwarded.Add(1)
	defer p.splices.Done()
	defer metricActivePeerForwards.Add(-1)
	defer client.Close()
	defer upstream.Close()
	splice(client, upstream, p.srv.limitsOrDefault().TCPIdleTimeout, peerHalfCloseGrace)
}

func (p *peerForwarder) forwardTCP(port int, c net.Conn) {
	src, ok := peerClientAddrPort(c.RemoteAddr())
	if !ok {
		c.Close()
		return
	}
	if _, err := proxyProtoV1Line(src); err != nil {
		c.Close()
		return
	}
	ip := remoteIP(c)
	if !p.srv.perIPLimiter.allow(ip) {
		metricRejectedRateLimited.Add(1)
		c.Close()
		return
	}
	var owners []storage.EdgePeer
	if snapshot := p.tcpOwners.Load(); snapshot != nil {
		owners = (*snapshot)[port]
	}
	if len(owners) == 0 {
		c.Close()
		return
	}
	release, ok := p.reserve(ip)
	if !ok {
		c.Close()
		return
	}
	defer release()
	frame := peerFrame{kind: peerFrameTCP, port: uint16(port), src: src}
	upstream, _ := p.connect("", &ownerEntry{peers: owners}, frame)
	if upstream == nil {
		metricPeerForwardFailed.Add(1)
		slog.Debug("edge: peer tcp forward failed", "port", port, "client", src.String())
		c.Close()
		return
	}
	p.run(c, upstream, metricPeerTCPForwarded)
}

func (p *peerForwarder) watchTCP(ctx context.Context) error {
	defer p.srv.tcpMgr.reconcileRemote(nil, p.forwardTCP)
	p.pollTCP(ctx, time.Now())
	ticker := time.NewTicker(peerTCPPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			p.pollTCP(ctx, time.Now())
		}
	}
}

func (p *peerForwarder) pollTCP(ctx context.Context, now time.Time) {
	mgr := p.srv.tcpMgr
	qctx, cancel := context.WithTimeout(ctx, peerLookupTimeout)
	ports, err := p.store.LiveRemoteTCPPorts(qctx, p.srv.cfg.Domain, p.selfID, mgr.lo, mgr.hi, now, 2*maxRemoteTCPListeners)
	cancel()
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		slogStorageError("live remote tcp ports", err)
		if last := p.tcpFresh.Load(); last != 0 && now.Sub(time.Unix(0, last)) > p.leaseTTL() {
			p.tcpFresh.Store(0)
			p.tcpOwners.Store(&map[int][]storage.EdgePeer{})
			mgr.reconcileRemote(nil, p.forwardTCP)
		}
		return
	}
	p.tcpFresh.Store(now.UnixNano())
	p.tcpOwners.Store(&ports)
	want := make(map[int]struct{}, len(ports))
	for port := range ports {
		want[port] = struct{}{}
	}
	mgr.reconcileRemote(want, p.forwardTCP)
}

func validatePeerListen(listen string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("edge: invalid peer listen address %q: %w", listen, err)
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		return fmt.Errorf("edge: peer listen address %q must name a port from 1 to 65535", listen)
	}
	if host != "" {
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("edge: invalid peer listen address %q: the host must be an IP address or empty", listen)
		}
	}
	return nil
}

func validatePeerAddr(cfg Config, hasStorage bool) error {
	if cfg.PeerListen != "" && cfg.PeerAddr == "" {
		return errors.New("edge: a peer listen address requires a peer address")
	}
	if !hasStorage {
		return errors.New("edge: a peer address requires durable storage")
	}
	if cfg.Insecure {
		return errors.New("edge: a peer address cannot be combined with insecure mode")
	}
	ap, err := netip.ParseAddrPort(cfg.PeerAddr)
	if err != nil {
		return fmt.Errorf("edge: invalid peer address %q: %w", cfg.PeerAddr, err)
	}
	if ap.Addr().IsUnspecified() || ap.Port() == 0 {
		return fmt.Errorf("edge: peer address %q must name a specific address and port", cfg.PeerAddr)
	}
	if cfg.PeerListen != "" {
		return validatePeerListen(cfg.PeerListen)
	}
	return nil
}
