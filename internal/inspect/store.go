package inspect

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	RingSize    = 200
	subChanSize = 16
)

const (
	KindHTTP    = "http"
	KindUpgrade = "upgrade"
)

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = 0
		}
	}
	return hex.EncodeToString(b)
}

var idSeq atomic.Uint64

func newID() string {
	return fmt.Sprintf("%012x-%s", idSeq.Add(1), randomHex(8))
}

type CapturedReq struct {
	Method    string
	URL       string
	Proto     string
	Header    http.Header
	Body      []byte
	BodySize  int64
	Truncated bool
}

type CapturedResp struct {
	Status    int
	Proto     string
	Header    http.Header
	Body      []byte
	BodySize  int64
	Truncated bool
}

type Exchange struct {
	ID       string
	ReqID    string
	Tunnel   string
	Kind     string
	Start    time.Time
	Duration time.Duration
	Req      CapturedReq
	Resp     CapturedResp
	Replayed bool
	ReplayOf string
	Err      string

	BytesClientToApp int64
	BytesAppToClient int64
}

func (e *Exchange) Clone() *Exchange {
	if e == nil {
		return nil
	}
	c := *e
	c.Req.Header = cloneHeader(e.Req.Header)
	c.Resp.Header = cloneHeader(e.Resp.Header)
	return &c
}

func cloneHeader(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	return h.Clone()
}

type Store struct {
	mu    sync.Mutex
	ring  []*Exchange
	head  int
	total int
	subs  map[chan *Exchange]struct{}
}

func NewStore() *Store {
	return &Store{
		ring: make([]*Exchange, RingSize),
		subs: make(map[chan *Exchange]struct{}),
	}
}

func (s *Store) NextID() string { return newID() }

func (s *Store) Add(e *Exchange) {
	if s == nil || e == nil {
		return
	}
	s.mu.Lock()
	s.ring[s.head] = e
	s.head = (s.head + 1) % len(s.ring)
	s.total++
	s.publishLocked(e)
	s.mu.Unlock()
}

func (s *Store) Update(id string, fn func(*Exchange)) (*Exchange, bool) {
	if s == nil || fn == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.ring {
		if e == nil || e.ID != id {
			continue
		}
		c := e.Clone()
		fn(c)
		s.ring[i] = c
		s.publishLocked(c)
		return c, true
	}
	return nil, false
}

func (s *Store) Get(id string) (*Exchange, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.ring {
		if e != nil && e.ID == id {
			return e, true
		}
	}
	return nil, false
}

func (s *Store) List() []*Exchange {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	n := s.total
	if n > len(s.ring) {
		n = len(s.ring)
	}
	out := make([]*Exchange, 0, n)
	start := (s.head - n + len(s.ring)) % len(s.ring)
	for i := 0; i < n; i++ {
		if e := s.ring[(start+i)%len(s.ring)]; e != nil {
			out = append(out, e)
		}
	}
	return out
}

func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.total > len(s.ring) {
		return len(s.ring)
	}
	return s.total
}

func (s *Store) Subscribe() (<-chan *Exchange, func()) {
	ch := make(chan *Exchange, subChanSize)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			s.mu.Lock()
			if _, ok := s.subs[ch]; ok {
				delete(s.subs, ch)
				close(ch)
			}
			s.mu.Unlock()
		})
	}
	return ch, cancel
}

func (s *Store) publishLocked(e *Exchange) {
	for ch := range s.subs {
		select {
		case ch <- e:
		default:
		}
	}
}
