package inspect

import (
	"sync"
	"testing"
	"time"
)

func mkExchange(id string) *Exchange {
	return &Exchange{ID: id, Kind: KindHTTP, Start: time.Now()}
}

func TestRingOverwritesOldest(t *testing.T) {
	s := NewStore()
	ids := make([]string, 0, RingSize+1)
	for i := 0; i < RingSize+1; i++ {
		e := mkExchange(s.NextID())
		ids = append(ids, e.ID)
		s.Add(e)
	}

	if got := s.Len(); got != RingSize {
		t.Fatalf("Len = %d, want %d", got, RingSize)
	}
	if _, ok := s.Get(ids[0]); ok {
		t.Fatalf("evicted id %q still present", ids[0])
	}
	if _, ok := s.Get(ids[1]); !ok {
		t.Fatalf("id %q should still be present", ids[1])
	}
	if _, ok := s.Get(ids[len(ids)-1]); !ok {
		t.Fatalf("newest id missing")
	}

	list := s.List()
	if len(list) != RingSize {
		t.Fatalf("List len = %d, want %d", len(list), RingSize)
	}
	if list[0].ID != ids[1] {
		t.Fatalf("List[0] = %q, want %q (oldest surviving)", list[0].ID, ids[1])
	}
	if list[len(list)-1].ID != ids[len(ids)-1] {
		t.Fatalf("List last = %q, want %q", list[len(list)-1].ID, ids[len(ids)-1])
	}
}

func TestIDsSortByArrival(t *testing.T) {
	s := NewStore()
	prev := ""
	for i := 0; i < 50; i++ {
		id := s.NextID()
		if prev != "" && !(prev < id) {
			t.Fatalf("id %q not greater than previous %q", id, prev)
		}
		prev = id
	}
}

func TestSubscribeReceivesAndCancelStops(t *testing.T) {
	s := NewStore()
	ch, cancel := s.Subscribe()

	e := mkExchange(s.NextID())
	s.Add(e)
	select {
	case got := <-ch:
		if got.ID != e.ID {
			t.Fatalf("got %q want %q", got.ID, e.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("no exchange delivered to subscriber")
	}

	cancel()
	cancel()
	if _, ok := <-ch; ok {
		t.Fatal("channel should be closed after cancel")
	}
	s.Add(mkExchange(s.NextID()))
}

func TestFullSubscriberIsDroppedNotBlocked(t *testing.T) {
	s := NewStore()
	_, cancel := s.Subscribe()

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 200; j++ {
					s.Add(mkExchange(s.NextID()))
				}
			}()
		}
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Add blocked on a full subscriber channel")
	}
	cancel()
}

func TestUpdatePublishesCopy(t *testing.T) {
	s := NewStore()
	ch, cancel := s.Subscribe()
	defer cancel()

	e := &Exchange{ID: s.NextID(), Kind: KindUpgrade}
	s.Add(e)
	first := <-ch

	updated, ok := s.Update(e.ID, func(x *Exchange) { x.BytesClientToApp = 42 })
	if !ok {
		t.Fatal("Update reported not found")
	}
	second := <-ch

	if second == first {
		t.Fatal("Update published the same pointer, readers can be raced")
	}
	if first.BytesClientToApp != 0 {
		t.Fatalf("original exchange mutated: %d", first.BytesClientToApp)
	}
	if updated.BytesClientToApp != 42 || second.BytesClientToApp != 42 {
		t.Fatalf("update not applied: %d / %d", updated.BytesClientToApp, second.BytesClientToApp)
	}
	got, _ := s.Get(e.ID)
	if got.BytesClientToApp != 42 {
		t.Fatalf("store not updated: %d", got.BytesClientToApp)
	}
}

func TestUpdateMissingID(t *testing.T) {
	s := NewStore()
	if _, ok := s.Update("nope", func(*Exchange) {}); ok {
		t.Fatal("Update on missing id reported success")
	}
}
