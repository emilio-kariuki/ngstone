package e2e

import (
	"context"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"ngstone/internal/agent"
	"ngstone/internal/edge"
)

const (
	memTestBodySize   = 100 * 1024 * 1024
	memTestHeapBudget = 32 << 20
)

type deterministicReader struct {
	remaining int64
	idx       byte
}

func newDeterministicReader(n int64) *deterministicReader {
	return &deterministicReader{remaining: n}
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	for i := 0; i < n; i++ {
		p[i] = r.idx
		r.idx++
	}
	r.remaining -= int64(n)
	return n, nil
}

func TestConstantMemory100MB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 100MB constant-memory test in -short mode")
	}

	wantHasher := crc32.NewIEEE()
	if _, err := io.Copy(wantHasher, newDeterministicReader(memTestBodySize)); err != nil {
		t.Fatalf("computing reference checksum: %v", err)
	}
	wantSum := wantHasher.Sum32()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__ngstone_ready" {
			w.WriteHeader(http.StatusOK)
			return
		}
		io.Copy(w, newDeterministicReader(memTestBodySize))
	}))
	defer origin.Close()

	token := "mem-test-token"
	domain := "tun.example.com"
	hostname := "mem." + domain
	controlAddr := freeAddr(t)
	publicAddr := freeAddr(t)

	edgeSrv := edge.New(edge.Config{
		ControlAddr: controlAddr,
		PublicAddr:  publicAddr,
		Domain:      domain,
		TokenSHA256: mustSHA256(token),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go edgeSrv.Run(ctx)

	waitForPort(t, controlAddr)

	agt := agent.New(agent.Config{
		ControlAddr: controlAddr,
		Token:       token,
		Subdomain:   "mem",
		TargetURL:   origin.URL,
	})
	go agt.Run(ctx)

	waitBound(t, publicAddr, hostname)

	stopSampler := make(chan struct{})
	samplerDone := make(chan struct{})
	var maxHeap uint64
	go func() {
		defer close(samplerDone)
		var ms runtime.MemStats
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				runtime.ReadMemStats(&ms)
				if ms.HeapInuse > maxHeap {
					maxHeap = ms.HeapInuse
				}
			case <-stopSampler:
				return
			}
		}
	}()

	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://"+publicAddr+"/", nil)
	if err != nil {
		close(stopSampler)
		<-samplerDone
		t.Fatalf("new request: %v", err)
	}
	req.Host = hostname

	resp, err := client.Do(req)
	if err != nil {
		close(stopSampler)
		<-samplerDone
		t.Fatalf("GET through tunnel: %v", err)
	}

	gotHasher := crc32.NewIEEE()
	n, copyErr := io.Copy(gotHasher, resp.Body)
	resp.Body.Close()

	close(stopSampler)
	<-samplerDone

	if copyErr != nil {
		t.Fatalf("reading response body: %v", copyErr)
	}
	if n != memTestBodySize {
		t.Fatalf("received %d bytes, want %d", n, memTestBodySize)
	}
	if gotHasher.Sum32() != wantSum {
		t.Fatalf("checksum mismatch: got %08x want %08x", gotHasher.Sum32(), wantSum)
	}

	t.Logf("max HeapInuse during 100MB transfer: %d bytes (%.2f MiB)", maxHeap, float64(maxHeap)/(1<<20))
	if maxHeap > memTestHeapBudget {
		t.Fatalf("max HeapInuse %d bytes exceeds %d byte budget", maxHeap, uint64(memTestHeapBudget))
	}
}
