package agent

import (
	"crypto/rand"
	"encoding/hex"
	mrand "math/rand/v2"
	"time"
)

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b)
}

type backoff struct {
	base time.Duration
	cap  time.Duration
	prev time.Duration
}

func newBackoff(base, cap time.Duration) *backoff {
	return &backoff{base: base, cap: cap, prev: base}
}

func (b *backoff) reset() {
	b.prev = b.base
}

func (b *backoff) next() time.Duration {
	upper := b.prev * 3
	if upper > b.cap {
		upper = b.cap
	}
	if upper < b.base {
		upper = b.base
	}
	span := int64(upper - b.base)
	var d time.Duration
	if span <= 0 {
		d = b.base
	} else {
		d = b.base + time.Duration(mrand.Int64N(span+1))
	}
	if d > b.cap {
		d = b.cap
	}
	b.prev = d
	return d
}
