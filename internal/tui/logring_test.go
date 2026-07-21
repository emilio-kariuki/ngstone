package tui

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestLogRingCapacityAndOrder(t *testing.T) {
	ring := NewLogRing(3)
	logger := slog.New(ring)

	logger.Info("one")
	logger.Info("two")
	logger.Info("three")
	logger.Info("four")

	lines := ring.Lines()
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines after exceeding capacity, got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "two") {
		t.Fatalf("expected oldest surviving line to be 'two', got %q", lines[0])
	}
	if !strings.Contains(lines[1], "three") {
		t.Fatalf("expected second line to be 'three', got %q", lines[1])
	}
	if !strings.Contains(lines[2], "four") {
		t.Fatalf("expected newest line to be 'four', got %q", lines[2])
	}
}

func TestLogRingDefaultCapacity(t *testing.T) {
	ring := NewLogRing(0)
	if ring.cap != 500 {
		t.Fatalf("expected default capacity 500, got %d", ring.cap)
	}
}

func TestLogRingWithAttrsAndGroup(t *testing.T) {
	ring := NewLogRing(10)
	base := slog.New(ring)

	base.Info("plain")

	derived := base.With("req", "abc").WithGroup("http").With("status", 200)
	derived.Info("grouped")

	base.Info("plain-again")

	lines := ring.Lines()
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %v", len(lines), lines)
	}
	if strings.Contains(lines[0], "req=") || strings.Contains(lines[0], "http.") {
		t.Fatalf("expected first line to not carry derived attrs, got %q", lines[0])
	}
	if !strings.Contains(lines[1], "req=abc") {
		t.Fatalf("expected second line to contain req=abc, got %q", lines[1])
	}
	if !strings.Contains(lines[1], "http.status=200") {
		t.Fatalf("expected second line to contain grouped status attr, got %q", lines[1])
	}
	if strings.Contains(lines[2], "req=") || strings.Contains(lines[2], "http.") {
		t.Fatalf("expected third line (from base handler) to not carry derived attrs, got %q", lines[2])
	}
}

func TestLogRingHandleContextIgnored(t *testing.T) {
	ring := NewLogRing(2)
	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "hello", 0)
	if err := ring.Handle(context.Background(), rec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := ring.Lines()
	if len(lines) != 1 || !strings.Contains(lines[0], "hello") {
		t.Fatalf("expected one line containing 'hello', got %v", lines)
	}
}
