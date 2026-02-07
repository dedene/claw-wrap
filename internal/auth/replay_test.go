package auth

import (
	"testing"
	"time"
)

func TestReplayCache_SeenOrStore(t *testing.T) {
	cache := NewReplayCache(2*time.Second, 10)
	now := time.Now()

	if seen := cache.SeenOrStore("k1", now); seen {
		t.Fatal("first SeenOrStore should not be replay")
	}
	if seen := cache.SeenOrStore("k1", now.Add(500*time.Millisecond)); !seen {
		t.Fatal("second SeenOrStore within TTL should be replay")
	}
	if seen := cache.SeenOrStore("k1", now.Add(3*time.Second)); seen {
		t.Fatal("entry should expire after TTL")
	}
}

func TestReplayCache_MaxEntries(t *testing.T) {
	cache := NewReplayCache(10*time.Minute, 2)
	now := time.Now()

	_ = cache.SeenOrStore("a", now)
	_ = cache.SeenOrStore("b", now)
	_ = cache.SeenOrStore("c", now)

	if got := len(cache.entries); got > 2 {
		t.Fatalf("cache size = %d, want <= 2", got)
	}
}

func TestReplayCache_UpdateSettings(t *testing.T) {
	cache := NewReplayCache(10*time.Minute, 100)
	now := time.Now()

	// Store some entries.
	_ = cache.SeenOrStore("a", now)
	_ = cache.SeenOrStore("b", now)
	_ = cache.SeenOrStore("c", now)

	// Update with smaller max — should trim.
	cache.UpdateSettings(5*time.Minute, 2)
	if got := len(cache.entries); got > 2 {
		t.Fatalf("after UpdateSettings(max=2): cache size = %d, want <= 2", got)
	}

	// Existing non-evicted entries still detected as replays.
	remaining := 0
	for _, k := range []string{"a", "b", "c"} {
		if cache.SeenOrStore(k, now.Add(1*time.Second)) {
			remaining++
		}
	}
	if remaining == 0 {
		t.Fatal("expected at least one entry to survive UpdateSettings")
	}

	// New TTL applies to new entries.
	_ = cache.SeenOrStore("d", now)
	if seen := cache.SeenOrStore("d", now.Add(6*time.Minute)); seen {
		t.Fatal("entry should expire under new 5m TTL")
	}
}

func TestReplayCache_UpdateSettings_Defaults(t *testing.T) {
	cache := NewReplayCache(1*time.Minute, 10)

	// Zero/negative values should get defaults, not panic.
	cache.UpdateSettings(0, 0)
	if cache.ttl != 2*time.Minute {
		t.Fatalf("expected default TTL 2m, got %v", cache.ttl)
	}
	if cache.maxEntries != 10000 {
		t.Fatalf("expected default maxEntries 10000, got %d", cache.maxEntries)
	}
}
