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
