package auth

import (
	"sync"
	"time"
)

// ReplayCache tracks recently seen request signatures to block short-window replays.
type ReplayCache struct {
	ttl        time.Duration
	maxEntries int

	mu      sync.Mutex
	entries map[string]time.Time
}

// NewReplayCache creates a replay cache with TTL and max size bounds.
func NewReplayCache(ttl time.Duration, maxEntries int) *ReplayCache {
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	return &ReplayCache{
		ttl:        ttl,
		maxEntries: maxEntries,
		entries:    make(map[string]time.Time, maxEntries),
	}
}

// SeenOrStore returns true if key already exists and is still valid, otherwise stores it and returns false.
func (c *ReplayCache) SeenOrStore(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.evictExpiredLocked(now)

	if exp, ok := c.entries[key]; ok && now.Before(exp) {
		return true
	}

	if len(c.entries) >= c.maxEntries {
		c.evictOneLocked()
	}

	c.entries[key] = now.Add(c.ttl)
	return false
}

func (c *ReplayCache) evictExpiredLocked(now time.Time) {
	for k, exp := range c.entries {
		if now.After(exp) {
			delete(c.entries, k)
		}
	}
}

func (c *ReplayCache) evictOneLocked() {
	var oldestKey string
	var oldestExpiry time.Time
	for k, exp := range c.entries {
		if oldestKey == "" || exp.Before(oldestExpiry) {
			oldestKey = k
			oldestExpiry = exp
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}
