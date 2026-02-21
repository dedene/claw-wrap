package credentials

import (
	"sync"
	"time"
)

const (
	minCredentialCacheSweepInterval = 5 * time.Second
	maxCredentialCacheSweepInterval = time.Minute
)

type credentialCacheEntry struct {
	value     string
	expiresAt time.Time
}

type credentialCache struct {
	mu              sync.RWMutex
	ttl             time.Duration
	entries         map[string]credentialCacheEntry
	sweeperStop     chan struct{}
	sweeperDone     chan struct{}
	sweeperInterval time.Duration
}

var (
	credentialResultCache   = newCredentialCache()
	credentialCacheNow      = time.Now
	credentialTickerFactory = func(interval time.Duration) (<-chan time.Time, func()) {
		ticker := time.NewTicker(interval)
		return ticker.C, ticker.Stop
	}
)

func newCredentialCache() *credentialCache {
	return &credentialCache{
		entries: make(map[string]credentialCacheEntry),
	}
}

// SetCredentialCacheTTL configures the in-memory credential cache TTL.
// Non-positive values disable the cache.
func SetCredentialCacheTTL(ttl time.Duration) {
	credentialResultCache.SetTTL(ttl)
}

func (c *credentialCache) SetTTL(ttl time.Duration) {
	var stopCh chan struct{}
	var doneCh chan struct{}
	startSweeper := false
	interval := time.Duration(0)

	c.mu.Lock()
	switch {
	case ttl <= 0:
		c.ttl = 0
		c.entries = make(map[string]credentialCacheEntry)
		stopCh, doneCh = c.detachSweeperLocked()
	case ttl != c.ttl:
		c.ttl = ttl
		c.entries = make(map[string]credentialCacheEntry)
		stopCh, doneCh = c.detachSweeperLocked()
		startSweeper = true
		interval = sweepInterval(ttl)
	default:
		// Same positive TTL should keep current sweeper unchanged.
		if c.sweeperStop == nil {
			startSweeper = true
			interval = sweepInterval(ttl)
		}
	}
	c.mu.Unlock()

	stopCredentialCacheSweeper(stopCh, doneCh)
	if startSweeper {
		c.startSweeper(interval)
	}
}

func (c *credentialCache) Get(key string, now time.Time) (string, bool) {
	c.mu.RLock()
	ttl := c.ttl
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if ttl <= 0 || !ok {
		return "", false
	}
	if !now.Before(entry.expiresAt) {
		c.mu.Lock()
		if current, exists := c.entries[key]; exists && !now.Before(current.expiresAt) {
			delete(c.entries, key)
		}
		c.mu.Unlock()
		return "", false
	}

	return entry.value, true
}

func (c *credentialCache) Set(key, value string, now time.Time) {
	if key == "" || value == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ttl <= 0 {
		return
	}
	c.sweepExpiredLocked(now)
	c.entries[key] = credentialCacheEntry{
		value:     value,
		expiresAt: now.Add(c.ttl),
	}
}

func (c *credentialCache) sweepExpiredLocked(now time.Time) {
	for key, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
}

func (c *credentialCache) detachSweeperLocked() (chan struct{}, chan struct{}) {
	stopCh := c.sweeperStop
	doneCh := c.sweeperDone
	c.sweeperStop = nil
	c.sweeperDone = nil
	c.sweeperInterval = 0
	return stopCh, doneCh
}

func stopCredentialCacheSweeper(stopCh, doneCh chan struct{}) {
	if stopCh == nil || doneCh == nil {
		return
	}
	close(stopCh)
	<-doneCh
}

func (c *credentialCache) startSweeper(interval time.Duration) {
	if interval <= 0 {
		return
	}

	c.mu.Lock()
	if c.ttl <= 0 || c.sweeperStop != nil {
		c.mu.Unlock()
		return
	}
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	c.sweeperStop = stopCh
	c.sweeperDone = doneCh
	c.sweeperInterval = interval
	c.mu.Unlock()

	tickCh, stopTicker := credentialTickerFactory(interval)
	go func() {
		defer close(doneCh)
		defer stopTicker()
		for {
			select {
			case <-stopCh:
				return
			case <-tickCh:
				now := credentialCacheNow()
				c.mu.Lock()
				c.sweepExpiredLocked(now)
				c.mu.Unlock()
			}
		}
	}()
}

func sweepInterval(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return 0
	}
	interval := ttl / 2
	if interval < minCredentialCacheSweepInterval {
		interval = minCredentialCacheSweepInterval
	}
	if interval > maxCredentialCacheSweepInterval {
		interval = maxCredentialCacheSweepInterval
	}
	return interval
}

func isCredentialCacheableBackend(backend Backend) bool {
	return backend == Backend1Password || backend == BackendBitwarden || backend == BackendVault
}

func credentialCacheKey(parsed *ParsedSource) string {
	return string(parsed.Backend) + "\x00" + parsed.Path + "\x00" + parsed.JQExpr
}
