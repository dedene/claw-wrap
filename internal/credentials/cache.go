package credentials

import (
	"log"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	minCredentialCacheSweepInterval = 5 * time.Second
	maxCredentialCacheSweepInterval = time.Minute
	credentialEarlyRefreshMargin    = 5 * time.Minute
)

type credentialCacheEntry struct {
	value         string
	refreshAt     time.Time
	hardExpiresAt time.Time
}

type credentialCache struct {
	mu              sync.RWMutex
	ttl             time.Duration
	entries         map[string]credentialCacheEntry
	sweeperStop     chan struct{}
	sweeperDone     chan struct{}
	sweeperInterval time.Duration
	fetchGroup      singleflight.Group
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

func (c *credentialCache) Get(key string, now time.Time) (Credential, bool) {
	c.mu.RLock()
	ttl := c.ttl
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if ttl <= 0 || !ok {
		return Credential{}, false
	}
	if !now.Before(entry.refreshAt) {
		if entry.hardExpiresAt.IsZero() || !now.Before(entry.hardExpiresAt) {
			c.mu.Lock()
			if current, exists := c.entries[key]; exists && !now.Before(current.refreshAt) {
				if current.hardExpiresAt.IsZero() || !now.Before(current.hardExpiresAt) {
					delete(c.entries, key)
				}
			}
			c.mu.Unlock()
		}
		return Credential{}, false
	}

	return Credential{Value: entry.value, ExpiresAt: entry.hardExpiresAt}, true
}

func (c *credentialCache) staleEntry(key string, now time.Time) (credentialCacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ttl <= 0 {
		return credentialCacheEntry{}, false
	}
	entry, ok := c.entries[key]
	if !ok || entry.hardExpiresAt.IsZero() || !now.Before(entry.hardExpiresAt) {
		return credentialCacheEntry{}, false
	}
	return entry, true
}

func (c *credentialCache) Set(key, value string, now time.Time) {
	c.SetCredential(key, Credential{Value: value}, now)
}

func (c *credentialCache) SetCredential(key string, cred Credential, now time.Time) {
	if key == "" || cred.Value == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ttl <= 0 {
		return
	}
	c.sweepExpiredLocked(now)
	c.entries[key] = credentialCacheEntry{
		value:         cred.Value,
		refreshAt:     computeRefreshAt(now, c.ttl, cred.ExpiresAt),
		hardExpiresAt: cred.ExpiresAt,
	}
}

func computeRefreshAt(now time.Time, ttl time.Duration, expiresAt time.Time) time.Time {
	refreshAt := now.Add(ttl)
	if expiresAt.IsZero() {
		return refreshAt
	}
	early := expiresAt.Add(-credentialEarlyRefreshMargin)
	if early.Before(refreshAt) {
		return early
	}
	return refreshAt
}

func (c *credentialCache) sweepExpiredLocked(now time.Time) {
	for key, entry := range c.entries {
		if entryExpired(entry, now) {
			delete(c.entries, key)
		}
	}
}

func entryExpired(entry credentialCacheEntry, now time.Time) bool {
	if !entry.hardExpiresAt.IsZero() {
		return !now.Before(entry.hardExpiresAt)
	}
	return !now.Before(entry.refreshAt)
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

func (c *credentialCache) fetchCached(
	cacheKey string,
	displaySource string,
	now time.Time,
	fetch func() (Credential, error),
) (Credential, error) {
	if cred, ok := c.Get(cacheKey, now); ok {
		return cred, nil
	}

	stale, hasStale := c.staleEntry(cacheKey, now)

	v, err, _ := c.fetchGroup.Do(cacheKey, func() (interface{}, error) {
		innerNow := credentialCacheNow()
		if cred, ok := c.Get(cacheKey, innerNow); ok {
			return cred, nil
		}
		cred, err := fetch()
		if err != nil {
			return nil, err
		}
		c.SetCredential(cacheKey, cred, credentialCacheNow())
		return cred, nil
	})
	if err != nil {
		if hasStale {
			log.Printf("[WARN] credential refresh failed for %s, serving stale value: %v", displaySource, err)
			return Credential{Value: stale.value, ExpiresAt: stale.hardExpiresAt}, nil
		}
		return Credential{}, err
	}
	return v.(Credential), nil
}
