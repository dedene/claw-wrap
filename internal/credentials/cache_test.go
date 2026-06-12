package credentials

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeCountingOPScript(t *testing.T, dir string) string {
	t.Helper()
	scriptPath := filepath.Join(dir, "op")
	script := `#!/bin/sh
counter="$CW_COUNTER_FILE"
count=0
if [ -f "$counter" ]; then
  count=$(cat "$counter")
fi
count=$((count + 1))
echo "$count" > "$counter"
echo "cached-secret"
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write mock op script: %v", err)
	}
	return scriptPath
}

func writeCountingPassScript(t *testing.T, dir string) string {
	t.Helper()
	scriptPath := filepath.Join(dir, "pass")
	script := `#!/bin/sh
counter="$CW_COUNTER_FILE"
count=0
if [ -f "$counter" ]; then
  count=$(cat "$counter")
fi
count=$((count + 1))
echo "$count" > "$counter"
shift
echo "secret-for-$1"
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write mock pass script: %v", err)
	}
	return scriptPath
}

func readCounterValue(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read counter file: %v", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("parse counter value: %v", err)
	}
	return n
}

func setupCredentialCacheTest(t *testing.T) func() {
	t.Helper()
	origNow := credentialCacheNow
	origTickerFactory := credentialTickerFactory
	origTTL := currentCredentialCacheTTL()
	credentialCacheNow = time.Now
	SetCredentialCacheTTL(0)
	clearCredentialCacheEntries()
	return func() {
		SetCredentialCacheTTL(0)
		clearCredentialCacheEntries()
		credentialCacheNow = origNow
		credentialTickerFactory = origTickerFactory
		SetCredentialCacheTTL(origTTL)
	}
}

func currentCredentialCacheTTL() time.Duration {
	credentialResultCache.mu.RLock()
	defer credentialResultCache.mu.RUnlock()
	return credentialResultCache.ttl
}

func cacheEntryExists(key string) bool {
	credentialResultCache.mu.RLock()
	defer credentialResultCache.mu.RUnlock()
	_, ok := credentialResultCache.entries[key]
	return ok
}

func cacheEntryCount() int {
	credentialResultCache.mu.RLock()
	defer credentialResultCache.mu.RUnlock()
	return len(credentialResultCache.entries)
}

func cacheSweeperState() (interval time.Duration, running bool) {
	credentialResultCache.mu.RLock()
	defer credentialResultCache.mu.RUnlock()
	return credentialResultCache.sweeperInterval, credentialResultCache.sweeperStop != nil
}

func waitUntil(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

type fakeTicker struct {
	ch      chan time.Time
	mu      sync.Mutex
	stopped bool
}

func newFakeTicker() *fakeTicker {
	return &fakeTicker{ch: make(chan time.Time, 4)}
}

func (t *fakeTicker) stop() {
	t.mu.Lock()
	t.stopped = true
	t.mu.Unlock()
}

func (t *fakeTicker) isStopped() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stopped
}

func (t *fakeTicker) tick(now time.Time) {
	select {
	case t.ch <- now:
	default:
	}
}

type fakeTickerFactory struct {
	mu        sync.Mutex
	tickers   []*fakeTicker
	intervals []time.Duration
}

func (f *fakeTickerFactory) newTicker(interval time.Duration) (<-chan time.Time, func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ticker := newFakeTicker()
	f.tickers = append(f.tickers, ticker)
	f.intervals = append(f.intervals, interval)
	return ticker.ch, ticker.stop
}

func (f *fakeTickerFactory) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.tickers)
}

func (f *fakeTickerFactory) ticker(i int) *fakeTicker {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tickers[i]
}

func (f *fakeTickerFactory) interval(i int) time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.intervals[i]
}

func TestFetch_Caches1PasswordWithinTTL(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	tmpDir := t.TempDir()
	counterPath := filepath.Join(tmpDir, "counter")
	opPath := writeCountingOPScript(t, tmpDir)
	t.Setenv("CW_COUNTER_FILE", counterPath)
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv(opTokenEnvVar, "test-token")

	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }
	SetCredentialCacheTTL(5 * time.Minute)

	for i := 0; i < 2; i++ {
		value, err := Fetch("op://Private/GitHub/token", WithOPBinary(opPath))
		if err != nil {
			t.Fatalf("Fetch() error = %v", err)
		}
		if value != "cached-secret" {
			t.Fatalf("Fetch() = %q, want %q", value, "cached-secret")
		}
	}

	if got := readCounterValue(t, counterPath); got != 1 {
		t.Fatalf("op invocation count = %d, want 1", got)
	}
}

func TestFetch_CacheTTLExpiryRefetches1Password(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	tmpDir := t.TempDir()
	counterPath := filepath.Join(tmpDir, "counter")
	opPath := writeCountingOPScript(t, tmpDir)
	t.Setenv("CW_COUNTER_FILE", counterPath)
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv(opTokenEnvVar, "test-token")

	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }
	SetCredentialCacheTTL(30 * time.Second)

	if _, err := Fetch("op://Private/GitHub/token", WithOPBinary(opPath)); err != nil {
		t.Fatalf("first Fetch() error = %v", err)
	}
	now = now.Add(31 * time.Second)
	if _, err := Fetch("op://Private/GitHub/token", WithOPBinary(opPath)); err != nil {
		t.Fatalf("second Fetch() error = %v", err)
	}

	if got := readCounterValue(t, counterPath); got != 2 {
		t.Fatalf("op invocation count = %d, want 2", got)
	}
}

func TestFetch_WithBypassCacheForcesLiveFetch(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	tmpDir := t.TempDir()
	counterPath := filepath.Join(tmpDir, "counter")
	opPath := writeCountingOPScript(t, tmpDir)
	t.Setenv("CW_COUNTER_FILE", counterPath)
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv(opTokenEnvVar, "test-token")

	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }
	SetCredentialCacheTTL(5 * time.Minute)

	if _, err := Fetch("op://Private/GitHub/token", WithOPBinary(opPath)); err != nil {
		t.Fatalf("first Fetch() error = %v", err)
	}
	if _, err := Fetch("op://Private/GitHub/token", WithOPBinary(opPath), WithBypassCache()); err != nil {
		t.Fatalf("second Fetch() error = %v", err)
	}

	if got := readCounterValue(t, counterPath); got != 2 {
		t.Fatalf("op invocation count = %d, want 2", got)
	}
}

func TestFetch_DoesNotCachePassBackend(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	tmpDir := t.TempDir()
	counterPath := filepath.Join(tmpDir, "counter")
	passPath := writeCountingPassScript(t, tmpDir)
	t.Setenv("CW_COUNTER_FILE", counterPath)

	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }
	SetCredentialCacheTTL(5 * time.Minute)

	for i := 0; i < 2; i++ {
		got, err := Fetch("pass:test/path", WithPassBinary(passPath))
		if err != nil {
			t.Fatalf("Fetch() error = %v", err)
		}
		want := "secret-for-test/path"
		if got != want {
			t.Fatalf("Fetch() = %q, want %q", got, want)
		}
	}

	if got := readCounterValue(t, counterPath); got != 2 {
		t.Fatalf("pass invocation count = %d, want 2", got)
	}
}

func TestSetCredentialCacheTTL_DisableClearsEntries(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	tmpDir := t.TempDir()
	counterPath := filepath.Join(tmpDir, "counter")
	opPath := writeCountingOPScript(t, tmpDir)
	t.Setenv("CW_COUNTER_FILE", counterPath)
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv(opTokenEnvVar, "test-token")

	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }

	SetCredentialCacheTTL(5 * time.Minute)
	if _, err := Fetch("op://Private/GitHub/token", WithOPBinary(opPath)); err != nil {
		t.Fatalf("first Fetch() error = %v", err)
	}

	SetCredentialCacheTTL(0)
	SetCredentialCacheTTL(5 * time.Minute)

	if _, err := Fetch("op://Private/GitHub/token", WithOPBinary(opPath)); err != nil {
		t.Fatalf("second Fetch() error = %v", err)
	}

	if got := readCounterValue(t, counterPath); got != 2 {
		t.Fatalf("op invocation count = %d, want 2", got)
	}
}

func TestSetCredentialCacheTTL_ChangingTTLFlushesEntries(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	tmpDir := t.TempDir()
	counterPath := filepath.Join(tmpDir, "counter")
	opPath := writeCountingOPScript(t, tmpDir)
	t.Setenv("CW_COUNTER_FILE", counterPath)
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv(opTokenEnvVar, "test-token")

	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }

	SetCredentialCacheTTL(5 * time.Minute)
	if _, err := Fetch("op://Private/GitHub/token", WithOPBinary(opPath)); err != nil {
		t.Fatalf("first Fetch() error = %v", err)
	}

	SetCredentialCacheTTL(1 * time.Minute)
	if _, err := Fetch("op://Private/GitHub/token", WithOPBinary(opPath)); err != nil {
		t.Fatalf("second Fetch() error = %v", err)
	}

	if got := readCounterValue(t, counterPath); got != 2 {
		t.Fatalf("op invocation count = %d, want 2", got)
	}
}

func TestCredentialCache_ActiveSweepEvictsExpiredWithoutRead(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	factory := &fakeTickerFactory{}
	credentialTickerFactory = factory.newTicker

	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }

	SetCredentialCacheTTL(10 * time.Second)
	if got := factory.count(); got != 1 {
		t.Fatalf("ticker count = %d, want 1", got)
	}
	if got := factory.interval(0); got != 5*time.Second {
		t.Fatalf("sweeper interval = %v, want 5s", got)
	}

	key := "op\x00op://Private/Item/field\x00"
	credentialResultCache.Set(key, "secret", now)
	if !cacheEntryExists(key) {
		t.Fatal("expected cache entry to exist before sweep")
	}

	now = now.Add(11 * time.Second)
	factory.ticker(0).tick(now)

	waitUntil(t, func() bool { return !cacheEntryExists(key) }, "expected sweeper to evict expired entry")
}

func TestCredentialCache_DisableClearsEntriesAndStopsSweeper(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	factory := &fakeTickerFactory{}
	credentialTickerFactory = factory.newTicker

	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }

	SetCredentialCacheTTL(30 * time.Second)
	credentialResultCache.Set("k1", "v1", now)
	if got := cacheEntryCount(); got != 1 {
		t.Fatalf("cache entry count = %d, want 1", got)
	}

	SetCredentialCacheTTL(0)

	if got := cacheEntryCount(); got != 0 {
		t.Fatalf("cache entry count after disable = %d, want 0", got)
	}
	interval, running := cacheSweeperState()
	if running {
		t.Fatal("expected sweeper to be stopped")
	}
	if interval != 0 {
		t.Fatalf("sweeper interval = %v, want 0", interval)
	}
	if !factory.ticker(0).isStopped() {
		t.Fatal("expected ticker stop func to be called")
	}
}

func TestCredentialCache_ChangingTTLRestartsSweeper(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	factory := &fakeTickerFactory{}
	credentialTickerFactory = factory.newTicker

	SetCredentialCacheTTL(20 * time.Second)
	if got := factory.count(); got != 1 {
		t.Fatalf("ticker count after first set = %d, want 1", got)
	}
	if got := factory.interval(0); got != 10*time.Second {
		t.Fatalf("first interval = %v, want 10s", got)
	}

	SetCredentialCacheTTL(40 * time.Second)
	if got := factory.count(); got != 2 {
		t.Fatalf("ticker count after ttl change = %d, want 2", got)
	}
	if !factory.ticker(0).isStopped() {
		t.Fatal("expected first ticker to be stopped after ttl change")
	}
	if got := factory.interval(1); got != 20*time.Second {
		t.Fatalf("second interval = %v, want 20s", got)
	}
	interval, running := cacheSweeperState()
	if !running {
		t.Fatal("expected sweeper to be running after ttl change")
	}
	if interval != 20*time.Second {
		t.Fatalf("stored sweeper interval = %v, want 20s", interval)
	}
}

func TestCredentialCache_SameTTLDoesNotSpawnDuplicateSweeper(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	factory := &fakeTickerFactory{}
	credentialTickerFactory = factory.newTicker

	SetCredentialCacheTTL(30 * time.Second)
	SetCredentialCacheTTL(30 * time.Second)

	if got := factory.count(); got != 1 {
		t.Fatalf("ticker count = %d, want 1", got)
	}
	if factory.ticker(0).isStopped() {
		t.Fatal("did not expect ticker to stop when ttl is unchanged")
	}
}

func TestSweepInterval(t *testing.T) {
	tests := []struct {
		name string
		ttl  time.Duration
		want time.Duration
	}{
		{"disabled", 0, 0},
		{"short ttl clamps min", 6 * time.Second, 5 * time.Second},
		{"normal ttl half", 40 * time.Second, 20 * time.Second},
		{"long ttl clamps max", 10 * time.Minute, time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sweepInterval(tt.ttl); got != tt.want {
				t.Fatalf("sweepInterval(%v) = %v, want %v", tt.ttl, got, tt.want)
			}
		})
	}
}

func TestCredentialCacheKey_NormalizesBackendPathAndJQ(t *testing.T) {
	parsed := &ParsedSource{
		Backend: Backend1Password,
		Path:    "op://Vault/Item/field",
		JQExpr:  ".foo",
	}
	key := credentialCacheKey(parsed)
	want := fmt.Sprintf("%s\x00%s\x00%s", Backend1Password, "op://Vault/Item/field", ".foo")
	if key != want {
		t.Fatalf("credentialCacheKey() = %q, want %q", key, want)
	}
}
