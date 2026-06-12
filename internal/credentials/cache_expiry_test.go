package credentials

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func writeAlwaysFailingOPScript(t *testing.T, dir string) string {
	t.Helper()
	scriptPath := filepath.Join(dir, "op")
	script := `#!/bin/sh
echo "simulated backend failure" >&2
exit 1
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write mock op script: %v", err)
	}
	return scriptPath
}

func cacheEntryRefreshAt(key string) (time.Time, bool) {
	credentialResultCache.mu.RLock()
	defer credentialResultCache.mu.RUnlock()
	entry, ok := credentialResultCache.entries[key]
	if !ok {
		return time.Time{}, false
	}
	return entry.refreshAt, true
}

func cacheEntryHardExpiresAt(key string) (time.Time, bool) {
	credentialResultCache.mu.RLock()
	defer credentialResultCache.mu.RUnlock()
	entry, ok := credentialResultCache.entries[key]
	if !ok {
		return time.Time{}, false
	}
	return entry.hardExpiresAt, true
}

func TestFetch_SingleflightDeduplicatesConcurrentFetches(t *testing.T) {
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

	const workers = 50
	var wg sync.WaitGroup
	errs := make([]error, workers)
	values := make([]string, workers)

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			value, err := Fetch("op://Private/GitHub/token", WithOPBinary(opPath))
			values[idx] = value
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Fetch() worker %d error = %v", i, err)
		}
		if values[i] != "cached-secret" {
			t.Fatalf("Fetch() worker %d = %q, want %q", i, values[i], "cached-secret")
		}
	}

	if got := readCounterValue(t, counterPath); got != 1 {
		t.Fatalf("op invocation count = %d, want 1", got)
	}
}

func TestComputeRefreshAt_ZeroExpiresAtUsesTTL(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ttl := 30 * time.Minute
	got := computeRefreshAt(now, ttl, time.Time{})
	want := now.Add(ttl)
	if !got.Equal(want) {
		t.Fatalf("computeRefreshAt() = %v, want %v", got, want)
	}
}

func TestComputeRefreshAt_NonZeroExpiresAtUsesEarlierOfTTLAndMargin(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ttl := 30 * time.Minute

	t.Run("expires_at_minus_margin_before_ttl", func(t *testing.T) {
		expiresAt := now.Add(10 * time.Minute)
		got := computeRefreshAt(now, ttl, expiresAt)
		want := expiresAt.Add(-credentialEarlyRefreshMargin)
		if !got.Equal(want) {
			t.Fatalf("computeRefreshAt() = %v, want %v", got, want)
		}
	})

	t.Run("ttl_before_expires_at_minus_margin", func(t *testing.T) {
		expiresAt := now.Add(2 * time.Hour)
		got := computeRefreshAt(now, ttl, expiresAt)
		want := now.Add(ttl)
		if !got.Equal(want) {
			t.Fatalf("computeRefreshAt() = %v, want %v", got, want)
		}
	})
}

func TestCredentialCache_SetCredentialStoresPerEntryRefreshAt(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }
	SetCredentialCacheTTL(30 * time.Minute)

	key := "test\x00key\x00"
	expiresAt := now.Add(10 * time.Minute)
	credentialResultCache.SetCredential(key, Credential{Value: "secret", ExpiresAt: expiresAt}, now)

	refreshAt, ok := cacheEntryRefreshAt(key)
	if !ok {
		t.Fatal("expected cache entry refreshAt")
	}
	wantRefresh := expiresAt.Add(-credentialEarlyRefreshMargin)
	if !refreshAt.Equal(wantRefresh) {
		t.Fatalf("refreshAt = %v, want %v", refreshAt, wantRefresh)
	}

	hardExpiresAt, ok := cacheEntryHardExpiresAt(key)
	if !ok || !hardExpiresAt.Equal(expiresAt) {
		t.Fatalf("hardExpiresAt = %v, want %v", hardExpiresAt, expiresAt)
	}
}

func TestFetchCredential_StaleIfValidBeforeHardExpiry(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	tmpDir := t.TempDir()
	opPath := writeAlwaysFailingOPScript(t, tmpDir)
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv(opTokenEnvVar, "test-token")

	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }
	SetCredentialCacheTTL(30 * time.Minute)

	key := credentialCacheKey(&ParsedSource{
		Backend: Backend1Password,
		Path:    "op://Private/GitHub/token",
	})
	hardExpiry := now.Add(1 * time.Hour)
	credentialResultCache.SetCredential(key, Credential{Value: "stale-secret", ExpiresAt: hardExpiry}, now)

	now = now.Add(31 * time.Minute)
	credentialCacheNow = func() time.Time { return now }

	cred, err := FetchCredential("op://Private/GitHub/token", WithOPBinary(opPath))
	if err != nil {
		t.Fatalf("FetchCredential() error = %v", err)
	}
	if cred.Value != "stale-secret" {
		t.Fatalf("FetchCredential().Value = %q, want %q", cred.Value, "stale-secret")
	}
	if !cred.ExpiresAt.Equal(hardExpiry) {
		t.Fatalf("FetchCredential().ExpiresAt = %v, want %v", cred.ExpiresAt, hardExpiry)
	}
}

func TestFetchCredential_StaleIfValidReturnsErrorAfterHardExpiry(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	tmpDir := t.TempDir()
	opPath := writeAlwaysFailingOPScript(t, tmpDir)
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv(opTokenEnvVar, "test-token")

	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }
	SetCredentialCacheTTL(30 * time.Minute)

	key := credentialCacheKey(&ParsedSource{
		Backend: Backend1Password,
		Path:    "op://Private/GitHub/token",
	})
	hardExpiry := now.Add(20 * time.Minute)
	credentialResultCache.SetCredential(key, Credential{Value: "stale-secret", ExpiresAt: hardExpiry}, now)

	now = hardExpiry.Add(time.Second)
	credentialCacheNow = func() time.Time { return now }

	_, err := FetchCredential("op://Private/GitHub/token", WithOPBinary(opPath))
	if err == nil {
		t.Fatal("FetchCredential() error = nil, want error after hard expiry")
	}
}

func TestFetchCredential_ZeroExpiresAtRefreshFailurePropagatesError(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	tmpDir := t.TempDir()
	failPath := filepath.Join(tmpDir, "op")
	script := `#!/bin/sh
echo "backend down" >&2
exit 1
`
	if err := os.WriteFile(failPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write failing op script: %v", err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv(opTokenEnvVar, "test-token")

	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }
	SetCredentialCacheTTL(5 * time.Minute)

	key := credentialCacheKey(&ParsedSource{
		Backend: Backend1Password,
		Path:    "op://Private/GitHub/token",
	})
	credentialResultCache.Set(key, "cached-secret", now)

	now = now.Add(6 * time.Minute)
	credentialCacheNow = func() time.Time { return now }

	_, err := FetchCredential("op://Private/GitHub/token", WithOPBinary(failPath))
	if err == nil {
		t.Fatal("FetchCredential() error = nil, want error for zero ExpiresAt refresh failure")
	}
}

func TestFetchCredential_ZeroExpiresAtRegressionMatchesFetchTTL(t *testing.T) {
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

	for i := 0; i < 2; i++ {
		cred, err := FetchCredential("op://Private/GitHub/token", WithOPBinary(opPath))
		if err != nil {
			t.Fatalf("FetchCredential() error = %v", err)
		}
		if cred.Value != "cached-secret" {
			t.Fatalf("FetchCredential().Value = %q, want %q", cred.Value, "cached-secret")
		}
		if !cred.ExpiresAt.IsZero() {
			t.Fatalf("FetchCredential().ExpiresAt = %v, want zero", cred.ExpiresAt)
		}
	}

	if got := readCounterValue(t, counterPath); got != 1 {
		t.Fatalf("op invocation count within TTL = %d, want 1", got)
	}

	now = now.Add(31 * time.Second)
	credentialCacheNow = func() time.Time { return now }
	if _, err := FetchCredential("op://Private/GitHub/token", WithOPBinary(opPath)); err != nil {
		t.Fatalf("FetchCredential() after TTL error = %v", err)
	}

	if got := readCounterValue(t, counterPath); got != 2 {
		t.Fatalf("op invocation count after TTL = %d, want 2", got)
	}
}
