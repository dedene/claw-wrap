package credentials

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTrustedExecJSONHelper(t *testing.T, dir, name, body string) string {
	t.Helper()
	scriptPath := filepath.Join(dir, name)
	if err := os.WriteFile(scriptPath, []byte(body), 0o700); err != nil {
		t.Fatalf("write helper script: %v", err)
	}
	return scriptPath
}

func writeCountingExecJSONHelper(t *testing.T, dir string, counterPath string, value string, expiresAt string) string {
	t.Helper()
	body := fmt.Sprintf(`#!/bin/sh
n=$(cat %q 2>/dev/null || echo 0)
echo $((n + 1)) > %q
`, counterPath, counterPath)
	if expiresAt != "" {
		body += fmt.Sprintf(`printf '{"value":"%s","expires_at":"%s"}\n'`, value, expiresAt)
	} else {
		body += fmt.Sprintf(`printf '{"value":"%s"}\n'`, value)
	}
	return writeTrustedExecJSONHelper(t, dir, "mint", body)
}

func TestParseSource_ExecJSON(t *testing.T) {
	got, err := ParseSource("exec-json:/usr/local/lib/openclaw/mint-aws")
	if err != nil {
		t.Fatalf("ParseSource() error = %v", err)
	}
	if got.Backend != BackendExecJSON {
		t.Fatalf("Backend = %q, want %q", got.Backend, BackendExecJSON)
	}
	if got.Path != "/usr/local/lib/openclaw/mint-aws" {
		t.Fatalf("Path = %q", got.Path)
	}
}

func TestParseSource_ExecJSON_RejectsJQ(t *testing.T) {
	_, err := ParseSource(`exec-json:/usr/local/bin/mint | .value`)
	if err == nil {
		t.Fatal("ParseSource() error = nil, want jq rejection")
	}
	if !strings.Contains(err.Error(), "exec-json backend does not support jq extraction") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestFetchFromExecJSON_HappyPath(t *testing.T) {
	tmpDir := t.TempDir()
	expiresAt := time.Unix(1_700_003_600, 0).UTC().Format(time.RFC3339)
	scriptPath := writeTrustedExecJSONHelper(t, tmpDir, "mint", fmt.Sprintf(`#!/bin/sh
printf '{"value":"secret-token","expires_at":"%s"}\n'
`, expiresAt))

	source := "exec-json:" + scriptPath
	cred, err := FetchCredential(source, WithBypassCache())
	if err != nil {
		t.Fatalf("FetchCredential() error = %v", err)
	}
	if cred.Value != "secret-token" {
		t.Fatalf("Value = %q, want %q", cred.Value, "secret-token")
	}
	wantExpiry, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		t.Fatalf("parse expires_at: %v", err)
	}
	if !cred.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("ExpiresAt = %v, want %v", cred.ExpiresAt, wantExpiry)
	}
}

func TestFetchFromExecJSON_AbsentExpiresAtUsesStaticBehavior(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	tmpDir := t.TempDir()
	scriptPath := writeTrustedExecJSONHelper(t, tmpDir, "mint", `#!/bin/sh
printf '{"value":"static-secret"}\n'
`)

	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }
	SetCredentialCacheTTL(time.Hour)

	source := "exec-json:" + scriptPath
	cred, err := FetchCredential(source)
	if err != nil {
		t.Fatalf("FetchCredential() error = %v", err)
	}
	if !cred.ExpiresAt.IsZero() {
		t.Fatalf("ExpiresAt = %v, want zero", cred.ExpiresAt)
	}

	parsed, err := ParseSource(source)
	if err != nil {
		t.Fatalf("ParseSource() error = %v", err)
	}
	refreshAt, ok := cacheEntryRefreshAt(credentialCacheKey(parsed))
	if !ok {
		t.Fatal("cache entry missing refreshAt")
	}
	if !refreshAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("refreshAt = %v, want %v", refreshAt, now.Add(time.Hour))
	}
	hardExpiry, ok := cacheEntryHardExpiresAt(credentialCacheKey(parsed))
	if !ok {
		t.Fatal("cache entry missing hardExpiresAt")
	}
	if !hardExpiry.IsZero() {
		t.Fatalf("hardExpiresAt = %v, want zero", hardExpiry)
	}
}

func TestFetchFromExecJSON_MalformedJSONDoesNotLeakStdout(t *testing.T) {
	tmpDir := t.TempDir()
	secret := "super-secret-stdout-leak"
	scriptPath := writeTrustedExecJSONHelper(t, tmpDir, "mint", fmt.Sprintf(`#!/bin/sh
printf '%s\n'
`, secret))

	_, err := FetchCredential("exec-json:"+scriptPath, WithBypassCache())
	if err == nil {
		t.Fatal("FetchCredential() error = nil, want error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks stdout: %q", err.Error())
	}
}

func TestFetchFromExecJSON_NonZeroExitIncludesStderrNotStdout(t *testing.T) {
	tmpDir := t.TempDir()
	secret := "stdout-secret-value"
	stderrMsg := "helper failed safely"
	scriptPath := writeTrustedExecJSONHelper(t, tmpDir, "mint", fmt.Sprintf(`#!/bin/sh
printf '%s\n' >&2
printf '%s\n'
exit 1
`, stderrMsg, secret))

	_, err := FetchCredential("exec-json:"+scriptPath, WithBypassCache())
	if err == nil {
		t.Fatal("FetchCredential() error = nil, want error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks stdout: %q", err.Error())
	}
	if !strings.Contains(err.Error(), stderrMsg) {
		t.Fatalf("error = %q, want stderr message", err.Error())
	}
}

func TestFetchFromExecJSON_Timeout(t *testing.T) {
	origTimeout := execJSONCommandTimeout
	execJSONCommandTimeout = 50 * time.Millisecond
	t.Cleanup(func() { execJSONCommandTimeout = origTimeout })

	tmpDir := t.TempDir()
	scriptPath := writeTrustedExecJSONHelper(t, tmpDir, "mint", `#!/bin/sh
sleep 20
`)

	_, err := FetchCredential("exec-json:"+scriptPath, WithBypassCache())
	if err == nil {
		t.Fatal("FetchCredential() error = nil, want timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error = %q, want timeout", err.Error())
	}
}

func TestValidateExecJSONCommand_RejectsRelativePath(t *testing.T) {
	err := validateExecJSONCommand("relative/helper")
	if err == nil {
		t.Fatal("validateExecJSONCommand() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestValidateExecJSONCommand_RejectsWorldWritable(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := writeTrustedExecJSONHelper(t, tmpDir, "mint", "#!/bin/sh\necho ok\n")
	if err := os.Chmod(scriptPath, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	err := validateExecJSONCommand(scriptPath)
	if err == nil {
		t.Fatal("validateExecJSONCommand() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "group or world writable") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestFetchExecJSON_CacheIntegration(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	tmpDir := t.TempDir()
	counterPath := filepath.Join(tmpDir, "counter")
	expiresAt := time.Unix(1_700_003_600, 0).UTC().Format(time.RFC3339)
	scriptPath := writeCountingExecJSONHelper(t, tmpDir, counterPath, "cached-token", expiresAt)

	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }
	SetCredentialCacheTTL(time.Hour)

	source := "exec-json:" + scriptPath
	if _, err := FetchCredential(source); err != nil {
		t.Fatalf("first FetchCredential() error = %v", err)
	}
	if got := readCounterValue(t, counterPath); got != 1 {
		t.Fatalf("exec count after first fetch = %d, want 1", got)
	}

	if _, err := FetchCredential(source); err != nil {
		t.Fatalf("second FetchCredential() error = %v", err)
	}
	if got := readCounterValue(t, counterPath); got != 1 {
		t.Fatalf("exec count after cached fetch = %d, want 1", got)
	}
}
