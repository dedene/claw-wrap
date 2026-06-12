package credentials

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func generateTestRSAKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return key, string(pemBytes)
}

func writePEMPassScript(t *testing.T, dir, pem string) string {
	t.Helper()
	scriptPath := filepath.Join(dir, "pass")
	script := "#!/bin/sh\ncat <<'EOF'\n" + pem + "EOF\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write pass script: %v", err)
	}
	return scriptPath
}

func TestSignGitHubAppJWT_VerifiesClaims(t *testing.T) {
	privateKey, _ := generateTestRSAKey(t)
	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }
	t.Cleanup(func() { credentialCacheNow = time.Now })

	const appID int64 = 12345
	jwt, err := signGitHubAppJWT(privateKey, appID, now)
	if err != nil {
		t.Fatalf("signGitHubAppJWT() error = %v", err)
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt parts = %d, want 3", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if string(headerJSON) != `{"alg":"RS256","typ":"JWT"}` {
		t.Fatalf("header = %s", headerJSON)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if claims.Iss != "12345" {
		t.Fatalf("iss = %q, want %q", claims.Iss, "12345")
	}
	wantIat := now.Add(-githubAppJWTIssuedOffset).Unix()
	wantExp := now.Add(githubAppJWTLifetime).Unix()
	if claims.Iat != wantIat {
		t.Fatalf("iat = %d, want %d", claims.Iat, wantIat)
	}
	if claims.Exp != wantExp {
		t.Fatalf("exp = %d, want %d", claims.Exp, wantExp)
	}

	digest := sha256Sum([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest, sig); err != nil {
		t.Fatalf("VerifyPKCS1v15() error = %v", err)
	}
}

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func TestMintGitHubAppInstallationToken_HTTPServerFlow(t *testing.T) {
	privateKey, pemData := generateTestRSAKey(t)
	tmpDir := t.TempDir()
	passPath := writePEMPassScript(t, tmpDir, pemData)

	var gotAuth string
	var gotBody githubAppExchangeRequest
	expiresAt := time.Unix(1_700_003_600, 0).UTC().Format(time.RFC3339)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/app/installations/99/access_tokens") {
			t.Errorf("path = %s", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("Accept = %q", r.Header.Get("Accept"))
		}
		if r.Header.Get("X-GitHub-Api-Version") != githubAPIVersionHeader {
			t.Errorf("X-GitHub-Api-Version = %q", r.Header.Get("X-GitHub-Api-Version"))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if err := json.Unmarshal(body, &gotBody); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(githubAppExchangeResponse{
			Token:     "ghs_test_installation_token",
			ExpiresAt: expiresAt,
		})
	}))
	t.Cleanup(server.Close)

	origClient := githubAppHTTPClient
	githubAppHTTPClient = server.Client()
	t.Cleanup(func() { githubAppHTTPClient = origClient })

	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }
	t.Cleanup(func() { credentialCacheNow = time.Now })

	spec := GitHubAppSpec{
		AppID:            42,
		InstallationID:   99,
		PrivateKeySource: "pass:github/app.pem",
		APIURL:           server.URL,
		Permissions:      map[string]string{"contents": "read"},
		Repositories:     []string{"org/repo"},
	}
	options := &FetchOptions{PassBinary: passPath}

	cred, err := mintGitHubAppInstallationToken(spec, options)
	if err != nil {
		t.Fatalf("mintGitHubAppInstallationToken() error = %v", err)
	}
	if cred.Value != "ghs_test_installation_token" {
		t.Fatalf("token = %q", cred.Value)
	}
	if cred.ExpiresAt.UTC().Format(time.RFC3339) != expiresAt {
		t.Fatalf("expires_at = %v, want %s", cred.ExpiresAt, expiresAt)
	}
	if !strings.HasPrefix(gotAuth, "Bearer ") {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	jwt := strings.TrimPrefix(gotAuth, "Bearer ")
	if err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, sha256Sum([]byte(strings.Split(jwt, ".")[0]+"."+strings.Split(jwt, ".")[1])), decodeSegment(t, strings.Split(jwt, ".")[2])); err != nil {
		t.Fatalf("jwt verify: %v", err)
	}
	if gotBody.Permissions["contents"] != "read" {
		t.Fatalf("permissions = %#v", gotBody.Permissions)
	}
	if len(gotBody.Repositories) != 1 || gotBody.Repositories[0] != "org/repo" {
		t.Fatalf("repositories = %#v", gotBody.Repositories)
	}
}

func decodeSegment(t *testing.T, seg string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("decode segment: %v", err)
	}
	return b
}

func TestFetchGitHubAppCredential_CacheIntegration(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	_, pemData := generateTestRSAKey(t)
	tmpDir := t.TempDir()
	passPath := writePEMPassScript(t, tmpDir, pemData)

	var requestCount atomic.Int32
	expiresAt := time.Unix(1_700_003_600, 0).UTC()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(githubAppExchangeResponse{
			Token:     "ghs_cached_token",
			ExpiresAt: expiresAt.Format(time.RFC3339),
		})
	}))
	t.Cleanup(server.Close)

	origClient := githubAppHTTPClient
	githubAppHTTPClient = server.Client()
	t.Cleanup(func() { githubAppHTTPClient = origClient })

	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }
	SetCredentialCacheTTL(time.Hour)

	input := ResolveInput{
		Label:          "gh-app",
		Type:           githubAppCredentialType,
		AppID:          1,
		InstallationID: 2,
		PrivateKey:     "pass:github/app.pem",
		APIURL:         server.URL,
	}

	opts := []FetchOption{WithPassBinary(passPath)}
	if _, err := ResolveCredential(input, opts...); err != nil {
		t.Fatalf("first ResolveCredential() error = %v", err)
	}
	if got := requestCount.Load(); got != 1 {
		t.Fatalf("request count after first fetch = %d, want 1", got)
	}

	if _, err := ResolveCredential(input, opts...); err != nil {
		t.Fatalf("second ResolveCredential() error = %v", err)
	}
	if got := requestCount.Load(); got != 1 {
		t.Fatalf("request count after cached fetch = %d, want 1", got)
	}

	refreshAt := expiresAt.Add(-credentialEarlyRefreshMargin)
	credentialCacheNow = func() time.Time { return refreshAt.Add(time.Second) }
	if _, err := ResolveCredential(input, opts...); err != nil {
		t.Fatalf("third ResolveCredential() error = %v", err)
	}
	if got := requestCount.Load(); got != 2 {
		t.Fatalf("request count after refresh window = %d, want 2", got)
	}
}

func TestFetchGitHubAppCredential_StaleIfValidOnMintFailure(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	_, pemData := generateTestRSAKey(t)
	tmpDir := t.TempDir()
	passPath := writePEMPassScript(t, tmpDir, pemData)

	expiresAt := time.Unix(1_700_003_600, 0).UTC()
	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := requestCount.Add(1)
		if count == 1 {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(githubAppExchangeResponse{
				Token:     "ghs_stale_token",
				ExpiresAt: expiresAt.Format(time.RFC3339),
			})
			return
		}
		http.Error(w, `{"message":"internal error"}`, http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	origClient := githubAppHTTPClient
	githubAppHTTPClient = server.Client()
	t.Cleanup(func() { githubAppHTTPClient = origClient })

	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }
	SetCredentialCacheTTL(time.Hour)

	input := ResolveInput{
		Label:          "gh-app",
		Type:           githubAppCredentialType,
		AppID:          1,
		InstallationID: 2,
		PrivateKey:     "pass:github/app.pem",
		APIURL:         server.URL,
	}
	opts := []FetchOption{WithPassBinary(passPath)}

	first, err := ResolveCredential(input, opts...)
	if err != nil {
		t.Fatalf("first ResolveCredential() error = %v", err)
	}
	if first.Value != "ghs_stale_token" {
		t.Fatalf("first token = %q", first.Value)
	}

	refreshAt := expiresAt.Add(-credentialEarlyRefreshMargin)
	credentialCacheNow = func() time.Time { return refreshAt.Add(time.Second) }
	stale, err := ResolveCredential(input, opts...)
	if err != nil {
		t.Fatalf("stale ResolveCredential() error = %v", err)
	}
	if stale.Value != "ghs_stale_token" {
		t.Fatalf("stale token = %q", stale.Value)
	}

	credentialCacheNow = func() time.Time { return expiresAt }
	if _, err := ResolveCredential(input, opts...); err == nil {
		t.Fatal("expected error after hard expiry")
	}
}

func TestMintGitHubAppInstallationToken_LogHygiene(t *testing.T) {
	_, pemData := generateTestRSAKey(t)
	tmpDir := t.TempDir()
	passPath := writePEMPassScript(t, tmpDir, pemData)

	tokenValue := "ghs_super_secret_token_value"
	expiresAt := time.Unix(1_700_003_600, 0).UTC().Format(time.RFC3339)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(githubAppExchangeResponse{
			Token:     tokenValue,
			ExpiresAt: expiresAt,
		})
	}))
	t.Cleanup(server.Close)

	origClient := githubAppHTTPClient
	githubAppHTTPClient = server.Client()
	t.Cleanup(func() { githubAppHTTPClient = origClient })

	var logBuf bytes.Buffer
	origOutput := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(origOutput) })

	credentialCacheNow = func() time.Time { return time.Unix(1_700_000_000, 0) }
	t.Cleanup(func() { credentialCacheNow = time.Now })

	spec := GitHubAppSpec{
		AppID:            7,
		InstallationID:   8,
		PrivateKeySource: "pass:github/app.pem",
		APIURL:           server.URL,
	}
	if _, err := mintGitHubAppInstallationToken(spec, &FetchOptions{PassBinary: passPath}); err != nil {
		t.Fatalf("mintGitHubAppInstallationToken() error = %v", err)
	}

	logOutput := logBuf.String()
	if strings.Contains(logOutput, tokenValue) {
		t.Fatalf("log output contains token: %s", logOutput)
	}
	if strings.Contains(logOutput, pemData) {
		t.Fatalf("log output contains private key material")
	}
}

func TestParseRSAPrivateKeyPEM_PKCS8(t *testing.T) {
	key, _ := generateTestRSAKey(t)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	pemData := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	parsed, err := parseRSAPrivateKeyPEM(pemData)
	if err != nil {
		t.Fatalf("parseRSAPrivateKeyPEM() error = %v", err)
	}
	if parsed.D.Cmp(key.D) != 0 {
		t.Fatal("parsed key mismatch")
	}
}

func TestFetchGitHubAppCredential_StaleLogUsesDisplayLabel(t *testing.T) {
	restore := setupCredentialCacheTest(t)
	defer restore()

	_, pemData := generateTestRSAKey(t)
	tmpDir := t.TempDir()
	passPath := writePEMPassScript(t, tmpDir, pemData)

	expiresAt := time.Unix(1_700_003_600, 0).UTC()
	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestCount.Add(1) == 1 {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(githubAppExchangeResponse{
				Token:     "ghs_stale_token",
				ExpiresAt: expiresAt.Format(time.RFC3339),
			})
			return
		}
		http.Error(w, `{"message":"internal error"}`, http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	origClient := githubAppHTTPClient
	githubAppHTTPClient = server.Client()
	t.Cleanup(func() { githubAppHTTPClient = origClient })

	var logBuf bytes.Buffer
	origOutput := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(origOutput) })

	now := time.Unix(1_700_000_000, 0)
	credentialCacheNow = func() time.Time { return now }
	SetCredentialCacheTTL(time.Hour)

	input := ResolveInput{
		Label:          "my-github-app-cred",
		Type:           githubAppCredentialType,
		AppID:          1,
		InstallationID: 2,
		PrivateKey:     "pass:github/app.pem",
		APIURL:         server.URL,
	}
	opts := []FetchOption{WithPassBinary(passPath)}

	if _, err := ResolveCredential(input, opts...); err != nil {
		t.Fatalf("first ResolveCredential() error = %v", err)
	}

	credentialCacheNow = func() time.Time { return expiresAt.Add(-credentialEarlyRefreshMargin).Add(time.Second) }
	if _, err := ResolveCredential(input, opts...); err != nil {
		t.Fatalf("stale ResolveCredential() error = %v", err)
	}

	if !strings.Contains(logBuf.String(), "my-github-app-cred") {
		t.Fatalf("stale log missing label, got: %s", logBuf.String())
	}
	if strings.Contains(logBuf.String(), "github-app\x00") {
		t.Fatalf("stale log contains cache key: %s", logBuf.String())
	}
}

func TestParseRSAPrivateKeyPEM_UnsupportedType(t *testing.T) {
	pemData := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("bad")}))
	if _, err := parseRSAPrivateKeyPEM(pemData); err == nil {
		t.Fatal("expected error for unsupported PEM type")
	}
}
