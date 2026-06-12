package credentials

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"claw-wrap/internal/paths"
)

const (
	githubAppCredentialType   = "github-app"
	defaultGitHubAPIURL       = "https://api.github.com"
	githubAppExchangeTimeout  = 10 * time.Second
	githubAppJWTIssuedOffset  = 60 * time.Second
	githubAppJWTLifetime      = 540 * time.Second
	githubAPIVersionHeader    = "2022-11-28"
)

var githubAppHTTPClient = &http.Client{Timeout: githubAppExchangeTimeout}

type githubAppExchangeRequest struct {
	Permissions  map[string]string `json:"permissions,omitempty"`
	Repositories []string          `json:"repositories,omitempty"`
}

type githubAppExchangeResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	Message   string `json:"message"`
}

func errUnknownCredentialType(typ string) error {
	return fmt.Errorf("unknown credential type %q", typ)
}

func githubAppDisplaySource(appID, installationID int64) string {
	return fmt.Sprintf("github-app:%d/%d", appID, installationID)
}

func fetchGitHubAppCredential(input ResolveInput, opts ...FetchOption) (Credential, error) {
	spec := githubAppSpecFromInput(input)
	options := &FetchOptions{PassBinary: paths.DefaultPassBinary()}
	for _, opt := range opts {
		opt(options)
	}

	cacheKey := githubAppCacheKey(spec)
	displaySource := input.DisplaySource()
	now := credentialCacheNow()
	if options.BypassCache {
		return mintGitHubAppInstallationToken(spec, options)
	}
	return credentialResultCache.fetchCached(cacheKey, displaySource, now, func() (Credential, error) {
		return mintGitHubAppInstallationToken(spec, options)
	})
}

func githubAppSpecFromInput(input ResolveInput) GitHubAppSpec {
	apiURL := strings.TrimSpace(input.APIURL)
	if apiURL == "" {
		apiURL = defaultGitHubAPIURL
	}
	return GitHubAppSpec{
		AppID:            input.AppID,
		InstallationID:   input.InstallationID,
		PrivateKeySource: strings.TrimSpace(input.PrivateKey),
		APIURL:           apiURL,
		Permissions:      input.Permissions,
		Repositories:     input.Repositories,
	}
}

// GitHubAppSpec is the neutral provider spec for GitHub App installation tokens.
type GitHubAppSpec struct {
	AppID            int64
	InstallationID   int64
	PrivateKeySource string
	APIURL           string
	Permissions      map[string]string
	Repositories     []string
}

func githubAppCacheKey(spec GitHubAppSpec) string {
	return "github-app\x00" +
		strconv.FormatInt(spec.AppID, 10) + "\x00" +
		strconv.FormatInt(spec.InstallationID, 10) + "\x00" +
		spec.APIURL + "\x00" +
		canonicalPermissionString(spec.Permissions) + "\x00" +
		canonicalRepositoryString(spec.Repositories)
}

func canonicalPermissionString(perms map[string]string) string {
	if len(perms) == 0 {
		return ""
	}
	keys := make([]string, 0, len(perms))
	for key := range perms {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+perms[key])
	}
	return strings.Join(parts, ",")
}

func canonicalRepositoryString(repos []string) string {
	if len(repos) == 0 {
		return ""
	}
	sorted := append([]string(nil), repos...)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}

func mintGitHubAppInstallationToken(spec GitHubAppSpec, options *FetchOptions) (Credential, error) {
	keyPEM, err := fetchPrivateKeyPEM(spec.PrivateKeySource, options)
	if err != nil {
		log.Printf("[ERROR] github-app mint failed for app_id=%d installation_id=%d: fetch private key: %v",
			spec.AppID, spec.InstallationID, err)
		return Credential{}, fmt.Errorf("github-app: fetch private key: %w", err)
	}

	privateKey, err := parseRSAPrivateKeyPEM(keyPEM)
	if err != nil {
		log.Printf("[ERROR] github-app mint failed for app_id=%d installation_id=%d: %v",
			spec.AppID, spec.InstallationID, err)
		return Credential{}, fmt.Errorf("github-app: %w", err)
	}

	now := credentialCacheNow()
	jwt, err := signGitHubAppJWT(privateKey, spec.AppID, now)
	if err != nil {
		log.Printf("[ERROR] github-app mint failed for app_id=%d installation_id=%d: sign jwt: %v",
			spec.AppID, spec.InstallationID, err)
		return Credential{}, fmt.Errorf("github-app: sign jwt: %w", err)
	}

	cred, err := exchangeGitHubAppInstallationToken(spec, jwt)
	if err != nil {
		log.Printf("[ERROR] github-app mint failed for app_id=%d installation_id=%d: %v",
			spec.AppID, spec.InstallationID, err)
		return Credential{}, err
	}

	log.Printf("[DEBUG] github-app mint succeeded for app_id=%d installation_id=%d expires_at=%s",
		spec.AppID, spec.InstallationID, cred.ExpiresAt.UTC().Format(time.RFC3339))
	return cred, nil
}

func fetchPrivateKeyPEM(source string, options *FetchOptions) (string, error) {
	opts := []FetchOption{
		WithPassBinary(options.PassBinary),
		WithOPBinary(options.OPBinary),
		WithBWBinary(options.BWBinary),
		WithVaultBinary(options.VaultBinary),
		WithBypassCache(),
	}
	cred, err := FetchCredential(source, opts...)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(cred.Value) == "" {
		return "", fmt.Errorf("private key source returned empty value")
	}
	return cred.Value, nil
}

func parseRSAPrivateKeyPEM(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("invalid private key PEM")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#1 private key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS#8 private key is not RSA")
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported private key PEM type %q", block.Type)
	}
}

func signGitHubAppJWT(privateKey *rsa.PrivateKey, appID int64, now time.Time) (string, error) {
	headerJSON := []byte(`{"alg":"RS256","typ":"JWT"}`)
	claimsJSON := fmt.Sprintf(
		`{"iss":"%d","iat":%d,"exp":%d}`,
		appID,
		now.Add(-githubAppJWTIssuedOffset).Unix(),
		now.Add(githubAppJWTLifetime).Unix(),
	)

	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString([]byte(claimsJSON))
	signingInput := header + "." + payload

	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func exchangeGitHubAppInstallationToken(spec GitHubAppSpec, jwt string) (Credential, error) {
	body, err := encodeGitHubAppExchangeBody(spec)
	if err != nil {
		return Credential{}, err
	}

	url := strings.TrimRight(spec.APIURL, "/") +
		"/app/installations/" + strconv.FormatInt(spec.InstallationID, 10) + "/access_tokens"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Credential{}, fmt.Errorf("github-app: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersionHeader)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := githubAppHTTPClient.Do(req)
	if err != nil {
		return Credential{}, fmt.Errorf("github-app: exchange request: %w", err)
	}
	defer resp.Body.Close()

	const maxErrorBody = 64 * 1024
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	if err != nil {
		return Credential{}, fmt.Errorf("github-app: read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return Credential{}, githubAppExchangeError(resp.StatusCode, respBody)
	}

	var parsed githubAppExchangeResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return Credential{}, fmt.Errorf("github-app: decode response: %w", err)
	}
	if strings.TrimSpace(parsed.Token) == "" {
		return Credential{}, fmt.Errorf("github-app: exchange response missing token")
	}
	expiresAt, err := time.Parse(time.RFC3339, parsed.ExpiresAt)
	if err != nil {
		return Credential{}, fmt.Errorf("github-app: parse expires_at: %w", err)
	}

	return Credential{Value: parsed.Token, ExpiresAt: expiresAt.UTC()}, nil
}

func encodeGitHubAppExchangeBody(spec GitHubAppSpec) ([]byte, error) {
	req := githubAppExchangeRequest{}
	if len(spec.Permissions) > 0 {
		req.Permissions = spec.Permissions
	}
	if len(spec.Repositories) > 0 {
		req.Repositories = spec.Repositories
	}
	if req.Permissions == nil && req.Repositories == nil {
		return nil, nil
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("github-app: encode request body: %w", err)
	}
	return body, nil
}

func githubAppExchangeError(statusCode int, body []byte) error {
	var parsed struct {
		Message string `json:"message"`
	}
	message := ""
	if err := json.Unmarshal(body, &parsed); err == nil {
		message = strings.TrimSpace(parsed.Message)
	}
	if message != "" {
		return fmt.Errorf("github-app: exchange failed: HTTP %d: %s", statusCode, message)
	}
	return fmt.Errorf("github-app: exchange failed: HTTP %d", statusCode)
}
