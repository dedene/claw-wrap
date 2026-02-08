package daemon

import (
	"encoding/json"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"claw-wrap/internal/auth"
	"claw-wrap/internal/config"
	"claw-wrap/internal/credentials"
	"claw-wrap/internal/protocol"
)

func TestHandleAdminRequest_CheckBypassesCredentialCache(t *testing.T) {
	origFetch := fetchCredentialFunc
	origExe := resolvePeerExecutableFunc
	origArgv0 := resolvePeerArgv0Func
	defer func() {
		fetchCredentialFunc = origFetch
		resolvePeerExecutableFunc = origExe
		resolvePeerArgv0Func = origArgv0
	}()

	resolvePeerExecutableFunc = func(pid int32) (string, error) {
		return "/usr/local/bin/claw-wrap", nil
	}
	resolvePeerArgv0Func = func(pid int32) (string, error) {
		return "/usr/local/bin/claw-wrap", nil
	}

	fetchCalled := false
	bypassCache := false
	fetchCredentialFunc = func(source string, opts ...credentials.FetchOption) (string, error) {
		fetchCalled = true
		if source != "op://Private/GitHub/token" {
			t.Fatalf("source = %q, want %q", source, "op://Private/GitHub/token")
		}
		fetchOpts := &credentials.FetchOptions{}
		for _, opt := range opts {
			opt(fetchOpts)
		}
		bypassCache = fetchOpts.BypassCache
		return "secret-value", nil
	}

	d := New(WithAllowedBinaries([]string{"/usr/local/bin/claw-wrap"}))
	d.secret = []byte("0123456789abcdef0123456789abcdef")
	d.replayCache = auth.NewReplayCache(2*time.Minute, 1000)

	cfg := &config.Config{
		Credentials: map[string]config.CredentialDef{
			"github-token": {Source: "op://Private/GitHub/token"},
		},
		Tools: map[string]config.ToolDef{},
	}
	d.cfg = cfg

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce, err := auth.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce() error = %v", err)
	}
	hmac, err := auth.ComputeHMAC(d.secret, timestamp, "admin:check", "", nil, nonce)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}

	req := protocol.AdminRequest{
		Version:   protocol.ProtocolVersion,
		Admin:     "check",
		Timestamp: timestamp,
		Nonce:     nonce,
		HMAC:      hmac,
	}
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		d.handleAdminRequest(server, payload, cfg, uint32(os.Getuid()), 1234)
	}()

	buf := make([]byte, 64*1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = client.Close()
	<-done

	var adminErr map[string]string
	if err := json.Unmarshal(buf[:n], &adminErr); err == nil {
		if msg := adminErr["error"]; msg != "" {
			t.Fatalf("admin error response: %s", msg)
		}
	}

	var resp protocol.AdminCheckResponse
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		t.Fatalf("unmarshal admin check response: %v", err)
	}

	if !fetchCalled {
		t.Fatal("fetchCredentialFunc was not called")
	}
	if !bypassCache {
		t.Fatal("expected admin check to call Fetch with WithBypassCache()")
	}

	info, ok := resp.Credentials["github-token"]
	if !ok {
		t.Fatal("response missing github-token credential status")
	}
	if info.Status != "ok" {
		t.Fatalf("credential status = %q, want %q", info.Status, "ok")
	}
}
