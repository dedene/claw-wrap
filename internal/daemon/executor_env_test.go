//go:build linux

package daemon

import (
	"strings"
	"testing"

	"claw-wrap/internal/config"
	"claw-wrap/internal/protocol"
)

// envContains checks if an env slice contains a given key and returns its value.
func envContains(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return strings.TrimPrefix(e, prefix), true
		}
	}
	return "", false
}

func TestIsDeniedEnvVar_ExactMatch(t *testing.T) {
	denied := []string{
		"LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "ENV",
		"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
		"PYTHONPATH", "PYTHONSTARTUP", "PERL5LIB", "RUBYLIB", "NODE_OPTIONS",
		"GIT_SSH_COMMAND", "EDITOR", "VISUAL", "PAGER",
	}

	for _, key := range denied {
		t.Run(key, func(t *testing.T) {
			if !isDeniedEnvVar(key) {
				t.Errorf("isDeniedEnvVar(%q) = false, want true", key)
			}
		})
	}
}

func TestIsDeniedEnvVar_PrefixMatch(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{"exact prefix", "BASH_FUNC_"},
		{"function export", "BASH_FUNC_myfunc%%"},
		{"nested name", "BASH_FUNC_some_helper%%"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !isDeniedEnvVar(tc.key) {
				t.Errorf("isDeniedEnvVar(%q) = false, want true", tc.key)
			}
		})
	}
}

func TestIsDeniedEnvVar_Allowed(t *testing.T) {
	allowed := []string{
		"MY_CUSTOM_VAR", "GOPATH", "LANG", "TZ",
		"HOME", "USER", "PATH", "TERM",
		"SHELL", "HOSTNAME", "TMPDIR",
	}

	for _, key := range allowed {
		t.Run(key, func(t *testing.T) {
			if isDeniedEnvVar(key) {
				t.Errorf("isDeniedEnvVar(%q) = true, want false", key)
			}
		})
	}
}

func TestIsDeniedEnvVar_CaseSensitive(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{"all lower", "ld_preload"},
		{"mixed case", "Ld_Preload"},
		{"title case", "Node_Options"},
		{"lower bash_func", "bash_func_myfunc%%"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if isDeniedEnvVar(tc.key) {
				t.Errorf("isDeniedEnvVar(%q) = true, want false (denylist is case-sensitive)", tc.key)
			}
		})
	}
}

func TestBuildEnvironment_DeniedVarRejected(t *testing.T) {
	executor := &ToolExecutor{
		req: &protocol.ProxyRequest{
			Env: map[string]string{
				"LD_PRELOAD": "/evil.so",
			},
		},
		tool: &config.ToolDef{},
		cfg:  &config.Config{},
	}

	env, err := executor.buildEnvironment()
	if err != nil {
		t.Fatalf("buildEnvironment() error: %v", err)
	}

	if _, found := envContains(env, "LD_PRELOAD"); found {
		t.Error("buildEnvironment() included denied var LD_PRELOAD in output")
	}
}

func TestBuildEnvironment_AllowedVarAccepted(t *testing.T) {
	executor := &ToolExecutor{
		req: &protocol.ProxyRequest{
			Env: map[string]string{
				"MY_VAR": "hello",
			},
		},
		tool: &config.ToolDef{},
		cfg:  &config.Config{},
	}

	env, err := executor.buildEnvironment()
	if err != nil {
		t.Fatalf("buildEnvironment() error: %v", err)
	}

	val, found := envContains(env, "MY_VAR")
	if !found {
		t.Fatal("buildEnvironment() did not include MY_VAR")
	}
	if val != "hello" {
		t.Errorf("MY_VAR = %q, want %q", val, "hello")
	}
}

func TestBuildEnvironment_ForcedEnvStillWorks(t *testing.T) {
	executor := &ToolExecutor{
		req: &protocol.ProxyRequest{
			Env: map[string]string{
				"GH_PAGER": "less",
			},
		},
		tool: &config.ToolDef{
			ForcedEnv: map[string]string{
				"GH_PAGER": "",
			},
		},
		cfg: &config.Config{},
	}

	env, err := executor.buildEnvironment()
	if err != nil {
		t.Fatalf("buildEnvironment() error: %v", err)
	}

	val, found := envContains(env, "GH_PAGER")
	if !found {
		t.Fatal("buildEnvironment() did not include GH_PAGER from forced_env")
	}
	if val != "" {
		t.Errorf("GH_PAGER = %q, want %q (forced_env should win)", val, "")
	}
}

func TestBuildEnvironment_MinimalBase(t *testing.T) {
	executor := &ToolExecutor{
		req:  &protocol.ProxyRequest{},
		tool: &config.ToolDef{},
		cfg:  &config.Config{},
	}

	env, err := executor.buildEnvironment()
	if err != nil {
		t.Fatalf("buildEnvironment() error: %v", err)
	}

	required := []string{"PATH", "HOME", "USER", "TERM"}
	for _, key := range required {
		if _, found := envContains(env, key); !found {
			t.Errorf("buildEnvironment() missing base env var %s", key)
		}
	}
}

func TestBuildEnvironment_DeniedVarInForcedEnv(t *testing.T) {
	// Admin controls forced_env; denylist only blocks req.Env
	executor := &ToolExecutor{
		req: &protocol.ProxyRequest{},
		tool: &config.ToolDef{
			ForcedEnv: map[string]string{
				"LD_PRELOAD": "/lib/something.so",
			},
		},
		cfg: &config.Config{},
	}

	env, err := executor.buildEnvironment()
	if err != nil {
		t.Fatalf("buildEnvironment() error: %v", err)
	}

	val, found := envContains(env, "LD_PRELOAD")
	if !found {
		t.Fatal("buildEnvironment() should allow LD_PRELOAD via forced_env (admin-controlled)")
	}
	if val != "/lib/something.so" {
		t.Errorf("LD_PRELOAD = %q, want %q", val, "/lib/something.so")
	}
}

func TestBuildEnvironment_MultipleDeniedVarsFiltered(t *testing.T) {
	executor := &ToolExecutor{
		req: &protocol.ProxyRequest{
			Env: map[string]string{
				"LD_PRELOAD":            "/evil.so",
				"PYTHONPATH":            "/tmp/backdoor",
				"NODE_OPTIONS":          "--require /tmp/evil.js",
				"BASH_FUNC_myfunc%%":    "() { evil; }",
				"MY_SAFE_VAR":           "safe-value",
			},
		},
		tool: &config.ToolDef{},
		cfg:  &config.Config{},
	}

	env, err := executor.buildEnvironment()
	if err != nil {
		t.Fatalf("buildEnvironment() error: %v", err)
	}

	// All denied vars must be absent
	deniedKeys := []string{"LD_PRELOAD", "PYTHONPATH", "NODE_OPTIONS", "BASH_FUNC_myfunc%%"}
	for _, key := range deniedKeys {
		if _, found := envContains(env, key); found {
			t.Errorf("buildEnvironment() should have filtered denied var %s", key)
		}
	}

	// Safe var must be present
	if _, found := envContains(env, "MY_SAFE_VAR"); !found {
		t.Error("buildEnvironment() filtered safe var MY_SAFE_VAR")
	}
}

func TestBuildEnvironment_ReqEnvCannotOverrideForcedEnv(t *testing.T) {
	executor := &ToolExecutor{
		req: &protocol.ProxyRequest{
			Env: map[string]string{
				"SOME_KEY": "attacker-value",
			},
		},
		tool: &config.ToolDef{
			ForcedEnv: map[string]string{
				"SOME_KEY": "admin-value",
			},
		},
		cfg: &config.Config{},
	}

	env, err := executor.buildEnvironment()
	if err != nil {
		t.Fatalf("buildEnvironment() error: %v", err)
	}

	val, found := envContains(env, "SOME_KEY")
	if !found {
		t.Fatal("buildEnvironment() missing SOME_KEY")
	}
	if val != "admin-value" {
		t.Errorf("SOME_KEY = %q, want %q (forced_env must win)", val, "admin-value")
	}
}
