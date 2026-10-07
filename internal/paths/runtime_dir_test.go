package paths

import (
	"path/filepath"
	"testing"
)

func TestRuntimeDir_EnvOverride(t *testing.T) {
	defaultEnv := EnvFile()
	t.Setenv(RuntimeDirEnv, "/run/claw-wrap/rt/")

	if got := RuntimeDir(); got != "/run/claw-wrap/rt" {
		t.Fatalf("RuntimeDir() = %q", got)
	}
	for name, got := range map[string]string{
		"SocketPath":         SocketPath(),
		"AuthPath":           AuthPath(),
		"ProxyAuthTokenPath": ProxyAuthTokenPath(),
	} {
		if filepath.Dir(got) != "/run/claw-wrap/rt" {
			t.Errorf("%s() = %q, want it under the override", name, got)
		}
	}
	// The env credential file must never follow the override: the runtime
	// dir may be shared with the (untrusted) client container.
	if got := EnvFile(); got != defaultEnv {
		t.Errorf("EnvFile() = %q, want unchanged %q", got, defaultEnv)
	}
}

func TestRuntimeDir_IgnoresRelativeOverride(t *testing.T) {
	t.Setenv(RuntimeDirEnv, "")
	want := RuntimeDir()
	t.Setenv(RuntimeDirEnv, "relative/dir")
	if got := RuntimeDir(); got != want {
		t.Fatalf("RuntimeDir() = %q, want default %q", got, want)
	}
	if err := ValidateRuntimeDirEnv(); err == nil {
		t.Fatal("ValidateRuntimeDirEnv() should reject a relative path")
	}
}
