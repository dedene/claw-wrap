package httpproxy

import (
	"os"
	"path/filepath"
	"testing"

	"claw-wrap/internal/config"
	"claw-wrap/internal/credentials"
)

func TestResolveHeaderValue_NoTemplates(t *testing.T) {
	tests := []string{
		"Bearer static-token",
		"plain-value",
		"",
	}

	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			got, err := resolveHeaderValue(tt, nil, nil)
			if err != nil {
				t.Errorf("resolveHeaderValue(%q) error = %v", tt, err)
			}
			if got != tt {
				t.Errorf("resolveHeaderValue(%q) = %q, want %q", tt, got, tt)
			}
		})
	}
}

// setupEnvFile creates a test env file and sets credentials.DefaultEnvFile.
// Returns cleanup function.
func setupEnvFile(t *testing.T, content string) func() {
	t.Helper()

	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, "env")

	if err := os.WriteFile(envPath, []byte(content), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	oldEnvFile := credentials.DefaultEnvFile
	credentials.DefaultEnvFile = envPath

	return func() {
		credentials.DefaultEnvFile = oldEnvFile
	}
}

func TestResolveHeaderValue_WithNamedCredential(t *testing.T) {
	// Set up test env file (not OS env var)
	cleanup := setupEnvFile(t, "TEST_TOKEN=my-secret-token\n")
	defer cleanup()

	creds := map[string]config.CredentialDef{
		"test-token": {Source: "env:TEST_TOKEN"},
	}

	template := "Bearer {{test-token}}"
	got, err := resolveHeaderValue(template, creds, nil)
	if err != nil {
		t.Fatalf("resolveHeaderValue() error = %v", err)
	}

	want := "Bearer my-secret-token"
	if got != want {
		t.Errorf("resolveHeaderValue() = %q, want %q", got, want)
	}
}

func TestResolveHeaderValue_MultipleRefs(t *testing.T) {
	cleanup := setupEnvFile(t, "USER=testuser\nPASS=testpass\n")
	defer cleanup()

	creds := map[string]config.CredentialDef{
		"user": {Source: "env:USER"},
		"pass": {Source: "env:PASS"},
	}

	template := "{{user}}:{{pass}}"
	got, err := resolveHeaderValue(template, creds, nil)
	if err != nil {
		t.Fatalf("resolveHeaderValue() error = %v", err)
	}

	want := "testuser:testpass"
	if got != want {
		t.Errorf("resolveHeaderValue() = %q, want %q", got, want)
	}
}

func TestResolveHeaderValue_EmptyRef(t *testing.T) {
	// Note: {{}} doesn't match the regex pattern, so it passes through unchanged
	template := "Bearer {{}}"
	got, err := resolveHeaderValue(template, nil, nil)
	if err != nil {
		t.Errorf("resolveHeaderValue() unexpected error = %v", err)
	}
	// Empty braces don't match the regex, so template passes through
	if got != template {
		t.Errorf("resolveHeaderValue() = %q, want %q (pass through)", got, template)
	}
}

func TestResolveHeaderValue_UnknownCredential(t *testing.T) {
	creds := map[string]config.CredentialDef{
		"known": {Source: "env:KNOWN"},
	}

	template := "Bearer {{unknown}}"
	_, err := resolveHeaderValue(template, creds, nil)
	if err == nil {
		t.Error("resolveHeaderValue() should error on unknown credential")
	}
}

func TestResolveHeaderValue_MissingEnvVar(t *testing.T) {
	// Set up env file without the var
	cleanup := setupEnvFile(t, "OTHER_VAR=value\n")
	defer cleanup()

	creds := map[string]config.CredentialDef{
		"missing": {Source: "env:NONEXISTENT_VAR"},
	}

	template := "Bearer {{missing}}"
	_, err := resolveHeaderValue(template, creds, nil)
	if err == nil {
		t.Error("resolveHeaderValue() should error on missing env var")
	}
}

func TestResolveHeaderValue_WithOptions(t *testing.T) {
	cleanup := setupEnvFile(t, "TEST_API_KEY=key-from-env\n")
	defer cleanup()

	creds := map[string]config.CredentialDef{
		"api-key": {Source: "env:TEST_API_KEY"},
	}

	// Test that options are passed through
	template := "{{api-key}}"
	opts := []credentials.FetchOption{
		// Options should be passed to Fetch but won't affect env: backend
	}

	got, err := resolveHeaderValue(template, creds, opts)
	if err != nil {
		t.Fatalf("resolveHeaderValue() error = %v", err)
	}

	want := "key-from-env"
	if got != want {
		t.Errorf("resolveHeaderValue() = %q, want %q", got, want)
	}
}

func TestHasCredentialRef(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"no template", false},
		{"{{github-token}}", true},
		{"Bearer {{api-key}}", true},
		{"{{a}} and {{b}}", true},
		{"{{ not closed", false},
		{"not opened }}", false},
		{"{single}", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := hasCredentialRef(tt.input); got != tt.want {
				t.Errorf("hasCredentialRef(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestCredentialRefRe_Patterns(t *testing.T) {
	tests := []struct {
		template string
		matches  []string
	}{
		{"{{github-token}}", []string{"github-token"}},
		{"{{api-key}}", []string{"api-key"}},
		{"{{my_credential}}", []string{"my_credential"}},
		{"{{a}} and {{b}}", []string{"a", "b"}},
		{"no match", nil},
	}

	for _, tt := range tests {
		t.Run(tt.template, func(t *testing.T) {
			matches := credentialRefRe.FindAllStringSubmatch(tt.template, -1)
			var got []string
			for _, m := range matches {
				if len(m) > 1 {
					got = append(got, m[1])
				}
			}
			if len(got) != len(tt.matches) {
				t.Errorf("credentialRefRe matches = %v, want %v", got, tt.matches)
				return
			}
			for i, want := range tt.matches {
				if got[i] != want {
					t.Errorf("match[%d] = %q, want %q", i, got[i], want)
				}
			}
		})
	}
}
