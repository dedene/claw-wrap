package config

import (
	"errors"
	"testing"
)

func TestFindCredentialRefs(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []string
	}{
		{
			name:  "no refs",
			value: "literal value",
			want:  nil,
		},
		{
			name:  "single ref",
			value: "prefix:{{ foo }}:suffix",
			want:  []string{"foo"},
		},
		{
			name:  "multiple refs",
			value: "{{ foo }}:{{ bar }}",
			want:  []string{"foo", "bar"},
		},
		{
			name:  "duplicate refs",
			value: "{{ foo }}:{{ bar }}:{{ foo }}",
			want:  []string{"foo", "bar"},
		},
		{
			name:  "whitespace tolerance",
			value: "{{  foo  }}:{{bar}}:{{ baz }}",
			want:  []string{"foo", "bar", "baz"},
		},
		{
			name:  "hyphens in name",
			value: "{{ my-secret }}",
			want:  []string{"my-secret"},
		},
		{
			name:  "underscores in name",
			value: "{{ my_secret }}",
			want:  []string{"my_secret"},
		},
		{
			name:  "numbers in name",
			value: "{{ secret123 }}",
			want:  []string{"secret123"},
		},
		{
			name:  "unclosed brace - literal",
			value: "literal {{ text",
			want:  nil,
		},
		{
			name:  "empty braces - no match",
			value: "{{  }}",
			want:  nil,
		},
		{
			name:  "nested braces - extracts inner",
			value: "{{ {{ inner }} }}",
			want:  []string{"inner"}, // regex finds valid inner match
		},
		{
			name:  "empty string",
			value: "",
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindCredentialRefs(tt.value)
			if !slicesEqual(got, tt.want) {
				t.Errorf("FindCredentialRefs(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestHasCredentialRefs(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"literal", false},
		{"{{ foo }}", true},
		{"prefix:{{ foo }}:suffix", true},
		{"{{ }}", false}, // empty ref doesn't count
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got := HasCredentialRefs(tt.value)
			if got != tt.want {
				t.Errorf("HasCredentialRefs(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestInterpolate(t *testing.T) {
	secrets := map[string]string{
		"foo":       "secret-foo",
		"bar":       "secret-bar",
		"my-secret": "hyphenated-value",
	}
	resolver := func(name string) (string, error) {
		if v, ok := secrets[name]; ok {
			return v, nil
		}
		return "", errors.New("not found")
	}

	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{
			name:  "no refs - passthrough",
			value: "literal value",
			want:  "literal value",
		},
		{
			name:  "single ref",
			value: "prefix:{{ foo }}:suffix",
			want:  "prefix:secret-foo:suffix",
		},
		{
			name:  "multiple refs",
			value: "{{ foo }}:{{ bar }}",
			want:  "secret-foo:secret-bar",
		},
		{
			name:  "duplicate refs",
			value: "{{ foo }}:{{ foo }}",
			want:  "secret-foo:secret-foo",
		},
		{
			name:  "whitespace tolerance",
			value: "{{  foo  }}",
			want:  "secret-foo",
		},
		{
			name:  "hyphenated name",
			value: "{{ my-secret }}",
			want:  "hyphenated-value",
		},
		{
			name:    "missing credential",
			value:   "{{ missing }}",
			wantErr: true,
		},
		{
			name:  "empty string",
			value: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Interpolate(tt.value, resolver)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Interpolate(%q) error = nil, want error", tt.value)
				}
				return
			}
			if err != nil {
				t.Errorf("Interpolate(%q) error = %v, want nil", tt.value, err)
				return
			}
			if got != tt.want {
				t.Errorf("Interpolate(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestClassifyEnvValue(t *testing.T) {
	creds := map[string]struct{}{
		"github-token": {},
		"db-password":  {},
	}

	tests := []struct {
		value string
		want  string
	}{
		{"github-token", "credential"},
		{"db-password", "credential"},
		{"/usr/bin:/bin", "literal"},
		{"literal-value", "literal"},
		{"postgres://user:{{ db-password }}@localhost/db", "interpolate"},
		{"{{ github-token }}", "interpolate"}, // template syntax, not exact match
		{"unknown-cred", "literal"},           // doesn't match any credential name
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got := ClassifyEnvValue(tt.value, creds)
			if got != tt.want {
				t.Errorf("ClassifyEnvValue(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestValidateEnvRefs(t *testing.T) {
	creds := map[string]struct{}{
		"github-token": {},
		"db-password":  {},
	}

	tests := []struct {
		name    string
		value   string
		missing []string
	}{
		{
			name:    "exact credential",
			value:   "github-token",
			missing: nil,
		},
		{
			name:    "valid interpolation",
			value:   "prefix:{{ db-password }}:suffix",
			missing: nil,
		},
		{
			name:    "literal",
			value:   "/usr/bin",
			missing: nil,
		},
		{
			name:    "missing ref",
			value:   "{{ missing }}",
			missing: []string{"missing"},
		},
		{
			name:    "multiple missing",
			value:   "{{ foo }}:{{ bar }}",
			missing: []string{"foo", "bar"},
		},
		{
			name:    "one valid one missing",
			value:   "{{ github-token }}:{{ missing }}",
			missing: []string{"missing"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateEnvRefs(tt.value, creds)
			if !slicesEqual(got, tt.missing) {
				t.Errorf("ValidateEnvRefs(%q) = %v, want %v", tt.value, got, tt.missing)
			}
		})
	}
}

func TestResolveEnvValue(t *testing.T) {
	creds := map[string]struct{}{
		"github-token": {},
		"db-password":  {},
	}
	secrets := map[string]string{
		"github-token": "ghp_xxx",
		"db-password":  "hunter2",
	}
	resolver := func(name string) (string, error) {
		if v, ok := secrets[name]; ok {
			return v, nil
		}
		return "", errors.New("not found")
	}

	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{
			name:  "exact credential",
			value: "github-token",
			want:  "ghp_xxx",
		},
		{
			name:  "interpolation",
			value: "postgres://user:{{ db-password }}@localhost/db",
			want:  "postgres://user:hunter2@localhost/db",
		},
		{
			name:  "literal",
			value: "/usr/bin:/bin",
			want:  "/usr/bin:/bin",
		},
		{
			name:    "missing credential",
			value:   "missing-cred",
			want:    "missing-cred", // literal, not error
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveEnvValue(tt.value, creds, resolver)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ResolveEnvValue(%q) error = nil, want error", tt.value)
				}
				return
			}
			if err != nil {
				t.Errorf("ResolveEnvValue(%q) error = %v, want nil", tt.value, err)
				return
			}
			if got != tt.want {
				t.Errorf("ResolveEnvValue(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestCredentialNamesSet(t *testing.T) {
	creds := map[string]CredentialDef{
		"foo": {Source: "pass:foo"},
		"bar": {Source: "env:BAR"},
	}

	set := CredentialNamesSet(creds)

	if _, ok := set["foo"]; !ok {
		t.Error("expected 'foo' in set")
	}
	if _, ok := set["bar"]; !ok {
		t.Error("expected 'bar' in set")
	}
	if _, ok := set["baz"]; ok {
		t.Error("unexpected 'baz' in set")
	}
}

// slicesEqual compares two string slices for equality.
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
