package daemon

import (
	"strings"
	"testing"
)

func TestYamlEscapeValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain", "abc123", "'abc123'"},
		{"with colon", "host:8080", "'host:8080'"},
		{"with hash", "value # comment", "'value # comment'"},
		{"with braces", "{key: val}", "'{key: val}'"},
		{"with single quote", "it's here", "'it''s here'"},
		{"multiple single quotes", "a'b'c", "'a''b''c'"},
		{"with newline", "line1\nline2", "'line1\nline2'"},
		{"empty", "", "''"},
		{"only quotes", "'''", "''''''''"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := yamlEscapeValue(tt.input)
			if got != tt.want {
				t.Errorf("yamlEscapeValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRenderTemplate(t *testing.T) {
	tests := []struct {
		name     string
		template string
		values   map[string]string
		want     string
	}{
		{
			name:     "simple substitution",
			template: "key: {{ .my-token }}",
			values:   map[string]string{"my-token": "secret123"},
			want:     "key: 'secret123'",
		},
		{
			name:     "underscore alias",
			template: "key: {{ .my_token }}",
			values:   map[string]string{"my-token": "secret123"},
			want:     "key: 'secret123'",
		},
		{
			name:     "multiple credentials",
			template: "bridge: {{ .bridge }}\nkey: {{ .key }}",
			values:   map[string]string{"bridge": "192.168.1.1", "key": "abc-def"},
			want:     "bridge: '192.168.1.1'\nkey: 'abc-def'",
		},
		{
			name:     "special yaml chars escaped",
			template: "token: {{ .tok }}",
			values:   map[string]string{"tok": "val: with {braces} # comment"},
			want:     "token: 'val: with {braces} # comment'",
		},
		{
			name:     "single quotes in value",
			template: "pass: {{ .pw }}",
			values:   map[string]string{"pw": "it's a secret"},
			want:     "pass: 'it''s a secret'",
		},
		{
			name:     "no placeholder match",
			template: "key: {{ .other }}",
			values:   map[string]string{"tok": "val"},
			want:     "key: {{ .other }}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := renderTemplate(tt.template, tt.values)
			if got != tt.want {
				t.Errorf("renderTemplate() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRenderTemplate_InjectionPrevention(t *testing.T) {
	// A credential value that tries to inject additional YAML structure
	malicious := "legit_value\nevil_key: evil_value"
	tmpl := "token: {{ .cred }}"
	result := renderTemplate(tmpl, map[string]string{"cred": malicious})

	// The value should be safely quoted — no bare evil_key at top level
	if strings.Contains(result, "evil_key: evil_value") && !strings.Contains(result, "'") {
		t.Error("renderTemplate() should YAML-escape values to prevent injection")
	}

	// Must contain single-quoted wrapping
	if !strings.HasPrefix(result, "token: '") {
		t.Errorf("renderTemplate() result should start with single-quoted value, got %q", result)
	}
}
