package config

import (
	"strings"
	"testing"
)

func TestLoad_AllowedArgsArgv(t *testing.T) {
	cfg, err := loadYAML(t, `
tools:
  t:
    binary: /usr/bin/true
    mode: allowlist
    allowed_args:
      - match: argv
        argv: ['call', 'front\.(read|list)', '--args', '(?s)\{.*\}']
`)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	rule := cfg.Tools["t"].AllowedArgs[0]
	if rule.Match != BlockedArgMatchArgv {
		t.Fatalf("Match = %q, want %q", rule.Match, BlockedArgMatchArgv)
	}
	if len(rule.CompiledArgv) != 4 {
		t.Fatalf("CompiledArgv has %d entries, want 4", len(rule.CompiledArgv))
	}

	// Each position is a full match: no prefix/suffix slack.
	if !rule.CompiledArgv[1].MatchString("front.read") {
		t.Error("position 1 should match front.read")
	}
	for _, s := range []string{"front.readX", "xfront.read", "front.read\n", "front.read --config"} {
		if rule.CompiledArgv[1].MatchString(s) {
			t.Errorf("position 1 must not match %q", s)
		}
	}
	if !rule.CompiledArgv[3].MatchString("{\n  \"a\": 1\n}") {
		t.Error("(?s) JSON pattern should match multi-line JSON")
	}
}

func TestValidate_ArgvRuleErrors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "argv without patterns",
			yaml: `
tools:
  t:
    binary: /usr/bin/true
    mode: allowlist
    allowed_args:
      - match: argv
`,
			wantErr: "match \"argv\" requires a non-empty argv list",
		},
		{
			name: "argv with pattern",
			yaml: `
tools:
  t:
    binary: /usr/bin/true
    mode: allowlist
    allowed_args:
      - match: argv
        pattern: call
        argv: [call]
`,
			wantErr: "use either pattern or argv",
		},
		{
			name: "argv list on non-argv rule",
			yaml: `
tools:
  t:
    binary: /usr/bin/true
    mode: allowlist
    allowed_args:
      - match: command
        argv: [call]
`,
			wantErr: "argv is only valid with match: argv",
		},
		{
			name: "invalid argv regex",
			yaml: `
tools:
  t:
    binary: /usr/bin/true
    mode: allowlist
    allowed_args:
      - match: argv
        argv: ['call', '(']
`,
			wantErr: "invalid allowed_args argv[1]",
		},
		{
			// Wrapped naively as ^(?:call)|(.*)$ this would match anything.
			name: "unbalanced parens cannot escape the anchors",
			yaml: `
tools:
  t:
    binary: /usr/bin/true
    mode: allowlist
    allowed_args:
      - match: argv
        argv: ['call)|(.*']
`,
			wantErr: "invalid allowed_args argv[0]",
		},
		{
			name: "argv in blocked_args",
			yaml: `
tools:
  t:
    binary: /usr/bin/true
    blocked_args:
      - match: argv
        argv: [call]
`,
			wantErr: "match \"argv\" is only supported in allowed_args",
		},
		{
			name: "unknown match mode lists argv",
			yaml: `
tools:
  t:
    binary: /usr/bin/true
    mode: allowlist
    allowed_args:
      - match: positional
        pattern: x
`,
			wantErr: "\"argv\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadYAML(t, tt.yaml)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
