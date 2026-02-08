package credentials

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestApplyJQ(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		expr    string
		want    string
		wantErr bool
		errMsg  string
	}{
		// Simple field access
		{
			name: "simple field",
			json: `{"password": "secret123"}`,
			expr: ".password",
			want: "secret123",
		},
		{
			name: "nested field",
			json: `{"fields": {"api_key": "abc123"}}`,
			expr: ".fields.api_key",
			want: "abc123",
		},

		// Array access
		{
			name: "array index",
			json: `{"items": ["first", "second", "third"]}`,
			expr: ".items[0]",
			want: "first",
		},
		{
			name: "array last element",
			json: `{"items": [1, 2, 3]}`,
			expr: ".items[-1]",
			want: "3",
		},

		// Complex filters
		{
			name: "select filter",
			json: `{"fields": [{"name": "username", "value": "user"}, {"name": "password", "value": "pass"}]}`,
			expr: `.fields[] | select(.name=="password") | .value`,
			want: "pass",
		},
		{
			name: "pipe chain",
			json: `{"data": {"nested": {"value": "found"}}}`,
			expr: ".data | .nested | .value",
			want: "found",
		},

		// Type coercion
		{
			name: "number result",
			json: `{"count": 42}`,
			expr: ".count",
			want: "42",
		},
		{
			name: "float result",
			json: `{"value": 3.14}`,
			expr: ".value",
			want: "3.14",
		},
		{
			name: "boolean true",
			json: `{"enabled": true}`,
			expr: ".enabled",
			want: "true",
		},
		{
			name: "boolean false",
			json: `{"enabled": false}`,
			expr: ".enabled",
			want: "false",
		},
		{
			name: "object result",
			json: `{"config": {"a": 1, "b": 2}}`,
			expr: ".config",
			want: `{"a":1,"b":2}`,
		},
		{
			name: "array result",
			json: `{"items": [1, 2, 3]}`,
			expr: ".items",
			want: "[1,2,3]",
		},

		// Error cases
		{
			name:    "null result",
			json:    `{"other": "value"}`,
			expr:    ".missing",
			wantErr: true,
			errMsg:  "null",
		},
		{
			name:    "invalid jq expression",
			json:    `{"a": 1}`,
			expr:    ".invalid[",
			wantErr: true,
			errMsg:  "invalid jq expression",
		},
		{
			name:    "invalid json",
			json:    `not json`,
			expr:    ".field",
			wantErr: true,
			errMsg:  "invalid JSON",
		},
		{
			name:    "no results from filter",
			json:    `{"items": []}`,
			expr:    ".items[]",
			wantErr: true,
			errMsg:  "no results",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := ApplyJQ(ctx, []byte(tt.json), tt.expr)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ApplyJQ() = %q, want error containing %q", result, tt.errMsg)
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want to contain %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("ApplyJQ() error = %v", err)
				return
			}

			if result != tt.want {
				t.Errorf("ApplyJQ() = %q, want %q", result, tt.want)
			}
		})
	}
}

func TestApplyJQ_Timeout(t *testing.T) {
	// Create a context that's already cancelled
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Give it a moment to timeout
	time.Sleep(10 * time.Millisecond)

	_, err := ApplyJQ(ctx, []byte(`{"a": 1}`), ".a")
	if err == nil {
		t.Error("ApplyJQ() with expired context should return error")
	}
}

func TestApplyJQ_LargeWholeNumber(t *testing.T) {
	// Verify large whole numbers don't get scientific notation
	json := `{"id": 1234567890}`
	result, err := ApplyJQ(context.Background(), []byte(json), ".id")
	if err != nil {
		t.Fatalf("ApplyJQ() error = %v", err)
	}
	if result != "1234567890" {
		t.Errorf("ApplyJQ() = %q, want %q", result, "1234567890")
	}
}

func TestResultToString(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		want    string
		wantErr bool
	}{
		{"string", "hello", "hello", false},
		{"int", 42, "42", false},
		{"float whole", 42.0, "42", false},
		{"float decimal", 3.14159, "3.14159", false},
		{"bool true", true, "true", false},
		{"bool false", false, "false", false},
		{"nil", nil, "", true},
		{"array", []any{1, 2, 3}, "[1,2,3]", false},
		{"object", map[string]any{"a": 1}, `{"a":1}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := resultToString(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("resultToString(%v) = %q, want error", tt.input, result)
				}
				return
			}

			if err != nil {
				t.Errorf("resultToString(%v) error = %v", tt.input, err)
				return
			}

			if result != tt.want {
				t.Errorf("resultToString(%v) = %q, want %q", tt.input, result, tt.want)
			}
		})
	}
}
