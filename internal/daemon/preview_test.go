package daemon

import "testing"

func TestCredentialPreview(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "long secret (12 chars)",
			value: "582a123459e9",
			want:  "58.....e9",
		},
		{
			name:  "exactly 8 chars",
			value: "abcdefgh",
			want:  "ab.....gh",
		},
		{
			name:  "seven chars - partial mask",
			value: "abcdefg",
			want:  "a.....g",
		},
		{
			name:  "five chars - partial mask",
			value: "abcde",
			want:  "a.....e",
		},
		{
			name:  "four chars - fully masked",
			value: "abcd",
			want:  "****...****",
		},
		{
			name:  "three chars - fully masked",
			value: "abc",
			want:  "****...****",
		},
		{
			name:  "two chars - fully masked",
			value: "ab",
			want:  "****...****",
		},
		{
			name:  "one char - fully masked",
			value: "a",
			want:  "****...****",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := credentialPreview(tc.value)
			if got != tc.want {
				t.Fatalf("credentialPreview(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}
