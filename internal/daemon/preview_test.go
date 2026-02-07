package daemon

import "testing"

func TestCredentialPreview(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "long secret",
			value: "582a123459e9",
			want:  "58.....e9",
		},
		{
			name:  "four chars",
			value: "abcd",
			want:  "a.....d",
		},
		{
			name:  "three chars",
			value: "abc",
			want:  "a.....c",
		},
		{
			name:  "two chars",
			value: "ab",
			want:  "****...****",
		},
		{
			name:  "one char",
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
