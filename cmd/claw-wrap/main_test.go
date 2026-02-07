package main

import "testing"

func TestSafeToolNameRegex(t *testing.T) {
	valid := []string{"gh", "my-tool", "tool.v2", "tool_name"}
	for _, name := range valid {
		if !safeToolNameRegex.MatchString(name) {
			t.Errorf("safeToolNameRegex rejected valid name %q", name)
		}
	}

	invalid := []string{"../../etc/passwd", "gh/repo", "gh repo", "gh;rm", ""}
	for _, name := range invalid {
		if safeToolNameRegex.MatchString(name) {
			t.Errorf("safeToolNameRegex accepted invalid name %q", name)
		}
	}
}
