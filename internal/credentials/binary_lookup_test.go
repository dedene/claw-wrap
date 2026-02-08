package credentials

import (
	"fmt"
	"testing"
)

func TestResolveOPBinary_UsesOverride(t *testing.T) {
	override := "/custom/op"
	got, err := resolveOPBinary(override)
	if err != nil {
		t.Fatalf("resolveOPBinary() error = %v", err)
	}
	if got != override {
		t.Fatalf("resolveOPBinary() = %q, want %q", got, override)
	}
}

func TestResolveBWBinary_UsesOverride(t *testing.T) {
	override := "/custom/bw"
	got, err := resolveBWBinary(override)
	if err != nil {
		t.Fatalf("resolveBWBinary() error = %v", err)
	}
	if got != override {
		t.Fatalf("resolveBWBinary() = %q, want %q", got, override)
	}
}

func TestResolveOPBinary_UsesTrustedLookup(t *testing.T) {
	orig := findTrustedBinaryFunc
	defer func() { findTrustedBinaryFunc = orig }()

	var lookedUp string
	findTrustedBinaryFunc = func(name string) (string, error) {
		lookedUp = name
		return "/trusted/op", nil
	}

	got, err := resolveOPBinary("")
	if err != nil {
		t.Fatalf("resolveOPBinary() error = %v", err)
	}
	if lookedUp != "op" {
		t.Fatalf("lookup name = %q, want %q", lookedUp, "op")
	}
	if got != "/trusted/op" {
		t.Fatalf("resolveOPBinary() = %q, want %q", got, "/trusted/op")
	}
}

func TestResolveBWBinary_UsesTrustedLookup(t *testing.T) {
	orig := findTrustedBinaryFunc
	defer func() { findTrustedBinaryFunc = orig }()

	var lookedUp string
	findTrustedBinaryFunc = func(name string) (string, error) {
		lookedUp = name
		return "/trusted/bw", nil
	}

	got, err := resolveBWBinary("")
	if err != nil {
		t.Fatalf("resolveBWBinary() error = %v", err)
	}
	if lookedUp != "bw" {
		t.Fatalf("lookup name = %q, want %q", lookedUp, "bw")
	}
	if got != "/trusted/bw" {
		t.Fatalf("resolveBWBinary() = %q, want %q", got, "/trusted/bw")
	}
}

func TestResolveBWBinary_PropagatesLookupError(t *testing.T) {
	orig := findTrustedBinaryFunc
	defer func() { findTrustedBinaryFunc = orig }()

	findTrustedBinaryFunc = func(name string) (string, error) {
		return "", fmt.Errorf("%s missing", name)
	}

	if _, err := resolveBWBinary(""); err == nil {
		t.Fatal("resolveBWBinary() error = nil, want error")
	}
}
