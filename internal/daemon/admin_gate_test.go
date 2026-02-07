package daemon

import (
	"errors"
	"testing"
)

func TestAuthorizeAdminCheckCaller_AllowsClawWrapArgv0(t *testing.T) {
	origExe := resolvePeerExecutableFunc
	origArgv0 := resolvePeerArgv0Func
	resolvePeerExecutableFunc = func(pid int32) (string, error) {
		return "/usr/local/bin/claw-wrap", nil
	}
	resolvePeerArgv0Func = func(pid int32) (string, error) {
		return "/usr/local/bin/claw-wrap", nil
	}
	defer func() {
		resolvePeerExecutableFunc = origExe
		resolvePeerArgv0Func = origArgv0
	}()

	d := New(WithAllowedBinaries([]string{"/usr/local/bin/claw-wrap"}))
	if err := d.authorizeAdminCheckCaller(1234); err != nil {
		t.Fatalf("authorizeAdminCheckCaller() error = %v, want nil", err)
	}
}

func TestAuthorizeAdminCheckCaller_DeniesNonClawWrapArgv0(t *testing.T) {
	origExe := resolvePeerExecutableFunc
	origArgv0 := resolvePeerArgv0Func
	resolvePeerExecutableFunc = func(pid int32) (string, error) {
		return "/usr/local/bin/claw-wrap", nil
	}
	resolvePeerArgv0Func = func(pid int32) (string, error) {
		return "/usr/local/bin/gh", nil
	}
	defer func() {
		resolvePeerExecutableFunc = origExe
		resolvePeerArgv0Func = origArgv0
	}()

	d := New(WithAllowedBinaries([]string{"/usr/local/bin/claw-wrap"}))
	if err := d.authorizeAdminCheckCaller(1234); err == nil {
		t.Fatal("authorizeAdminCheckCaller() returned nil, want error for non-claw-wrap argv0")
	}
}

func TestAuthorizeAdminCheckCaller_DeniesUnreadableArgv0(t *testing.T) {
	origExe := resolvePeerExecutableFunc
	origArgv0 := resolvePeerArgv0Func
	resolvePeerExecutableFunc = func(pid int32) (string, error) {
		return "/usr/local/bin/claw-wrap", nil
	}
	resolvePeerArgv0Func = func(pid int32) (string, error) {
		return "", errors.New("read cmdline failed")
	}
	defer func() {
		resolvePeerExecutableFunc = origExe
		resolvePeerArgv0Func = origArgv0
	}()

	d := New(WithAllowedBinaries([]string{"/usr/local/bin/claw-wrap"}))
	if err := d.authorizeAdminCheckCaller(1234); err == nil {
		t.Fatal("authorizeAdminCheckCaller() returned nil, want error for unreadable argv0")
	}
}

func TestAuthorizeAdminCheckCaller_DeniesUnreadableExecutable(t *testing.T) {
	origExe := resolvePeerExecutableFunc
	origArgv0 := resolvePeerArgv0Func
	resolvePeerExecutableFunc = func(pid int32) (string, error) {
		return "", errors.New("read exe failed")
	}
	resolvePeerArgv0Func = func(pid int32) (string, error) {
		return "/usr/local/bin/claw-wrap", nil
	}
	defer func() {
		resolvePeerExecutableFunc = origExe
		resolvePeerArgv0Func = origArgv0
	}()

	d := New(WithAllowedBinaries([]string{"/usr/local/bin/claw-wrap"}))
	if err := d.authorizeAdminCheckCaller(1234); err == nil {
		t.Fatal("authorizeAdminCheckCaller() returned nil, want error for unreadable executable")
	}
}
