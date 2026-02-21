package wrapper

import (
	"errors"
	"testing"
)

func TestDetectWindowSizeFromFDs_PrefersStdout(t *testing.T) {
	isTerminal := func(fd int) bool {
		return fd == 1 || fd == 0
	}
	getSize := func(fd int) (int, int, error) {
		switch fd {
		case 1:
			return 120, 40, nil
		case 0:
			return 80, 24, nil
		default:
			return 0, 0, errors.New("unexpected fd")
		}
	}

	size := detectWindowSizeFromFDs([]int{1, 0, 2}, isTerminal, getSize)
	if size == nil {
		t.Fatal("detectWindowSizeFromFDs() returned nil")
	}
	if size.Cols != 120 || size.Rows != 40 {
		t.Fatalf("size = %dx%d, want %dx%d", size.Cols, size.Rows, 120, 40)
	}
}

func TestDetectWindowSizeFromFDs_Fallbacks(t *testing.T) {
	t.Run("stdin fallback", func(t *testing.T) {
		isTerminal := func(fd int) bool {
			return fd == 0
		}
		getSize := func(fd int) (int, int, error) {
			if fd == 0 {
				return 95, 31, nil
			}
			return 0, 0, errors.New("unexpected fd")
		}

		size := detectWindowSizeFromFDs([]int{1, 0, 2}, isTerminal, getSize)
		if size == nil {
			t.Fatal("detectWindowSizeFromFDs() returned nil")
		}
		if size.Cols != 95 || size.Rows != 31 {
			t.Fatalf("size = %dx%d, want %dx%d", size.Cols, size.Rows, 95, 31)
		}
	})

	t.Run("stderr fallback", func(t *testing.T) {
		isTerminal := func(fd int) bool {
			return fd == 1 || fd == 2
		}
		getSize := func(fd int) (int, int, error) {
			if fd == 1 {
				return 0, 0, errors.New("size unavailable")
			}
			if fd == 2 {
				return 101, 33, nil
			}
			return 0, 0, errors.New("unexpected fd")
		}

		size := detectWindowSizeFromFDs([]int{1, 0, 2}, isTerminal, getSize)
		if size == nil {
			t.Fatal("detectWindowSizeFromFDs() returned nil")
		}
		if size.Cols != 101 || size.Rows != 33 {
			t.Fatalf("size = %dx%d, want %dx%d", size.Cols, size.Rows, 101, 33)
		}
	})
}

func TestDetectWindowSizeFromFDs_IgnoresInvalidSizes(t *testing.T) {
	isTerminal := func(fd int) bool {
		return true
	}
	getSize := func(fd int) (int, int, error) {
		switch fd {
		case 1:
			return 0, 24, nil
		case 0:
			return 80, 0, nil
		case 2:
			return 132, 44, nil
		default:
			return 0, 0, errors.New("unexpected fd")
		}
	}

	size := detectWindowSizeFromFDs([]int{1, 0, 2}, isTerminal, getSize)
	if size == nil {
		t.Fatal("detectWindowSizeFromFDs() returned nil")
	}
	if size.Cols != 132 || size.Rows != 44 {
		t.Fatalf("size = %dx%d, want %dx%d", size.Cols, size.Rows, 132, 44)
	}
}

func TestDetectWindowSizeFromFDs_NoValidTTY(t *testing.T) {
	isTerminal := func(fd int) bool {
		return false
	}
	getSize := func(fd int) (int, int, error) {
		return 80, 24, nil
	}

	size := detectWindowSizeFromFDs([]int{1, 0, 2}, isTerminal, getSize)
	if size != nil {
		t.Fatalf("detectWindowSizeFromFDs() = %v, want nil", size)
	}
}

func TestCallerTerminalEnv(t *testing.T) {
	t.Run("returns nil when empty", func(t *testing.T) {
		t.Setenv("TERM", "")
		t.Setenv("COLORTERM", "")

		env := callerTerminalEnv()
		if env != nil {
			t.Fatalf("callerTerminalEnv() = %v, want nil", env)
		}
	})

	t.Run("forwards term values", func(t *testing.T) {
		t.Setenv("TERM", "xterm-256color")
		t.Setenv("COLORTERM", "truecolor")

		env := callerTerminalEnv()
		if env == nil {
			t.Fatal("callerTerminalEnv() returned nil")
		}
		if env["TERM"] != "xterm-256color" {
			t.Fatalf("TERM = %q, want %q", env["TERM"], "xterm-256color")
		}
		if env["COLORTERM"] != "truecolor" {
			t.Fatalf("COLORTERM = %q, want %q", env["COLORTERM"], "truecolor")
		}
	})
}
