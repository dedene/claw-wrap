package daemon

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

var (
	allowedAuthFileModes = map[os.FileMode]struct{}{
		0o600: {},
		0o640: {},
	}
	allowedSocketFileModes = map[os.FileMode]struct{}{
		0o600: {},
		0o660: {},
	}
)

// ParseAuthFileMode parses and validates auth file mode values.
func ParseAuthFileMode(raw string) (os.FileMode, error) {
	mode, err := parsePermMode(raw)
	if err != nil {
		return 0, err
	}
	if !IsAllowedAuthFileMode(mode) {
		return 0, fmt.Errorf("invalid auth mode %04o (allowed: 0600, 0640)", mode)
	}
	return mode, nil
}

// ParseSocketFileMode parses and validates socket file mode values.
func ParseSocketFileMode(raw string) (os.FileMode, error) {
	mode, err := parsePermMode(raw)
	if err != nil {
		return 0, err
	}
	if !IsAllowedSocketFileMode(mode) {
		return 0, fmt.Errorf("invalid socket mode %04o (allowed: 0600, 0660)", mode)
	}
	return mode, nil
}

// IsAllowedAuthFileMode returns true for supported auth file modes.
func IsAllowedAuthFileMode(mode os.FileMode) bool {
	_, ok := allowedAuthFileModes[mode.Perm()]
	return ok
}

// IsAllowedSocketFileMode returns true for supported socket file modes.
func IsAllowedSocketFileMode(mode os.FileMode) bool {
	_, ok := allowedSocketFileModes[mode.Perm()]
	return ok
}

func parsePermMode(raw string) (os.FileMode, error) {
	modeStr := strings.TrimSpace(raw)
	if modeStr == "" {
		return 0, fmt.Errorf("mode cannot be empty")
	}
	modeStr = strings.TrimPrefix(modeStr, "0o")
	value, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid mode %q: %w", raw, err)
	}
	return os.FileMode(value).Perm(), nil
}
