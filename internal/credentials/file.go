package credentials

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// maxSecretFileSize bounds how much of a file: credential is read.
const maxSecretFileSize = 64 * 1024

// fetchFromFile reads a mounted secret file (Docker/Kubernetes secret
// convention). Symlinks are followed because Kubernetes secret volumes are
// built from ..data symlinks. Trust comes from the file itself: it must be a
// regular file owned by root or the daemon user, and not group-writable or
// accessible by others. Trailing newlines are trimmed.
func fetchFromFile(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("secret file path must be absolute: %s", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open secret file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat secret file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("secret file must be a regular file: %s", path)
	}
	if perm := info.Mode().Perm(); perm&0o027 != 0 {
		return "", fmt.Errorf("secret file must not be group-writable or accessible by others: %s has %04o", path, perm)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("secret file: unsupported file stat type")
	}
	if owner := int(stat.Uid); owner != 0 && owner != currentEUIDFunc() {
		return "", fmt.Errorf("secret file owner must be root or the daemon uid: %s owner=%d daemon=%d", path, owner, currentEUIDFunc())
	}

	data, err := io.ReadAll(io.LimitReader(f, maxSecretFileSize+1))
	if err != nil {
		return "", fmt.Errorf("read secret file: %w", err)
	}
	if len(data) > maxSecretFileSize {
		return "", fmt.Errorf("secret file exceeds %d bytes: %s", maxSecretFileSize, path)
	}

	return strings.TrimRight(string(data), "\r\n"), nil
}
