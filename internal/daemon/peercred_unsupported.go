//go:build !linux && !darwin

package daemon

import (
	"fmt"
	"net"
)

func getPeerCredentials(conn *net.UnixConn) (*Ucred, error) {
	_ = conn
	return nil, fmt.Errorf("peer credential verification is unsupported on this platform")
}

func resolvePeerExecutable(pid int32) (string, error) {
	_ = pid
	return "", fmt.Errorf("peer executable resolution is unsupported on this platform")
}
