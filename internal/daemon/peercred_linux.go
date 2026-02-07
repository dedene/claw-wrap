//go:build linux

package daemon

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func getPeerCredentials(conn *net.UnixConn) (*Ucred, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var out *Ucred
	var controlErr error
	err = rawConn.Control(func(fd uintptr) {
		ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			controlErr = err
			return
		}
		out = &Ucred{PID: ucred.Pid, UID: ucred.Uid, GID: ucred.Gid}
	})
	if err != nil {
		return nil, err
	}
	if controlErr != nil {
		return nil, controlErr
	}
	if out == nil {
		return nil, fmt.Errorf("peer credentials unavailable")
	}
	return out, nil
}

func resolvePeerExecutable(pid int32) (string, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	exe, err := os.Readlink(exePath)
	if err != nil {
		return "", err
	}
	if exe == "" {
		return "", fmt.Errorf("empty executable path")
	}
	return exe, nil
}
