//go:build darwin

package daemon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

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
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			controlErr = err
			return
		}
		pid, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		if err != nil {
			controlErr = err
			return
		}
		var gid uint32
		if cred.Ngroups > 0 {
			gid = cred.Groups[0]
		}
		out = &Ucred{PID: int32(pid), UID: cred.Uid, GID: gid}
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
	raw, err := unix.SysctlRaw("kern.procargs2", int(pid))
	if err != nil {
		return "", err
	}
	if len(raw) < 4 {
		return "", fmt.Errorf("invalid procargs payload")
	}

	_ = binary.LittleEndian.Uint32(raw[:4]) // argc, not required for extracting executable path
	data := raw[4:]
	start := 0
	for start < len(data) && data[start] == 0 {
		start++
	}
	if start >= len(data) {
		return "", fmt.Errorf("missing executable path")
	}

	endRel := bytes.IndexByte(data[start:], 0)
	if endRel < 0 {
		return "", fmt.Errorf("unterminated executable path")
	}
	exe := string(data[start : start+endRel])
	if exe == "" {
		return "", fmt.Errorf("empty executable path")
	}
	return exe, nil
}

func resolvePeerArgv0(pid int32) (string, error) {
	raw, err := unix.SysctlRaw("kern.procargs2", int(pid))
	if err != nil {
		return "", err
	}
	if len(raw) < 4 {
		return "", fmt.Errorf("invalid procargs payload")
	}

	_ = binary.LittleEndian.Uint32(raw[:4]) // argc, not required for extracting argv0
	data := raw[4:]

	// Skip executable path.
	start := 0
	for start < len(data) && data[start] == 0 {
		start++
	}
	if start >= len(data) {
		return "", fmt.Errorf("missing executable path")
	}
	endRel := bytes.IndexByte(data[start:], 0)
	if endRel < 0 {
		return "", fmt.Errorf("unterminated executable path")
	}
	pos := start + endRel

	// Skip NUL padding between executable path and argv entries.
	for pos < len(data) && data[pos] == 0 {
		pos++
	}
	if pos >= len(data) {
		return "", fmt.Errorf("missing argv0")
	}

	argvEndRel := bytes.IndexByte(data[pos:], 0)
	if argvEndRel < 0 {
		return "", fmt.Errorf("unterminated argv0")
	}
	argv0 := string(data[pos : pos+argvEndRel])
	if argv0 == "" {
		return "", fmt.Errorf("empty argv0")
	}
	return argv0, nil
}
