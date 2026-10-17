//go:build unix

package portsplit

import (
	"errors"
	"io"
	"net"
	"syscall"
)

// peekKind reads c's first bytes with MSG_PEEK until they classify it,
// leaving them in the socket for whoever reads the connection next. A
// connection that cannot be peeked at is CEDAR.
func peekKind(c net.Conn) (Kind, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return CEDAR, nil
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return CEDAR, err
	}
	var (
		buf     [maxPeek]byte
		kind    Kind
		peekErr error
	)
	err = rc.Read(func(fd uintptr) bool {
		n, _, rerr := syscall.Recvfrom(int(fd), buf[:], syscall.MSG_PEEK)
		switch {
		case errors.Is(rerr, syscall.EAGAIN), errors.Is(rerr, syscall.EINTR):
			return false
		case rerr != nil:
			peekErr = rerr
			return true
		case n == 0:
			peekErr = io.EOF
			return true
		}
		var decided bool
		kind, decided = Classify(buf[:n])
		// Undecided: wait for more bytes to arrive.
		return decided
	})
	if err != nil {
		return CEDAR, err
	}
	return kind, peekErr
}
